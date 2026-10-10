/* SPDX-License-Identifier: MIT
 * warden_exec.inc.c — v1.27: the launch ruleset (included by warden.c).
 *
 * docs/security/v1.27-program-launches.md, section 2. With `require warden
 * 1.27` the Warden builds, before the agent starts, the set of files the
 * agent may launch: every file the policy's allow exec rules admit (a matcher
 * rule expanded against the files that exist; each candidate decided by the
 * decision procedure, so an earlier deny wins), each one's dynamic loader,
 * and the program the operator named (with a script's interpreter). The
 * kernel enforces the set: a Landlock ruleset that handles
 * LANDLOCK_ACCESS_FS_EXECUTE and grants it on these files only, applied in
 * the agent's process before its own launch and inherited by everything it
 * starts. Each file is held by device and inode, with its SHA-256 at
 * startup, and listed in run_start.
 *
 * Decisions stay on the path as the agent names it (the policy's names);
 * the set is of files. Without Landlock the set is still built and recorded,
 * no domain is applied, and every later launch is refused (exec_no_landlock,
 * section 3 of the design, step 3).
 */

#include <sys/prctl.h>
#include <dirent.h>
#include <elf.h>
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
struct landlock_ruleset_attr { uint64_t handled_access_fs; };
struct landlock_path_beneath_attr { uint64_t allowed_access; int32_t parent_fd; } __attribute__((packed));
#endif
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

#define EXEC_RS_MAX         4096      /* files in the set */
#define EXEC_RULE_MAX_FILES 256       /* files one rule may admit (design section 2) */
#define EXEC_WALK_MAX       200000    /* directory entries one expansion may visit */
#define EXEC_WALK_DEPTH     16

struct exec_file {
    dev_t  dev;
    ino_t  ino;
    char  *name;          /* the name it was admitted by (a policy name, or the loader's) */
    char  *path;          /* canonical path at startup */
    char   sha[65];       /* SHA-256 at startup */
    const char *why;      /* "rule", "loader", "bootstrap", "interpreter" */
    int    line;          /* the deciding rule's policy line (why "rule"), else 0 */
    bool   image;         /* step 4: a program the Warden decided to run (a process may run it) */
};

static int exec_image_of(const char *path, dev_t *dev, ino_t *ino);      /* step 4, below */
static void exec_mark_image(dev_t dev, ino_t ino);
static int exec_pend_add(pid_t tid, dev_t edev, ino_t eino, uint64_t seq);

static struct exec_file *g_exec_rs;
static size_t g_exec_n;
static int g_ll_abi = -1;         /* Landlock ABI; -1 when it is not available */
static int g_ll_fd = -1;          /* the ruleset, applied in the agent */
static char g_ll_why[160];        /* why Landlock is not available */
static size_t g_exec_walked;

/* The Landlock ABI, or -1 with the reason. VAREK_WARDEN_TEST_NO_LANDLOCK=1
 * acts as if it were missing (make test-v1270). */
static int exec_landlock_abi(void) {
    if (getenv("VAREK_WARDEN_TEST_NO_LANDLOCK")) {
        snprintf(g_ll_why, sizeof g_ll_why, "VAREK_WARDEN_TEST_NO_LANDLOCK is set");
        return -1;
    }
    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        snprintf(g_ll_why, sizeof g_ll_why, "%s",
                 errno == ENOSYS ? "the kernel has no Landlock (5.13 or later is needed)" :
                 errno == EOPNOTSUPP ? "Landlock is not enabled (it is not in the kernel's LSM list)" :
                 strerror(errno));
        return -1;
    }
    return (int)abi;
}

/* PT_INTERP of the ELF file on fd: 1 with the loader's path, 0 when there is
 * none (a static program, or not ELF), -1 for a malformed header. Bounded:
 * at most 512 program headers, an interpreter path under PATH_MAX. */
static int exec_elf_interp(int fd, char *out, size_t outn) {
    unsigned char e[64];
    if (pread(fd, e, sizeof e, 0) != (ssize_t)sizeof e || memcmp(e, ELFMAG, SELFMAG)) return 0;
    if (e[EI_DATA] != ELFDATA2LSB) return 0;                 /* the hosts we run on */
    uint64_t phoff; uint16_t phentsize, phnum;
    if (e[EI_CLASS] == ELFCLASS64) {
        const Elf64_Ehdr *h = (const Elf64_Ehdr *)e;
        phoff = h->e_phoff; phentsize = h->e_phentsize; phnum = h->e_phnum;
        if (phentsize != sizeof(Elf64_Phdr)) return -1;
    } else if (e[EI_CLASS] == ELFCLASS32) {
        const Elf32_Ehdr *h = (const Elf32_Ehdr *)e;
        phoff = h->e_phoff; phentsize = h->e_phentsize; phnum = h->e_phnum;
        if (phentsize != sizeof(Elf32_Phdr)) return -1;
    } else return 0;
    if (phnum > 512) return -1;
    for (uint16_t k = 0; k < phnum; k++) {
        uint64_t off, sz;
        uint32_t type;
        if (e[EI_CLASS] == ELFCLASS64) {
            Elf64_Phdr ph;
            if (pread(fd, &ph, sizeof ph, (off_t)(phoff + (uint64_t)k * phentsize)) != (ssize_t)sizeof ph) return -1;
            type = ph.p_type; off = ph.p_offset; sz = ph.p_filesz;
        } else {
            Elf32_Phdr ph;
            if (pread(fd, &ph, sizeof ph, (off_t)(phoff + (uint64_t)k * phentsize)) != (ssize_t)sizeof ph) return -1;
            type = ph.p_type; off = ph.p_offset; sz = ph.p_filesz;
        }
        if (type != PT_INTERP) continue;
        if (sz < 2 || sz >= outn || sz >= PATH_MAX) return -1;
        if (pread(fd, out, (size_t)sz, (off_t)off) != (ssize_t)sz) return -1;
        out[sz] = '\0';
        if (strlen(out) != sz - 1 || out[0] != '/') return -1;
        return 1;
    }
    return 0;
}

/* A script's interpreter: the first word after "#!", 1 with it, 0 for a
 * file that is not a script, -1 for a malformed line. */
static int exec_script_interp(int fd, char *out, size_t outn) {
    char b[PATH_MAX + 8];
    ssize_t n = pread(fd, b, sizeof b - 1, 0);
    if (n < 2 || b[0] != '#' || b[1] != '!') return 0;
    b[n] = '\0';
    char *s = b + 2;
    while (*s == ' ' || *s == '\t') s++;
    size_t k = strcspn(s, " \t\n");
    if (k == 0 || k >= outn || s[0] != '/' || (s[k] != ' ' && s[k] != '\t' && s[k] != '\n')) return -1;
    memcpy(out, s, k);
    out[k] = '\0';
    return 1;
}

static int exec_hash_fd(int fd, char out[65]) {
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    unsigned char buf[65536];
    off_t at = 0;
    for (;;) {
        ssize_t n = pread(fd, buf, sizeof buf, at);
        if (n < 0) return -1;
        if (n == 0) break;
        crypto_hash_sha256_update(&st, buf, (size_t)n);
        at += n;
    }
    unsigned char h[32];
    crypto_hash_sha256_final(&st, h);
    sodium_bin2hex(out, 65, h, sizeof h);
    return 0;
}

static const struct exec_file *exec_rs_find(dev_t dev, ino_t ino) {
    for (size_t k = 0; k < g_exec_n; k++)
        if (g_exec_rs[k].dev == dev && g_exec_rs[k].ino == ino) return &g_exec_rs[k];
    return NULL;
}

/* Add the file name names (following symlinks) with its loader. 1 added (or
 * already there), 0 not a launchable file (missing, not regular, no execute
 * bit), -1 an error that stops the run (why in err). */
static int exec_rs_add(const char *name, const char *why, int line, char *err, size_t en) {
    int fd = open(name, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) { close(fd); return 0; }
    if (exec_rs_find(st.st_dev, st.st_ino)) { close(fd); return 1; }
    if (g_exec_n == EXEC_RS_MAX) {
        close(fd);
        snprintf(err, en, "the launch set would hold more than %d files", EXEC_RS_MAX);
        return -1;
    }
    struct exec_file *f = &g_exec_rs[g_exec_n];
    char canon[PATH_MAX];
    char fdp[64];
    snprintf(fdp, sizeof fdp, "/proc/self/fd/%d", fd);
    ssize_t cl = readlink(fdp, canon, sizeof canon - 1);
    if (cl <= 0) { close(fd); snprintf(err, en, "%s: cannot name the file", name); return -1; }
    canon[cl] = '\0';
    if (exec_hash_fd(fd, f->sha) < 0) { close(fd); snprintf(err, en, "%s: cannot read it", name); return -1; }
    f->dev = st.st_dev;
    f->ino = st.st_ino;
    f->name = strdup(name);
    f->path = strdup(canon);
    f->why = why;
    f->line = line;
    if (!f->name || !f->path) { close(fd); snprintf(err, en, "out of memory"); return -1; }
    g_exec_n++;
    /* the kernel opens a dynamic program's loader to launch it */
    char interp[PATH_MAX];
    int ir = exec_elf_interp(fd, interp, sizeof interp);
    close(fd);
    if (ir < 0) { snprintf(err, en, "%s: a malformed ELF header", name); return -1; }
    if (ir == 1) {
        int lr = exec_rs_add(interp, "loader", 0, err, en);
        if (lr < 0) return -1;
        if (lr == 0) {
            snprintf(err, en, "%s: its loader %s is not a launchable file", name, interp);
            return -1;
        }
    }
    return 1;
}

/* Expanding allow exec rules: each candidate the walk finds is decided like a
 * launch of that name. Counts per deciding rule in admitted[]. */
static int exec_consider(const struct policy *p, const char *cand, size_t *admitted, char *err, size_t en) {
    int ri = -1;
    vdp_why_t why;
    if (vdp_decide(&p->v, VDP_KIND_EXEC, cand, 0, false, &ri, &why) != VDP_SATISFIED || ri < 0) return 0;
    int r = exec_rs_add(cand, "rule", p->v.rules[ri].line, err, en);
    if (r < 0) return -1;
    if (r > 0 && ++admitted[ri] > EXEC_RULE_MAX_FILES) {
        snprintf(err, en, "line %d admits more than %d files to launch; name them, or narrow the rule",
                 p->v.rules[ri].line, EXEC_RULE_MAX_FILES);
        return -1;
    }
    return 0;
}

static int exec_walk(const struct policy *p, const char *dir, const char *must, int depth,
                     size_t *admitted, int line, char *err, size_t en) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int rc = 0;
    while (rc == 0 && (de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (++g_exec_walked > EXEC_WALK_MAX) {
            snprintf(err, en, "expanding line %d visits more than %d entries; narrow the rule",
                     line, EXEC_WALK_MAX);
            rc = -1;
            break;
        }
        char cand[PATH_MAX];
        size_t dl = strlen(dir);
        if (snprintf(cand, sizeof cand, "%s%s%s", dir, dl && dir[dl - 1] == '/' ? "" : "/", de->d_name)
            >= (int)sizeof cand) continue;
        struct stat st;
        if (lstat(cand, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {           /* real directories only: no symlink loops */
            if (depth < EXEC_WALK_DEPTH && !strncmp(cand, must, strnlen(must, strlen(cand))))
                rc = exec_walk(p, cand, must, depth + 1, admitted, line, err, en);
            continue;
        }
        if (strncmp(cand, must, strlen(must))) continue;
        rc = exec_consider(p, cand, admitted, err, en);
    }
    closedir(d);
    return rc;
}

/* Build the set (and with Landlock the ruleset). 0, or -1 (the Warden does
 * not start, the reason printed). */
static int exec_ruleset_build(const struct policy *p, const char *boot_path) {
    char err[600] = "";
    g_exec_policy = p;
    g_exec_rs = calloc(EXEC_RS_MAX, sizeof *g_exec_rs);
    size_t *admitted = calloc(p->v.n ? p->v.n : 1, sizeof *admitted);
    if (!g_exec_rs || !admitted) { fprintf(stderr, "[warden] out of memory\n"); return -1; }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind != VDP_KIND_EXEC || r->verb != VDP_ALLOW) continue;
        /* an exact or prefix constant not starting with '/' matches no
         * launch (the Warden decides on absolute paths; lint notes it) */
        if ((r->s.op == VDP_STR_EQ || r->s.op == VDP_STR_PREFIX) && r->s.c[0] != '/') continue;
        if (r->s.op == VDP_STR_EQ) {
            struct stat st;
            if (stat(r->s.c, &st) < 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111))
                fprintf(stderr, "[warden] note: policy line %d: %s is not a launchable file on this host "
                        "(missing, not a regular file, or no execute bit); it is not in the launch set\n",
                        r->line, r->s.c);
            rc = exec_consider(p, r->s.c, admitted, err, sizeof err);
            continue;
        }
        if (r->s.op != VDP_STR_PREFIX && r->s.op != VDP_STR_GLOB) {
            snprintf(err, sizeof err, "line %d: an allow exec rule with %s cannot be expanded to the "
                     "files it admits; use an exact path, prefix or glob", r->line, vdp_matcher_prefix(r));
            rc = -1;
            break;
        }
        /* the literal part: a prefix's constant; a glob's, to its first wildcard */
        char must[VDP_STR_MAX + 1];
        size_t k = 0;
        for (const char *c = r->s.c; *c && k < sizeof must - 1; c++) {
            if (r->s.op == VDP_STR_GLOB && (*c == '*' || *c == '?' || *c == '[' || *c == '\\')) break;
            must[k++] = *c;
        }
        must[k] = '\0';
        if (must[0] != '/') {          /* a glob that starts with a wildcard */
            snprintf(err, sizeof err, "line %d: an allow exec glob must start with a directory "
                     "(\"/...\") to be expanded to the files it admits", r->line);
            rc = -1;
            break;
        }
        char dir[VDP_STR_MAX + 1];
        snprintf(dir, sizeof dir, "%s", must);
        char *sl = strrchr(dir, '/');
        if (sl) sl[1] = '\0';
        g_exec_walked = 0;
        rc = exec_walk(p, dir, must, 0, admitted, r->line, err, sizeof err);
    }
    free(admitted);
    /* the program the operator named, and a script's interpreter */
    if (rc == 0 && boot_path) {
        int br = exec_rs_add(boot_path, "bootstrap", 0, err, sizeof err);
        if (br < 0) rc = -1;
        int fd = br > 0 ? open(boot_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;
        char interp[PATH_MAX];
        int sr = fd >= 0 ? exec_script_interp(fd, interp, sizeof interp) : 0;
        if (fd >= 0) close(fd);
        if (rc == 0 && sr < 0) { snprintf(err, sizeof err, "%s: a malformed #! line", boot_path); rc = -1; }
        if (rc == 0 && sr == 1) {
            int ir = exec_rs_add(interp, "interpreter", 0, err, sizeof err);
            if (ir == 0) { snprintf(err, sizeof err, "%.250s: its interpreter %.250s is not a launchable file",
                                    boot_path, interp); rc = -1; }
            else if (ir < 0) rc = -1;
        }
    }
    if (rc < 0) {
        fprintf(stderr, "[warden] the launch set: %s; refusing to start\n", err);
        return -1;
    }
    /* step 4: the agent's own launch runs the bootstrap's image */
    if (boot_path) {
        dev_t d; ino_t i;
        if (exec_image_of(boot_path, &d, &i) == 0) exec_mark_image(d, i);
    }
    /* notes on what the set holds */
    for (size_t k = 0; k < g_exec_n; k++) {
        const struct exec_file *f = &g_exec_rs[k];
        if (strcmp(f->why, "rule")) continue;
        bool exact = false;            /* an exact rule's name was noted at load */
        for (size_t i = 0; i < p->v.n; i++)
            if (p->v.rules[i].kind == VDP_KIND_EXEC && p->v.rules[i].s.op == VDP_STR_EQ &&
                !strcmp(p->v.rules[i].s.c, f->name)) exact = true;
        if (!exact && (vdp_exec_is_interpreter(f->name) || vdp_exec_is_interpreter(f->path)))
            fprintf(stderr, "[warden] note: launch set: %s (line %d) is a shell or general-purpose "
                    "interpreter: the agent can run any code it can read with it\n", f->name, f->line);
        static const uint32_t kW[] = { O_WRONLY, O_RDWR, O_WRONLY | O_TRUNC, O_RDWR | O_TRUNC };
        for (size_t w = 0; w < sizeof kW / sizeof kW[0]; w++)
            if (vdp_decide(&p->v, VDP_KIND_PATH, f->path, kW[w], true, NULL, NULL) == VDP_SATISFIED) {
                fprintf(stderr, "[warden] note: launch set: %s (%s) may be both launched and written by "
                        "the agent: a launch runs the file as it is then, not as hashed now\n",
                        f->name, f->path);
                break;
            }
        int fd = open(f->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        char interp[PATH_MAX];
        if (fd >= 0 && exec_script_interp(fd, interp, sizeof interp) == 1) {
            struct stat st;
            if (stat(interp, &st) < 0 || !exec_rs_find(st.st_dev, st.st_ino))
                fprintf(stderr, "[warden] note: launch set: %s is a script for %s, which the policy does "
                        "not allow to launch: launching it will fail\n", f->name, interp);
        }
        if (fd >= 0) close(fd);
    }
    g_ll_abi = exec_landlock_abi();
    if (g_ll_abi < 0) {
        fprintf(stderr, "[warden] Landlock is not available (%s): launches after the first will be "
                "refused (exec_no_landlock)\n", g_ll_why);
        return 0;
    }
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE };
    g_ll_fd = (int)syscall(__NR_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (g_ll_fd < 0) {
        fprintf(stderr, "[warden] cannot create the Landlock ruleset (%s); refusing to start\n", strerror(errno));
        return -1;
    }
    (void)fcntl(g_ll_fd, F_SETFD, FD_CLOEXEC);
    for (size_t k = 0; k < g_exec_n; k++) {
        const struct exec_file *f = &g_exec_rs[k];
        int fd = open(f->path, O_PATH | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) < 0 || st.st_dev != f->dev || st.st_ino != f->ino) {
            if (fd >= 0) close(fd);
            fprintf(stderr, "[warden] %s changed while the launch set was built; refusing to start\n", f->path);
            return -1;
        }
        struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE, .parent_fd = fd };
        long ar = syscall(__NR_landlock_add_rule, g_ll_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        close(fd);
        if (ar < 0) {
            fprintf(stderr, "[warden] cannot add %s to the Landlock ruleset (%s); refusing to start\n",
                    f->path, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* In the agent's process, before its own launch: enter the domain. 0, or -1
 * (the agent does not start). */
static int exec_ruleset_apply(void) {
    if (g_ll_fd < 0) return 0;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        syscall(__NR_landlock_restrict_self, g_ll_fd, 0) < 0) return -1;
    close(g_ll_fd);
    g_ll_fd = -1;
    return 0;
}

/* run_start: the Landlock ABI (or null) and the launch set */
static void exec_ruleset_record(FILE *f) {
    if (g_ll_abi >= 1) fprintf(f, "\"landlock\":{\"abi\":%d},", g_ll_abi);
    else fputs("\"landlock\":null,", f);
    fputs("\"exec_ruleset\":[", f);
    for (size_t k = 0; k < g_exec_n; k++) {
        const struct exec_file *e = &g_exec_rs[k];
        fprintf(f, "%s{\"name\":\"", k ? "," : "");
        json_escape(f, e->name);
        fputs("\",\"path\":\"", f);
        json_escape(f, e->path);
        fprintf(f, "\",\"dev\":%llu,\"ino\":%llu,\"sha256\":\"%s\",\"why\":\"%s\"",
                (unsigned long long)e->dev, (unsigned long long)e->ino, e->sha, e->why);
        if (e->line) fprintf(f, ",\"policy_line\":%d", e->line);
        fputs("}", f);
    }
    fputs("],", f);
}

/* ---- v1.27 step 3: deciding a launch (design section 3) ---- */

/* The name a launch is decided on, and the file it reaches. The name is the
 * path as the agent wrote it, made absolute: a relative path joined to the
 * canonical path of the directory it is relative to (the agent's cwd, or
 * execveat's dirfd), "." and empty segments dropped, and the part through a
 * last ".." segment replaced by the directory it resolves to. A final
 * symlink keeps its own name, as the policy writes names (/usr/bin/python3).
 * execveat(fd, "", AT_EMPTY_PATH) is named by the descriptor's file. The file
 * is opened (O_PATH, following symlinks as the launch would, no magic links)
 * and its device and inode returned. 0, or -1 (refused: exec_unresolved). */
static int exec_name(const struct seccomp_notif *req, struct action *a, struct stat *st) {
    a->resolved[0] = '\0';
    pid_t tid = (pid_t)req->pid;
    bool at = req->data.nr == __NR_execveat;
    int dirfd = at ? (int)(int32_t)req->data.args[0] : AT_FDCWD;
    uint64_t flags = at ? req->data.args[4] : 0;
    if (flags & ~(uint64_t)(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) return -1;
    char bp[64];
    int base;
    if (dirfd == AT_FDCWD) snprintf(bp, sizeof bp, "/proc/%d/cwd", tid);
    else if (dirfd >= 0) snprintf(bp, sizeof bp, "/proc/%d/fd/%d", tid, dirfd);
    else return -1;
    if ((flags & AT_EMPTY_PATH) && a->target[0] == '\0') {
        /* by descriptor: the file it refers to */
        int fd = open(bp, O_PATH | O_CLOEXEC);
        if (fd < 0) return -1;
        int ok = fstat(fd, st) == 0 && S_ISREG(st->st_mode) &&
                 fd_canonical_path(fd, a->resolved, sizeof a->resolved) == 0;
        close(fd);
        if (!ok) { a->resolved[0] = '\0'; return -1; }
        return 0;
    }
    if (a->target[0] == '\0') return -1;
    base = open(bp, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (base < 0) return -1;
    /* the file */
    int fd = openat2_path(base, a->target, (flags & AT_SYMLINK_NOFOLLOW) ? (uint64_t)O_NOFOLLOW : 0);
    if (fd < 0 || fstat(fd, st) < 0 || !S_ISREG(st->st_mode)) {
        if (fd >= 0) close(fd);
        close(base);
        return -1;
    }
    close(fd);
    /* the name */
    char joined[PATH_LIMIT * 2];
    if (a->target[0] == '/') snprintf(joined, sizeof joined, "%s", a->target);
    else {
        char dir[PATH_LIMIT];
        if (fd_canonical_path(base, dir, sizeof dir) < 0) { close(base); return -1; }
        snprintf(joined, sizeof joined, "%s/%s", dir, a->target);
    }
    /* through the last ".." segment: the directory it resolves to */
    const char *rest = joined;
    char head[PATH_LIMIT] = "";
    for (const char *q = joined; (q = strstr(q, "/..")); q++)
        if (q[3] == '/' || q[3] == '\0') rest = q + 3;
    if (rest != joined) {
        char pre[PATH_LIMIT * 2];
        snprintf(pre, sizeof pre, "%.*s", (int)(rest - joined), joined);
        int dfd = openat2_path(base, pre, (uint64_t)O_DIRECTORY);
        if (dfd < 0 || fd_canonical_path(dfd, head, sizeof head) < 0) {
            if (dfd >= 0) close(dfd);
            close(base);
            return -1;
        }
        close(dfd);
        if (!strcmp(head, "/")) head[0] = '\0';
    }
    close(base);
    /* drop "." and empty segments */
    size_t n = strlen(head);
    char seg[PATH_LIMIT * 2];
    snprintf(seg, sizeof seg, "%s", rest);
    char *save = NULL;
    for (char *t = strtok_r(seg, "/", &save); t; t = strtok_r(NULL, "/", &save)) {
        if (!strcmp(t, ".")) continue;
        size_t tl = strlen(t);
        if (n + 1 + tl >= sizeof a->resolved) { a->resolved[0] = '\0'; return -1; }
        head[n++] = '/';
        memcpy(head + n, t, tl);
        n += tl;
        head[n] = '\0';
    }
    if (n == 0) return -1;
    memcpy(a->resolved, head, n + 1);
    return 0;
}

/* A launch after the first, with `require warden 1.27`: decided on its name
 * (certified), then CONTINUE only if Landlock holds the agent and the file
 * is one of the set (by device and inode). Recorded before it is answered. */
static void exec_launch(int notify_fd, const struct seccomp_notif *req, struct action *a,
                        const struct policy *p, const struct timespec *t0) {
    struct stat st;
    const struct exec_file *ef = NULL;
    const char *rule = NULL;
    decision_t d_raw = DEC_UNKNOWN, d_final = DEC_DENY;
    if (exec_name(req, a, &st) < 0) {
        rule = "exec_unresolved";
    } else {
        d_raw = policy_decide(p, a);
        d_final = d_raw == DEC_ALLOW ? DEC_ALLOW : DEC_DENY;
        if (d_final == DEC_ALLOW && !certify(p, a)) { d_final = DEC_DENY; rule = "certificate_refused"; }
        else if (d_final == DEC_ALLOW && g_ll_abi < 1) { d_final = DEC_DENY; rule = "exec_no_landlock"; }
        else if (d_final == DEC_ALLOW && !(ef = exec_rs_find(st.st_dev, st.st_ino))) {
            d_final = DEC_DENY;
            rule = "exec_not_in_ruleset";
        }
        if (!rule) rule = d_final == DEC_ALLOW ? "exec_allowed" : decision_rule_id(a, d_raw);
    }
    if (ef) {
        size_t k = (size_t)(ef - g_exec_rs);
        snprintf(a->extra, sizeof a->extra, "\"exec_set\":%zu,\"exec_dev\":%llu,\"exec_ino\":%llu,"
                 "\"exec_sha256\":\"%s\",", k, (unsigned long long)ef->dev, (unsigned long long)ef->ino, ef->sha);
    }
    /* step 4: the image the launch runs becomes one a process may run, and
     * the launch is pending until the Warden sees it (exec_identity) */
    if (d_final == DEC_ALLOW) {
        dev_t idev = 0; ino_t iino = 0;
        static int mismatch_test = -1;      /* make test-v1270: force a mismatch */
        if (mismatch_test < 0) mismatch_test = getenv("VAREK_WARDEN_TEST_EXEC_MISMATCH") != NULL;
        if (!mismatch_test && exec_image_of(ef->path, &idev, &iino) == 0) exec_mark_image(idev, iino);
        if (mismatch_test) { idev = 0; iino = 0; }
        if (exec_pend_add((pid_t)req->pid, idev, iino, g_records) < 0) {
            d_final = DEC_DENY;
            rule = "exec_unresolved";
            a->extra[0] = '\0';
        }
    }
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t lat = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
    emit_pathology(g_report_seq++, (pid_t)req->pid, a, d_raw, d_final, rule, lat,
                   d_final == DEC_ALLOW ? 0 : EACCES);
    send_simple(notify_fd, req->id, d_final);
}

/* ---- v1.27 step 4: the identity check (design section 3) ---- */

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
#define EXEC_PEND_MAX 512

/* A launch continued and not yet seen: the image it should become (the
 * decided file, or the interpreter a script names), and the image the process
 * ran when it asked. */
struct exec_pend {
    pid_t    tid, tgid;
    dev_t    edev, odev;
    ino_t    eino, oino;
    uint64_t seq;          /* the exec_allowed record */
    int      pidfd;        /* the thread group, to tell it from a later one with its pid */
};
static struct exec_pend g_xp[EXEC_PEND_MAX];
static size_t g_nxp;
static bool g_exec_checking;     /* launches on and the agent's own launch done */

/* The image a launch of path runs: the file itself, or for a script the
 * interpreter its #! names (followed up to 4 levels, as the kernel does). 0
 * with dev/ino, or -1. */
static int exec_image_of(const char *path, dev_t *dev, ino_t *ino) {
    char cur[PATH_MAX];
    snprintf(cur, sizeof cur, "%s", path);
    for (int depth = 0; depth < 5; depth++) {
        int fd = open(cur, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) < 0) { if (fd >= 0) close(fd); return -1; }
        char interp[PATH_MAX];
        int r = exec_script_interp(fd, interp, sizeof interp);
        close(fd);
        if (r != 1) { *dev = st.st_dev; *ino = st.st_ino; return 0; }
        snprintf(cur, sizeof cur, "%s", interp);
    }
    return -1;
}

static void exec_mark_image(dev_t dev, ino_t ino) {
    for (size_t k = 0; k < g_exec_n; k++)
        if (g_exec_rs[k].dev == dev && g_exec_rs[k].ino == ino) g_exec_rs[k].image = true;
}

static void exec_result(const struct exec_pend *x, const char *result) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"exec_result\",\"run\":\"%s\",\"decision_seq\":%" PRIu64 ",\"agent_pid\":%d,"
               "\"result\":\"%s\",\"timestamp_ns\":%lld}\n",
            g_run_id, x->seq, (int)x->tgid, result, (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);
}

static void exec_pend_drop(size_t k, const char *result) {
    if (result) exec_result(&g_xp[k], result);
    if (g_xp[k].pidfd >= 0) close(g_xp[k].pidfd);
    g_xp[k] = g_xp[--g_nxp];
}

/* Register a continued launch, before it is answered. 0, or -1 (refuse it). */
static int exec_pend_add(pid_t tid, dev_t edev, ino_t eino, uint64_t seq) {
    if (g_nxp == EXEC_PEND_MAX) return -1;
    char ep[64];
    struct stat ost;
    snprintf(ep, sizeof ep, "/proc/%d/exe", tid);
    pid_t tgid = task_tgid(tid);
    if (tgid < 0 || stat(ep, &ost) < 0) return -1;
    int pidfd = (int)syscall(__NR_pidfd_open, tgid, 0);
    if (pidfd < 0) return -1;
    g_xp[g_nxp++] = (struct exec_pend){ .tid = tid, .tgid = tgid, .edev = edev, .eino = eino,
                                        .odev = ost.st_dev, .oino = ost.st_ino, .seq = seq, .pidfd = pidfd };
    return 0;
}

/* Before any call of the agent is answered (launches on, after its own
 * launch): the calling process must run a program the Warden decided to run,
 * and a process with a launch pending must run either the image it asked
 * from (the launch has not happened, or failed) or the one decided. Else it
 * is killed and the call refused (exec_identity_mismatch). true when the call
 * was answered here. */
static bool exec_identity(int notify_fd, const struct seccomp_notif *req, struct action *a,
                          const struct timespec *t0) {
    if (!g_exec_checking) return false;
    pid_t tid = (pid_t)req->pid;
    /* launches whose process has gone without a call seen */
    for (size_t k = 0; k < g_nxp; )
        if (syscall(__NR_pidfd_send_signal, g_xp[k].pidfd, 0, NULL, 0) < 0 && errno == ESRCH)
            exec_pend_drop(k, "gone");
        else k++;
    char ep[64];
    struct stat st;
    snprintf(ep, sizeof ep, "/proc/%d/exe", tid);
    const char *why = NULL;
    if (stat(ep, &st) < 0) why = "exec_identity_unreadable";
    for (size_t k = 0; !why && k < g_nxp; ) {
        struct exec_pend *x = &g_xp[k];
        if (x->tid != tid && x->tgid != tid) { k++; continue; }
        if (st.st_dev == x->edev && st.st_ino == x->eino) { exec_pend_drop(k, "launched"); continue; }
        if (st.st_dev == x->odev && st.st_ino == x->oino) {
            if (tid == x->tid) { exec_pend_drop(k, "failed"); continue; }   /* the launching thread, back */
            k++;
            continue;
        }
        why = "exec_identity_mismatch";
    }
    const struct exec_file *e = why ? NULL : exec_rs_find(st.st_dev, st.st_ino);
    if (!why && !(e && e->image)) why = "exec_identity_mismatch";
    if (!why) return false;
    /* kill the process (it is blocked in this call, so its pid is its own) */
    pid_t tgid = task_tgid(tid);
    int pfd = tgid > 0 ? (int)syscall(__NR_pidfd_open, tgid, 0) : -1;
    if (pfd >= 0) { (void)syscall(__NR_pidfd_send_signal, pfd, SIGKILL, NULL, 0); close(pfd); }
    for (size_t k = 0; k < g_nxp; )
        if (g_xp[k].tgid == tgid || g_xp[k].tid == tid) exec_pend_drop(k, "killed"); else k++;
    g_exec_mismatch++;
    char canon[PATH_MAX] = "";
    ssize_t n = readlink(ep, canon, sizeof canon - 1);
    if (n > 0) canon[n] = '\0';
    int w = snprintf(a->extra, sizeof a->extra, "\"exe_dev\":%llu,\"exe_ino\":%llu,\"exe\":\"",
                     (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
    for (const char *c = canon; *c && w < (int)sizeof a->extra - 8; c++) {   /* a path: escape for JSON */
        unsigned char u = (unsigned char)*c;
        if (u == '"' || u == '\\') { a->extra[w++] = '\\'; a->extra[w++] = (char)u; }
        else if (u < 0x20 || u >= 0x7f) w += snprintf(a->extra + w, sizeof a->extra - (size_t)w, "\\u%04x", u);
        else a->extra[w++] = (char)u;
    }
    snprintf(a->extra + w, sizeof a->extra - (size_t)w, "\",");
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t lat = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
    log_line_start();
    fprintf(g_log, "[warden] %s: pid %d runs %s, not a program the Warden decided to run; killed\n",
            why, (int)tid, canon[0] ? canon : "(unreadable)");
    emit_pathology(g_report_seq++, tid, a, DEC_DENY, DEC_DENY, why, lat, EACCES);
    send_simple(notify_fd, req->id, DEC_DENY);
    return true;
}

/* At the run's end: launches never seen */
static void exec_finish(void) {
    while (g_nxp) exec_pend_drop(g_nxp - 1, "gone");
}

/* ---- v1.27: access(X_OK), answered for what launches allow ---- */

/* Before 1.27 nothing may be launched after the agent's own launch, so X_OK
 * is refused (v1.17). With launches decided: a directory's X_OK is search,
 * granted as the read the policy already decided; a file's is granted when a
 * launch of that name would be allowed now: the policy allows the name (the
 * path as written when absolute, else the resolved one), the file is in the
 * launch set, and it has an execute bit. 0 or -EACCES. */
static int exec_access_x(int ofd, const struct action *a) {
    if (!g_exec_checking || !g_exec_policy) return -EACCES;
    struct stat st;
    if (fstat(ofd, &st) < 0) return -EACCES;
    if (S_ISDIR(st.st_mode)) return 0;
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111) || g_ll_abi < 1) return -EACCES;
    const struct exec_file *e = exec_rs_find(st.st_dev, st.st_ino);
    if (!e) return -EACCES;
    const char *name = a->target[0] == '/' && !strstr(a->target, "/.") ? a->target : a->resolved;
    if (!name[0]) return -EACCES;
    return vdp_decide(&g_exec_policy->v, VDP_KIND_EXEC, name, 0, false, NULL, NULL) == VDP_SATISFIED
           ? 0 : -EACCES;
}
