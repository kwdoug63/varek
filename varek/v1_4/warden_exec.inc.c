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
static void exec_pend_last_sub(int s);                                   /* v1.28.1 */
static void exec_dry_image(dev_t dev, ino_t ino);                       /* v1.29 */
static bool exec_is_dry_image(dev_t dev, ino_t ino);

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
    /* v1.27 review: read as fs/binfmt_script.c does. The kernel reads the
     * first 256 bytes (BINPRM_BUF_SIZE); the line ends at a newline or at the
     * end of what it read; the name ends at a space, tab, NUL or that end. A
     * name the 256 bytes cut short, or no name at all, is ENOEXEC: no script
     * (0). A #! line ending at the end of the file runs. */
    char b[256 + 1];
    ssize_t n = pread(fd, b, 256, 0);
    if (n < 2 || b[0] != '#' || b[1] != '!') return 0;
    b[n] = '\0';
    char *nl = memchr(b, '\n', (size_t)n);
    char *end = nl ? nl : b + n;
    char *s = b + 2;
    while (s < end && (*s == ' ' || *s == '\t')) s++;
    size_t k = 0;
    while (s + k < end && s[k] != ' ' && s[k] != '\t' && s[k] != '\0') k++;
    if (k == 0) return 0;
    if (!nl && s + k == b + n && n == 256) return 0;      /* the name runs past what the kernel reads */
    if (k >= outn || s[0] != '/') return -1;
    memcpy(out, s, k);
    out[k] = '\0';
    return 1;
}

/* v1.29 (step 9): SHA-256 by OpenSSL's libcrypto, which uses the CPU's
 * SHA extensions (or AVX2) where it has them: libsodium's portable code
 * took about 0.6 s on a 123 MB Node.js at every start. Only the digest is
 * used; OpenSSL's configuration file is never read (no module or provider
 * it names is loaded into the Warden: warden.c calls OPENSSL_init_crypto
 * with OPENSSL_INIT_NO_LOAD_CONFIG first), and the built-in default
 * provider's SHA-256 is fetched once. */
static EVP_MD *g_sha256;

static int exec_hash_fd(int fd, char out[65]) {
    if (!g_sha256 && !(g_sha256 = EVP_MD_fetch(NULL, "SHA2-256", "provider=default"))) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, g_sha256, NULL) != 1) { EVP_MD_CTX_free(ctx); return -1; }
    static unsigned char buf[1 << 20];
    off_t at = 0;
    for (;;) {
        ssize_t n = pread(fd, buf, sizeof buf, at);
        if (n < 0 || (n > 0 && EVP_DigestUpdate(ctx, buf, (size_t)n) != 1)) { EVP_MD_CTX_free(ctx); return -1; }
        if (n == 0) break;
        at += n;
    }
    unsigned char h[EVP_MAX_MD_SIZE];
    unsigned int hl = 0;
    int ok = EVP_DigestFinal_ex(ctx, h, &hl) == 1 && hl == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) return -1;
    sodium_bin2hex(out, 65, h, 32);
    return 0;
}

static const struct exec_file *exec_rs_find(dev_t dev, ino_t ino) {
    for (size_t k = 0; k < g_exec_n; k++)
        if (g_exec_rs[k].dev == dev && g_exec_rs[k].ino == ino) return &g_exec_rs[k];
    return NULL;
}

/* Add the file name names (following symlinks) with its loader. 1 added, 2
 * already there, 0 not a launchable file (missing, not regular, no execute
 * bit), -1 an error that stops the run (why in err). The loader is added as
 * the kernel uses it: its own PT_INTERP is not followed (v1.27 review). */
static int exec_rs_add(const char *name, const char *why, int line, char *err, size_t en) {
    /* v1.27 review: look before opening it to read: a FIFO or a device a rule
     * names is never opened for reading (opening some has effects) */
    int pfd = open(name, O_PATH | O_CLOEXEC);
    if (pfd < 0) return 0;
    struct stat st;
    if (fstat(pfd, &st) < 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) { close(pfd); return 0; }
    if (exec_rs_find(st.st_dev, st.st_ino)) { close(pfd); return 2; }
    int fd = proc_openf(O_RDONLY | O_NONBLOCK | O_NOCTTY, 0, "self/fd/%d", pfd);   /* the same file */
    close(pfd);
    struct stat st2;
    if (fd < 0 || fstat(fd, &st2) < 0 || st2.st_dev != st.st_dev || st2.st_ino != st.st_ino) {
        if (fd >= 0) close(fd);
        return 0;
    }
    if (g_exec_n == EXEC_RS_MAX) {
        close(fd);
        snprintf(err, en, "the launch set would hold more than %d files", EXEC_RS_MAX);
        return -1;
    }
    struct exec_file *f = &g_exec_rs[g_exec_n];
    char canon[PATH_MAX];
    ssize_t cl = proc_readlinkf(canon, sizeof canon - 1, "self/fd/%d", fd);
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
    if (ir == 1 && strcmp(why, "loader") != 0) {
        int lr = exec_rs_add(interp, "loader", 0, err, en);
        if (lr < 0) return -1;
        if (lr == 0) {
            snprintf(err, en, "%s: its loader %s is not a launchable file", name, interp);
            return -1;
        }
    }
    return 1;
}

/* v1.31: the subject whose allow exec rule is being expanded */
static int g_exec_subj;

/* v1.31 (docs/security/v1.31-standards.md, section 2): a confined subject's
 * launch file. Refused at the start: an `mcp server` line's file that is not
 * in the launch set, or (sha256=) has another hash; a file a confined
 * subject is launched from, or a directory above it, that any subject's
 * rules let be written (the agent could rewrite the server it is confined
 * from). 0, or -1 with the reason printed. */
static int exec_confined_checks(const struct policy *p) {
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (!r->confined_subj) continue;
        bool found = false;
        for (size_t k = 0; k < g_exec_n; k++) {
            const struct exec_file *f = &g_exec_rs[k];
            if (strcmp(f->why, "rule") || f->line != r->line) continue;
            found = true;
            /* v1.31 review: by the file it reaches too (a symlink to python3) */
            if (vdp_exec_is_launcher(f->path)) {
                fprintf(stderr, "[warden] policy line %d: %s is %s, an interpreter or a launcher: as an MCP "
                        "server or confined sub-agent, whatever it is given to run would be decided by %s's "
                        "rules; refusing to start\n", r->line, f->name, f->path, r->subagent);
                return -1;
            }
            if (r->sha256[0] && strcmp(f->sha, r->sha256)) {
                fprintf(stderr, "[warden] policy line %d: %s has SHA-256 %s, not the %s the line pins; "
                        "refusing to start\n", r->line, f->name, f->sha, r->sha256);
                return -1;
            }
            const char *names[2] = { f->name, f->path };
            for (int n = 0; n < 2; n++) {
                char d[PATH_MAX];
                snprintf(d, sizeof d, "%s", names[n]);
                for (;;) {
                    if (vdpc_path_writable(&p->c, d, strlen(d))) {
                        fprintf(stderr, "[warden] policy line %d: the policy lets %s be written, so %s, "
                                "which %s is launched from, could be replaced; refusing to start\n",
                                r->line, d, f->path, r->subagent);
                        return -1;
                    }
                    char *sl = strrchr(d, '/');
                    if (!sl) break;
                    if (sl == d) { if (!d[1]) break; d[1] = '\0'; continue; }
                    *sl = '\0';
                }
            }
        }
        if (r->mcp_server && !found) {
            /* review: or an earlier exec rule decides it (it would run unconfined) */
            bool earlier = false;
            for (size_t k = 0; k < g_exec_n && !earlier; k++)
                earlier = !strcmp(g_exec_rs[k].why, "rule") && g_exec_rs[k].line < r->line &&
                          !strcmp(g_exec_rs[k].name, r->s.c);
            if (earlier)
                fprintf(stderr, "[warden] policy line %d: MCP server %s (%s) is launched by an earlier exec rule, "
                        "so it would run unconfined: put its mcp server line first; refusing to start\n",
                        r->line, r->subagent, r->s.c);
            else
                fprintf(stderr, "[warden] policy line %d: MCP server %s (%s) is not a launchable file on this "
                        "host; refusing to start\n", r->line, r->subagent, r->s.c);
            return -1;
        }
    }
    return 0;
}

/* Expanding allow exec rules: each candidate the walk finds is decided like a
 * launch of that name, by the subject whose rule it is (v1.31: the launch
 * set holds what any subject may launch; each launch is still decided by its
 * caller's rules). Counts per deciding rule in admitted[]. */
static int exec_consider(const struct policy *p, const char *cand, size_t *admitted, char *err, size_t en) {
    int ri = -1;
    vdp_why_t why;
    if (vdp_decide_subj(&p->v, g_exec_subj, VDP_KIND_EXEC, cand, 0, false, &ri, &why) != VDP_SATISFIED || ri < 0)
        return 0;
    /* v1.27 review: a deny exec rule on the file's own path keeps it out,
     * whatever other name an allow rule reaches it by (a symlink) */
    char real[PATH_MAX];
    int dri = -1;
    if (realpath(cand, real) && strcmp(real, cand) != 0 &&
        vdp_decide_subj(&p->v, g_exec_subj, VDP_KIND_EXEC, real, 0, false, &dri, &why) == VDP_UNSATISFIED &&
        dri >= 0 && p->v.rules[dri].verb == VDP_DENY) {
        fprintf(stderr, "[warden] note: launch set: %s (line %d) is %s, which line %d denies; it is not "
                "in the launch set\n", cand, p->v.rules[ri].line, real, p->v.rules[dri].line);
        return 0;
    }
    int r = exec_rs_add(cand, "rule", p->v.rules[ri].line, err, en);
    if (r < 0) return -1;
    if (r == 1 && ++admitted[ri] > EXEC_RULE_MAX_FILES) {
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
        g_exec_subj = r->subj;               /* v1.31 */
        /* an exact or prefix constant not starting with '/' matches no
         * launch (the Warden decides on absolute paths; lint notes it) */
        if ((r->s.op == VDP_STR_EQ || r->s.op == VDP_STR_PREFIX) && r->s.c[0] != '/') continue;
        /* v1.27 review: a launch is decided on its name made absolute, with
         * "." and ".." segments resolved; a constant holding them would admit
         * a file no launch could ever be allowed by */
        {
            const char *c = r->s.c;
            size_t cl = strlen(c);
            if (strstr(c, "/./") || strstr(c, "/../") || strstr(c, "//") ||
                (cl >= 2 && !strcmp(c + cl - 2, "/.")) || (cl >= 3 && !strcmp(c + cl - 3, "/.."))) {
                snprintf(err, sizeof err, "line %d: an allow exec rule's path holds a \".\" or \"..\" "
                         "segment or \"//\"; launches are decided on names without them", r->line);
                rc = -1;
                break;
            }
        }
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
            const char *mp = vdp_matcher_prefix(r);
            int ml = (int)strlen(mp);
            while (ml > 0 && mp[ml - 1] == ' ') ml--;
            snprintf(err, sizeof err, "line %d: an allow exec rule with %.*s cannot be expanded to the "
                     "files it admits; use an exact path, prefix or glob", r->line, ml, mp);
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
        /* v1.31: by any subject's rules */
        bool wr = false;
        for (size_t w = 0; w < sizeof kW / sizeof kW[0] && !wr; w++)
            for (size_t sj = 0; sj <= p->v.nsubjects && !wr; sj++)
                wr = vdp_decide_subj(&p->v, (int)sj, VDP_KIND_PATH, f->path, kW[w], true, NULL, NULL) == VDP_SATISFIED;
        if (wr)
            fprintf(stderr, "[warden] note: launch set: %s (%s) may be both launched and written by "
                    "the agent: a launch runs the file as it is then, not as hashed now\n",
                    f->name, f->path);
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
    char bp[64];     /* below the node's /proc (v1.34) */
    int base;
    if (dirfd == AT_FDCWD) snprintf(bp, sizeof bp, "%d/cwd", tid);
    else if (dirfd >= 0) snprintf(bp, sizeof bp, "%d/fd/%d", tid, dirfd);
    else return -1;
    if (proc_dir() < 0) return -1;
    if ((flags & AT_EMPTY_PATH) && a->target[0] == '\0') {
        /* by descriptor: the file it refers to */
        int fd = openat(g_procfd, bp, O_PATH | O_CLOEXEC);
        if (fd < 0) return -1;
        int ok = fstat(fd, st) == 0 && S_ISREG(st->st_mode) &&
                 fd_canonical_path(fd, a->resolved, sizeof a->resolved) == 0;
        close(fd);
        if (!ok) { a->resolved[0] = '\0'; return -1; }
        return 0;
    }
    if (a->target[0] == '\0') return -1;
    base = openat(g_procfd, bp, O_PATH | O_DIRECTORY | O_CLOEXEC);
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

/* ---- v1.31 review: the environment a confined subject is launched with ----
 *
 * The launcher chooses the environment of the program it launches, and a
 * program's loader or interpreter may take code from a path or a value an
 * environment variable names. A confined subject (an MCP server, or
 * `subagent=NAME confined`) is decided by its own rules, so code its
 * launcher chose would run with them. A confined launch whose environment
 * sets one of these is refused (subagent_env): checked in the launcher's
 * memory when the launch is decided, and again in the new image's own copy
 * (/proc/PID/environ, which the launcher can no longer change) before any
 * of its calls is answered. The list is of variables that name code; a
 * program that reads code from somewhere else is the operator's to know. */
static const char *const kEnvCodePrefix[] = { "LD_", "BASH_FUNC_", "PERL", "RUBY", "LUA_", "GIT_", "PYTHON", NULL };
static const char *const kEnvCodeName[] = {
    "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4",
    "PROMPT_COMMAND", "CLASSPATH", "GCONV_PATH",
    "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "HOSTALIASES", "TCLLIBPATH", "PHPRC", "PHP_INI_SCAN_DIR",
    "GEM_PATH", "GEM_HOME", "EDITOR", "VISUAL", "PAGER", "MANPAGER", "BROWSER", "LESSOPEN", "LESSCLOSE",
    "SSH_ASKPASS", "SUDO_ASKPASS", NULL };
/* settings under those prefixes that name no code (common in agents' and MCP
 * servers' environments) */
static const char *const kEnvOk[] = {
    "PYTHONUNBUFFERED", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8", "PYTHONNOUSERSITE",
    "PYTHONSAFEPATH", "PYTHONHASHSEED", "PYTHONFAULTHANDLER", "GIT_TERMINAL_PROMPT", "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE", "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE", "GIT_HTTP_LOW_SPEED_LIMIT", "GIT_HTTP_LOW_SPEED_TIME", NULL };
/* NODE_OPTIONS flags that load no code */
static const char *const kNodeOk[] = {
    "--max-old-space-size=", "--max-semi-space-size=", "--max-http-header-size=", "--stack-size=",
    "--stack-trace-limit=", "--no-warnings", "--no-deprecation", "--trace-warnings", "--trace-deprecation",
    "--trace-uncaught", "--enable-source-maps", "--dns-result-order=", "--use-openssl-ca", "--use-bundled-ca",
    "--tls-min-v1.", "--tls-max-v1.", "--unhandled-rejections=", "--network-family-autoselection", NULL };

/* JVM options (JAVA_TOOL_OPTIONS and the like) that load no code: the
 * Warden's own trust store in inspecting mode, proxies, encodings, heap */
static const char *const kJavaOk[] = {
    "-Djavax.net.ssl.", "-Dhttps.proxy", "-Dhttp.proxy", "-Dhttps.nonProxyHosts=", "-Dhttp.nonProxyHosts=",
    "-Dfile.encoding=", "-Dsun.jnu.encoding=", "-Duser.language=", "-Duser.country=", "-Duser.timezone=",
    "-Djava.net.preferIPv4Stack=", "-Xmx", "-Xms", "-Xss", "-XX:MaxRAMPercentage=", "-XX:InitialRAMPercentage=",
    "-XX:+UseContainerSupport", NULL };
static const struct { const char *name; const char *const *ok; } kEnvOptions[] = {
    { "NODE_OPTIONS", kNodeOk }, { "JAVA_TOOL_OPTIONS", kJavaOk }, { "_JAVA_OPTIONS", kJavaOk },
    { "JDK_JAVA_OPTIONS", kJavaOk }, { NULL, NULL } };

static bool env_listed(const char *const *l, const char *s, size_t n) {
    for (int i = 0; l[i]; i++) if (strlen(l[i]) == n && !memcmp(s, l[i], n)) return true;
    return false;
}

/* The variable entry kv (NAME=value, n bytes; whole: all of it was read)
 * sets, if it names code; else NULL. An empty value names nothing. */
static const char *exec_env_code(const char *kv, size_t n, bool whole, char *name, size_t nn) {
    const char *eq = memchr(kv, '=', n);
    size_t l = eq ? (size_t)(eq - kv) : n;
    if (!l) return NULL;
    snprintf(name, nn, "%.*s", (int)(l < nn - 1 ? l : nn - 1), kv);
    if (eq && whole && eq + 1 == kv + n) return NULL;             /* NAME= */
    const char *const *opts = NULL;
    for (int i = 0; kEnvOptions[i].name && !opts; i++)
        if (strlen(kEnvOptions[i].name) == l && !memcmp(kv, kEnvOptions[i].name, l)) opts = kEnvOptions[i].ok;
    if (opts) {
        /* an options variable: every option one that loads no code */
        if (!eq || !whole) return name;
        const char *v = eq + 1, *e = kv + n;
        while (v < e) {
            while (v < e && (*v == ' ' || *v == '\t')) v++;
            if (v == e) break;
            const char *t = v;
            while (v < e && *v != ' ' && *v != '\t') v++;
            bool ok = false;
            for (int i = 0; opts[i] && !ok; i++) {          /* each entry a prefix of the option */
                size_t fl = strlen(opts[i]);
                ok = (size_t)(v - t) >= fl && !memcmp(t, opts[i], fl);
            }
            if (!ok) return name;
        }
        return NULL;
    }
    if (env_listed(kEnvCodeName, kv, l)) return name;
    if (env_listed(kEnvOk, kv, l)) return NULL;
    for (int i = 0; kEnvCodePrefix[i]; i++) {
        size_t pl = strlen(kEnvCodePrefix[i]);
        if (l >= pl && !memcmp(kv, kEnvCodePrefix[i], pl)) return name;
    }
    return NULL;
}

/* In the launcher's memory: the envp of the launch asked (execve: args[2],
 * execveat: args[3]). 1 with the first variable that names code, 0 none, -1
 * unreadable (refused). */
static int exec_env_launch(const struct seccomp_notif *req, char *name, size_t nn) {
    uint64_t envp = req->data.nr == __NR_execveat ? req->data.args[3] : req->data.args[2];
    if (!envp) return 0;
    int fd = proc_openf(O_RDONLY, 0, "%d/mem", (int)req->pid);
    if (fd < 0) return -1;
    int r = 0;
    for (size_t k = 0; k < 65536 && !r; k++) {
        uint64_t sp;
        if (pread(fd, &sp, sizeof sp, (off_t)(envp + k * sizeof sp)) != (ssize_t)sizeof sp) { r = -1; break; }
        if (!sp) break;
        char kv[256];
        ssize_t n = pread(fd, kv, sizeof kv, (off_t)sp);
        if (n <= 0) { r = -1; break; }
        const char *z = memchr(kv, '\0', (size_t)n);
        if (exec_env_code(kv, z ? (size_t)(z - kv) : (size_t)n, z != NULL, name, nn)) r = 1;
    }
    close(fd);
    return r;
}

/* In the new image's own copy (/proc/PID/environ). 1 with the first variable
 * that names code, 0 none, -1 unreadable. */
static int exec_env_image(pid_t pid, char *name, size_t nn) {
    int fd = proc_openf(O_RDONLY, 0, "%d/environ", (int)pid);
    if (fd < 0) return -1;
    size_t cap = 1 << 16, len = 0;
    char *b = malloc(cap);
    for (;;) {
        if (!b) { close(fd); return -1; }
        if (len == cap) {
            if (cap >= (8u << 20)) { free(b); close(fd); return -1; }
            char *nb = realloc(b, cap * 2);
            if (!nb) { free(b); close(fd); return -1; }
            b = nb;
            cap *= 2;
        }
        ssize_t n = read(fd, b + len, cap - len);
        if (n < 0) { free(b); close(fd); return -1; }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    int r = 0;
    for (size_t i = 0; i < len && !r; ) {
        const char *z = memchr(b + i, '\0', len - i);
        size_t l = z ? (size_t)(z - (b + i)) : len - i;
        if (exec_env_code(b + i, l, true, name, nn)) r = 1;
        i += l + 1;
    }
    free(b);
    return r;
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
        /* v1.27 review: the checker's own reading of the opt-in gates every launch too */
        if (d_final == DEC_ALLOW && (!p->c.launches || !certify(p, a))) {
            d_final = DEC_DENY; rule = "certificate_refused";
        }
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
    /* v1.31 review: a confined subject's environment names no code */
    char envn[64] = "";
    if (d_final == DEC_ALLOW && a->rule_index >= 0 && p->v.rules[a->rule_index].subagent[0] &&
        p->v.rules[a->rule_index].confined_subj > 0) {
        static int late_test = -1;          /* make test-v1310: only the check in the new image */
        if (late_test < 0) late_test = getenv("VAREK_WARDEN_TEST_ENV_LATE") != NULL;
        int er = late_test ? 0 : exec_env_launch(req, envn, sizeof envn);
        if (er != 0) {
            d_final = DEC_DENY;
            rule = "subagent_env";
            if (er < 0) snprintf(envn, sizeof envn, "(unreadable)");
            snprintf(a->extra, sizeof a->extra, "\"env\":\"%s\",", envn);
            ef = NULL;
        }
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
        } else if (a->rule_index >= 0 && p->v.rules[a->rule_index].subagent[0]) {
            /* v1.28.1: a sub-agent: its group made, the process moved, before the answer */
            const char *srule = NULL;
            const vdp_rule_t *lr = &p->v.rules[a->rule_index];
            int s = sub_launch((pid_t)req->pid, a->subject, lr->subagent, lr->confined_subj, lr->mcp_server, idev, iino,
                               g_records, &srule);
            exec_pend_last_sub(s);               /* refused: the pending launch goes */
            if (s < 0) {
                d_final = DEC_DENY;
                rule = srule;
                a->extra[0] = '\0';
            } else {
                sub_launch_fields(a, s);
            }
        }
    }
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t lat = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
    /* v1.29: a dry run lets a launch the policy refuses through to the
     * kernel (no Landlock holds it), and remembers its image, which the
     * identity check then lets run */
    bool let = d_final != DEC_ALLOW && dry_let(a, rule);
    dev_t ddev = 0;
    ino_t dino = 0;
    if (let && exec_image_of(a->resolved[0] ? a->resolved : a->target, &ddev, &dino) == 0)
        exec_dry_image(ddev, dino);
    emit_pathology(g_report_seq++, (pid_t)req->pid, a, d_raw, d_final, rule, lat,
                   d_final == DEC_ALLOW || let ? 0 : EACCES);
    send_simple(notify_fd, req->id, let ? DEC_ALLOW : d_final);
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
    int      sub;          /* v1.28.1: the sub-agent it starts (0: none) */
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
    /* v1.27 review: a file in the set only as a loader is never a process's
     * image, even when a script's #! names it */
    for (size_t k = 0; k < g_exec_n; k++)
        if (g_exec_rs[k].dev == dev && g_exec_rs[k].ino == ino && strcmp(g_exec_rs[k].why, "loader") != 0)
            g_exec_rs[k].image = true;
}

/* v1.29: the images of launches a dry run let through (the identity check
 * lets a process run one). At most 1024; past that, a mismatch is recorded. */
static struct { dev_t dev; ino_t ino; } g_dry_img[1024];
static size_t g_dry_nimg;
static void exec_dry_image(dev_t dev, ino_t ino) {
    for (size_t k = 0; k < g_dry_nimg; k++) if (g_dry_img[k].dev == dev && g_dry_img[k].ino == ino) return;
    if (g_dry_nimg < sizeof g_dry_img / sizeof g_dry_img[0]) {
        g_dry_img[g_dry_nimg].dev = dev;
        g_dry_img[g_dry_nimg].ino = ino;
        g_dry_nimg++;
    }
}
static bool exec_is_dry_image(dev_t dev, ino_t ino) {
    for (size_t k = 0; k < g_dry_nimg; k++) if (g_dry_img[k].dev == dev && g_dry_img[k].ino == ino) return true;
    return false;
}

static void exec_result(const struct exec_pend *x, const char *result) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"exec_result\",\"run\":\"%s\",\"decision_seq\":%" PRIu64 ",\"agent_pid\":%d,"
               "\"result\":\"%s\",", g_run_id, x->seq, (int)x->tgid, result);
    if (x->sub > 0) fprintf(f, "\"subagent\":\"%s#%u\",", g_sub[x->sub].name, g_sub[x->sub].n);   /* v1.28.1 */
    fprintf(f, "\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);
}

static void exec_pend_drop(size_t k, const char *result) {
    /* v1.28.1: a sub-agent's launch says how it settled */
    if (result && g_xp[k].sub > 0) result = sub_pend_end(g_xp[k].sub, g_xp[k].tid, result);
    if (result) exec_result(&g_xp[k], result);
    if (g_xp[k].pidfd >= 0) close(g_xp[k].pidfd);
    g_xp[k] = g_xp[--g_nxp];
}

/* v1.28.1: the launch just registered starts sub-agent s; or, s < 0, it was
 * refused after all (no record: it never happened) */
static void exec_pend_last_sub(int s) {
    if (!g_nxp) return;
    if (s < 0) exec_pend_drop(g_nxp - 1, NULL);
    else g_xp[g_nxp - 1].sub = s;
}

/* Register a continued launch, before it is answered. 0, or -1 (refuse it). */
static int exec_pend_add(pid_t tid, dev_t edev, ino_t eino, uint64_t seq) {
    if (g_nxp == EXEC_PEND_MAX) return -1;
    struct stat ost;
    pid_t tgid = task_tgid(tid);
    if (tgid < 0 || proc_statf(&ost, "%d/exe", tid) < 0) return -1;
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
    struct stat st;
    const char *why = NULL;
    char envn[64] = "";
    if (proc_statf(&st, "%d/exe", tid) < 0) why = "exec_identity_unreadable";
    /* The process's pending launches (one per thread that asked). If it now
     * runs the file one of them decided, that launch happened, and the others
     * cannot have (a launch ends every other thread): launched, and failed.
     * Else each must still run the image it asked from: a launch whose own
     * thread is back, or gone, failed; one whose thread is still in its
     * launch is kept. Anything else is a mismatch. */
    bool group = false, hit = false, seen = false;
    for (size_t k = 0; k < g_nxp; k++) {
        struct exec_pend *x = &g_xp[k];
        if (x->tid != tid && x->tgid != tid) continue;
        group = true;
        if (st.st_dev == x->edev && st.st_ino == x->eino) hit = true;
    }
    for (size_t k = 0; !why && group && k < g_nxp; ) {
        struct exec_pend *x = &g_xp[k];
        if (x->tid != tid && x->tgid != tid) { k++; continue; }
        if (hit) {                            /* one launch happened; any others failed */
            bool mine = !seen && st.st_dev == x->edev && st.st_ino == x->eino;
            if (mine) seen = true;
            /* v1.31 review: a confined subject's own copy of its environment */
            if (mine && x->sub > 0 && g_sub[x->sub].confined) {
                int er = exec_env_image(x->tgid, envn, sizeof envn);
                if (er != 0) {
                    if (er < 0) snprintf(envn, sizeof envn, "(unreadable)");
                    why = "subagent_env";
                    exec_pend_drop(k, "killed");
                    break;
                }
            }
            exec_pend_drop(k, mine ? "launched" : "failed");
            continue;
        }
        if (st.st_dev == x->odev && st.st_ino == x->oino) {
            char tp[64];     /* below the node's /proc (v1.34) */
            snprintf(tp, sizeof tp, "%d/task/%d", (int)x->tgid, (int)x->tid);
            if (tid == x->tid || proc_dir() < 0 || faccessat(g_procfd, tp, F_OK, 0) != 0) { exec_pend_drop(k, "failed"); continue; }
            k++;                              /* its thread is still in its launch */
            continue;
        }
        why = "exec_identity_mismatch";
    }
    const struct exec_file *e = why ? NULL : exec_rs_find(st.st_dev, st.st_ino);
    if (!why && !(e && e->image)) why = "exec_identity_mismatch";
    /* v1.29: in a dry run, an image a refused launch let through runs on */
    if (why && !strcmp(why, "exec_identity_mismatch") && g_dry && exec_is_dry_image(st.st_dev, st.st_ino))
        return false;
    if (!why) return false;
    if (!strcmp(why, "exec_identity_unreadable")) {
        /* A live process's image is always readable here (the Warden is
         * root); it is not only while the thread is being torn down, as
         * another thread's launch ends it. Refuse the call; nothing to kill. */
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t lat = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
        a->extra[0] = '\0';
        emit_pathology(g_report_seq++, tid, a, DEC_DENY, DEC_DENY, why, lat, EACCES);
        send_simple(notify_fd, req->id, DEC_DENY);
        return true;
    }
    /* what it runs, read before the kill (v1.27 review: after, it may be gone) */
    char canon[PATH_MAX] = "";
    ssize_t n = proc_readlinkf(canon, sizeof canon - 1, "%d/exe", tid);
    if (n > 0) canon[n] = '\0';
    /* kill the process (it is blocked in this call, so its pid is its own) */
    pid_t tgid = task_tgid(tid);
    int pfd = tgid > 0 ? (int)syscall(__NR_pidfd_open, tgid, 0) : -1;
    if (pfd >= 0) { (void)syscall(__NR_pidfd_send_signal, pfd, SIGKILL, NULL, 0); close(pfd); }
    for (size_t k = 0; k < g_nxp; )
        if (g_xp[k].tgid == tgid || g_xp[k].tid == tid) exec_pend_drop(k, "killed"); else k++;
    if (strcmp(why, "subagent_env")) g_exec_mismatch++;      /* v1.31 review: a kill of its own kind */
    int w = snprintf(a->extra, sizeof a->extra, "\"exe_dev\":%llu,\"exe_ino\":%llu,\"exe\":\"",
                     (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
    for (const char *c = canon; *c && w < (int)sizeof a->extra - 8; c++) {   /* a path: escape for JSON */
        unsigned char u = (unsigned char)*c;
        if (u == '"' || u == '\\') { a->extra[w++] = '\\'; a->extra[w++] = (char)u; }
        else if (u < 0x20 || u >= 0x7f) w += snprintf(a->extra + w, sizeof a->extra - (size_t)w, "\\u%04x", u);
        else a->extra[w++] = (char)u;
    }
    snprintf(a->extra + w, sizeof a->extra - (size_t)w, "\",");
    if (envn[0]) {
        size_t el = strlen(a->extra);
        snprintf(a->extra + el, sizeof a->extra - el, "\"env\":\"%s\",", envn);
    }
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t lat = (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
    log_line_start();
    if (envn[0])
        fprintf(g_log, "[warden] %s: pid %d (%s) was launched as a confined subject with %s set, which names "
                "code; killed\n", why, (int)tid, canon[0] ? canon : "(unreadable)", envn);
    else
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
    return vdp_decide_subj(&g_exec_policy->v, sub_policy_subject(a->subject), VDP_KIND_EXEC, name, 0, false,
                           NULL, NULL) == VDP_SATISFIED ? 0 : -EACCES;     /* v1.31: by the caller's rules */
}
