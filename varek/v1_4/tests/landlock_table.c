/* SPDX-License-Identifier: MIT
 * landlock_table.c — VAREK v1.27 open item 1, "the measured table as checks"
 * (docs/security/v1.27-program-launches.md). Written by the
 * review (AI review agents); run by tests/landlock_table.sh and make test-v1270.
 *
 * Built static, so that "one program" is exactly one file: the ruleset
 * handles LANDLOCK_ACCESS_FS_EXECUTE and grants it on this program's own
 * file only (no loader needed). Every row runs in a fresh child, twice: once
 * outside any Landlock domain (the control: does the launch work at all on
 * this host?) and once inside the domain. A row is refused BY LANDLOCK when
 * the control runs and the domain refuses.
 *
 *   landlock_table probe          print the table (TSV: id, launch, control, domain, verdict)
 *   landlock_table payload        the program the rows launch: exits 42
 *   landlock_table memfd-agent    run as the agent under the Warden: tries
 *                                 memfd_create three ways, each in a child, and
 *                                 prints how each child ended
 *
 * Exit status of probe: 0 when every row marked "must be refused" was refused
 * in the domain and the control row ran, 1 otherwise.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/landlock.h>

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

static char self[PATH_MAX];          /* this program: the one file in the set */
static char loader[PATH_MAX];        /* the host's dynamic loader (row "loader") */
static char scratch[PATH_MAX];       /* a directory for files written during the run */
extern char **environ;

/* enter a domain granting EXECUTE on self (and on the loader when with_loader) */
static int enter_domain(int with_loader) {
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) return -1;
    const char *files[2] = { self, with_loader ? loader : NULL };
    for (int i = 0; i < 2 && files[i]; i++) {
        int fd = open(files[i], O_PATH | O_CLOEXEC);
        if (fd < 0) return -1;
        struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE, .parent_fd = fd };
        if (syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) return -1;
        close(fd);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    if (syscall(SYS_landlock_restrict_self, rs, 0) < 0) return -1;
    close(rs);
    return 0;
}

/* write this program's bytes to fd, mode 0755 where it applies */
static int copy_self_to(int fd) {
    int in = open(self, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    char b[65536];
    ssize_t n;
    while ((n = read(in, b, sizeof b)) > 0)
        if (write(fd, b, (size_t)n) != n) { close(in); return -1; }
    close(in);
    (void)fchmod(fd, 0755);
    return n < 0 ? -1 : 0;
}

/* a new file at path with this program's bytes, closed (no ETXTBSY) */
static int write_copy(const char *path) {
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
    if (fd < 0) return -1;
    int r = copy_self_to(fd);
    close(fd);
    return r;
}

enum how { BY_PATH, BY_FD_PROC, BY_FD_EXECVEAT };

/* Each row: prepare (before or inside the domain, as the row says) and launch.
 * Returns only on failure, with errno set. */
struct row {
    const char *id, *what;
    int must_refuse;          /* 1: open item 1 requires a refusal in the domain; 0: informational */
    int with_loader;          /* the domain also grants the loader */
};

static char g_prep_path[PATH_MAX];

static void do_exec_path(const char *p, char *const argv[]) { execve(p, argv, environ); }
static void do_exec_fd(int fd, enum how h, char *const argv[]) {
    if (h == BY_FD_EXECVEAT) { syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH); return; }
    char pp[64];
    snprintf(pp, sizeof pp, "/proc/self/fd/%d", fd);
    execve(pp, argv, environ);
}

/* the launch of row id, in the calling child; in_domain says whether the
 * domain is entered (before the file is written, for "written during the run") */
static void launch(const char *id, int in_domain, int with_loader) {
    char *pay[] = { self, "payload", NULL };
    int dom = 0;
#define DOMAIN() do { if (in_domain && !dom) { if (enter_domain(with_loader) < 0) { perror("landlock"); _exit(3); } dom = 1; } } while (0)
    if (!strcmp(id, "in_set")) { DOMAIN(); do_exec_path(self, pay); return; }
    if (!strcmp(id, "not_in_set")) {           /* a copy of the program made before the domain */
        snprintf(g_prep_path, sizeof g_prep_path, "%s/not_in_set", scratch);
        if (write_copy(g_prep_path) < 0) _exit(4);
        DOMAIN(); char *a[] = { g_prep_path, "payload", NULL }; do_exec_path(g_prep_path, a); return;
    }
    if (!strcmp(id, "not_in_set_dyn")) {       /* a host program not in the set */
        DOMAIN(); char *a[] = { "/usr/bin/true", NULL }; do_exec_path("/usr/bin/true", a); return;
    }
    if (!strcmp(id, "written")) {               /* written during the run (inside the domain) */
        DOMAIN();
        snprintf(g_prep_path, sizeof g_prep_path, "%s/written", scratch);
        if (write_copy(g_prep_path) < 0) _exit(4);
        char *a[] = { g_prep_path, "payload", NULL }; do_exec_path(g_prep_path, a); return;
    }
    if (!strncmp(id, "tmpfile", 7) || !strncmp(id, "unlinked", 8)) {
        DOMAIN();
        int wfd, rfd;
        if (id[0] == 't') {
            wfd = open(scratch, O_TMPFILE | O_RDWR, 0755);
            if (wfd < 0) _exit(5);
            if (copy_self_to(wfd) < 0) _exit(4);
            char pp[64]; snprintf(pp, sizeof pp, "/proc/self/fd/%d", wfd);
            rfd = open(pp, O_RDONLY);          /* a read-only descriptor of the same file */
            close(wfd);                        /* no writer left: no ETXTBSY */
        } else {
            snprintf(g_prep_path, sizeof g_prep_path, "%s/unlinked", scratch);
            if (write_copy(g_prep_path) < 0) _exit(4);
            rfd = open(g_prep_path, O_RDONLY);
            unlink(g_prep_path);
        }
        if (rfd < 0) _exit(5);
        do_exec_fd(rfd, strstr(id, "execveat") ? BY_FD_EXECVEAT : BY_FD_PROC, pay);
        return;
    }
    if (!strcmp(id, "dev_shm")) {
        DOMAIN();
        snprintf(g_prep_path, sizeof g_prep_path, "/dev/shm/varek_ll_table.%d", (int)getpid());
        if (write_copy(g_prep_path) < 0) _exit(4);
        char *a[] = { g_prep_path, "payload", NULL };
        do_exec_path(g_prep_path, a);
        int e = errno; unlink(g_prep_path); errno = e;
        return;
    }
    if (!strncmp(id, "memfd", 5)) {
        DOMAIN();
        unsigned fl = strstr(id, "noexec_seal") ? MFD_NOEXEC_SEAL : MFD_EXEC;
        int mfd = (int)syscall(SYS_memfd_create, "p", fl);
        if (mfd < 0) _exit(6);
        if (copy_self_to(mfd) < 0) _exit(4);
        do_exec_fd(mfd, strstr(id, "execveat") ? BY_FD_EXECVEAT : BY_FD_PROC, pay);
        return;
    }
    if (!strcmp(id, "loader_written")) {        /* ld.so given a file written during the run */
        DOMAIN();
        snprintf(g_prep_path, sizeof g_prep_path, "%s/written_dyn", scratch);
        unlink(g_prep_path);
        /* a dynamic program written during the run: a copy of /usr/bin/true */
        int in = open("/usr/bin/true", O_RDONLY), out = open(g_prep_path, O_WRONLY | O_CREAT | O_EXCL, 0755);
        if (in < 0 || out < 0) _exit(4);
        char b[65536]; ssize_t n;
        while ((n = read(in, b, sizeof b)) > 0) if (write(out, b, (size_t)n) != n) _exit(4);
        close(in); close(out);
        char *a[] = { loader, g_prep_path, NULL };
        do_exec_path(loader, a);
        return;
    }
    errno = EINVAL;
}

/* run one launch in a child: "runs" (the payload exited 42, or for
 * loader_written /usr/bin/true's 0), or "refused <ERRNO>", or "setup failed" */
static void run_child(const char *id, int in_domain, int with_loader, char *out, size_t on) {
    int pp[2];
    if (pipe2(pp, O_CLOEXEC) < 0) { snprintf(out, on, "pipe failed"); return; }
    pid_t c = fork();
    if (c == 0) {
        close(pp[0]);
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, 1);
        launch(id, in_domain, with_loader);
        int e = errno;
        (void)!write(pp[1], &e, sizeof e);
        _exit(200);
    }
    close(pp[1]);
    int st = 0, e = 0;
    ssize_t n = read(pp[0], &e, sizeof e);
    close(pp[0]);
    waitpid(c, &st, 0);
    int ok_code = (!strcmp(id, "loader_written") || !strcmp(id, "not_in_set_dyn")) ? 0 : 42;
    if (WIFEXITED(st) && WEXITSTATUS(st) == ok_code && n <= 0) snprintf(out, on, "runs");
    else if (n == (ssize_t)sizeof e) snprintf(out, on, "refused %s", strerrorname_np(e) ? strerrorname_np(e) : "?");
    else if (WIFSIGNALED(st)) snprintf(out, on, "killed by signal %d", WTERMSIG(st));
    else snprintf(out, on, "setup failed (exit %d)", WEXITSTATUS(st));
}

static int probe(void) {
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) { printf("Landlock is not available (%s)\n", strerror(errno)); return 2; }
    printf("# kernel Landlock ABI %ld; the set: %s (static), one file%s\n", abi, self, "");
    printf("# scratch directory for written files: %s\n", scratch);
    static const struct row rows[] = {
        { "in_set",                  "the program in the set",                                   -1, 0 },
        { "not_in_set",              "a program not in the set (a copy made before the domain)",  1, 0 },
        { "not_in_set_dyn",          "a host program not in the set (/usr/bin/true)",             1, 0 },
        { "written",                 "a file written during the run",                             1, 0 },
        { "tmpfile_proc",            "an O_TMPFILE file, through /proc/self/fd/N",                1, 0 },
        { "tmpfile_execveat",        "an O_TMPFILE file, execveat(fd, \"\", AT_EMPTY_PATH)",       1, 0 },
        { "unlinked_proc",           "an unlinked file, through /proc/self/fd/N",                 1, 0 },
        { "unlinked_execveat",       "an unlinked file, execveat(fd, \"\", AT_EMPTY_PATH)",        1, 0 },
        { "dev_shm",                 "a file in /dev/shm",                                        1, 0 },
        { "memfd_noexec_seal_proc",  "a memfd made with MFD_NOEXEC_SEAL, /proc/self/fd/N",        1, 0 },
        { "memfd_noexec_seal_execveat", "a memfd made with MFD_NOEXEC_SEAL, execveat",            1, 0 },
        { "memfd_plain_proc",        "a plain memfd (MFD_EXEC), /proc/self/fd/N [not governed]",  0, 0 },
        { "memfd_plain_execveat",    "a plain memfd (MFD_EXEC), execveat [not governed]",         0, 0 },
        { "loader_written",          "the loader given a written file (set: program only)",       1, 0 },
        { "loader_written",          "the loader given a written file (set: program + loader)",   0, 1 },
    };
    int bad = 0;
    /* v1.32: overlayfs before Linux 6.6 (a container's /tmp) has no
     * O_TMPFILE; those rows cannot be set up there, and say so */
    int tf = open(scratch, O_TMPFILE | O_RDWR, 0600);
    int have_tmpfile = tf >= 0;
    if (tf >= 0) close(tf);
    /* v1.36: MFD_NOEXEC_SEAL and MFD_EXEC came with Linux 6.3; before it
     * (Amazon Linux 2023's 6.1) memfd_create refuses them (EINVAL), so the
     * memfd rows cannot be set up there, and say so */
    int mf = (int)syscall(SYS_memfd_create, "probe", MFD_NOEXEC_SEAL);
    int have_mfd_flags = mf >= 0;
    if (mf >= 0) close(mf);
    printf("%-28s\t%-62s\t%-16s\t%-16s\t%s\n", "id", "launch", "control", "in the domain", "verdict");
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        char c[64], d[64];
        run_child(rows[i].id, 0, rows[i].with_loader, c, sizeof c);
        run_child(rows[i].id, 1, rows[i].with_loader, d, sizeof d);
        const char *v;
        int refused = !strncmp(d, "refused", 7);
        if (!have_tmpfile && !strncmp(rows[i].id, "tmpfile", 7)) v = "skip (no O_TMPFILE on this filesystem)";
        else if (!have_mfd_flags && !strncmp(rows[i].id, "memfd", 5))
            v = "skip (no MFD_NOEXEC_SEAL or MFD_EXEC before Linux 6.3)";
        else if (rows[i].must_refuse < 0) { v = !strcmp(d, "runs") ? "ok (runs)" : "FAIL (the set's program must run)"; bad |= strcmp(d, "runs") != 0; }
        else if (rows[i].must_refuse) {
            if (!refused) { v = "FAIL (must be refused)"; bad = 1; }
            else v = !strcmp(c, "runs") ? "ok (refused by Landlock)" : "ok (refused; refused without Landlock too)";
        } else v = !strcmp(d, "runs") ? "info: runs in the domain" : "info: refused in the domain";
        printf("%-28s\t%-62s\t%-16s\t%-16s\t%s\n", rows[i].id, rows[i].what, c, d, v);
    }
    return bad;
}

/* as the agent under the Warden: each memfd_create in its own child */
static int memfd_agent(void) {
    static const struct { const char *what; unsigned fl; int raw; } t[] = {
        { "memfd_create(\"x\", 0) (glibc)", 0, 0 },
        { "memfd_create(\"x\", MFD_NOEXEC_SEAL) (glibc)", MFD_NOEXEC_SEAL, 0 },
        { "syscall(SYS_memfd_create, \"x\", MFD_EXEC)", MFD_EXEC, 1 },
    };
    int all_refused = 1;
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        pid_t c = fork();
        if (c < 0) { printf("fork: %s\n", strerror(errno)); return 1; }
        if (c == 0) {
            int fd = t[i].raw ? (int)syscall(SYS_memfd_create, "x", t[i].fl) : memfd_create("x", t[i].fl);
            _exit(fd >= 0 ? 0 : 100 + (errno & 0x3f));
        }
        int st;
        waitpid(c, &st, 0);
        char r[96];
        if (WIFSIGNALED(st)) snprintf(r, sizeof r, "refused: process killed by %s", strsignal(WTERMSIG(st)));
        else if (WEXITSTATUS(st) >= 100) snprintf(r, sizeof r, "refused: %s", strerrorname_np(WEXITSTATUS(st) - 100));
        else { snprintf(r, sizeof r, "MADE A MEMFD"); all_refused = 0; }
        printf("MEMFD\t%s\t%s\n", t[i].what, r);
        fflush(stdout);
    }
    printf("MEMFD\tverdict\t%s\n", all_refused ? "ok (memfd_create refused for the agent)" : "FAIL");
    return all_refused ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "payload")) return 42;
    if (argc > 1 && !strcmp(argv[1], "memfd-agent")) return memfd_agent();
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return 2;
    self[n] = '\0';
    n = readlink("/lib64/ld-linux-x86-64.so.2", loader, sizeof loader - 1);
    if (n > 0) { loader[n] = '\0'; if (loader[0] != '/') snprintf(loader, sizeof loader, "/lib64/ld-linux-x86-64.so.2"); }
    else snprintf(loader, sizeof loader, "/lib64/ld-linux-x86-64.so.2");
    {   /* follow to the real file */
        char rp[PATH_MAX];
        if (realpath("/lib64/ld-linux-x86-64.so.2", rp)) snprintf(loader, sizeof loader, "%s", rp);
    }
    const char *sd = getenv("LL_TABLE_SCRATCH");
    snprintf(scratch, sizeof scratch, "%s", sd ? sd : "/tmp");
    if (argc > 1 && !strcmp(argv[1], "probe")) return probe();
    fprintf(stderr, "usage: %s probe | payload | memfd-agent\n", argv[0]);
    return 2;
}
