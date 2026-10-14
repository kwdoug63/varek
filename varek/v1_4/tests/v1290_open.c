// SPDX-License-Identifier: MIT
// v1290_open.c — a program for test_v1290.sh section 1 (opening files as the
// agent): run as the agent, it makes one open per argument pair and prints the
// result of each on its own line, so the test can compare the agent's view
// with the file on disk.
//
//   v1290_open [umask OCTAL] OP PATH [OP PATH ...]
//     create PATH    open(O_CREAT|O_EXCL|O_WRONLY, 0666); "create ok UID GID MODE"
//     write PATH     open(O_WRONLY|O_APPEND), write "x"; "write ok" or "write ERR"
//     read PATH      open(O_RDONLY); "read ok" or "read ERR"
//     tmpfile DIR    open(O_TMPFILE|O_RDWR, 0600); "tmpfile ok UID GID"
//   v1.29 step 2b, changes by name ("OP ok" or "OP ERR"):
//     unlink PATH, rmdir PATH, mkdir PATH (0777, under the umask),
//     chmod PATH (0600), utime PATH (both times to 1000000000), truncate PATH
//     (to 1 byte), ftruncate PATH (opened O_WRONLY, then to 1 byte),
//     fchmod PATH (opened O_RDONLY, then 0640), chdir PATH (then prints
//     "cwd PATH" from getcwd), symlink PATH (a link to /etc/hostname),
//     link PATH (a hard link of PATH to PATH.l),
//     rename OLD:NEW, exchange A:B (renameat2 RENAME_EXCHANGE),
//     unlinkat DIR:NAME (relative to a descriptor on DIR)
//   v1.29 step 6:
//     rstat PATH, rlstat PATH   the raw stat(2) and lstat(2), as musl calls them
//                               ("rstat ok" or "rstat ERR")
//     admits FILE               the calls admitted under 1.29, each "NAME ok" or
//                               "NAME ERR" (FILE: a file it may read)
//   ERR is strerror's text of the call's errno.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <linux/capability.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void res(const char *op, int r) {
    printf("%s %s\n", op, r == 0 ? "ok" : strerror(errno));
}

int main(int argc, char **argv) {
    int i = 1;
    if (argc >= 3 && !strcmp(argv[1], "umask")) { umask((mode_t)strtoul(argv[2], NULL, 8)); i = 3; }
    for (; i + 1 < argc; i += 2) {
        const char *op = argv[i], *path = argv[i + 1];
        struct stat st;
        int fd;
        if (!strcmp(op, "create")) {
            fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0666);
            if (fd < 0 || fstat(fd, &st) < 0) { printf("create %s\n", strerror(errno)); continue; }
            printf("create ok %u %u %o\n", (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)(st.st_mode & 07777));
        } else if (!strcmp(op, "write")) {
            fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) { printf("write %s\n", strerror(errno)); continue; }
            printf("write %s\n", write(fd, "x", 1) == 1 ? "ok" : strerror(errno));
        } else if (!strcmp(op, "read")) {
            fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) { printf("read %s\n", strerror(errno)); continue; }
            printf("read ok\n");
        } else if (!strcmp(op, "tmpfile")) {
            fd = open(path, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
            if (fd < 0 || fstat(fd, &st) < 0) { printf("tmpfile %s\n", strerror(errno)); continue; }
            printf("tmpfile ok %u %u\n", (unsigned)st.st_uid, (unsigned)st.st_gid);
        } else if (!strcmp(op, "unlink")) { res(op, unlink(path)); continue;
        } else if (!strcmp(op, "rmdir"))  { res(op, rmdir(path)); continue;
        } else if (!strcmp(op, "mkdir"))  { res(op, mkdir(path, 0777)); continue;
        } else if (!strcmp(op, "chmod"))  { res(op, chmod(path, 0600)); continue;
        } else if (!strcmp(op, "utime"))  {
            struct timespec t[2] = { { 1000000000, 0 }, { 1000000000, 0 } };
            res(op, utimensat(AT_FDCWD, path, t, 0)); continue;
        } else if (!strcmp(op, "truncate")) { res(op, truncate(path, 1)); continue;
        } else if (!strcmp(op, "ftruncate") || !strcmp(op, "fchmod")) {
            fd = open(path, (op[1] == 't' ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
            if (fd < 0) { printf("%s open %s\n", op, strerror(errno)); continue; }
            res(op, op[1] == 't' ? ftruncate(fd, 1) : fchmod(fd, 0640));
        } else if (!strcmp(op, "chdir"))  {
            int r = chdir(path);
            res(op, r);
            char cwd[4096];
            if (!r && getcwd(cwd, sizeof cwd)) printf("cwd %s\n", cwd);
            continue;
        } else if (!strcmp(op, "symlink")) { res(op, symlink("/etc/hostname", path)); continue;
        } else if (!strcmp(op, "link")) {
            char l[4096];
            snprintf(l, sizeof l, "%s.l", path);
            res(op, link(path, l)); continue;
        } else if (!strcmp(op, "rename") || !strcmp(op, "exchange") || !strcmp(op, "unlinkat")) {
            char a[4096], *b;
            snprintf(a, sizeof a, "%s", path);
            b = strchr(a, ':');
            if (!b) { printf("%s: need A:B\n", op); continue; }
            *b++ = '\0';
            if (op[0] == 'r') res(op, rename(a, b));
            else if (op[0] == 'e') res(op, (int)syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 2));
            else {
                int d = open(a, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (d < 0) { printf("%s open %s\n", op, strerror(errno)); continue; }
                res(op, unlinkat(d, b, 0));
                close(d);
            }
            continue;
        } else if (!strcmp(op, "rstat") || !strcmp(op, "rlstat")) {
#ifdef SYS_stat
            res(op, (int)syscall(op[1] == 's' ? SYS_stat : SYS_lstat, path, &st));
#else       /* v1.30: arm64 has only newfstatat, which the legacy calls are */
            res(op, (int)syscall(SYS_newfstatat, AT_FDCWD, path, &st, op[1] == 's' ? 0 : AT_SYMLINK_NOFOLLOW));
#endif
            continue;
        } else if (!strcmp(op, "admits")) {
            struct rusage ru;
            struct statfs sf;
            struct itimerval it;
            struct __user_cap_header_struct ch = { _LINUX_CAPABILITY_VERSION_3, 0 };
            struct __user_cap_data_struct cd[2];
            char nm[16];
            fd = open(path, O_RDONLY | O_CLOEXEC);
            res("getrusage", getrusage(RUSAGE_SELF, &ru));
            res("getpgrp", getpgrp() < 0 ? -1 : 0);
            res("setpgid", setpgid(0, 0));
            res("getsid", getsid(0) < 0 ? -1 : 0);
            res("capget", (int)syscall(SYS_capget, &ch, cd));
            res("fadvise64", (errno = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL)) ? -1 : 0);
            res("flock", flock(fd, LOCK_SH));
            res("fstatfs", fstatfs(fd, &sf));
            res("getitimer", getitimer(ITIMER_REAL, &it));
            errno = 0; alarm(0); res("alarm", errno ? -1 : 0);
            errno = 0; mode_t old = umask(077); res("umask", errno ? -1 : 0); umask(old);
            res("prctl_set_name", prctl(PR_SET_NAME, "v1290", 0, 0, 0));
            res("prctl_get_name", prctl(PR_GET_NAME, nm, 0, 0, 0));
            res("prctl_set_dumpable", prctl(PR_SET_DUMPABLE, 0, 0, 0, 0));      /* refused */
            int pfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
            res("pidfd_open", pfd < 0 ? -1 : 0);
            pid_t c = fork();
            if (c == 0) _exit(setsid() < 0 ? 1 : 0);
            int ws = 0;
            waitpid(c, &ws, 0);
            printf("setsid %s\n", WIFEXITED(ws) && WEXITSTATUS(ws) == 0 ? "ok" : "refused");
            if (pfd >= 0) close(pfd);
        } else {
            printf("%s: unknown\n", op);
            continue;
        }
        close(fd);
    }
    fflush(stdout);
    return 0;
}
