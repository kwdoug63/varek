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
//   ERR is strerror's text of the call's errno.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
        } else {
            printf("%s: unknown\n", op);
            continue;
        }
        close(fd);
    }
    fflush(stdout);
    return 0;
}
