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
//   ERR is strerror's text of the open's errno.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        } else {
            printf("%s: unknown\n", op);
            continue;
        }
        close(fd);
    }
    fflush(stdout);
    return 0;
}
