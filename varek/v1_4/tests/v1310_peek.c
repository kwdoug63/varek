// SPDX-License-Identifier: MIT
// v1310_peek.c — a program for test_v1310.sh section 2 (confined subjects):
// launched by a confined MCP server, it tries to reach into another process
// through /proc and prints what happened, one line per entry:
//
//   v1310_peek ENTRY...     open /proc/<its parent>/ENTRY for reading
//                           (environ, mem, cwd/., root/., fd/0, ...) and
//                           print "ENTRY ok" or "ENTRY refused <errno name>"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t pp = getppid();
    for (int i = 1; i < argc; i++) {
        char p[256];
        snprintf(p, sizeof p, "/proc/%d/%s", (int)pp, argv[i]);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { printf("%s ok\n", argv[i]); close(fd); }
        else printf("%s refused %s\n", argv[i], errno == EACCES ? "EACCES" : errno == EPERM ? "EPERM" : strerror(errno));
    }
    fflush(stdout);
    return 0;
}
