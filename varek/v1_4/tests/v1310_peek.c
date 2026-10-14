// SPDX-License-Identifier: MIT
// v1310_peek.c — a program for test_v1310.sh section 2 (confined subjects):
// launched by a confined MCP server, it tries to reach into another process
// through /proc and prints what happened, one line per entry:
//
//   v1310_peek ENTRY...     open /proc/<its parent>/ENTRY for reading
//                           (environ, mem, cwd/., root/., fd/0, ...) and
//                           print "ENTRY ok" or "ENTRY refused <errno name>";
//                           self:ENTRY opens /proc/self/ENTRY (a control)
// The parent's pid is the one /proc/self/status gives (v1.31 review: the
// pid in the /proc the paths resolve in, not getppid()'s, which is the
// agent's pid namespace's); it prints "parent PID" first.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t pp = getppid();
    FILE *f = fopen("/proc/self/status", "re");
    char ln[256];
    while (f && fgets(ln, sizeof ln, f)) if (!strncmp(ln, "PPid:", 5)) pp = (pid_t)atoi(ln + 5);
    if (f) fclose(f);
    printf("parent %d\n", (int)pp);
    for (int i = 1; i < argc; i++) {
        char p[256];
        if (!strncmp(argv[i], "self:", 5)) snprintf(p, sizeof p, "/proc/self/%s", argv[i] + 5);
        else snprintf(p, sizeof p, "/proc/%d/%s", (int)pp, argv[i]);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { printf("%s ok\n", argv[i]); close(fd); }
        else printf("%s refused %s\n", argv[i], errno == EACCES ? "EACCES" : errno == EPERM ? "EPERM" : strerror(errno));
    }
    fflush(stdout);
    return 0;
}
