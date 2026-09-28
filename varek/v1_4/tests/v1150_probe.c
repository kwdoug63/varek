// SPDX-License-Identifier: MIT
// v1150_probe.c — target for the v1.15.0 regression test.
//
// Run UNDER the Warden with tests/v1150_policy.txt. Every open the Warden
// authorizes must carry a certificate its independent checker accepted. Under
// the test-only fault-injected Warden (make warden_faultinject), whose
// decision procedure wrongly says SATISFIED for any path ending in "/.inject",
// the checker must refuse the two wrong verdicts (a path under an explicit deny
// rule, and one under a denied directory) and accept the one that is right.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define D "/tmp/varek_v1150"

static void line(const char *tag, const char *verdict, int err) {
    if (err) printf("PROBE %-22s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-22s %s\n", tag, verdict);
    fflush(stdout);
}

static void must_open(const char *tag, const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd >= 0) { line(tag, "OK", 0); close(fd); }
    else line(tag, "DENIED", errno);
}

static void must_refuse(const char *tag, const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd >= 0) { line(tag, "BYPASSED", 0); close(fd); }
    else line(tag, "REFUSED", errno);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    must_open("prefix_write",        D "/work/a.txt", O_WRONLY | O_CREAT | O_TRUNC);
    must_open("glob_read",           D "/logs/app.log", O_RDONLY);
    must_open("contains_read",       D "/shared/c/data.bin", O_RDONLY);
    must_refuse("suffix_pem",        D "/work/k.pem", O_RDONLY);
    must_refuse("glob_write",        D "/logs/app.log", O_WRONLY);
    must_refuse("inject_under_deny", D "/work/x/.inject", O_RDONLY);
    must_refuse("inject_denied_dir", D "/secret/.inject", O_RDONLY);
    must_open("inject_allowed",      D "/pub/.inject", O_RDONLY);
    return 0;
}
