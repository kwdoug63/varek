// SPDX-License-Identifier: MIT
// v1170_probe.c — adversarial target for the v1.17.0 regression test.
//
// Run UNDER the Warden with tests/v1170_policy.txt. Modes:
//   alias  open (and stat) the signing key, the verdict stream and the anchor
//          through a second, allowed path (a bind mount the test creates), and
//          raw devices planted inside the allowed tree
//   meta   stat / statx / access / readlink, allowed and refused
//   priv   report the agent's own uid, gid and capabilities
// Each line is "PROBE <tag> <result>" on stdout; test_v1170.sh asserts on these
// lines and on the Warden's verdict stream.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define D "/tmp/varek_v1170/allowed"

static void res(const char *tag, int ok, int err) {
    if (ok) printf("PROBE %-22s OK\n", tag);
    else    printf("PROBE %-22s ERR %s\n", tag, strerror(err));
    fflush(stdout);
}

static void try_read(const char *tag, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char b[128];
        ssize_t n = read(fd, b, sizeof b);
        printf("PROBE %-22s READ %zd\n", tag, n);
        fflush(stdout);
        close(fd);
    } else {
        res(tag, 0, errno);
    }
}

static void try_stat(const char *tag, const char *path, int flags) {
    struct stat st;
    int r = fstatat(AT_FDCWD, path, &st, flags);
    if (r == 0) printf("PROBE %-22s OK size=%lld\n", tag, (long long)st.st_size);
    else        printf("PROBE %-22s ERR %s\n", tag, strerror(errno));
    fflush(stdout);
}

static int mode_alias(void) {
    try_read("key_via_alias", D "/keys/log.key");
    try_stat("key_stat_via_alias", D "/keys/log.key", 0);
    try_read("stream_via_alias", D "/logs/run.log");
    try_read("anchor_via_alias", D "/logs/anchor.log");
    try_read("block_device", D "/blk");
    try_read("dev_mem", D "/mem");
    try_read("ordinary_file", D "/ok.txt");
    return 0;
}

static int mode_meta(void) {
    try_stat("stat_allowed", D "/ok.txt", 0);
    try_stat("stat_shadow", "/etc/shadow", 0);
    try_stat("stat_missing_inside", D "/nope", 0);
    try_stat("stat_missing_outside", "/root/nope", 0);
    try_stat("lstat_link", D "/lnk", AT_SYMLINK_NOFOLLOW);
    char b[PATH_MAX];
    ssize_t n = readlink(D "/lnk", b, sizeof b - 1);
    if (n >= 0) { b[n] = 0; printf("PROBE %-22s OK %s\n", "readlink_link", b); }
    else res("readlink_link", 0, errno);
    n = readlink("/proc/1/cwd", b, sizeof b - 1);          /* the host's init */
    int e = errno;
    res("readlink_host_proc", n >= 0, e);
    n = readlink("/proc/self/exe", b, sizeof b - 1);
    e = errno;
    res("readlink_self_exe", n >= 0, e);
    int a;
    a = access("/etc/shadow", F_OK); e = errno; res("access_F_shadow", a == 0, e);
    a = access(D "/ro/x", R_OK);     e = errno; res("access_R_readonly", a == 0, e);
    a = access(D "/ro/x", W_OK);     e = errno; res("access_W_readonly", a == 0, e);
    a = access(D "/ok.txt", X_OK);   e = errno; res("access_X", a == 0, e);
    int fd = open(D "/ok.txt", O_RDONLY);
    struct stat st;
    int r = fstat(fd, &st);
    if (r == 0) printf("PROBE %-22s OK size=%lld\n", "fstat_held", (long long)st.st_size);
    else res("fstat_held", 0, errno);
    struct statx x;
    r = statx(AT_FDCWD, D "/ok.txt", 0, STATX_SIZE, &x);
    if (r == 0) printf("PROBE %-22s OK size=%llu\n", "statx", (unsigned long long)x.stx_size);
    else res("statx", 0, errno);
    char *rp = realpath(D "/sub/../lnk", b);
    if (rp) printf("PROBE %-22s OK %s\n", "realpath", rp);
    else res("realpath", 0, errno);
    return 0;
}

static int mode_priv(void) {
    char b[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    b[n > 0 ? n : 0] = 0;
    for (char *l = strtok(b, "\n"); l; l = strtok(NULL, "\n"))
        if (!strncmp(l, "Uid:", 4) || !strncmp(l, "Gid:", 4) || !strncmp(l, "CapEff:", 7) ||
            !strncmp(l, "CapBnd:", 7) || !strncmp(l, "CapPrm:", 7))
            printf("PROBE %s\n", l);
    int r = setuid(0);
    res("setuid_0", r == 0, errno);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int rc = !strcmp(argv[1], "alias") ? mode_alias()
           : !strcmp(argv[1], "meta")  ? mode_meta()
           : !strcmp(argv[1], "priv")  ? mode_priv() : 2;
    printf("PROBE done\n");
    return rc;
}
