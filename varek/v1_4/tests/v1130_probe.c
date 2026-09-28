// SPDX-License-Identifier: MIT
// v1130_probe.c — target for the v1.13.0 regression test.
//
// Run UNDER the Warden with tests/v1130_policy.txt, which uses the bitvector
// (open-flag) fragment of the v1.13 SMT decision procedure:
//
//   allow path /tmp/varek_ro_v1130/ readonly      (access=ro -O_CREAT -O_TRUNC)
//   allow path /tmp/varek_rw_v1130/
//
// Through v1.12.4 a policy could only allow or deny a path prefix, whatever the
// open flags; "read-only" could not be expressed. The probe checks that a
// read-only rule admits reads and refuses every way of modifying the file
// through open() (write access, O_TRUNC even with O_RDONLY, O_CREAT even with
// O_RDONLY), and that flag bits outside the ABI open(2) set, and access mode
// 3, are refused as outside the decision procedure's fragment.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RO "/tmp/varek_ro_v1130"
#define RW "/tmp/varek_rw_v1130"

static void line(const char *tag, const char *verdict, int err) {
    if (err) printf("PROBE %-24s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-24s %s\n", tag, verdict);
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

/* openat with a raw 32-bit flags value, bypassing libc's flag handling. */
static void raw_refuse(const char *tag, const char *path, unsigned int flags) {
    long fd = syscall(SYS_openat, AT_FDCWD, path, (long)(int)flags, 0);
    if (fd >= 0) { line(tag, "BYPASSED", 0); close((int)fd); }
    else line(tag, "REFUSED", errno);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Read-only directory. */
    must_open("ro_read",                RO "/data.txt", O_RDONLY);
    must_open("ro_read_cloexec",        RO "/data.txt", O_RDONLY | O_CLOEXEC);
    {
        int fd = open(RO "/data.txt", O_RDONLY);
        char b[64] = {0};
        ssize_t n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (fd >= 0) close(fd);
        line("ro_read_content", n > 0 && !strncmp(b, "original", 8) ? "OK" : "WRONG", 0);
    }
    must_refuse("ro_write",             RO "/data.txt", O_WRONLY);
    must_refuse("ro_readwrite",         RO "/data.txt", O_RDWR);
    must_refuse("ro_append",            RO "/data.txt", O_WRONLY | O_APPEND);
    must_refuse("ro_rdonly_trunc",      RO "/data.txt", O_RDONLY | O_TRUNC);
    must_refuse("ro_rdonly_creat_new",  RO "/new.txt",  O_RDONLY | O_CREAT);
    must_refuse("ro_tmpfile",           RO,             O_TMPFILE | O_RDWR);

    /* Read-write directory: everything the read-only rule refuses is allowed. */
    must_open("rw_write",               RW "/w.txt",    O_WRONLY | O_CREAT | O_TRUNC);
    must_open("rw_append",              RW "/w.txt",    O_WRONLY | O_APPEND);
    must_open("rw_read",                RW "/w.txt",    O_RDONLY);

    /* Flag bits outside the ABI open(2) set: outside the fragment -> UNKNOWN
     * -> refused, even under the permissive rule. */
    raw_refuse("unknown_bit_31",        RW "/w.txt",    0x80000000u);
    raw_refuse("unknown_bit_24",        RW "/w.txt",    0x01000000u);
    /* Access mode 3 (O_WRONLY|O_RDWR): matches no access= clause, yet the
     * kernel honours O_TRUNC with it. Outside the fragment -> refused. */
    raw_refuse("access_mode_3_trunc",   RW "/w.txt",    0x3u | O_TRUNC);

    line("done", "", 0);
    return 0;
}
