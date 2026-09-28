// SPDX-License-Identifier: MIT
// v1140_probe.c — target for the v1.14.0 regression test.
//
// Run UNDER the Warden with tests/v1140_policy.txt, which uses the bounded
// string fragment of the v1.14 SMT decision procedure (suffix, contains, glob
// and exact matchers). Through v1.13 a path rule could only name a prefix, so
// "any .pem file", "any .ssh directory", "a secret-* file at any depth" or
// "exactly this file, not its siblings" could not be written. The probe checks
// each matcher under the live Warden, on the resolved path (a symlink with an
// innocent name that points at a .pem file is refused).

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define D "/tmp/varek_v1140"

static void line(const char *tag, const char *verdict, int err) {
    if (err) printf("PROBE %-26s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-26s %s\n", tag, verdict);
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

    /* prefix (the default) still admits the workspace */
    must_open("work_write",              D "/work/a.txt", O_WRONLY | O_CREAT | O_TRUNC);
    /* suffix .pem, including through a symlink with an innocent name */
    must_refuse("suffix_pem",            D "/work/cert.pem", O_RDONLY);
    must_refuse("suffix_pem_via_symlink", D "/work/innocent.txt", O_RDONLY);
    must_open("suffix_nearmiss",         D "/work/pem-notes.txt", O_RDONLY);
    /* contains /.ssh */
    must_refuse("contains_ssh_key",      D "/work/.ssh/id_ed25519", O_RDONLY);
    must_refuse("contains_ssh_dir",      D "/work/.ssh", O_RDONLY | O_DIRECTORY);
    // glob with the slash-star-star-slash unit: zero or more segments
    must_refuse("glob_segs_zero",        D "/work/secret-top", O_RDONLY);
    must_refuse("glob_segs_deep",        D "/work/x/y/secret-token", O_RDONLY);
    must_open("glob_segs_nearmiss",      D "/work/x/y/not-secret", O_RDONLY);
    /* glob with * (one segment, never crossing '/') */
    must_refuse("glob_star_one_segment", D "/work/private/k", O_RDONLY);
    must_open("glob_star_no_cross",      D "/work/sub/private/k", O_RDONLY);
    /* exact: this file read-only; its siblings fall to the prefix deny */
    must_open("exact_read",              D "/only.txt", O_RDONLY);
    must_refuse("exact_write",           D "/only.txt", O_WRONLY);
    must_refuse("exact_sibling",         D "/only.txt.bak", O_RDONLY);
    /* glob *.log read-only in logs/, not in a subdirectory */
    must_open("glob_log_read",           D "/logs/app.log", O_RDONLY);
    must_refuse("glob_log_write",        D "/logs/app.log", O_WRONLY | O_APPEND);
    must_refuse("glob_log_subdir",       D "/logs/2026/app.log", O_RDONLY);
    return 0;
}
