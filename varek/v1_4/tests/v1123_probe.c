// SPDX-License-Identifier: MIT
// v1123_probe.c — target for the v1.12.3 regression test.
//
// Built DYNAMICALLY on purpose: its own loader opens (ld.so.cache, libc, and
// the /lib -> /usr/lib and libc.so.6 -> libc.so.6.* symlinks) go through the
// Warden and must succeed. Through v1.12.2 the filter resolved with
// RESOLVE_NO_SYMLINKS, so any path with a symlink component was refused and a
// dynamically linked program could not start. v1.12.3 follows ordinary
// symlinks and decides on the canonical path.
//
// Run UNDER the Warden with tests/v1123_policy.txt. Each check reports a
// "PROBE <tag> <verdict>" line; test_v1123.sh asserts on these and on the
// Warden's verdict stream. Legitimate symlinked opens must succeed; symlinks
// that escape to a denied object, other processes' /proc, and a trailing
// symlink opened O_NOFOLLOW must all be refused.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ALLOW  "/tmp/varek_allowed_v1123"
#define DENIED "/tmp/varek_denied_v1123"

static void line(const char *tag, const char *verdict, int err) {
    if (err) printf("PROBE %-24s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-24s %s\n", tag, verdict);
    fflush(stdout);
}

// An open that must succeed, optionally reading and matching a marker.
static void must_open(const char *tag, const char *path, int flags,
                      const char *want) {
    int fd = open(path, flags);
    if (fd < 0) { line(tag, "DENIED", errno); return; }
    if (want) {
        char b[512] = {0};
        ssize_t n = read(fd, b, sizeof b - 1);
        close(fd);
        if (n <= 0) { line(tag, "READ_FAILED", errno); return; }
        line(tag, memmem(b, (size_t)n, want, strlen(want)) ? "OK" : "WRONG", 0);
        return;
    }
    close(fd);
    line(tag, "OK", 0);
}

// An open that must be refused. Success is a bypass.
static void must_refuse(const char *tag, const char *path, int flags) {
    int fd = open(path, flags);
    if (fd >= 0) { line(tag, "BYPASSED", 0); close(fd); }
    else           line(tag, "REFUSED", errno);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    // 1. A symlink in an allowed dir pointing at an allowed file: followed and
    //    delivered. This is the case v1.12.2 refused.
    must_open("symlink_to_allowed", ALLOW "/link_to_ok", O_RDONLY, "legitimate");

    // 2. A symlinked DIRECTORY component, then a real file beneath it.
    must_open("dir_symlink_component", ALLOW "/dirlink/inner.txt", O_RDONLY, "inner ok");

    // 3. A relative symlink resolved within the allowed dir.
    must_open("relative_symlink", ALLOW "/rel_link", O_RDONLY, "legitimate");

    // 4. A symlink in an allowed dir pointing OUT to a denied file: decided on
    //    the canonical target, so refused.
    must_refuse("symlink_escape", ALLOW "/link_to_secret", O_RDONLY);

    // 5. A symlink pointing at an absolute denied path.
    must_refuse("symlink_abs_denied", ALLOW "/link_to_etc_shadow", O_RDONLY);

    // 6. A chain of symlinks ending at a denied file.
    must_refuse("symlink_chain_escape", ALLOW "/chain_a", O_RDONLY);

    // 7. Opening the trailing symlink itself with O_NOFOLLOW: the link is a
    //    denied object, so refused (a normal open would ELOOP).
    must_refuse("nofollow_trailing_link", ALLOW "/link_to_secret", O_RDONLY | O_NOFOLLOW);

    // 8. /proc/self maps to the AGENT, not the supervisor: /proc/self/cmdline
    //    must read back THIS probe's own argv, proving the mapping. Policy
    //    allows /proc/self/.
    must_open("proc_self_is_agent", "/proc/self/cmdline", O_RDONLY, "v1123_probe");

    // 9. /proc/thread-self likewise maps to the agent's own task.
    must_open("proc_thread_self_agent", "/proc/thread-self/cmdline", O_RDONLY, "v1123_probe");

    // 10. Another process's /proc: even though /proc/self/ is allowed, an
    //     absolute /proc/<pid>/ that is not the agent's own is refused.
    must_refuse("proc_pid1_mem", "/proc/1/mem", O_RDONLY);

    // 11. A symlink pointing at /proc/self/mem: /proc/self is a MAGIC link, so
    //     RESOLVE_NO_MAGICLINKS refuses it during resolution (before any policy
    //     or /proc check) — the agent cannot follow a planted link into the
    //     supervisor's context.
    must_refuse("symlink_to_proc_self", ALLOW "/link_to_proc_self_mem", O_RDONLY);

    // 12. A symlink pointing at another process's NUMERIC /proc/<pid>/mem: this
    //     resolves (no magic link in the path), and the post-resolution /proc
    //     check refuses it because it is not the agent's own /proc/<tgid>.
    must_refuse("symlink_to_proc_pid1", ALLOW "/link_to_proc_pid1_mem", O_RDONLY);

    // 13. A bare denied /proc entry stays refused by default-deny (it is a
    //     non-process procfs entry, so the /proc check does not itself refuse
    //     it; the policy does not name it).
    must_refuse("proc_kcore", "/proc/kcore", O_RDONLY);

    // 14. A legitimate non-symlink open in the allowed dir still works.
    must_open("plain_allowed", ALLOW "/ok.txt", O_RDONLY, "legitimate");

    // 15. The denied file opened directly is still refused.
    must_refuse("denied_direct", DENIED "/secret.txt", O_RDONLY);

    line("done", "", 0);
    return 0;
}
