// SPDX-License-Identifier: MIT
// test_v193_lifecycle.c — supervisor/target lifecycle coupling, end to end (v1.9.3).
//
// Runs the real Warden binary over tests/lifecycle_target (which forks one
// descendant), then stops the Warden and asserts that the target AND its
// descendant are gone within a deadline. Two scenarios:
//
//   crash    — Warden is SIGKILLed (no cleanup code runs)
//   orderly  — Warden receives SIGTERM (normal shutdown path)
//
// A third, unit-level check exercises the fork/re-parent race guard: a target
// whose supervisor is already dead must refuse to continue.
//
// Build/run from varek/v1_4:  make test-lifecycle   (requires root)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "warden_lifecycle.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#define DEADLINE_MS 3000

static int failures = 0;
#define CHECK(cond, ...) do { \
    if (cond) { printf("  PASS  "); printf(__VA_ARGS__); printf("\n"); } \
    else      { printf("  FAIL  "); printf(__VA_ARGS__); printf("\n"); failures++; } \
} while (0)

static pid_t ppid_of(pid_t pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *rp = strrchr(buf, ')');            // comm may contain spaces
    if (!rp) return -1;
    char state; int ppid;
    if (sscanf(rp + 2, "%c %d", &state, &ppid) != 2) return -1;
    return (pid_t)ppid;
}

// Collect every live process whose ancestry includes `root` (excluding root).
static int descendants_of(pid_t root, pid_t *out, int max) {
    int n = 0;
    // A few passes so grandchildren are found regardless of /proc order.
    for (int pass = 0; pass < 4; ++pass) {
        DIR *d = opendir("/proc");
        if (!d) return n;
        struct dirent *e;
        while ((e = readdir(d))) {
            pid_t p = (pid_t)atoi(e->d_name);
            if (p <= 0) continue;
            pid_t pp = ppid_of(p);
            int parent_known = (pp == root);
            for (int i = 0; i < n && !parent_known; ++i) parent_known = (pp == out[i]);
            if (!parent_known) continue;
            int dup = 0;
            for (int i = 0; i < n; ++i) dup |= (out[i] == p);
            if (!dup && n < max) out[n++] = p;
        }
        closedir(d);
    }
    return n;
}

static int wait_exit_pidfd(int pidfd, int timeout_ms) {
    struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);
    return r == 1;                            // readable => process exited
}

static void reap_orphans(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

static void run_scenario(const char *warden, const char *policy,
                         const char *target, const char *name, int stop_sig) {
    printf("scenario: %s (Warden gets %s)\n", name, strsignal(stop_sig));

    int out[2];
    if (pipe2(out, O_CLOEXEC) < 0) { perror("pipe2"); failures++; return; }

    pid_t w = fork();
    if (w == 0) {
        dup2(out[1], STDOUT_FILENO);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, STDERR_FILENO);
        execl(warden, warden, policy, "--", target, (char *)NULL);
        _exit(127);
    }
    close(out[1]);

    // Wait for the workload to report in (proves it is running under Warden).
    char buf[128] = {0};
    struct pollfd pfd = { .fd = out[0], .events = POLLIN };
    int ready = poll(&pfd, 1, DEADLINE_MS) == 1 && read(out[0], buf, sizeof buf - 1) > 0;
    CHECK(ready && buf[0] == 'T', "workload started under Warden");
    if (!ready) { kill(w, SIGKILL); waitpid(w, NULL, 0); close(out[0]); return; }

    pid_t procs[16];
    int np = descendants_of(w, procs, 16);
    CHECK(np >= 2, "found target and its descendant (%d processes under Warden)", np);

    int pidfds[16];
    for (int i = 0; i < np; ++i)
        pidfds[i] = (int)syscall(__NR_pidfd_open, procs[i], 0u);

    kill(w, stop_sig);
    waitpid(w, NULL, 0);

    int survivors = 0;
    for (int i = 0; i < np; ++i) {
        int gone = pidfds[i] >= 0 && wait_exit_pidfd(pidfds[i], DEADLINE_MS);
        if (!gone) { survivors++; kill(procs[i], SIGKILL); }
        if (pidfds[i] >= 0) close(pidfds[i]);
    }
    reap_orphans();
    CHECK(survivors == 0, "no agent process outlives the Warden (%d survivor%s)",
          survivors, survivors == 1 ? "" : "s");
    close(out[0]);
}

// Race guard: the supervisor dies between fork and PR_SET_PDEATHSIG. The
// target must detect it and refuse to run unmonitored.
static void run_race_guard(void) {
    printf("scenario: supervisor already dead before coupling\n");
    int sync[2];
    if (pipe(sync) < 0) { perror("pipe"); failures++; return; }

    pid_t sup = fork();
    if (sup == 0) {
        // stand-in supervisor: create the liveness pipe, fork the target,
        // then die immediately.
        int live[2];
        if (pipe(live) < 0) _exit(1);
        pid_t t = fork();
        if (t == 0) {
            close(live[1]);
            // wait until our parent is certainly gone
            char c; if (read(sync[0], &c, 1) != 1) _exit(2);
            int rc = wd_target_couple_to_supervisor(live[0]);
            _exit(rc == -ESRCH ? 0 : 1);
        }
        _exit(0);   // die holding live[1]; kernel closes it
    }
    close(sync[0]);
    waitpid(sup, NULL, 0);          // supervisor is dead now
    if (write(sync[1], "x", 1) != 1) { perror("write"); failures++; }  // let the orphan proceed
    close(sync[1]);

    // The orphan is re-parented to us (we are a child subreaper).
    int status = 0; pid_t r;
    do { r = waitpid(-1, &status, 0); } while (r < 0 && errno == EINTR);
    CHECK(r > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "target refuses to continue once its supervisor is gone (-ESRCH)");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <warden> <policy> <lifecycle_target (absolute)>\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) { perror("subreaper"); return 2; }

    run_scenario(argv[1], argv[2], argv[3], "crash", SIGKILL);
    run_scenario(argv[1], argv[2], argv[3], "orderly", SIGTERM);
    run_race_guard();

    printf("%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
