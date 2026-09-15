// SPDX-License-Identifier: MIT
// lifecycle_target.c — v1.9.3 lifecycle-coupling test workload.
//
// Behaves like an agent that spawns a helper: forks one descendant, reports
// both pids on stdout as "T <target_pid> G <descendant_pid>\n", then both
// processes idle. Uses only syscalls in the v1.9.2 baseline allowlist
// (clone without namespace bits, write, clock_nanosleep, getpid, exit_group).
// The pids it prints are as seen from inside its own pid namespace, so the
// harness does not rely on them; it discovers the real pids from /proc.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void idle_forever(void) {
    struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
    for (;;) nanosleep(&ts, NULL);
}

int main(void) {
    pid_t g = fork();
    if (g < 0) return 1;
    if (g == 0) idle_forever();

    char line[64];
    int n = snprintf(line, sizeof line, "T %d G %d\n", (int)getpid(), (int)g);
    if (n > 0 && write(STDOUT_FILENO, line, (size_t)n) != n) return 1;
    idle_forever();
}
