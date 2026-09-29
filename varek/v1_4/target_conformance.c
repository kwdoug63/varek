// SPDX-License-Identifier: MIT
// target_conformance.c — VAREK Warden conformance target ("Test Target 1")
//
// A realistic agent-shaped workload that exercises the v1.9.2+ default-deny
// enforcement boundary end to end, then reports whether each operation behaved
// as the policy requires. Run it under the Warden:
//
//   make run-conformance
//
// which builds this target, creates its work directory, and runs:
//
//   sudo ./warden conformance_policy.txt -- ./target_conformance
//
// The work directory (/tmp/varek_conf) must exist before the run: creating
// directories is outside the baseline allowlist, so the target cannot make it
// under enforcement. A missing directory is reported as a setup failure, not
// as a boundary failure.
//
// It is the executable analogue of the test suite: where the unit tests assert
// the filter denies ptrace/x32 in isolation, this proves a *running program*
// can do its legitimate work (open an allowed file, use a socket) while the
// boundary blocks the rest (read /etc, dial the network) — the claim a customer
// or auditor actually cares about.
//
// Build STATIC so the dynamic loader's own library opens don't have to be in
// policy; the only mediated openats are the ones this program makes on purpose:
//
//   cc -O2 -static -o target_conformance target_conformance.c
//
// Exit code: 0 if every phase matched its expectation under enforcement,
// 1 otherwise. Phase results are printed to stderr as JSON-ish lines so they
// interleave cleanly with the Warden's own pathology records.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ALLOWED_DIR  "/tmp/varek_conf"
#define ALLOWED_FILE ALLOWED_DIR "/work.txt"
#define DENIED_FILE  "/etc/shadow"
#define PROBE_MSG    "VAREK conformance probe\n"

static int g_pass = 0, g_fail = 0;

static void verdict(const char *phase, int ok, const char *detail) {
    fprintf(stderr,
        "{\"target\":\"conformance\",\"phase\":\"%s\",\"result\":\"%s\",\"detail\":\"%s\"}\n",
        phase, ok ? "PASS" : "FAIL", detail);
    if (ok) g_pass++; else g_fail++;
}

// Phase 1: open an ALLOWED file, write, read back. Under the Warden the open is
// mediated and (on allow) satisfied via supervisor fd injection; the read/write
// ride the injected, authorized fd. Expect: works, round-trips.
static void phase_allowed_file(void) {
    int fd = open(ALLOWED_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { verdict("allowed_open", 0, strerror(errno)); return; }

    if (write(fd, PROBE_MSG, sizeof(PROBE_MSG) - 1) != (ssize_t)(sizeof(PROBE_MSG) - 1)) {
        verdict("allowed_write", 0, strerror(errno)); close(fd); return;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) { verdict("allowed_seek", 0, strerror(errno)); close(fd); return; }

    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) { verdict("allowed_read", 0, strerror(errno)); return; }

    verdict("allowed_file", strcmp(buf, PROBE_MSG) == 0,
            strcmp(buf, PROBE_MSG) == 0 ? "round-trip ok" : "content mismatch");
}

// Phase 2: open a DENIED file. Expect: refused (EACCES/EPERM). A success here
// means the boundary failed open.
static void phase_denied_file(void) {
    int fd = open(DENIED_FILE, O_RDONLY);
    if (fd >= 0) { close(fd); verdict("denied_file", 0, "opened a denied path"); return; }
    verdict("denied_file", (errno == EACCES || errno == EPERM), strerror(errno));
}

// Phase 3: create a socket. socket() is admitted (the v1.4 supervisor does not
// mediate it). Expect: works.
static int phase_socket(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    verdict("socket_create", s >= 0, s >= 0 ? "socket ok" : strerror(errno));
    return s;
}

// Phase 4: connect that socket outbound. connect() IS mediated; through
// v1.20.0 every connect was refused (deny-only), and from v1.21 a connect is
// dialed only when a host rule allows it. The conformance policy has no host
// rule for 1.1.1.1:80, so either way. Expect: refused.
static void phase_connect(int s) {
    if (s < 0) { verdict("connect_denied", 0, "no socket from phase 3"); return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons(80);
    inet_pton(AF_INET, "1.1.1.1", &a.sin_addr);

    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    if (rc == 0) { verdict("connect_denied", 0, "connect succeeded"); return; }
    verdict("connect_denied", (errno == EACCES || errno == EPERM), strerror(errno));
}

int main(void) {
    fprintf(stderr, "{\"target\":\"conformance\",\"phase\":\"start\","
                    "\"note\":\"verdicts assume Warden enforcement is active\"}\n");

    // Setup check (v1.9.3): without the work directory the allowed open fails
    // for a reason unrelated to the boundary. stat() is in the allowlist and
    // not mediated, so this does not consume a policy decision.
    struct stat st;
    if (stat(ALLOWED_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        verdict("setup", 0, "missing work directory " ALLOWED_DIR
                "; run 'make run-conformance' or 'mkdir -p " ALLOWED_DIR "'");
        fprintf(stderr, "{\"target\":\"conformance\",\"phase\":\"summary\","
                        "\"pass\":0,\"fail\":1}\n");
        return 2;
    }

    phase_allowed_file();
    phase_denied_file();
    int s = phase_socket();
    phase_connect(s);
    if (s >= 0) close(s);

    fprintf(stderr, "{\"target\":\"conformance\",\"phase\":\"summary\","
                    "\"pass\":%d,\"fail\":%d}\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
