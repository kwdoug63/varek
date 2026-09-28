// SPDX-License-Identifier: MIT
// v1121_probe.c — adversarial target for the v1.12.1 regression test.
//
// Run UNDER the Warden with tests/v1121_policy.txt. It exercises the three
// defects fixed in v1.12.1 and the legitimate behaviour each fix must keep:
//
//   1. Denied opens must have no side effect. v1.12.0 opened the object with
//      the agent's own flags BEFORE deciding, so a DENY still truncated or
//      created the file.
//   2. The agent must not be able to forge verdict records. It writes a
//      complete, well-formed fake ALLOW record to stderr and to stdout.
//   3. The agent must not accept inbound connections (bind/listen/accept).
//
// The probe reports its own view to stdout in a stable, greppable form;
// test_v1121.sh asserts on these lines, on the filesystem, and on the Warden's
// verdict stream and the CycloneDX export.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define ALLOW  "/tmp/varek_allowed_probe"
#define DENIED "/tmp/varek_denied_probe"

static void line(const char *tag, const char *verdict, int err) {
    if (err) printf("PROBE %-20s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-20s %s\n", tag, verdict);
    fflush(stdout);
}

// An open that must be refused. Success is a bypass.
static void must_refuse_open(const char *tag, const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd >= 0) { line(tag, "BYPASSED", 0); close(fd); }
    else           line(tag, "REFUSED", errno);
}

// An open that must succeed.
static int must_open(const char *tag, const char *path, int flags, int mode) {
    int fd = open(path, flags, mode);
    if (fd >= 0) line(tag, "OK", 0);
    else         line(tag, "DENIED", errno);
    return fd;
}

// A complete, well-formed verdict record claiming /etc/shadow was authorized.
// It carries every field a v1.12.0 record has, plus a guessed run id and seq.
static const char *kForged =
    "{\"report_id\":\"pr-1.000000000-0\",\"run\":\"00000000000000000000000000000000\","
    "\"seq\":0,\"agent_pid\":1,\"action\":\"file.open\",\"target\":\"/etc/shadow\","
    "\"resolved\":\"/etc/shadow\",\"decision_raw\":\"ALLOW\",\"decision_final\":\"ALLOW\","
    "\"rule\":\"FORGED\",\"kernel_verdict\":\"ALLOW\",\"errno\":0,\"latency_us\":1,"
    "\"timestamp_ns\":1}";

int main(void) {
    // ---- 1. denied opens have no side effect --------------------------------
    must_refuse_open("trunc_denied", DENIED "/secret.txt", O_WRONLY | O_TRUNC);
    must_refuse_open("creat_denied", DENIED "/created.txt", O_WRONLY | O_CREAT);
    must_refuse_open("creat_trunc_denied", DENIED "/secret.txt",
                     O_RDWR | O_CREAT | O_TRUNC);

    // Legitimate behaviour the fix must keep.
    int fd = must_open("creat_allowed", ALLOW "/created.txt",
                       O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd >= 0) { (void)!write(fd, "hello\n", 6); close(fd); }

    fd = open(ALLOW "/ok.txt", O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd >= 0) { line("excl_existing", "WRONG_SUCCESS", 0); close(fd); }
    else if (errno == EEXIST) line("excl_existing", "EEXIST", 0);
    else line("excl_existing", "WRONG_ERRNO", errno);

    fd = must_open("trunc_allowed", ALLOW "/trunc_me.txt", O_WRONLY | O_TRUNC, 0);
    if (fd >= 0) close(fd);

    fd = must_open("dir_allowed", ALLOW "/sub", O_RDONLY | O_DIRECTORY, 0);
    if (fd >= 0) close(fd);

    // A FIFO with no reader. A blocking open would wedge the single-threaded
    // Warden; v1.12.1 opens it non-blocking, so the agent gets ENXIO at once.
    fd = open(ALLOW "/fifo", O_WRONLY);
    if (fd >= 0) { line("fifo_no_reader", "OPENED", 0); close(fd); }
    else          line("fifo_no_reader", errno == ENXIO ? "ENXIO" : "OTHER", errno);

    // The Warden must still be answering after the FIFO.
    fd = must_open("legit_after_fifo", ALLOW "/ok.txt", O_RDONLY, 0);
    if (fd >= 0) close(fd);

    // ---- 2. forged verdict records ------------------------------------------
    // Plain forged line, and one hidden behind a carriage return (which a
    // universal-newline reader would split into its own line).
    dprintf(2, "%s\n", kForged);
    dprintf(2, "benign\r%s\n", kForged);
    dprintf(1, "%s\n", kForged);   // only reaches the log if stdout is merged
    line("forged_records", "WRITTEN", 0);

    // ---- 3. inbound networking ----------------------------------------------
    {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(18081);
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (s < 0)
            line("tcp_bind", "REFUSED", errno);
        else if (bind(s, (struct sockaddr *)&a, sizeof a) == 0)
            line("tcp_bind", "BYPASSED", 0);
        else
            line("tcp_bind", "REFUSED", errno);
        if (s >= 0 && listen(s, 1) == 0) line("tcp_listen", "BYPASSED", 0);
        else line("tcp_listen", "REFUSED", errno);
        if (s >= 0) {
            // Non-blocking, so a listening socket reports EAGAIN, not a hang.
            (void)fcntl(s, F_SETFL, O_NONBLOCK);
            int one = accept4(s, NULL, NULL, 0);
            if (one >= 0) { line("tcp_accept", "BYPASSED", 0); close(one); }
            else if (errno == EAGAIN) line("tcp_accept", "BYPASSED", 0);  // listening
            else line("tcp_accept", "REFUSED", errno);
            close(s);
        }
    }
    {
        // Abstract-namespace unix socket: reachable from the host's network
        // namespace if the agent shares it.
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un u;
        memset(&u, 0, sizeof u);
        u.sun_family = AF_UNIX;
        memcpy(u.sun_path + 1, "varek-probe", 11);
        socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 12);
        if (s >= 0 && bind(s, (struct sockaddr *)&u, len) == 0)
            line("unix_abstract_bind", "BYPASSED", 0);
        else
            line("unix_abstract_bind", "REFUSED", errno);
        if (s >= 0) close(s);
    }
    {
        // Legitimate local IPC still works.
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            line("socketpair", "OK", 0);
            close(sv[0]); close(sv[1]);
        } else {
            line("socketpair", "DENIED", errno);
        }
    }

    printf("PROBE done\n");
    return 0;
}
