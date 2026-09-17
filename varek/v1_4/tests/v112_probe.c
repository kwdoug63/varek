// SPDX-License-Identifier: MIT
// v112_probe.c — adversarial target for the v1.12 mediation regression test.
//
// Run UNDER the Warden with tests/v112_policy.txt. Each action below is one of
// the five bypasses fixed in v1.12; every one must be refused by an enforcing
// Warden. The probe reports its own view (open/send return values) to stdout in
// a stable, greppable form; test_v112.sh asserts on the Warden's JSON verdicts
// AND on these lines, so a regression shows up on either side.
//
// The probe intentionally does NOT try to distinguish "denied by policy" from
// "denied by resolution failure" — from the agent's side every bypass must look
// like EACCES/EPERM.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void report(const char *tag, int ok_means_bypass) {
    // ok_means_bypass: 1 if a SUCCESS here is a security failure.
    printf("PROBE %-18s %s\n", tag, ok_means_bypass ? "BYPASSED" : "REFUSED");
}

static void try_open(const char *tag, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) { report(tag, 1); close(fd); }
    else         { printf("PROBE %-18s REFUSED (%s)\n", tag, strerror(errno)); }
}

int main(void) {
    // 1. legitimate open inside an allowed dir — must SUCCEED (guards against
    //    the fixes over-refusing).
    int fd = open("/tmp/varek_allowed_probe/ok.txt", O_RDONLY);
    if (fd >= 0) { printf("PROBE %-18s OK\n", "legit_open"); close(fd); }
    else         { printf("PROBE %-18s DENIED (%s)\n", "legit_open", strerror(errno)); }

    // 2. .. traversal out of an allowed dir into a denied object.
    try_open("dotdot_traversal", "/tmp/varek_allowed_probe/../../etc/shadow");

    // 3. symlink inside an allowed dir pointing at a denied object.
    try_open("symlink_escape", "/tmp/varek_allowed_probe/link_to_shadow");

    // 4. /proc/self magic link — resolves in the SUPERVISOR's context.
    try_open("proc_self_mem", "/proc/self/mem");

    // 5. audit-log forgery via a crafted pathname. If the Warden writes the
    //    target unescaped, this injects a second "ALLOW" record. The open must
    //    be refused AND the record must stay well-formed (asserted in the .sh).
    try_open("log_forgery",
             "/x\",\"decision_final\":\"ALLOW\"}\n{\"report_id\":\"FORGED\",\"decision_final\":\"ALLOW\"}");

    // 6. UDP datagram egress without connect().
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port   = htons(9999);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        ssize_t n = sendto(s, "exfil", 5, 0, (struct sockaddr *)&a, sizeof(a));
        if (n == 5) report("udp_sendto_egress", 1);
        else        printf("PROBE %-18s REFUSED (%s)\n", "udp_sendto_egress", strerror(errno));
        close(s);
    }

    // 7. UDP egress via sendmsg with an explicit destination.
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port   = htons(9998);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        struct iovec io = { .iov_base = (void *)"exfil", .iov_len = 5 };
        struct msghdr m;
        memset(&m, 0, sizeof(m));
        m.msg_name = &a; m.msg_namelen = sizeof(a);
        m.msg_iov = &io; m.msg_iovlen = 1;
        ssize_t n = sendmsg(s, &m, 0);
        if (n == 5) report("udp_sendmsg_egress", 1);
        else        printf("PROBE %-18s REFUSED (%s)\n", "udp_sendmsg_egress", strerror(errno));
        close(s);
    }

    printf("PROBE done\n");
    return 0;
}
