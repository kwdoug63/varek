// SPDX-License-Identifier: MIT
/*
 * warden.c — VAREK v1.4 reference implementation
 *
 * Privileged seccomp-unotify supervisor implementing the architecture
 * described in USPTO Provisional 64/059,592 (Warden architecture).
 *
 * Components implemented:
 *
 *   1. Privileged parent process (Warden) installs a seccomp filter in
 *      a forked child and acquires the SECCOMP_FILTER_FLAG_NEW_LISTENER
 *      file descriptor for the supervisor side of the unotify channel.
 *
 *   2. Receive loop — Warden waits on SECCOMP_IOCTL_NOTIF_RECV. Each
 *      notification carries the syscall number, raw arguments, and the
 *      pid of the trapped thread.
 *
 *   3. Cross-process memory extraction — Warden opens /proc/<pid>/mem
 *      with the SECCOMP_IOCTL_NOTIF_ID_VALID guard to materialize
 *      pointer arguments into the supervisor's address space.
 *
 *   4. Stateful Execution Context — per-pid state object tracking
 *      cwd snapshots, opened-fd lineage, and a sequence number used
 *      for pathology-report correlation.
 *
 *   5. Semantic Derivation Engine — maps (syscall, args, ExecCtx) to
 *      a structured Action {kind, target, parameters}, the form the
 *      Policy Decision layer reasons about.
 *
 *   6. Policy Decision — three-state return ALLOW / DENY / UNKNOWN.
 *      UNKNOWN is suppressed (treated as DENY for safety) per the
 *      symmetric-suppression invariant in the patent.
 *
 *   7. Kernel Injection — for path-arg syscalls (openat) Warden
 *      resolves the path itself via openat2(RESOLVE_NO_SYMLINKS |
 *      RESOLVE_NO_MAGICLINKS) and returns the resolved fd through
 *      SECCOMP_IOCTL_NOTIF_ADDFD with SECCOMP_ADDFD_FLAG_SEND. The
 *      kernel never re-reads the userspace pathname pointer.
 *
 *   8. Pathology Report — every decision is emitted as a JSON record
 *      to the configured sink (stderr by default), with monotonic-
 *      clock decision latency in microseconds.
 *
 * Trapped syscalls in this reference: openat, connect, execve.
 * The architecture extends to any syscall by adding a new case to
 * derive_intent() and policy_decide().
 *
 * Build:    make
 * Run:      sudo ./warden policy.txt -- ./target_program [args...]
 *
 * Requires: Linux kernel >= 5.14, x86_64 (BPF arch check).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* v1.9.1: io_uring syscall numbers (x86_64 / arm64-generic) */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup    425
#define __NR_io_uring_enter    426
#define __NR_io_uring_register 427
#endif
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* VAREK v1.6 plan-graph integration headers.
 * The v1_6/ directory ships these as a self-contained module; this
 * Warden translation unit only references them through the public
 * APIs declared below. See varek/v1_6/README.md for the contract. */
#include "execution_plan.h"
#include "pathology.h"
#include "plan_parser.h"
#include "plan_spec.h"
#include "warden_adapter.h"
#include "warden_baseline_filter.h"
#include "warden_lifecycle.h"   /* v1.9.3 supervisor/target lifecycle coupling */

/* Kernel/libc compatibility shims --------------------------------- */
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS    0x04
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS  0x02
#endif
#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

/* v1.12: pidfd_open / pidfd_getfd for the bootstrap listener-fd handoff.
 * Mediating sendto/sendmsg means the child can no longer use SCM_RIGHTS
 * (sendmsg) to pass the seccomp listener fd to the supervisor — that sendmsg
 * would trap on the just-installed filter with no one to answer it. Instead
 * the child writes the fd NUMBER over the socketpair (a plain write(), which
 * is admitted) and the supervisor pulls the actual fd out of the child with
 * pidfd_getfd(). The supervisor is not under seccomp, so these are free. */
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

struct open_how_local {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

#define ARCH_NR     AUDIT_ARCH_X86_64
#define PATH_LIMIT  4096
#define MAX_RULES    256
#define MAX_CTX       64

/* ---------------- decision types ---------------- */

typedef enum {
    DEC_ALLOW   = 0,
    DEC_DENY    = 1,
    DEC_UNKNOWN = 2,   /* suppressed -> treated as DENY */
} decision_t;

static const char *decision_name(decision_t d) {
    switch (d) {
        case DEC_ALLOW:   return "ALLOW";
        case DEC_DENY:    return "DENY";
        case DEC_UNKNOWN: return "UNKNOWN";
    }
    return "INVALID";
}

/* ---------------- Action (Semantic Derivation output) ---------------- */

typedef enum {
    ACT_FILE_OPEN,
    ACT_NET_CONNECT,
    ACT_NET_SEND,        /* v1.12: sendto/sendmsg egress */
    ACT_PROCESS_EXEC,
    ACT_OTHER,
} action_kind_t;

struct action {
    action_kind_t kind;
    char          target[PATH_LIMIT];   /* path or "host:port" or argv[0] */
    int           open_dirfd;           /* v1.12: openat's dirfd argument */
    char          resolved[PATH_LIMIT]; /* v1.12: canonical path of the object
                                         * the policy actually decided on */
    int           open_flags;
    int           open_mode;
    int           connect_family;
    int           connect_port;
};

static const char *action_kind_name(action_kind_t k) {
    switch (k) {
        case ACT_FILE_OPEN:    return "file.open";
        case ACT_NET_CONNECT:  return "net.connect";
        case ACT_NET_SEND:     return "net.send";
        case ACT_PROCESS_EXEC: return "process.exec";
        case ACT_OTHER:        return "other";
    }
    return "invalid";
}

/* ---------------- Policy ---------------- */

typedef enum { RULE_PATH_PREFIX, RULE_HOST, RULE_EXEC } rule_kind_t;

struct rule {
    rule_kind_t kind;
    char        match[PATH_LIMIT];
    decision_t  decision;
};

struct policy {
    char         name[64];
    char         version[16];
    struct rule  rules[MAX_RULES];
    size_t       n_rules;
};

static int policy_load(const char *path, struct policy *p) {
    memset(p, 0, sizeof(*p));
    snprintf(p->name,    sizeof(p->name),    "default");
    snprintf(p->version, sizeof(p->version), "1.4");

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[warden] policy: cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f) && p->n_rules < MAX_RULES) {
        lineno++;
        char *q = line;
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == '#' || *q == '\0' || *q == '\n') continue;
        size_t L = strlen(q);
        while (L && (q[L-1] == '\n' || q[L-1] == '\r' || q[L-1] == ' ')) {
            q[--L] = '\0';
        }

        char verb[16] = {0}, kind[16] = {0}, match[PATH_LIMIT] = {0};
        if (sscanf(q, "%15s %15s %4095s", verb, kind, match) != 3) {
            fprintf(stderr, "[warden] policy %s:%d: bad rule\n",
                    path, lineno);
            fclose(f); return -1;
        }
        struct rule *r = &p->rules[p->n_rules];
        if      (!strcmp(kind, "path"))   r->kind = RULE_PATH_PREFIX;
        else if (!strcmp(kind, "host"))   r->kind = RULE_HOST;
        else if (!strcmp(kind, "exec"))   r->kind = RULE_EXEC;
        else { fprintf(stderr, "[warden] policy %s:%d: unknown kind %s\n",
                       path, lineno, kind); fclose(f); return -1; }
        if      (!strcmp(verb, "allow"))  r->decision = DEC_ALLOW;
        else if (!strcmp(verb, "deny"))   r->decision = DEC_DENY;
        else { fprintf(stderr, "[warden] policy %s:%d: unknown verb %s\n",
                       path, lineno, verb); fclose(f); return -1; }
        snprintf(r->match, sizeof(r->match), "%s", match);
        p->n_rules++;
    }
    fclose(f);
    fprintf(stderr, "[warden] loaded policy %s v%s with %zu rules\n",
            p->name, p->version, p->n_rules);
    return 0;
}

/* ---------------- Execution Context (per-pid state) ---------------- */

struct exec_ctx {
    pid_t   pid;
    bool    in_use;
    uint64_t seq;
    char    cwd[PATH_LIMIT];
    bool    launched;
};

static struct exec_ctx g_ctx[MAX_CTX];

static struct exec_ctx *ctx_get(pid_t pid) {
    struct exec_ctx *free_slot = NULL;
    for (size_t i = 0; i < MAX_CTX; i++) {
        if (g_ctx[i].in_use && g_ctx[i].pid == pid) return &g_ctx[i];
        if (!g_ctx[i].in_use && !free_slot) free_slot = &g_ctx[i];
    }
    if (!free_slot) return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->pid = pid;
    free_slot->in_use = true;
    free_slot->seq = 0;
    return free_slot;
}

/* ---------------- cross-process memory ---------------- */

static int xproc_read_str(pid_t pid, uint64_t addr, char *out, size_t outlen) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t n = read(fd, out, outlen - 1);
    close(fd);
    if (n < 0) return -1;
    out[n] = '\0';
    for (ssize_t i = 0; i < n; i++) if (out[i] == '\0') return 0;
    /* v1.12: no terminator inside the window. An over-length (or unreadable)
     * string is refused, never truncated and then checked: the policy would
     * be deciding on a path the kernel was never asked to open. */
    out[0] = '\0';
    return -1;
}

static int xproc_read_bytes(pid_t pid, uint64_t addr, void *out, size_t len) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t n = read(fd, out, len);
    close(fd);
    return n == (ssize_t)len ? 0 : -1;
}

/* ---------------- BPF filter ---------------- */



/* ---------------- fd passing ---------------- */

/* v1.12: full-buffer write/read helpers over the socketpair. These carry the
 * listener fd NUMBER (an int) and a one-byte ack, using write()/read() — both
 * admitted by the baseline filter — so the bootstrap needs no post-filter
 * sendmsg. The listener fd itself is transferred out-of-band via pidfd_getfd()
 * on the supervisor side. */
static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* ---------------- Semantic Derivation ---------------- */

static int derive_intent(const struct seccomp_notif *req,
                         struct action *out)
{
    memset(out, 0, sizeof(*out));
    int nr = (int)req->data.nr;

    if (nr == __NR_openat) {
        out->kind = ACT_FILE_OPEN;
        if (xproc_read_str(req->pid, req->data.args[1],
                           out->target, sizeof(out->target)) < 0)
            return -1;
        out->open_dirfd = (int)req->data.args[0];
        out->resolved[0] = '\0';
        out->open_flags = (int)req->data.args[2];
        out->open_mode  = (int)(req->data.args[3] & 0777);
        return 0;
    }
    if (nr == __NR_connect) {
        out->kind = ACT_NET_CONNECT;
        socklen_t len = (socklen_t)req->data.args[2];
        if (len > sizeof(struct sockaddr_storage)) len = sizeof(struct sockaddr_storage);
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        if (xproc_read_bytes(req->pid, req->data.args[1], &ss, len) < 0)
            return -1;
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            snprintf(out->target, sizeof(out->target), "%s:%u",
                     ip, ntohs(sin->sin_port));
            out->connect_family = AF_INET;
            out->connect_port   = ntohs(sin->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            char ip[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
            snprintf(out->target, sizeof(out->target), "[%s]:%u",
                     ip, ntohs(sin6->sin6_port));
            out->connect_family = AF_INET6;
            out->connect_port   = ntohs(sin6->sin6_port);
        } else if (ss.ss_family == AF_UNIX) {
            struct sockaddr_un *sun = (struct sockaddr_un *)&ss;
            snprintf(out->target, sizeof(out->target), "unix:%s",
                     sun->sun_path[0] ? sun->sun_path : "<abstract>");
            out->connect_family = AF_UNIX;
        } else {
            snprintf(out->target, sizeof(out->target), "family:%u",
                     (unsigned)ss.ss_family);
            out->connect_family = ss.ss_family;
        }
        return 0;
    }
    if (nr == __NR_sendto || nr == __NR_sendmsg) {
        /* v1.12: extract the destination sockaddr, if any, so the send is
         * subject to the deny-only network posture. sendto passes dest_addr in
         * arg4 / addrlen in arg5; sendmsg carries msg_name / msg_namelen inside
         * the struct msghdr in arg1. A send with NO destination (connected
         * socket, or a purely local send) still lands here as ACT_NET_SEND and
         * is denied — in the v1.4 deny-only model no inet socket can be
         * connected (connect is denied), and egress-capable sends are not
         * authorizable. */
        out->kind = ACT_NET_SEND;
        uint64_t addr = 0, alen = 0;
        if (nr == __NR_sendto) {
            addr = req->data.args[4];
            alen = req->data.args[5];
        } else {
            struct { uint64_t name; uint32_t namelen; } mh; /* head of msghdr */
            if (xproc_read_bytes(req->pid, req->data.args[1], &mh, sizeof(mh)) == 0) {
                addr = mh.name;
                alen = mh.namelen;
            }
        }
        if (addr && alen >= sizeof(sa_family_t)) {
            struct sockaddr_storage ss;
            memset(&ss, 0, sizeof(ss));
            socklen_t l = alen > sizeof(ss) ? sizeof(ss) : (socklen_t)alen;
            if (xproc_read_bytes(req->pid, addr, &ss, l) == 0) {
                if (ss.ss_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                    char ip[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                    snprintf(out->target, sizeof(out->target), "%s:%u",
                             ip, ntohs(sin->sin_port));
                } else if (ss.ss_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                    char ip[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                    snprintf(out->target, sizeof(out->target), "[%s]:%u",
                             ip, ntohs(sin6->sin6_port));
                } else {
                    snprintf(out->target, sizeof(out->target), "family:%u",
                             (unsigned)ss.ss_family);
                }
            }
        }
        if (out->target[0] == '\0')
            snprintf(out->target, sizeof(out->target), "<no-dest>");
        return 0;
    }
    if (nr == __NR_execve || nr == __NR_execveat) {
        out->kind = ACT_PROCESS_EXEC;
        uint64_t pathaddr = (nr == __NR_execve)
            ? req->data.args[0]
            : req->data.args[1];
        if (xproc_read_str(req->pid, pathaddr,
                           out->target, sizeof(out->target)) < 0)
            return -1;
        return 0;
    }
    out->kind = ACT_OTHER;
    return 0;
}

/* ---------------- Policy Decision ---------------- */

static decision_t policy_decide(const struct policy *p,
                                const struct action *a)
{
    if (a->kind == ACT_FILE_OPEN) {
        /* v1.12: decide on the RESOLVED, canonical path — the object the
         * kernel actually opened — not the raw pathname the agent supplied.
         * `..` traversal and symlink/bind-mount indirection can no longer
         * make a denied object match an allow rule, because resolved is the
         * real target after `..` collapse and (with RESOLVE_NO_SYMLINKS) with
         * no symlink component permitted at all. If resolution has not run or
         * failed, resolved is empty and nothing matches -> UNKNOWN -> deny. */
        const char *decide_on = a->resolved[0] ? a->resolved : "";
        if (decide_on[0] == '\0') return DEC_UNKNOWN;
        for (size_t i = 0; i < p->n_rules; i++) {
            const struct rule *r = &p->rules[i];
            if (r->kind != RULE_PATH_PREFIX) continue;
            size_t L = strlen(r->match);
            if (strncmp(decide_on, r->match, L) == 0) return r->decision;
        }
        return DEC_UNKNOWN;
    }
    if (a->kind == ACT_NET_CONNECT) {
        for (size_t i = 0; i < p->n_rules; i++) {
            const struct rule *r = &p->rules[i];
            if (r->kind != RULE_HOST) continue;
            if (strcmp(a->target, r->match) == 0) return r->decision;
            const char *colon = strchr(a->target, ':');
            if (colon) {
                size_t hostlen = (size_t)(colon - a->target);
                if (strlen(r->match) == hostlen &&
                    strncmp(a->target, r->match, hostlen) == 0)
                    return r->decision;
            }
        }
        return DEC_UNKNOWN;
    }
    if (a->kind == ACT_PROCESS_EXEC) {
        for (size_t i = 0; i < p->n_rules; i++) {
            const struct rule *r = &p->rules[i];
            if (r->kind != RULE_EXEC) continue;
            if (strcmp(a->target, r->match) == 0) return r->decision;
        }
        return DEC_UNKNOWN;
    }
    return DEC_UNKNOWN;
}

/* ---------------- v1.6 plan-graph integration ---------------- */

/* Map a plan_spec_action_t kind string to the v1.4 action_kind_t.
 * Unknown kinds map to ACT_OTHER, which policy_decide() treats as
 * unmatched -> DEC_UNKNOWN under symmetric suppression. */
static action_kind_t kind_from_string(const char *s) {
    if (!s)                                  return ACT_OTHER;
    if (strcmp(s, "file_open")    == 0)      return ACT_FILE_OPEN;
    if (strcmp(s, "net_connect")  == 0)      return ACT_NET_CONNECT;
    if (strcmp(s, "process_exec") == 0)      return ACT_PROCESS_EXEC;
    return ACT_OTHER;
}

struct warden_plan_ud {
    const struct policy *policy;
};

/* Adapter decider that wraps the existing per-action policy_decide()
 * for use by warden_adapter_verify(). The plan_spec_action_t's
 * (kind, target) pair is sufficient because policy_decide() only
 * inspects those two fields. */
static plan_decision_t warden_plan_decider(const plan_spec_action_t *a,
                                           void *ud)
{
    const struct warden_plan_ud *u = (const struct warden_plan_ud *)ud;
    if (!u || !u->policy || !a) return PLAN_DEC_UNKNOWN;

    struct action act;
    memset(&act, 0, sizeof(act));
    act.kind = kind_from_string(a->kind);
    if (a->target) {
        snprintf(act.target, sizeof(act.target), "%s", a->target);
    }
    decision_t d = policy_decide(u->policy, &act);
    switch (d) {
        case DEC_ALLOW:   return PLAN_DEC_SATISFIED;
        case DEC_DENY:    return PLAN_DEC_UNSATISFIED;
        case DEC_UNKNOWN: return PLAN_DEC_UNKNOWN;
    }
    return PLAN_DEC_UNKNOWN;
}

/* Verify an agent's declared plan against the current policy, ahead
 * of any execution. Returns 0 if the plan is authorized, non-zero
 * otherwise. Emits a plan-level pathology record to stderr. */
static int warden_verify_plan(const char *plan_path,
                              const struct policy *policy)
{
    char err[256] = {0};
    plan_parsed_t *parsed = plan_parser_load(plan_path, err, sizeof(err));
    if (!parsed) {
        fprintf(stderr, "[warden] plan load failed: %s\n", err);
        return 1;
    }

    const plan_spec_t *spec = plan_parser_spec(parsed);
    pathology_sink_t *sink = pathology_sink_new(stderr);
    struct warden_plan_ud ud = { .policy = policy };

    plan_decision_t pd = warden_adapter_verify(spec, warden_plan_decider,
                                               &ud, sink);

    pathology_sink_free(sink);
    plan_parser_free(parsed);

    if (pd != PLAN_DEC_SATISFIED) {
        fprintf(stderr,
                "[warden] plan rejected (%s); refusing to fork target\n",
                plan_decision_name(pd));
        return 1;
    }
    fprintf(stderr,
            "[warden] plan authorized (%zu actions); proceeding to supervise\n",
            spec->n_actions);
    return 0;
}

/* ---------------- Pathology Report ---------------- */

/* v1.12: emit s as a JSON string body (without the surrounding quotes),
 * escaping every character that would otherwise let an attacker-controlled
 * path forge a second record or break out of the string. Control bytes go to
 * \uXXXX; the record is well-formed JSON for any byte sequence. This closes
 * the audit-log-forgery class: before this, a path containing `","...` was
 * written verbatim into the verdict stream. */
static void json_escape(FILE *f, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\b': fputs("\\b", f);  break;
            case '\f': fputs("\\f", f);  break;
            case '\n': fputs("\\n", f);  break;
            case '\r': fputs("\\r", f);  break;
            case '\t': fputs("\\t", f);  break;
            default:
                if (*p < 0x20) fprintf(f, "\\u%04x", (unsigned)*p);
                else           fputc(*p, f);
        }
    }
}

static FILE *g_log = NULL;

static void log_init(void) {
    g_log = stderr;
}

static void emit_pathology(uint64_t seq,
                           pid_t pid,
                           const struct action *a,
                           decision_t d_raw,
                           decision_t d_final,
                           const char *rule_id,
                           uint64_t latency_ns,
                           int kernel_errno)
{
    if (!g_log) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* v1.12: target and resolved are escaped via json_escape(); every other
     * field is drawn from a fixed enum or an integer, so the whole record is
     * well-formed JSON regardless of agent-controlled input. */
    fprintf(g_log,
        "{\"report_id\":\"pr-%ld.%09ld-%" PRIu64 "\","
        "\"agent_pid\":%d,"
        "\"action\":\"%s\","
        "\"target\":\"",
        (long)ts.tv_sec, ts.tv_nsec, seq,
        (int)pid,
        action_kind_name(a->kind));
    json_escape(g_log, a->target);
    fputs("\",\"resolved\":\"", g_log);
    json_escape(g_log, a->resolved[0] ? a->resolved : "");
    fprintf(g_log,
        "\",\"decision_raw\":\"%s\","
        "\"decision_final\":\"%s\","
        "\"rule\":\"%s\","
        "\"kernel_verdict\":\"%s\","
        "\"latency_us\":%" PRIu64 ","
        "\"timestamp_ns\":%lld}\n",
        decision_name(d_raw),
        decision_name(d_final),
        rule_id ? rule_id : "none",
        d_final == DEC_ALLOW ? "ALLOW" : "EPERM",
        (uint64_t)(latency_ns / 1000ULL),
        (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    fflush(g_log);
    (void)kernel_errno;
}

/* ---------------- Kernel Injection ---------------- */

static bool notif_id_valid(int notify_fd, uint64_t id) {
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

static void send_simple(int notify_fd, uint64_t id, decision_t d) {
    struct seccomp_notif_resp resp = {
        .id    = id,
        .val   = 0,
        .error = (d == DEC_ALLOW) ? 0 : -EACCES,
        .flags = 0,
    };
    if (d == DEC_ALLOW) resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

/* v1.12 AT_FDCWD constant (avoid pulling a divergent libc definition). */
#ifndef VAREK_AT_FDCWD
#define VAREK_AT_FDCWD (-100)
#endif

/* v1.12: resolve-once. Open the object the agent named, exactly once, in a
 * way that pins WHICH object every later step reasons about, and record its
 * canonical path into a->resolved for the policy decision and the audit log.
 *
 * Resolution flags (the header and bypass-classes.md claimed these; the code
 * shipped only RESOLVE_NO_MAGICLINKS through v1.9.3 — this is the fix):
 *   RESOLVE_NO_SYMLINKS   — no symlink component anywhere in the path. A
 *                           symlink planted inside an allowed directory can no
 *                           longer redirect the open to a denied object.
 *   RESOLVE_NO_MAGICLINKS — /proc/<pid>/fd/N and /proc/self magic links do not
 *                           resolve, so the agent cannot reach the Warden's own
 *                           /proc/self view (it named /proc/self; the kernel
 *                           would resolve that in the SUPERVISOR's context).
 *   RESOLVE_BENEATH is deliberately NOT set: allow rules legitimately name
 *   absolute paths outside the cwd (e.g. /lib/). `..` is instead defanged by
 *   deciding on the post-`..`-collapse canonical path (see below), not by
 *   forbidding `..` outright.
 *
 * dirfd handling: the v1.4 supervisor does not mirror the target's fd table,
 * so a relative open against a target-held dirfd cannot be resolved soundly.
 * Only AT_FDCWD (resolved against /proc/<pid>/cwd) and absolute paths are
 * handled; any other dirfd fails closed. Returns the resolved fd (>=0, caller
 * owns it) or -1. On success a->resolved holds the canonical path. */
static int resolve_target_open(pid_t target_pid, struct action *a)
{
    a->resolved[0] = '\0';

    if (a->open_dirfd != VAREK_AT_FDCWD && a->target[0] != '/') {
        /* relative open against a dirfd we do not track: fail closed. */
        return -1;
    }

    char proc_cwd[64];
    snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", target_pid);
    int cwd_fd = open(proc_cwd, O_PATH | O_DIRECTORY);
    if (cwd_fd < 0) return -1;

    struct open_how_local how = {
        .flags   = (uint64_t)a->open_flags & ~(uint64_t)O_PATH,
        .mode    = ((uint64_t)a->open_flags & (uint64_t)O_CREAT) ? ((uint64_t)a->open_mode & 0777) : 0,
        .resolve = (uint64_t)RESOLVE_NO_SYMLINKS | (uint64_t)RESOLVE_NO_MAGICLINKS,
    };
    int resolved = (int)syscall(__NR_openat2,
                                cwd_fd, a->target, &how, sizeof(how));
    close(cwd_fd);
    if (resolved < 0) return -1;

    /* Canonical path of exactly this fd — this is the string the policy
     * decides on and the audit log records. Reading the magic link of a fd we
     * ourselves hold is safe; it is the agent naming /proc/self that the
     * RESOLVE_NO_MAGICLINKS above blocks. */
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", resolved);
    ssize_t rl = readlink(linkpath, a->resolved, sizeof(a->resolved) - 1);
    if (rl < 0) { close(resolved); a->resolved[0] = '\0'; return -1; }
    a->resolved[rl] = '\0';
    /* readlink can annotate a deleted/anon inode as " (deleted)"; such an
     * object has no stable policy identity. Fail closed. */
    if (a->resolved[0] != '/') { close(resolved); a->resolved[0] = '\0'; return -1; }

    return resolved;
}

/* v1.12: hand an already-resolved fd (from resolve_target_open) to the target.
 * No second open — the object decided on IS the object delivered, so there is
 * no resolve/decide/open TOCTOU window. */
static int inject_fd(int notify_fd, uint64_t id, int resolved)
{
    struct seccomp_notif_addfd addfd = {
        .id          = id,
        .flags       = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd       = (uint32_t)resolved,
        .newfd       = 0,
        .newfd_flags = O_CLOEXEC,
    };
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0 ? -1 : 0;
}

/* ---------------- receive loop ---------------- */

static volatile sig_atomic_t g_stop = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }

static void supervise(int notify_fd, int target_pidfd,
                      const struct policy *p, const char *bootstrap_path) {
    uint64_t seq = 0;
    while (!g_stop) {
        /* v1.9.3: wait on the listener AND the target's pidfd. Blocking in
         * NOTIF_RECV alone can hang forever if the target exits between the
         * g_stop check and the ioctl (the SIGCHLD is already spent). */
        struct pollfd pfds[2] = {
            { .fd = notify_fd,    .events = POLLIN },
            { .fd = target_pidfd, .events = POLLIN },
        };
        int pr = poll(pfds, target_pidfd >= 0 ? 2 : 1, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (target_pidfd >= 0 && (pfds[1].revents & POLLIN))
            return;                       /* target exited */
        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            return;                       /* no process left under the filter */
        if (!(pfds[0].revents & POLLIN))
            continue;

        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;  /* ENOENT: requester died */
            return;
        }

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        struct exec_ctx *ctx = ctx_get(req.pid);
        if (ctx) ctx->seq++;

        struct action act;
        if (derive_intent(&req, &act) < 0 || !notif_id_valid(notify_fd, req.id)) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                         + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY,
                           "intent_derivation_failed", lat, EACCES);
            send_simple(notify_fd, req.id, DEC_DENY);
            continue;
        }

        /* Bootstrap launch: the target's own first execve of the operator-
         * specified binary is authorized by the act of launching it. Allowed
         * exactly once per pid, before the target runs any code (no TOCTOU on
         * the path: single-threaded, blocked in execve). Later execs fall
         * through to the deny-only block below. */
        if (act.kind == ACT_PROCESS_EXEC && ctx && !ctx->launched &&
            bootstrap_path && strcmp(act.target, bootstrap_path) == 0) {
            ctx->launched = true;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_b = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,
                           "bootstrap_exec_allow", lat_b, 0);
            send_simple(notify_fd, req.id, DEC_ALLOW);
            continue;
        }

        /* v1.12: resolve-then-decide for file opens. The object is opened once,
         * canonicalized, and only then matched against policy, so the decision
         * and the delivered fd refer to the same inode. Resolution failure
         * (symlink component, untracked dirfd, over-long path, deleted inode)
         * is a hard deny before any policy match. */
        int resolved_fd = -1;
        if (act.kind == ACT_FILE_OPEN) {
            resolved_fd = resolve_target_open(req.pid, &act);
            if (resolved_fd < 0) {
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat_r = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY,
                               "resolution_failed", lat_r, EACCES);
                send_simple(notify_fd, req.id, DEC_DENY);
                continue;
            }
        }

        decision_t d_raw   = policy_decide(p, &act);
        decision_t d_final = (d_raw == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;

        if (act.kind == ACT_FILE_OPEN) {
            if (d_final == DEC_ALLOW && inject_fd(notify_fd, req.id, resolved_fd) == 0) {
                close(resolved_fd);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                             + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                               "resolved_fd_injection", lat, 0);
                continue;
            }
            /* denied by policy, or injection failed: drop the resolved fd and
             * fall through to a fail-closed deny. */
            close(resolved_fd);
            d_final = DEC_DENY;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_d = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                           d_raw == DEC_UNKNOWN ? "default_deny_unknown" : "policy_match",
                           lat_d, EACCES);
            send_simple(notify_fd, req.id, d_final);
            continue;
        }

        /* v1.9.1: deny-only network/exec mediation. A connect/execve
         * allow cannot be enforced via CONTINUE without a TOCTOU race
         * on its pointer argument, and there is no fd to inject
         * (dial-and-inject is a v1.10 item). Fail closed. */
        if (d_final == DEC_ALLOW && act.kind != ACT_FILE_OPEN) {
            d_final = DEC_DENY;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_dn = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                            + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                           "deny_only_nonfile_v191", lat_dn, EACCES);
            send_simple(notify_fd, req.id, d_final);
            continue;
        }

        send_simple(notify_fd, req.id, d_final);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                     + (t1.tv_nsec - t0.tv_nsec);
        emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                       d_raw == DEC_UNKNOWN ? "default_deny_unknown" : "policy_match",
                       lat, d_final == DEC_ALLOW ? 0 : EACCES);
    }
}

/* v1.9.3: stop the agent and everything it started. With a PID namespace,
 * killing the target (its init) makes the kernel kill the rest; the process
 * group signal covers the VAREK_WARDEN_NO_PIDNS case. */
static void kill_target_tree(pid_t target) {
    kill(-target, SIGKILL);
    kill(target, SIGKILL);
}

/* v1.9.3: CAP_SYS_ADMIN preflight. The PID namespace that carries lifecycle
 * coupling needs it; checking up front gives a clear error before any policy
 * or plan work, instead of failing at unshare(). */
static int have_cap_sys_admin(void) {
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capget, &hdr, data) != 0)
        return 0;
    return (data[CAP_TO_INDEX(CAP_SYS_ADMIN)].effective
            & CAP_TO_MASK(CAP_SYS_ADMIN)) != 0;
}

/* ---------------- main ---------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <policy.txt> [--plan <plan.txt>] -- <target> [args...]\n"
        "\n"
        "  Privileged seccomp-unotify supervisor (VAREK Warden v1.4).\n"
        "\n"
        "  Requires CAP_SYS_ADMIN (run as root or via sudo): the target runs\n"
        "  as init of its own PID namespace so it, and everything it spawns,\n"
        "  dies with the Warden. VAREK_WARDEN_NO_PIDNS=1 skips the namespace\n"
        "  and the requirement; processes the agent spawns may then outlive\n"
        "  a crashed Warden.\n"
        "\n"
        "  Optional --plan <plan.txt> enables v1.6 pre-execution plan\n"
        "  verification. The target is not forked unless the plan\n"
        "  verifies as SATISFIED against the loaded policy.\n"
        "\n"
        "  Policy file format (one rule per line):\n"
        "    allow path /tmp/safe/\n"
        "    deny  path /etc/\n"
        "    allow host 127.0.0.1:8080\n"
        "    deny  host evil.example.com\n"
        "    allow exec /usr/bin/env\n"
        "\n"
        "  Plan file format (see varek/v1_6/sample_plan.txt):\n"
        "    action <label> <kind> <target>\n"
        "    edge   <from_label> <to_label>\n",
        argv0);
}

int main(int argc, char **argv) {
    /* Positional parse with optional --plan between policy_path and --.
     * Accepted forms:
     *   warden policy.txt -- target [args...]
     *   warden policy.txt --plan plan.txt -- target [args...] */
    if (argc < 4) { usage(argv[0]); return 2; }

    const char *policy_path = argv[1];
    const char *plan_path   = NULL;
    int sep_idx = -1;

    if (strcmp(argv[2], "--") == 0) {
        sep_idx = 2;
    } else if (strcmp(argv[2], "--plan") == 0) {
        if (argc < 6 || strcmp(argv[4], "--") != 0) {
            usage(argv[0]); return 2;
        }
        plan_path = argv[3];
        sep_idx   = 4;
    } else {
        usage(argv[0]); return 2;
    }

    if (sep_idx + 1 >= argc) { usage(argv[0]); return 2; }
    char *const *target_argv = &argv[sep_idx + 1];

    const int pidns = getenv("VAREK_WARDEN_NO_PIDNS") == NULL;
    if (pidns && !have_cap_sys_admin()) {
        fprintf(stderr,
            "[warden] CAP_SYS_ADMIN is required (run as root or via sudo). The "
            "Warden runs the agent in its own PID namespace so the agent and "
            "everything it spawns die with the Warden. To run without it, set "
            "VAREK_WARDEN_NO_PIDNS=1 and accept that processes the agent spawns "
            "may outlive a crashed Warden.\n");
        return 1;
    }

    struct policy p;
    if (policy_load(policy_path, &p) < 0) return 1;

    log_init();

    /* v1.6 pre-execution plan verification. Fires before fork; on
     * any non-SATISFIED result the target is not started. */
    if (plan_path && warden_verify_plan(plan_path, &p) != 0) {
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_term };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* no SA_RESTART: we want EINTR to break ioctl */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); return 1;
    }

    /* v1.9.3 lifecycle coupling.
     *
     * (1) Liveness pipe: only the supervisor holds the write end. The target
     *     uses it to detect a supervisor that died before PR_SET_PDEATHSIG
     *     took effect.
     * (2) PID namespace: the target becomes init of a fresh namespace, so the
     *     kernel kills everything the agent spawned when the target dies.
     *     Fail closed if unavailable; VAREK_WARDEN_NO_PIDNS=1 opts out, in
     *     which case descendants are NOT guaranteed to die on a supervisor
     *     crash. */
    int live[2];
    if (pipe2(live, O_CLOEXEC) < 0) { perror("pipe2"); return 1; }

    if (pidns) {
        int rc = wd_supervisor_isolate_pids();
        if (rc < 0) {
            fprintf(stderr,
                "[warden] cannot create PID namespace (%s); refusing to start. "
                "Run with CAP_SYS_ADMIN, or set VAREK_WARDEN_NO_PIDNS=1 to accept "
                "that processes the agent spawns may outlive a crashed supervisor.\n",
                strerror(-rc));
            return 1;
        }
    } else {
        fprintf(stderr,
            "[warden] WARNING: VAREK_WARDEN_NO_PIDNS set; agent descendants are "
            "not guaranteed to die if the supervisor crashes\n");
    }

    pid_t target = fork();
    if (target < 0) { perror("fork"); return 1; }

    if (target == 0) {
        close(sv[0]);
        close(live[1]);
        /* Own process group, so orderly shutdown can signal the whole tree
         * even without a PID namespace. setpgid/setsid are not in the
         * baseline allowlist, so the agent cannot leave the group. */
        if (setpgid(0, 0) < 0) { perror("setpgid"); _exit(1); }
        int crc = wd_target_couple_to_supervisor(live[0]);
        if (crc < 0) {
            fprintf(stderr, "[warden-target] lifecycle coupling failed (%s); "
                            "refusing to run unsupervised\n", strerror(-crc));
            _exit(1);
        }
        int notify_fd =
            install_baseline_user_notif_filter(getenv("VAREK_WARDEN_OBSERVE") != NULL);
        if (notify_fd < 0) { perror("seccomp"); _exit(1); }
        /* v1.12: hand the fd NUMBER to the supervisor and wait for it to pull
         * the fd via pidfd_getfd(). write()/read() are admitted; no sendmsg. */
        if (write_all(sv[1], &notify_fd, sizeof(notify_fd)) < 0) {
            perror("write notify_fd"); _exit(1);
        }
        char ack = 0;
        if (read_all(sv[1], &ack, 1) < 0 || ack != 1) {
            fprintf(stderr, "[warden-target] supervisor did not acquire listener\n");
            _exit(1);
        }
        close(notify_fd);
        close(sv[1]);
        execvp(target_argv[0], target_argv);
        perror("execvp");
        _exit(127);
    }

    close(sv[1]);
    close(live[0]);   /* live[1] stays open for the supervisor's lifetime */

    /* v1.12: acquire the seccomp listener fd via pidfd_getfd(). The child sent
     * the fd number; we pull the fd out of the child's table, then ack so the
     * child can drop its copy and exec. This replaces the SCM_RIGHTS handoff so
     * that sendto/sendmsg can be mediated without deadlocking the bootstrap. */
    int child_fd_num = -1;
    if (read_all(sv[0], &child_fd_num, sizeof(child_fd_num)) < 0 || child_fd_num < 0) {
        fprintf(stderr, "[warden] failed to read listener fd number\n");
        close(sv[0]); kill_target_tree(target); waitpid(target, NULL, 0);
        return 1;
    }
    int target_pidfd_h = (int)syscall(__NR_pidfd_open, target, 0);
    if (target_pidfd_h < 0) {
        fprintf(stderr, "[warden] pidfd_open for handoff failed: %s\n", strerror(errno));
        close(sv[0]); kill_target_tree(target); waitpid(target, NULL, 0);
        return 1;
    }
    int notify_fd = (int)syscall(__NR_pidfd_getfd, target_pidfd_h, child_fd_num, 0);
    if (notify_fd < 0) {
        fprintf(stderr, "[warden] pidfd_getfd of listener failed: %s\n", strerror(errno));
        close(target_pidfd_h); close(sv[0]);
        kill_target_tree(target); waitpid(target, NULL, 0);
        return 1;
    }
    close(target_pidfd_h);
    char ack = 1;
    if (write_all(sv[0], &ack, 1) < 0) {
        fprintf(stderr, "[warden] failed to ack listener handoff\n");
        close(notify_fd); close(sv[0]);
        kill_target_tree(target); waitpid(target, NULL, 0);
        return 1;
    }
    close(sv[0]);

    /* v1.9.3: watch the target via pidfd (readable when it exits). */
    int target_pidfd = wd_supervisor_watch_target(target);
    if (target_pidfd < 0) {
        fprintf(stderr, "[warden] pidfd_open failed (%s); refusing to supervise\n",
                strerror(-target_pidfd));
        kill_target_tree(target);
        waitpid(target, NULL, 0);
        return 1;
    }

    fprintf(stderr,
        "[warden] supervising pid=%d  notify_fd=%d  policy=%s (%zu rules)  pidns=%s\n",
        target, notify_fd, p.name, p.n_rules, pidns ? "on" : "off");

    supervise(notify_fd, target_pidfd, &p, target_argv[0]);

    kill_target_tree(target);  /* the agent and everything it spawned */
    int status = 0;
    waitpid(target, &status, 0);
    close(target_pidfd);
    close(notify_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
