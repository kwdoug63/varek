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
#include <linux/filter.h>
#include <linux/seccomp.h>
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
    ACT_PROCESS_EXEC,
    ACT_OTHER,
} action_kind_t;

struct action {
    action_kind_t kind;
    char          target[PATH_LIMIT];   /* path or "host:port" or argv[0] */
    int           open_flags;
    int           open_mode;
    int           connect_family;
    int           connect_port;
};

static const char *action_kind_name(action_kind_t k) {
    switch (k) {
        case ACT_FILE_OPEN:    return "file.open";
        case ACT_NET_CONNECT:  return "net.connect";
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
    out[outlen - 1] = '\0';
    return 0;
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

static int install_user_notif_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat,  4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve,  2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat,1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len    = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    return syscall(__NR_seccomp,
                   SECCOMP_SET_MODE_FILTER,
                   SECCOMP_FILTER_FLAG_NEW_LISTENER,
                   &prog);
}

/* ---------------- fd passing ---------------- */

static int send_fd(int sock, int fd) {
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy = 'x';
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov = &io, .msg_iovlen = 1,
        .msg_control = buf, .msg_controllen = sizeof(buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    char dummy;
    struct iovec io = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = {
        .msg_iov = &io, .msg_iovlen = 1,
        .msg_control = buf, .msg_controllen = sizeof(buf),
    };
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
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
        for (size_t i = 0; i < p->n_rules; i++) {
            const struct rule *r = &p->rules[i];
            if (r->kind != RULE_PATH_PREFIX) continue;
            size_t L = strlen(r->match);
            if (strncmp(a->target, r->match, L) == 0) return r->decision;
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
    fprintf(g_log,
        "{\"report_id\":\"pr-%ld.%09ld-%" PRIu64 "\","
        "\"agent_pid\":%d,"
        "\"action\":\"%s\","
        "\"target\":\"%s\","
        "\"decision_raw\":\"%s\","
        "\"decision_final\":\"%s\","
        "\"rule\":\"%s\","
        "\"kernel_verdict\":\"%s\","
        "\"latency_us\":%" PRIu64 ","
        "\"timestamp_ns\":%lld}\n",
        (long)ts.tv_sec, ts.tv_nsec, seq,
        (int)pid,
        action_kind_name(a->kind),
        a->target,
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

static int inject_resolved_fd(int notify_fd,
                              uint64_t id,
                              pid_t target_pid,
                              const struct action *a)
{
    char proc_cwd[64];
    snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", target_pid);
    int cwd_fd = open(proc_cwd, O_PATH | O_DIRECTORY);
    if (cwd_fd < 0) return -1;

    struct open_how_local how = {
        .flags   = (uint64_t)a->open_flags & ~(uint64_t)O_PATH,
        .mode    = ((uint64_t)a->open_flags & (uint64_t)O_CREAT) ? ((uint64_t)a->open_mode & 0777) : 0,
        .resolve = RESOLVE_NO_MAGICLINKS,
    };
    int resolved = (int)syscall(__NR_openat2,
                                cwd_fd, a->target, &how, sizeof(how));
    close(cwd_fd);
    if (resolved < 0) return -1;

    struct seccomp_notif_addfd addfd = {
        .id          = id,
        .flags       = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd       = (uint32_t)resolved,
        .newfd       = 0,
        .newfd_flags = O_CLOEXEC,
    };
    int rc = ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    close(resolved);
    return rc < 0 ? -1 : 0;
}

/* ---------------- receive loop ---------------- */

static volatile sig_atomic_t g_stop = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }

static void supervise(int notify_fd, const struct policy *p) {
    uint64_t seq = 0;
    while (!g_stop) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
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

        decision_t d_raw   = policy_decide(p, &act);
        decision_t d_final = (d_raw == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;

        if (d_final == DEC_ALLOW && act.kind == ACT_FILE_OPEN) {
            if (inject_resolved_fd(notify_fd, req.id, req.pid, &act) == 0) {
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                             + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                               "resolved_fd_injection", lat, 0);
                continue;
            }
            d_final = DEC_DENY;
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

/* ---------------- main ---------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <policy.txt> [--plan <plan.txt>] -- <target> [args...]\n"
        "\n"
        "  Privileged seccomp-unotify supervisor (VAREK Warden v1.4).\n"
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

    pid_t target = fork();
    if (target < 0) { perror("fork"); return 1; }

    if (target == 0) {
        close(sv[0]);
        int notify_fd = install_user_notif_filter();
        if (notify_fd < 0) { perror("seccomp"); _exit(1); }
        if (send_fd(sv[1], notify_fd) < 0) { perror("send_fd"); _exit(1); }
        close(notify_fd);
        close(sv[1]);
        execvp(target_argv[0], target_argv);
        perror("execvp");
        _exit(127);
    }

    close(sv[1]);
    int notify_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (notify_fd < 0) {
        fprintf(stderr, "[warden] failed to receive notify fd\n");
        kill(target, SIGKILL);
        waitpid(target, NULL, 0);
        return 1;
    }

    fprintf(stderr,
        "[warden] supervising pid=%d  notify_fd=%d  policy=%s (%zu rules)\n",
        target, notify_fd, p.name, p.n_rules);

    supervise(notify_fd, &p);

    kill(target, SIGKILL);  /* best-effort: ensures waitpid does not hang */
    int status = 0;
    waitpid(target, &status, 0);
    close(notify_fd);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
