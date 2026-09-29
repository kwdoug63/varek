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
 *      resolves the path itself via openat2(O_PATH, RESOLVE_NO_MAGICLINKS;
 *      ordinary symlinks followed from v1.12.3, with /proc/self mapped to the
 *      agent), decides on the canonical path, and only after ALLOW opens the
 *      pinned object with the agent's flags (v1.12.1) and returns that fd
 *      through SECCOMP_IOCTL_NOTIF_ADDFD with SECCOMP_ADDFD_FLAG_SEND. The
 *      kernel never re-reads the userspace pathname pointer.
 *
 *   8. Pathology Report — every decision is emitted as a JSON record
 *      to the Warden's stderr, with monotonic-clock decision latency in
 *      microseconds. v1.12.1: records carry a per-run id and seq, are framed
 *      by run_start/run_end, and the agent's own stderr is relayed with an
 *      "[agent] " prefix so it cannot write a record (see log_init()).
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
#include <sys/random.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <sodium.h>              /* v1.16: SHA-256 chain, Ed25519 signatures */

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
#include "smt_decide.h"            /* v1.13 SMT decision procedure */
#include "checker/vdp_checker.h"   /* v1.15 independent certificate checker */
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
    bool          flags_known;          /* v1.13: open_flags came from the syscall */
    int           policy_line;          /* v1.13: deciding rule's line, or -1 */
    const char   *why;                  /* v1.13: decision-procedure reason */
    int           rule_index;           /* v1.15: deciding rule's index, or -1 */
    bool          certified;            /* v1.15: the checker accepted the certificate */
    char          cert[420];            /* v1.15: the certificate, as record fields */
    char          check_why[160];       /* v1.15: why the checker refused it */
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

/* v1.13: the policy is parsed and decided by the SMT decision procedure in
 * smt_decide.c. See smt_decide.h for the fragment (bounded strings for the
 * path/host/exec constant, a 32-bit bitvector for open flags), the verdict
 * semantics, and the soundness obligations. v1.14 adds the bounded string
 * fragment: exact, prefix, suffix, contains and glob matchers. */
struct policy {
    char          name[64];
    char          version[16];
    vdp_policy_t  v;
    vdpc_policy_t c;                    /* v1.15: the checker's own parse */
    char          sha256[65];           /* v1.15: of the policy bytes both parsed */
};

#define POLICY_MAX_BYTES (16u << 20)

static int policy_load(const char *path, struct policy *p) {
    memset(p, 0, sizeof(*p));
#ifdef VDP_FAULT_INJECT
    fprintf(stderr, "[warden] WARNING: TEST BUILD with a planted decision-procedure bug "
            "(warden_faultinject); never use it to supervise a real agent\n");
#endif
    snprintf(p->name,    sizeof(p->name),    "default");
    snprintf(p->version, sizeof(p->version), "1.16");
    char err[512];
    /* v1.15: read the file once. The decision procedure and the certificate
     * checker parse these same bytes, and their SHA-256 goes in run_start, so
     * an audit can tie every certificate to the exact policy text. */
    FILE *f = fopen(path, "re");
    if (!f) { fprintf(stderr, "[warden] policy %s: %s\n", path, strerror(errno)); return -1; }
    char *buf = malloc(POLICY_MAX_BYTES + 1);
    size_t len = buf ? fread(buf, 1, POLICY_MAX_BYTES + 1, f) : 0;
    bool rd_err = !buf || ferror(f);
    fclose(f);
    if (rd_err || len > POLICY_MAX_BYTES) {
        fprintf(stderr, "[warden] policy %s: %s\n", path,
                rd_err ? "read error" : "larger than 16 MiB");
        free(buf);
        return -1;
    }
    if (vdp_policy_load_mem(path, buf, len, &p->v, err, sizeof err) < 0) {
        fprintf(stderr, "[warden] policy %s\n", err);
        free(buf);
        return -1;
    }
    if (vdpc_load(path, buf, len, &p->c, err, sizeof err) < 0) {
        fprintf(stderr, "[warden] policy %s (certificate checker)\n", err);
        free(buf);
        return -1;
    }
    free(buf);
    vdpc_digest_hex(&p->c, p->sha256);
    if (p->c.n != p->v.n) {
        fprintf(stderr, "[warden] policy %s: the decision procedure read %zu rules and the "
                "certificate checker %zu; refusing to start\n", path, p->v.n, p->c.n);
        return -1;
    }
    /* Rule by rule, the two parses must agree: verb, kind, matcher, constant
     * and flag clause. (A divergence could only cause denials, since an
     * authorization needs both; this makes it fail loudly at startup.) */
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        vdpc_rule_info_t ci;
        static const int op_to_match[] = {
            [VDP_STR_PREFIX] = VDPC_M_PREFIX, [VDP_STR_EQ] = VDPC_M_EXACT,
            [VDP_STR_HOST] = VDPC_M_HOST, [VDP_STR_SUFFIX] = VDPC_M_SUFFIX,
            [VDP_STR_CONTAINS] = VDPC_M_CONTAINS, [VDP_STR_GLOB] = VDPC_M_GLOB,
        };
        static const int kind_to_c[] = {
            [VDP_KIND_PATH] = VDPC_PATH, [VDP_KIND_HOST] = VDPC_HOST, [VDP_KIND_EXEC] = VDPC_EXEC,
        };
        if (vdpc_rule_info(&p->c, i, &ci) < 0 || ci.allow != (r->verb == VDP_ALLOW) ||
            ci.kind != kind_to_c[r->kind] || ci.match != op_to_match[r->s.op] ||
            ci.clen != r->s.len || memcmp(ci.c, r->s.c, r->s.len) != 0 ||
            ci.mask != r->b.mask || ci.value != r->b.value || ci.line != r->line) {
            fprintf(stderr, "[warden] policy %s:%d: the decision procedure and the certificate "
                    "checker read this rule differently; refusing to start\n", path, r->line);
            return -1;
        }
    }
    /* v1.13: load-time analysis. The decision procedure decides, for every
     * rule, whether ANY action can reach it as the first matching rule. A rule
     * that can never fire is almost always a policy bug (typically a deny
     * shadowed by an earlier, broader allow), so it is reported. It does not
     * change any decision. */
    size_t dead = 0;
    for (size_t i = 0; i < p->v.n; i++) {
        vdp_reach_t rr = vdp_rule_reachable(&p->v, i);
        const vdp_rule_t *r = &p->v.rules[i];
        char adv[512];
        if (vdp_rule_advisory(r, adv, sizeof adv))
            fprintf(stderr, "[warden] policy %s:%d: note: %s\n", path, r->line, adv);
        if (rr == VDP_DEAD) {
            dead++;
            fprintf(stderr, "[warden] policy %s:%d: WARNING: %s %s rule can never "
                    "fire: every action it matches is decided by an earlier rule, "
                    "or it matches no string within the length bound\n",
                    path, r->line, r->verb == VDP_ALLOW ? "allow" : "deny",
                    vdp_kind_name(r->kind));
        } else if (rr == VDP_REACH_UNKNOWN) {
            fprintf(stderr, "[warden] policy %s:%d: note: reachability not decided "
                    "(%s)\n", path, r->line,
                    vdp_reach_unknown_text());
        }
    }
    fprintf(stderr, "[warden] loaded policy %s v%s with %zu rules (%zu can never fire), "
            "sha256 %s\n", p->name, p->version, p->v.n, dead, p->sha256);
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
    out->policy_line = -1;
    int nr = (int)req->data.nr;

    if (nr == __NR_openat) {
        out->kind = ACT_FILE_OPEN;
        if (xproc_read_str(req->pid, req->data.args[1],
                           out->target, sizeof(out->target)) < 0)
            return -1;
        out->open_dirfd = (int)req->data.args[0];
        out->resolved[0] = '\0';
        /* The kernel's openat() takes `int flags`: the upper 32 bits of the
         * register are ignored, and so is the decision procedure's model. */
        out->open_flags = (int)req->data.args[2];
        out->flags_known = true;
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

static decision_t policy_decide(const struct policy *p, struct action *a)
{
    /* v1.13: every decision is made by the SMT decision procedure
     * (smt_decide.c). A file open is decided on the RESOLVED canonical path
     * (v1.12: the object actually delivered, after `..` collapse and every
     * symlink followed) together with the open flags; if resolution has not
     * run or failed, resolved is empty and the verdict is UNKNOWN -> deny.
     * When the flags are not known (the --plan gate), they are symbolic:
     * SATISFIED only if every admissible flags value is. */
    a->policy_line = -1;
    a->rule_index = -1;
    a->why = NULL;
    vdp_kind_t kind;
    const char *s;
    switch (a->kind) {
        case ACT_FILE_OPEN:
            kind = VDP_KIND_PATH;
            s = a->resolved;
            if (s[0] == '\0') { a->why = "no_resolved_path"; return DEC_UNKNOWN; }
            break;
        case ACT_NET_CONNECT:  kind = VDP_KIND_HOST; s = a->target; break;
        case ACT_PROCESS_EXEC: kind = VDP_KIND_EXEC; s = a->target; break;
        default:
            a->why = "not_in_fragment";
            return DEC_UNKNOWN;
    }
    int ri;
    vdp_why_t why;
    vdp_verdict_t v = vdp_decide(&p->v, kind, s, (uint32_t)a->open_flags,
                                 a->kind == ACT_FILE_OPEN && a->flags_known,
                                 &ri, &why);
    a->why = vdp_why_name(why);
    a->rule_index = ri;
    if (ri >= 0) a->policy_line = p->v.rules[ri].line;
    switch (v) {
        case VDP_SATISFIED:   return DEC_ALLOW;
        case VDP_UNSATISFIED: return DEC_DENY;
        default:              return DEC_UNKNOWN;
    }
}

/* v1.13: the record's rule id for a policy decision. An UNKNOWN because the
 * action lies outside the decision procedure's fragment is named as such. */
static const char *decision_rule_id(const struct action *a, decision_t d_raw) {
    if (d_raw != DEC_UNKNOWN) return "policy_match";
    if (a->why && (!strcmp(a->why, "unknown_flag_bits") ||
                   !strcmp(a->why, "access_mode_3")))  return "fragment_escape_flags";
    if (a->why && !strcmp(a->why, "length_guard"))      return "fragment_escape_length";
    return "default_deny_unknown";
}

/* The verdict stream (defined below). */
static FILE *g_log;
static void log_line_start(void);
static void json_escape(FILE *f, const char *s);

/* v1.15: before a SATISFIED verdict authorizes anything, the procedure emits a
 * certificate (the deciding rule and a witness that its constant matches) and
 * the independent checker (checker/vdp_checker.c: its own parser and
 * matchers) must accept it. A certificate the checker refuses denies the
 * action, so a logic bug confined to the decision procedure cannot authorize one.
 * Returns true if the checker accepted. */
static bool certify(const struct policy *p, struct action *a) {
    a->certified = false;
    a->cert[0] = '\0';
    a->check_why[0] = '\0';
    int kind;
    const char *s;
    switch (a->kind) {
        case ACT_FILE_OPEN:    kind = VDPC_PATH; s = a->resolved; break;
        case ACT_NET_CONNECT:  kind = VDPC_HOST; s = a->target;   break;
        case ACT_PROCESS_EXEC: kind = VDPC_EXEC; s = a->target;   break;
        default:
            snprintf(a->check_why, sizeof a->check_why, "no certificate for this action kind");
            return false;
    }
    vdp_cert_t vc;
    if (vdp_certificate(&p->v, a->rule_index, s, &vc) < 0) {
        snprintf(a->cert, sizeof a->cert, "\"cert_rule\":%d,\"cert_witness\":\"!\"", a->rule_index);
        snprintf(a->check_why, sizeof a->check_why, "the procedure built no witness");
        return false;
    }
    vdpc_cert_t cc;
    memset(&cc, 0, sizeof cc);
    cc.r = vc.rule;
    cc.wkind = vc.wkind;
    cc.off = vc.off;
    cc.nspan = vc.nspan;
    for (uint32_t k = 0; k < vc.nspan && k < VDPC_MAX_STRETCH; k++) {
        cc.span[k][0] = vc.span[k][0];
        cc.span[k][1] = vc.span[k][1];
    }
    bool has_flags = a->kind != ACT_FILE_OPEN || a->flags_known;
    /* The certificate as recorded, as flat fields (no nested object, so a
     * consumer that reads records as flat JSON objects keeps working):
     * "cert_rule" the rule index, "cert_witness" the witness. */
    int n = snprintf(a->cert, sizeof a->cert, "\"cert_rule\":%d,\"cert_witness\":\"", cc.r);
    if (cc.wkind == 1) n += snprintf(a->cert + n, sizeof a->cert - (size_t)n, "c:%u", cc.off);
    else if (cc.wkind == 2) {
        n += snprintf(a->cert + n, sizeof a->cert - (size_t)n, "g:");
        for (uint32_t k = 0; k < cc.nspan && (size_t)n < sizeof a->cert; k++)
            n += snprintf(a->cert + n, sizeof a->cert - (size_t)n, "%s%u-%u", k ? "," : "",
                          cc.span[k][0], cc.span[k][1]);
    } else n += snprintf(a->cert + n, sizeof a->cert - (size_t)n, "-");
    if ((size_t)n < sizeof a->cert) snprintf(a->cert + n, sizeof a->cert - (size_t)n, "\"");
    if (!vdpc_check(&p->c, kind, s, strlen(s), (uint32_t)a->open_flags, has_flags, &cc,
                    a->check_why, sizeof a->check_why)) {
        for (char *q = a->check_why; *q; q++)          /* recorded inside a JSON string */
            if (*q == '"' || *q == '\\' || (unsigned char)*q < 0x20) *q = '\'';
        return false;
    }
    a->certified = true;
    return true;
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

/* v1.12.4: lexical canonicalization of an absolute path for PLAN verification.
 *
 * The runtime file-open decision (policy_decide on ACT_FILE_OPEN) is made on
 * the object's canonical path as resolved against the live agent's cwd, with
 * every symlink followed (resolve_target). A plan is verified BEFORE the agent
 * is forked, so there is no process to resolve against and the named file may
 * not exist yet. Plan verification is therefore an approximation: it collapses
 * `.`, `..` and duplicate slashes lexically and decides policy on that, which
 * is the pre-execution analog of the runtime canonical path. It does not follow
 * symlinks (there is nothing to follow yet), so a plan that lexically clears the
 * policy is still enforced per-syscall at runtime; the gate is an advisory
 * pre-check, not a substitute for enforcement.
 *
 * Only absolute paths can be verified this way. A relative plan path has no
 * cwd to resolve against before fork, so it stays UNKNOWN (the plan is not
 * SATISFIED) rather than being guessed. Returns 0 with out filled, or -1.
 *
 * `..` that would rise above `/` is clamped at `/` (as the kernel does for an
 * absolute path), never allowed to escape. */
static int plan_lexical_canon(const char *in, char *out, size_t outlen) {
    if (outlen) out[0] = '\0';                  /* NUL-terminate on every -1 path */
    if (!in || in[0] != '/') return -1;         /* absolute only */
    const char *seg[PATH_LIMIT / 2];
    size_t nseg = 0;
    const char *p = in;
    while (*p) {
        while (*p == '/') p++;                   /* skip slashes */
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - start);
        if (len == 1 && start[0] == '.') {
            continue;                            /* "." : no-op */
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (nseg > 0) nseg--;                /* ".." : pop, clamped at / */
            continue;
        }
        if (nseg >= sizeof seg / sizeof seg[0]) { if (outlen) out[0] = '\0'; return -1; }
        seg[nseg++] = start;                     /* remember start; length re-derived below */
    }
    /* Rebuild. Re-derive each segment's length by scanning to the next '/'. */
    size_t w = 0;
    if (nseg == 0) {
        if (outlen < 2) return -1;
        out[0] = '/'; out[1] = '\0';
        return 0;
    }
    for (size_t i = 0; i < nseg; i++) {
        const char *st = seg[i];
        size_t len = 0;
        while (st[len] && st[len] != '/') len++;
        if (w + 1 + len >= outlen) { out[0] = '\0'; return -1; }
        out[w++] = '/';
        memcpy(out + w, st, len);
        w += len;
    }
    out[w] = '\0';
    return 0;
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
    /* v1.12.4: policy_decide() decides a file open on the RESOLVED canonical
     * path (v1.12.0+), not the raw target. At plan time there is no live agent
     * to resolve against, so fill act.resolved with the lexically canonical
     * form of the declared absolute path. Without this, resolved stays empty
     * and every file_open node is UNKNOWN -> the plan gate rejected every plan
     * that opened a file (the bug present since v1.12.0). A relative or
     * unparseable path leaves resolved empty and stays UNKNOWN. */
    if (act.kind == ACT_FILE_OPEN) {
        (void)plan_lexical_canon(act.target, act.resolved, sizeof(act.resolved));
    }
    decision_t d = policy_decide(u->policy, &act);
    if (d == DEC_ALLOW && !certify(u->policy, &act)) {
        /* v1.15: the plan gate authorizes only what the checker confirms. */
        log_line_start();
        fputs("[warden] plan: certificate refused for \"", g_log);
        json_escape(g_log, act.target);
        fprintf(g_log, "\": %s\n", act.check_why);
        fflush(g_log);
        return PLAN_DEC_UNKNOWN;
    }
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

/* v1.12.1: authenticated verdict stream.
 *
 * v1.12.0 escaped agent-controlled strings inside a record, but the agent
 * shared the Warden's stderr, so it could still write a whole, well-formed
 * record of its own ("ALLOW /etc/shadow") that no consumer could tell apart
 * from a real one. Three changes close that:
 *
 *   1. The agent no longer shares the stream. Its stderr is a pipe the Warden
 *      relays line by line with an "[agent] " prefix and control bytes
 *      escaped, so no agent byte can begin a line of the verdict stream.
 *   2. Every record carries a per-run id (128 random bits the agent never
 *      sees) and a contiguous seq. A record the agent smuggles in by another
 *      route (stdout merged with 2>&1) cannot carry the right id.
 *   3. The stream is framed by run_start and run_end records, so truncation
 *      and a missing tail are detectable.
 *
 * tools/varek_cyclonedx.py verifies all three and refuses to attest a stream
 * that fails any of them. */
static char     g_run_id[33];
static uint64_t g_records = 0;       /* decision records emitted */
static bool     g_relay_midline = false;

/* v1.16: log integrity against whoever HOLDS the log.
 *
 * v1.12.1 made the stream unforgeable by the supervised agent. It did nothing
 * against a person who holds the log file afterwards and edits it. Three
 * layers address that:
 *
 *   1. Hash chain (always on). Every record of this run (run_start, each
 *      decision record, checkpoint, anchor_error, run_end) ends with
 *        "chain":"<hex>"   chain_i = SHA-256(chain_{i-1} || body_i)
 *      where body_i is the record's exact bytes from its '{' up to (not
 *      including) the ',"chain":' that follows, and chain_{-1} =
 *      SHA-256("VAREK-LOG-CHAIN-1"). Editing, inserting, removing or
 *      reordering any record changes every chain value after it.
 *   2. Ed25519 signatures (--sign-key). run_start, every checkpoint and
 *      run_end also carry "sig": an Ed25519 signature over
 *      "VAREK-LOG-SIG-1" || chain_i (the raw 32 bytes). A checkpoint is written
 *      after every N decision records (--checkpoint-every, default 64) and once
 *      a second while records are pending. With the public key pinned, an
 *      auditor detects any change to the log up to the last signature; without
 *      the private key nobody can re-sign a rewritten log, and a log cut short
 *      has no signed run_end.
 *   3. External anchor (--anchor PATH). Each signed record (or, without a key,
 *      each checkpoint-type record) is also appended, as one line, to PATH:
 *      storage the log's holder cannot rewrite (a FIFO to a forwarder, remote
 *      syslog, WORM or object-lock storage, an RFC 3161 timestamping step).
 *      Once a chain value is anchored, not even the key holder can rewrite the
 *      history before it undetected. A failed anchor write is recorded in the
 *      stream (event anchor_error) and never blocks supervision.
 *
 * Human status lines ("[warden] ...") and the agent's relayed stderr
 * ("[agent] ...") are not records and are not chained. */
#define LOG_CHAIN_IV   "VAREK-LOG-CHAIN-1"
#define LOG_SIG_DOMAIN "VAREK-LOG-SIG-1"
static unsigned char g_chain[32];
static bool          g_signing = false;
static unsigned char g_pk[crypto_sign_PUBLICKEYBYTES];
static unsigned char g_sk[crypto_sign_SECRETKEYBYTES];
static int           g_anchor_fd = -1;
static uint64_t      g_ckpt_every = 64;
static uint64_t      g_since_ckpt = 0;      /* decision records since the last signed record */
static struct timespec g_last_ckpt;         /* CLOCK_MONOTONIC */
static uint64_t      g_anchor_errors = 0;
static bool          g_log_broken = false;  /* a record could not be written */
static FILE         *g_rf;                  /* the record being built */
static char         *g_rb;
static size_t        g_rl;

static bool checkpoints_on(void) { return g_signing || g_anchor_fd >= 0; }

static FILE *rec_begin(void) {
    rewind(g_rf);
    return g_rf;
}

static void emit_anchor_error(const char *event, int err);

/* Append one checkpoint-type record to the anchor, in a single write(). The
 * descriptor is non-blocking: a slow or absent reader never stalls the
 * Warden; the failure is recorded instead. */
static void anchor_write(const char *event, const char *chain_hex, const char *sig_hex) {
    if (g_anchor_fd < 0) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char line[512];
    int n = snprintf(line, sizeof line,
                     "{\"run\":\"%s\",\"event\":\"%s\",\"records\":%" PRIu64 ","
                     "\"chain\":\"%s\"%s%s%s,\"timestamp_ns\":%lld}\n",
                     g_run_id, event, g_records, chain_hex,
                     sig_hex ? ",\"sig\":\"" : "", sig_hex ? sig_hex : "", sig_hex ? "\"" : "",
                     (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    ssize_t w;
    do { w = write(g_anchor_fd, line, (size_t)n); } while (w < 0 && errno == EINTR);
    if (w != n) {
        int err = w < 0 ? errno : EIO;
        g_anchor_errors++;
        if (strcmp(event, "run_end") != 0) {
            emit_anchor_error(event, err);
        } else {
            /* Nothing may follow run_end in the stream; the audit finds the
             * unanchored run_end by itself. */
            log_line_start();
            fprintf(g_log, "[warden] could not anchor run_end: %s\n", strerror(err));
            fflush(g_log);
        }
    }
}

/* Finish the record in g_rf (a complete "{...}\n"): chain it, sign it if it is
 * checkpoint-type and a key is loaded, write it to the stream in one write(),
 * and anchor it. event is NULL for a plain (decision) record. */
static void rec_end(const char *ckpt_event) {
    fflush(g_rf);
    if (g_rl < 2 || memcmp(g_rb + g_rl - 2, "}\n", 2) != 0) {
        /* Cannot happen: every writer ends its record with "}\n". */
        fprintf(stderr, "[warden] internal error: malformed record; stopping\n");
        abort();
    }
    size_t bl = g_rl - 2;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, g_chain, sizeof g_chain);
    crypto_hash_sha256_update(&st, (const unsigned char *)g_rb, bl);
    crypto_hash_sha256_final(&st, g_chain);
    char chain_hex[65], sig_hex[2 * crypto_sign_BYTES + 1];
    sodium_bin2hex(chain_hex, sizeof chain_hex, g_chain, sizeof g_chain);
    bool sign = ckpt_event && g_signing;
    if (sign) {
        unsigned char msg[sizeof LOG_SIG_DOMAIN - 1 + 32], sig[crypto_sign_BYTES];
        memcpy(msg, LOG_SIG_DOMAIN, sizeof LOG_SIG_DOMAIN - 1);
        memcpy(msg + sizeof LOG_SIG_DOMAIN - 1, g_chain, 32);
        crypto_sign_detached(sig, NULL, msg, sizeof msg, g_sk);
        sodium_bin2hex(sig_hex, sizeof sig_hex, sig, sizeof sig);
    }
    log_line_start();
    fwrite(g_rb, 1, bl, g_log);
    fprintf(g_log, ",\"chain\":\"%s\"%s%s%s}\n", chain_hex,
            sign ? ",\"sig\":\"" : "", sign ? sig_hex : "", sign ? "\"" : "");
    /* A stream that cannot be written stops supervision (fail closed): the
     * agent must not run on unrecorded. */
    if (fflush(g_log) != 0 || ferror(g_log)) g_log_broken = true;
    if (ckpt_event) {
        g_since_ckpt = 0;
        clock_gettime(CLOCK_MONOTONIC, &g_last_ckpt);
        anchor_write(ckpt_event, chain_hex, sign ? sig_hex : NULL);
    }
}

static void emit_anchor_error(const char *event, int err) {
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"anchor_error\",\"run\":\"%s\",\"anchoring\":\"%s\","
               "\"records\":%" PRIu64 ",\"errno\":%d,\"anchor_errors\":%" PRIu64 "}\n",
            g_run_id, event, g_records, err, g_anchor_errors);
    rec_end(NULL);                      /* chained; not itself anchored */
}

/* A checkpoint: a signed (and anchored) record that seals every record before
 * it. */
static void emit_checkpoint(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"checkpoint\",\"run\":\"%s\",\"records\":%" PRIu64 ","
               "\"timestamp_ns\":%lld}\n",
            g_run_id, g_records, (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end("checkpoint");
}

#define CKPT_INTERVAL_MS 1000

/* Called between notifications (never while an agent thread waits on an
 * answer): a checkpoint after every g_ckpt_every decision records, and once a
 * second while any are pending. Returns the poll() timeout until the next
 * time-based checkpoint (-1: none pending). */
static int maybe_checkpoint(void) {
    if (!checkpoints_on() || g_since_ckpt == 0) return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long ms = (now.tv_sec - g_last_ckpt.tv_sec) * 1000LL
                 + (now.tv_nsec - g_last_ckpt.tv_nsec) / 1000000LL;
    if (g_since_ckpt >= g_ckpt_every || ms >= CKPT_INTERVAL_MS) {
        emit_checkpoint();
        return -1;
    }
    return (int)(CKPT_INTERVAL_MS - ms);
}

static int log_init(void) {
    /* The stream is the Warden's stderr, through a private descriptor
     * (close-on-exec, never inherited by the agent) that is fully buffered
     * and flushed once per record: each record reaches the file in a single
     * write(), so nothing else writing to the same file can land inside it. */
    int fd = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return -1;
    g_log = fdopen(fd, "w");
    if (!g_log) { close(fd); return -1; }
    static char logbuf[1 << 17];
    setvbuf(g_log, logbuf, _IOFBF, sizeof logbuf);
    /* v1.16: records are built here, then chained and written in one piece. */
    g_rf = open_memstream(&g_rb, &g_rl);
    if (!g_rf) return -1;
    crypto_hash_sha256(g_chain, (const unsigned char *)LOG_CHAIN_IV, sizeof LOG_CHAIN_IV - 1);
    clock_gettime(CLOCK_MONOTONIC, &g_last_ckpt);
    unsigned char rnd[16];
    size_t got = 0;
    while (got < sizeof rnd) {
        ssize_t n = getrandom(rnd + got, sizeof rnd - got, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)n;
    }
    for (size_t i = 0; i < sizeof rnd; i++)
        snprintf(g_run_id + 2 * i, 3, "%02x", rnd[i]);
    return 0;
}

/* A Warden record always starts on a fresh line, even if the agent's last
 * relayed output ended mid-line. */
static void log_line_start(void) {
    if (g_relay_midline) { fputc('\n', g_log); g_relay_midline = false; }
}

/* Relay what the agent has written to its stderr pipe. Returns 0 while the
 * pipe may produce more, -1 at EOF or error (stop polling it). While
 * supervising, at most 64 KiB is relayed per call, so an agent flooding its
 * stderr cannot keep the supervisor from answering seccomp notifications;
 * drain_all empties the pipe at the end of the run (up to 1 MiB, so a
 * surviving writer cannot hold the Warden open). */
static int relay_agent_stderr(int fd, bool drain_all) {
    unsigned char buf[4096];
    for (int chunks = 0; chunks < (drain_all ? 256 : 16); chunks++) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { fflush(g_log); return 0; }
            fflush(g_log);
            return -1;
        }
        if (n == 0) { fflush(g_log); return -1; }
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (!g_relay_midline) { fputs("[agent] ", g_log); g_relay_midline = true; }
            if (c == '\n') { fputc('\n', g_log); g_relay_midline = false; }
            else if ((c < 0x20 && c != '\t') || c == 0x7f)
                fprintf(g_log, "\\x%02x", (unsigned)c);   /* \r cannot split a line */
            else fputc(c, g_log);
        }
    }
    fflush(g_log);
    return 0;
}

static void emit_run_start(const char *policy_path, const struct policy *p) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"run_start\",\"run\":\"%s\",\"warden\":\"1.16.0\","
               "\"policy_path\":\"", g_run_id);
    json_escape(f, policy_path);
    fprintf(f, "\",\"policy_rules\":%zu,\"policy_sha256\":\"%s\",%s", p->v.n, p->sha256,
#ifdef VDP_FAULT_INJECT
            "\"build\":\"faultinject\","      /* a test build: never a real run */
#else
            ""
#endif
            );
    /* v1.16: how this stream is protected (see the log integrity notes). */
    fputs("\"log\":\"chain-1\",", f);
    if (g_signing) {
        char pk_hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
        sodium_bin2hex(pk_hex, sizeof pk_hex, g_pk, sizeof g_pk);
        fprintf(f, "\"log_pubkey\":\"%s\",\"checkpoint_every\":%" PRIu64 ",", pk_hex, g_ckpt_every);
    }
    if (g_anchor_fd >= 0) fputs("\"anchored\":true,", f);
    fprintf(f, "\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end("run_start");
}

static void emit_run_end(int exit_status) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"run_end\",\"run\":\"%s\",\"records\":%" PRIu64 ","
               "\"exit_status\":%d,%s\"timestamp_ns\":%lld}\n",
            g_run_id, g_records, exit_status,
            g_anchor_errors ? "\"anchor_errors_seen\":true," : "",
            (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end("run_end");
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
    char flags_json[16] = "";
    if (a->kind == ACT_FILE_OPEN && a->flags_known)
        snprintf(flags_json, sizeof flags_json, "0x%x", (unsigned)a->open_flags);
    /* v1.12: target and resolved are escaped via json_escape(); every other
     * field is drawn from a fixed enum or an integer, so the whole record is
     * well-formed JSON regardless of agent-controlled input. */
    FILE *f = rec_begin();
    fprintf(f,
        "{\"report_id\":\"pr-%ld.%09ld-%" PRIu64 "\","
        "\"run\":\"%s\","
        "\"seq\":%" PRIu64 ","
        "\"agent_pid\":%d,"
        "\"action\":\"%s\","
        "\"target\":\"",
        (long)ts.tv_sec, ts.tv_nsec, seq,
        g_run_id, g_records,
        (int)pid,
        action_kind_name(a->kind));
    json_escape(f, a->target);
    fputs("\",\"resolved\":\"", f);
    json_escape(f, a->resolved[0] ? a->resolved : "");
    fprintf(f,
        "\",\"decision_raw\":\"%s\","
        "\"decision_final\":\"%s\","
        "\"rule\":\"%s\","
        "\"policy_line\":%d,"
        "%s%s%s"
        "%s%s%s%s%s%s"
        "\"kernel_verdict\":\"%s\","
        "\"errno\":%d,"
        "\"latency_us\":%" PRIu64 ","
        "\"timestamp_ns\":%lld}\n",
        decision_name(d_raw),
        decision_name(d_final),
        rule_id ? rule_id : "none",
        a->policy_line,
        /* v1.15: the open flags, so an audit can re-check the certificate */
        flags_json[0] ? "\"open_flags\":\"" : "", flags_json, flags_json[0] ? "\"," : "",
        /* v1.15: the certificate and the checker's answer */
        "", a->cert, a->cert[0] ? "," : "",
        a->cert[0] ? (a->certified ? "\"check\":\"ok\"," : "\"check\":\"refused\",\"check_why\":\"") : "",
        a->cert[0] && !a->certified ? a->check_why : "",
        a->cert[0] && !a->certified ? "\"," : "",
        /* v1.12.1: an ALLOW whose open then failed (EEXIST, ENXIO, ...)
         * delivered nothing; say so rather than reporting ALLOW. */
        d_final == DEC_ALLOW ? (kernel_errno ? "ERRNO" : "ALLOW") : "EPERM",
        kernel_errno,
        (uint64_t)(latency_ns / 1000ULL),
        (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);
    g_records++;
    g_since_ckpt++;
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

/* v1.12.1: fail the agent's syscall with a specific errno (used when an
 * ALLOWED open fails for an ordinary reason such as EEXIST or ENXIO). */
static void send_errno(int notify_fd, uint64_t id, int err) {
    struct seccomp_notif_resp resp = {
        .id = id, .val = 0, .error = -err, .flags = 0,
    };
    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

/* v1.12 AT_FDCWD constant (avoid pulling a divergent libc definition). */
#ifndef VAREK_AT_FDCWD
#define VAREK_AT_FDCWD (-100)
#endif

/* v1.12.1: resolve without side effects, decide, THEN open.
 *
 * v1.12.0 resolved the object by opening it with the agent's own flags and
 * only then consulted policy. The open ran as root before the decision, so a
 * DENY still had effects: O_TRUNC emptied a denied file, O_CREAT created a
 * root-owned file in a denied directory, and a blocking open (a FIFO with no
 * peer) wedged the single-threaded supervisor.
 *
 * v1.12.1 splits the step in two:
 *
 *   resolve_target()      pins the object with an O_PATH descriptor, which
 *                         opens nothing (no truncation, no creation, no device
 *                         or FIFO open semantics), and records its canonical
 *                         path for the decision and the audit log;
 *   materialize_target()  runs only after ALLOW, and opens the pinned object
 *                         with the agent's real flags.
 *
 * The decision and the delivered fd still name the same inode: the real open
 * goes through the pinned O_PATH fd (/proc/self/fd/N of the supervisor's own
 * descriptor), not through the agent's pathname a second time.
 *
 * Creation. An O_PATH open of a name that does not exist fails, so for O_CREAT
 * the parent directory is pinned instead and the decision is made on
 * <canonical parent>/<name>. After ALLOW the file is created with
 * openat(parent_fd, name, flags | O_NOFOLLOW): the parent is the directory
 * that was decided on, and a symlink raced into the name is refused (ELOOP).
 *
 * Resolution flags:
 *   Ordinary symlinks are FOLLOWED (v1.12.3). v1.12.0 through v1.12.2 set
 *   RESOLVE_NO_SYMLINKS, which refused every path with a symlink anywhere in
 *   it. On merged-/usr systems /lib is a symlink, and shared-library names
 *   (libz.so.1 -> libz.so.1.3) are symlinks, so the dynamic loader could not
 *   open most libraries and every dynamically linked agent failed before
 *   main(). Following symlinks does not weaken the decision: policy is matched
 *   on the canonical path of the object the resolution actually reached, and
 *   that same object is what is delivered. A symlink in an allowed directory
 *   that points at a denied file is decided as the denied file.
 *   RESOLVE_NO_MAGICLINKS — /proc/<pid>/fd/N, /proc/<pid>/cwd, exe and root do
 *                           not resolve.
 *   /proc/self — an ordinary symlink, but resolved by the SUPERVISOR it would
 *                name the supervisor's own process. So (v1.12.3) a leading
 *                /proc/self or /proc/thread-self in the agent's path is
 *                rewritten to the agent's own /proc/<tgid> before resolution
 *                (it is a magic link RESOLVE_NO_MAGICLINKS would otherwise
 *                refuse). A planted symlink pointing at a magic link such as
 *                /proc/self/mem is refused by RESOLVE_NO_MAGICLINKS during
 *                resolution. After resolution any object on a procfs mount must
 *                lie under /proc/<the agent's tgid>/ or be a non-process /proc
 *                entry; a numeric /proc/<pid> that is not the agent's (the
 *                supervisor's own, or another process's) fails closed. An
 *                object under the agent's own /proc/<tgid>/ is decided and
 *                recorded as /proc/self/..., which is how policies name it.
 *   RESOLVE_BENEATH is deliberately NOT set: allow rules legitimately name
 *   absolute paths outside the cwd. `..` is defanged by deciding on the
 *   post-collapse canonical path.
 *   O_NOFOLLOW from the agent is honoured: it is passed to the O_PATH resolve,
 *   which then returns the trailing symlink itself, and a trailing symlink
 *   fails closed (EACCES; a normal open would say ELOOP).
 *
 * dirfd handling: only AT_FDCWD (resolved against /proc/<pid>/cwd) and
 * absolute paths are handled; any other dirfd fails closed. */

struct resolved_target {
    int  path_fd;          /* O_PATH fd on the object, or -1 when creating */
    int  parent_fd;        /* O_PATH fd on the parent directory when creating */
    char name[256];        /* final component when creating */
};

static void resolved_target_close(struct resolved_target *r) {
    if (r->path_fd   >= 0) close(r->path_fd);
    if (r->parent_fd >= 0) close(r->parent_fd);
    r->path_fd = r->parent_fd = -1;
}

/* Canonical path of a descriptor the supervisor holds. Fails closed on a
 * deleted or anonymous inode (readlink does not start with '/'). */
static int fd_canonical_path(int fd, char *out, size_t outlen) {
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    ssize_t rl = readlink(linkpath, out, outlen - 1);
    if (rl < 0 || (size_t)rl >= outlen - 1) { out[0] = '\0'; return -1; }
    out[rl] = '\0';
    if (out[0] != '/') { out[0] = '\0'; return -1; }
    return 0;
}

static int openat2_path(int dirfd, const char *path, uint64_t extra_flags) {
    struct open_how_local how = {
        .flags   = (uint64_t)O_PATH | (uint64_t)O_CLOEXEC | extra_flags,
        .mode    = 0,
        .resolve = (uint64_t)RESOLVE_NO_MAGICLINKS,
    };
    return (int)syscall(__NR_openat2, dirfd, path, &how, sizeof(how));
}

/* v1.12.3: thread-group id of a requesting task (req.pid is a thread id). */
static pid_t task_tgid(pid_t tid) {
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    pid_t tgid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Tgid:", 5) == 0) { tgid = (pid_t)strtol(line + 5, NULL, 10); break; }
    }
    fclose(f);
    return tgid > 0 ? tgid : -1;
}

/* v1.12.3: does this path start with /proc/self or /proc/thread-self? Only
 * these need the requester's tgid before resolution; every other path is left
 * alone, so the common open never reads /proc/<tid>/status. */
static bool path_is_proc_self(const char *in, bool *thread_self) {
    static const char kSelf[] = "/proc/self", kThread[] = "/proc/thread-self";
    if (!strncmp(in, kThread, sizeof(kThread) - 1) &&
        (in[sizeof(kThread) - 1] == '\0' || in[sizeof(kThread) - 1] == '/')) {
        *thread_self = true; return true;
    }
    if (!strncmp(in, kSelf, sizeof(kSelf) - 1) &&
        (in[sizeof(kSelf) - 1] == '\0' || in[sizeof(kSelf) - 1] == '/')) {
        *thread_self = false; return true;
    }
    return false;
}

/* Rewrite a leading /proc/self or /proc/thread-self (already matched) to the
 * agent's own /proc/<tgid>[/task/<tid>], so the supervisor does not resolve it
 * to itself. Returns 0 (out filled), or -1 if it does not fit. */
static int rewrite_proc_self(const char *in, bool thread_self,
                             pid_t tgid, pid_t tid, char *out, size_t outlen) {
    static const char kSelf[] = "/proc/self", kThread[] = "/proc/thread-self";
    int n;
    if (thread_self) {
        const char *rest = in + sizeof(kThread) - 1;
        n = snprintf(out, outlen, "/proc/%d/task/%d%s", tgid, tid, rest);
    } else {
        const char *rest = in + sizeof(kSelf) - 1;
        n = snprintf(out, outlen, "/proc/%d%s", tgid, rest);
    }
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif

/* v1.12.3: after resolution, an object on procfs must be the agent's own
 * (/proc/<tgid>/...) or a non-process entry (/proc/cpuinfo, /proc/sys/...).
 * The agent's own entries are rewritten to /proc/self/... for the decision and
 * the record. The tgid is looked up here, only when the object is actually on
 * procfs, and cached in *tgid_cache across the calls of one resolution.
 * Returns 0, or -1 to fail closed. */
static int check_proc_object(int fd, pid_t tid, pid_t *tgid_cache,
                             char *canon, size_t canonlen) {
    struct statfs sf;
    if (fstatfs(fd, &sf) < 0) return -1;
    if ((unsigned long)sf.f_type != (unsigned long)PROC_SUPER_MAGIC) return 0;
    if (strncmp(canon, "/proc", 5) != 0 || (canon[5] != '/' && canon[5] != '\0'))
        return -1;                        /* a procfs mounted somewhere else */
    const char *p = canon + 5;
    if (*p == '\0') return 0;             /* /proc itself */
    p++;                                  /* past the '/' */
    if (*p < '0' || *p > '9') return 0;   /* not a /proc/<pid> entry */
    char *end;
    long n = strtol(p, &end, 10);
    if (*end != '/' && *end != '\0') return 0;   /* e.g. a name starting with a digit */
    if (*tgid_cache < 0) {
        *tgid_cache = task_tgid(tid);
        if (*tgid_cache < 0) return -1;
    }
    if (n != (long)*tgid_cache) return -1;   /* the supervisor's, or another process's */
    char tmp[PATH_LIMIT];
    int w = snprintf(tmp, sizeof(tmp), "/proc/self%s", end);
    if (w < 0 || (size_t)w >= sizeof(tmp) || (size_t)w >= canonlen) return -1;
    memcpy(canon, tmp, (size_t)w + 1);
    return 0;
}

/* Returns 0 with r filled and a->resolved set, or -1 (fail closed). Nothing
 * on the filesystem is opened, created or modified. */
static int resolve_target(pid_t target_pid, struct action *a,
                          struct resolved_target *r)
{
    a->resolved[0] = '\0';
    r->path_fd = r->parent_fd = -1;
    r->name[0] = '\0';

    if (a->open_dirfd != VAREK_AT_FDCWD && a->target[0] != '/')
        return -1;   /* relative open against a dirfd we do not track */

    /* tgid is needed only for a /proc/self path (before resolution) or a procfs
     * object (after). Compute it lazily so an ordinary open never reads
     * /proc/<tid>/status. */
    pid_t tgid = -1;
    char path[PATH_LIMIT];
    bool thread_self = false;
    if (path_is_proc_self(a->target, &thread_self)) {
        tgid = task_tgid(target_pid);
        if (tgid < 0) return -1;
        if (rewrite_proc_self(a->target, thread_self, tgid, target_pid,
                              path, sizeof(path)) < 0)
            return -1;
    } else {
        if ((size_t)snprintf(path, sizeof(path), "%s", a->target) >= sizeof(path))
            return -1;
    }

    char proc_cwd[64];
    snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", target_pid);
    int cwd_fd = open(proc_cwd, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (cwd_fd < 0) return -1;

    int fd = openat2_path(cwd_fd, path,
                          (uint64_t)a->open_flags &
                          ((uint64_t)O_DIRECTORY | (uint64_t)O_NOFOLLOW));
    if (fd >= 0) {
        close(cwd_fd);
        struct stat st;
        /* O_NOFOLLOW on a trailing symlink: O_PATH handed back the link. */
        if (fstat(fd, &st) < 0 || S_ISLNK(st.st_mode) ||
            fd_canonical_path(fd, a->resolved, sizeof(a->resolved)) < 0 ||
            check_proc_object(fd, target_pid, &tgid, a->resolved, sizeof(a->resolved)) < 0) {
            a->resolved[0] = '\0';
            close(fd);
            return -1;
        }
        r->path_fd = fd;
        return 0;
    }
    if (errno != ENOENT || !(a->open_flags & O_CREAT)) {
        close(cwd_fd);
        return -1;
    }

    /* O_CREAT of a name that does not exist yet: pin the parent. */
    const char *t = path;
    size_t tl = strlen(t);
    if (tl == 0 || t[tl - 1] == '/') { close(cwd_fd); return -1; }
    const char *slash = strrchr(t, '/');
    const char *name  = slash ? slash + 1 : t;
    if (!strcmp(name, ".") || !strcmp(name, "..") ||
        strlen(name) >= sizeof(r->name)) {
        close(cwd_fd);
        return -1;
    }
    char dir[PATH_LIMIT];
    if (!slash)          snprintf(dir, sizeof(dir), ".");
    else if (slash == t) snprintf(dir, sizeof(dir), "/");
    else                 snprintf(dir, sizeof(dir), "%.*s", (int)(slash - t), t);

    int pfd = openat2_path(cwd_fd, dir, (uint64_t)O_DIRECTORY);
    close(cwd_fd);
    if (pfd < 0) return -1;

    char parent[PATH_LIMIT];
    if (fd_canonical_path(pfd, parent, sizeof(parent)) < 0 ||
        check_proc_object(pfd, target_pid, &tgid, parent, sizeof(parent)) < 0) {
        close(pfd);
        return -1;
    }
    int n = snprintf(a->resolved, sizeof(a->resolved), "%s%s%s",
                     parent, strcmp(parent, "/") ? "/" : "", name);
    if (n < 0 || (size_t)n >= sizeof(a->resolved)) {
        a->resolved[0] = '\0';
        close(pfd);
        return -1;
    }
    r->parent_fd = pfd;
    snprintf(r->name, sizeof(r->name), "%s", name);
    return 0;
}

/* The agent's umask, so a file the supervisor creates on its behalf gets the
 * permissions the agent's own open would have produced. Falls back to 022. */
static mode_t target_umask(pid_t pid) {
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "re");
    mode_t m = 022;
    if (!f) return m;
    while (fgets(line, sizeof(line), f)) {
        unsigned int v;
        if (sscanf(line, "Umask: %o", &v) == 1) { m = (mode_t)(v & 0777); break; }
    }
    fclose(f);
    return m;
}

/* Runs only after ALLOW. Opens the pinned object with the agent's own flags
 * and returns the fd to inject, or -errno (the agent receives that errno,
 * exactly as its own open would have).
 *
 * O_NONBLOCK is added for the open itself so a FIFO or device cannot block
 * the single-threaded supervisor, then cleared again unless the agent asked
 * for it. Two visible differences follow for FIFOs: opening one for writing
 * when no reader exists returns ENXIO instead of waiting, and opening one
 * for reading when no writer exists returns at once, so read() reports
 * end-of-file until a writer connects instead of the open waiting for it. */
static int materialize_target(pid_t target_pid, const struct action *a,
                              const struct resolved_target *r)
{
    int want = a->open_flags;
    int fd;

    if (r->path_fd >= 0) {
        if (want & O_PATH) {
            fd = fcntl(r->path_fd, F_DUPFD_CLOEXEC, 0);
            return fd < 0 ? -errno : fd;
        }
        char self[64];
        snprintf(self, sizeof(self), "/proc/self/fd/%d", r->path_fd);
        /* Through the pinned descriptor: same inode that was decided on.
         * O_NOFOLLOW is dropped here only because /proc/self/fd/N is itself a
         * link; the agent's O_NOFOLLOW was already honoured at resolution
         * (a trailing symlink fails closed there). */
        int flags = (want & ~O_NOFOLLOW) | O_NONBLOCK | O_CLOEXEC;
        if ((want & O_TMPFILE) == O_TMPFILE) {
            /* O_TMPFILE creates an unnamed file in the pinned directory:
             * apply the agent's mode and umask, as for O_CREAT. */
            mode_t old = umask(target_umask(target_pid));
            fd = open(self, flags, (mode_t)(a->open_mode & 07777));
            int saved = errno;
            umask(old);
            errno = saved;
        } else {
            fd = open(self, flags, 0);
        }
    } else if (r->parent_fd >= 0) {
        if (want & O_PATH) return -ENOENT;
        int flags = want | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        mode_t old = umask(target_umask(target_pid));
        fd = openat(r->parent_fd, r->name, flags, (mode_t)(a->open_mode & 07777));
        int saved = errno;
        umask(old);
        errno = saved;
    } else {
        return -EACCES;
    }
    if (fd < 0) return -errno;

    if (!(want & O_NONBLOCK)) {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    return fd;
}

/* v1.12: hand an already-opened fd (from materialize_target) to the target.
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

/* Returns true when the agent went away on its own (its pidfd fired, or no
 * task is left under the filter), false when the Warden stopped supervising for
 * another reason and is about to kill it. */
static bool supervise(int notify_fd, int target_pidfd, int agent_err_fd,
                      const struct policy *p, const char *bootstrap_path,
                      pid_t bootstrap_pid) {
    uint64_t seq = 0;
    bool bootstrap_done = false;
    while (!g_stop && !g_log_broken) {
        /* v1.9.3: wait on the listener AND the target's pidfd. Blocking in
         * NOTIF_RECV alone can hang forever if the target exits between the
         * g_stop check and the ioctl (the SIGCHLD is already spent).
         * v1.12.1: also on the agent's stderr pipe, which is relayed. A
         * negative fd is ignored by poll(). */
        struct pollfd pfds[3] = {
            { .fd = notify_fd,    .events = POLLIN },
            { .fd = target_pidfd, .events = POLLIN },
            { .fd = agent_err_fd, .events = POLLIN },
        };
        /* v1.16: checkpoints are written here, between notifications, so
         * signing never delays an answer the agent is waiting for. */
        int pr = poll(pfds, 3, maybe_checkpoint());
        if (pr < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (agent_err_fd >= 0 && (pfds[2].revents & (POLLIN | POLLHUP | POLLERR))) {
            if (relay_agent_stderr(agent_err_fd, false) < 0) agent_err_fd = -1;
        }
        if (target_pidfd >= 0 && (pfds[1].revents & POLLIN))
            return true;                        /* target exited */
        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            return true;                        /* no process left under the filter */
        if (!(pfds[0].revents & POLLIN))
            continue;

        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;  /* ENOENT: requester died */
            return false;
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
         * specified binary is authorized by the act of launching it, and is
         * answered with CONTINUE. That is sound only while nothing else can
         * touch the path buffer: the launching process, before it has run any
         * agent code, single-threaded, blocked in execve.
         *
         * v1.12.2: allowed exactly ONCE per run, and only to the process the
         * Warden launched. Through v1.12.1 it was allowed once per pid, so any
         * thread or child the agent started could execve the bootstrap path
         * and get CONTINUE while a sibling sharing its memory rewrote the path
         * between the Warden's read and the kernel's, executing a binary the
         * policy never allowed. Raw clone(CLONE_VM) made that reachable
         * before; with threads admitted it would be routine. Every later exec,
         * including a re-exec of the agent's own binary, falls through to the
         * deny-only block below. */
        if (act.kind == ACT_PROCESS_EXEC && !bootstrap_done &&
            (pid_t)req.pid == bootstrap_pid &&
            bootstrap_path && strcmp(act.target, bootstrap_path) == 0) {
            bootstrap_done = true;
            if (ctx) ctx->launched = true;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_b = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,
                           "bootstrap_exec_allow", lat_b, 0);
            send_simple(notify_fd, req.id, DEC_ALLOW);
            continue;
        }

        /* v1.12.1: resolve-then-decide-then-open for file opens. The object
         * is pinned with O_PATH (no side effect), canonicalized, matched
         * against policy, and only on ALLOW opened with the agent's flags
         * through the pinned descriptor. Resolution failure (symlink
         * component, untracked dirfd, over-long path, deleted inode, missing
         * parent) is a hard deny before any policy match. */
        struct resolved_target rt = { .path_fd = -1, .parent_fd = -1 };
        if (act.kind == ACT_FILE_OPEN) {
            if (resolve_target(req.pid, &act, &rt) < 0) {
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
        /* v1.15: a file open is authorized only if the independent checker
         * accepts the verdict's certificate. */
        bool cert_refused = false;
        if (d_final == DEC_ALLOW && act.kind == ACT_FILE_OPEN && !certify(p, &act)) {
            d_final = DEC_DENY;
            cert_refused = true;
            /* No agent-controlled byte here: the path is in the record. */
            log_line_start();
            fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n",
                    g_records, act.check_why);
        }

        if (act.kind == ACT_FILE_OPEN) {
            if (d_final == DEC_ALLOW) {
                /* Nothing has been opened with the agent's flags until here. */
                int ofd = materialize_target(req.pid, &act, &rt);
                resolved_target_close(&rt);
                const char *rule = "resolved_fd_injection";
                int err = 0;
                if (ofd < 0) {
                    err  = -ofd;
                    rule = "allowed_open_failed";
                } else if (!notif_id_valid(notify_fd, req.id) ||
                           inject_fd(notify_fd, req.id, ofd) != 0) {
                    /* Requester gone, or injection failed: nothing delivered. */
                    err  = EACCES;
                    rule = "injection_failed";
                }
                if (ofd >= 0) close(ofd);
                if (err) send_errno(notify_fd, req.id, err);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                             + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(seq++, req.pid, &act, d_raw, d_final, rule, lat, err);
                continue;
            }
            /* Denied by policy: the pinned object was never opened. */
            resolved_target_close(&rt);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_d = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(seq++, req.pid, &act, d_raw, d_final,
                           cert_refused ? "certificate_refused" : decision_rule_id(&act, d_raw),
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
                       decision_rule_id(&act, d_raw),
                       lat, d_final == DEC_ALLOW ? 0 : EACCES);
    }
    return false;                         /* the Warden was asked to stop */
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

/* ---------------- v1.16: signing key and anchor ---------------- */

/* The policy must not let the agent open the file at path (with any flags):
 * decided by the certificate checker, which every authorization needs. */
static int refuse_if_agent_can_open(const struct policy *p, const char *path, const char *what) {
    char rp[PATH_MAX];
    if (!realpath(path, rp)) {
        fprintf(stderr, "[warden] %s %s: %s\n", what, path, strerror(errno));
        return -1;
    }
    if (vdpc_path_openable(&p->c, rp, strlen(rp))) {
        fprintf(stderr, "[warden] the policy would let the agent open the %s (%s); deny that "
                "path or keep the file outside every path the policy allows. Refusing to start.\n",
                what, rp);
        return -1;
    }
    return 0;
}

/* --sign-key FILE: an Ed25519 seed, 64 hex characters (tools/varek_keygen
 * makes one), in a regular file no one but its owner can read or write. */
static int load_sign_key(const char *path, const struct policy *p) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        fprintf(stderr, "[warden] signing key %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[warden] signing key %s: not a regular file\n", path);
        close(fd);
        return -1;
    }
    if (st.st_mode & 077) {
        fprintf(stderr, "[warden] signing key %s: readable or writable by group or others "
                "(chmod 600 it)\n", path);
        close(fd);
        return -1;
    }
    char buf[80];
    ssize_t n;
    do { n = read(fd, buf, sizeof buf); } while (n < 0 && errno == EINTR);
    close(fd);
    unsigned char seed[crypto_sign_SEEDBYTES];
    size_t bl = 0;
    bool ok = (n == 64 || (n == 65 && buf[64] == '\n')) &&
              sodium_hex2bin(seed, sizeof seed, buf, 64, NULL, &bl, NULL) == 0 &&
              bl == sizeof seed;
    sodium_memzero(buf, sizeof buf);
    if (!ok) {
        sodium_memzero(seed, sizeof seed);
        fprintf(stderr, "[warden] signing key %s: not a VAREK signing key (64 hex characters; "
                "make one with tools/varek_keygen)\n", path);
        return -1;
    }
    crypto_sign_seed_keypair(g_pk, g_sk, seed);
    sodium_memzero(seed, sizeof seed);
    (void)sodium_mlock(g_sk, sizeof g_sk);
    if (refuse_if_agent_can_open(p, path, "signing key") < 0) {
        sodium_memzero(g_sk, sizeof g_sk);
        return -1;
    }
    g_signing = true;
    return 0;
}

/* --anchor PATH: a regular file, FIFO or character device the Warden appends
 * checkpoint-type records to. Opened non-blocking: a FIFO needs its reader
 * running first. */
static int open_anchor(const char *path, const struct policy *p) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "[warden] anchor %s: %s%s\n", path, strerror(errno),
                errno == ENXIO ? " (no reader on the FIFO: start the forwarder first)" : "");
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !(S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode))) {
        fprintf(stderr, "[warden] anchor %s: not a regular file, FIFO or character device\n", path);
        close(fd);
        return -1;
    }
    if (refuse_if_agent_can_open(p, path, "anchor") < 0) { close(fd); return -1; }
    g_anchor_fd = fd;
    return 0;
}

/* ---------------- main ---------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <policy.txt> [--plan <plan.txt>] [--sign-key <key>] [--anchor <path>]\n"
        "              [--checkpoint-every <n>] -- <target> [args...]\n"
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
        "  v1.16 log integrity: every record is hash-chained. --sign-key <key>\n"
        "  (from tools/varek_keygen) signs run_start, a checkpoint every <n>\n"
        "  records (default 64, and at least once a second) and run_end with\n"
        "  Ed25519; --anchor <path> also appends each checkpoint to <path>\n"
        "  (append-only or off-host storage). tools/varek_audit.py verifies both.\n"
        "\n"
        "  Policy file format (one rule per line):\n"
        "    allow path /tmp/safe/\n"
        "    deny  path /etc/\n"
        "    allow host 127.0.0.1:8080\n"
        "    deny  host evil.example.com\n"
        "    allow exec /usr/bin/env\n"
        "    allow path /var/log/ readonly     (v1.13: access=ro -O_CREAT -O_TRUNC)\n"
        "    deny  path suffix .pem            (v1.14 matchers: exact, prefix,\n"
        "    deny  path glob /home/*/.ssh/**    suffix, contains, glob; path and exec)\n"
        "  Path rules also take access=ro|wo|rw, +O_NAME, -O_NAME. Begin a policy\n"
        "  that uses flag clauses with require warden 1.13, matchers with 1.14.\n"
        "  Check a policy with: tools/vdp_check <policy> lint\n"
        "\n"
        "  Plan file format (see varek/v1_6/sample_plan.txt):\n"
        "    action <label> <kind> <target>\n"
        "    edge   <from_label> <to_label>\n"
        "  A file_open target is verified against the policy on its lexically\n"
        "  canonical path (. and .. collapsed); it must be absolute. Symlinks\n"
        "  are not followed at plan time (there is no agent yet), so the gate is\n"
        "  an advisory pre-check and every open is still mediated at runtime.\n",
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
    const char *key_path    = NULL;     /* v1.16 */
    const char *anchor_path = NULL;     /* v1.16 */
    int sep_idx = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep_idx = i; break; }
        if (i + 1 >= argc) { usage(argv[0]); return 2; }
        if (strcmp(argv[i], "--plan") == 0 && !plan_path) {
            plan_path = argv[++i];
        } else if (strcmp(argv[i], "--sign-key") == 0 && !key_path) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--anchor") == 0 && !anchor_path) {
            anchor_path = argv[++i];
        } else if (strcmp(argv[i], "--checkpoint-every") == 0) {
            const char *v = argv[++i];
            uint64_t n = 0;
            size_t k = 0;
            for (; v[k] >= '0' && v[k] <= '9' && k < 8; k++) n = n * 10 + (uint64_t)(v[k] - '0');
            if (k == 0 || v[k] || n < 1 || n > 1000000) {
                fprintf(stderr, "[warden] --checkpoint-every takes 1 to 1000000\n");
                return 2;
            }
            g_ckpt_every = n;
        } else {
            usage(argv[0]); return 2;
        }
    }

    if (sep_idx < 0 || sep_idx + 1 >= argc) { usage(argv[0]); return 2; }
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

    /* ~1 MB (256 rules x 4 KB constants): static, not on the stack. */
    static struct policy p;
    if (policy_load(policy_path, &p) < 0) return 1;

    /* v1.16: log integrity. */
    if (sodium_init() < 0) {
        fprintf(stderr, "[warden] libsodium failed to initialize\n");
        return 1;
    }
    if (key_path && load_sign_key(key_path, &p) < 0) return 1;
    if (anchor_path && open_anchor(anchor_path, &p) < 0) return 1;
    /* A FIFO anchor whose reader went away must fail the write (EPIPE, then
     * an anchor_error record), not kill the Warden. The agent gets the
     * default disposition back before it runs (see the child below). */
    if (anchor_path) signal(SIGPIPE, SIG_IGN);

    if (log_init() < 0) {
        fprintf(stderr, "[warden] cannot open the verdict stream or create a run id (%s)\n",
                strerror(errno));
        return 1;
    }
    /* v1.12.1: if stdout and stderr are the same file (2>&1), the agent's
     * stdout lands in the verdict stream unprefixed. Records stay
     * authenticated by run id and seq, and the exporter refuses a stream
     * holding anything that parses as a foreign record, but say so. */
    {
        struct stat so, se;
        if (fstat(1, &so) == 0 && fstat(2, &se) == 0 &&
            so.st_dev == se.st_dev && so.st_ino == se.st_ino) {
            fprintf(stderr,
                "[warden] WARNING: stdout and stderr are the same file; the agent's "
                "stdout will be mixed into the verdict stream. Keep them separate "
                "(e.g. 2> run.log) for an attestable log.\n");
        }
    }
    emit_run_start(policy_path, &p);

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

    /* v1.12.1: the agent's stderr is a pipe the supervisor relays, so the
     * agent never writes to the verdict stream directly. */
    int errpipe[2];
    if (pipe2(errpipe, O_CLOEXEC) < 0) { perror("pipe2"); return 1; }

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
        signal(SIGPIPE, SIG_DFL);       /* v1.16: an ignored signal survives execve */
        close(sv[0]);
        close(live[1]);
        close(errpipe[0]);
        if (dup2(errpipe[1], STDERR_FILENO) < 0) _exit(1);   /* dup2 clears CLOEXEC */
        close(errpipe[1]);
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
        /* v1.12.1: the agent gets its own network namespace, holding only a
         * loopback interface that is down. Nothing can reach it and it can
         * reach nothing, whatever sockets it creates; the filter also refuses
         * bind/listen/accept. Must precede the filter, which denies
         * CLONE_NEWNET. With the PID namespace (CAP_SYS_ADMIN held) failure is
         * fatal; in VAREK_WARDEN_NO_PIDNS mode it is a warning. */
        if (unshare(CLONE_NEWNET) < 0) {
            if (pidns) {
                fprintf(stderr, "[warden-target] cannot create a network namespace "
                                "(%s); refusing to run\n", strerror(errno));
                _exit(1);
            }
            fprintf(stderr, "[warden-target] WARNING: no network namespace (%s); "
                            "the agent shares the host network (bind/listen/accept "
                            "are still refused)\n", strerror(errno));
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
    close(errpipe[1]);
    int agent_err_fd = errpipe[0];
    (void)fcntl(agent_err_fd, F_SETFL, fcntl(agent_err_fd, F_GETFL) | O_NONBLOCK);

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

    /* v1.12.1: report whether the agent really has its own network
     * namespace, by comparing namespace identities rather than trusting
     * the child. */
    const char *netns = "unknown";
    {
        char mine[64], theirs[64], path[64];
        ssize_t a = readlink("/proc/self/ns/net", mine, sizeof mine - 1);
        snprintf(path, sizeof path, "/proc/%d/ns/net", target);
        ssize_t b = readlink(path, theirs, sizeof theirs - 1);
        if (a > 0 && b > 0) {
            mine[a] = theirs[b] = '\0';
            netns = strcmp(mine, theirs) ? "on" : "off";
        }
    }
    fprintf(stderr,
        "[warden] supervising pid=%d  notify_fd=%d  policy=%s (%zu rules)  pidns=%s  netns=%s\n",
        target, notify_fd, p.name, p.v.n, pidns ? "on" : "off", netns);

    bool agent_ended = supervise(notify_fd, target_pidfd, agent_err_fd, &p,
                                 target_argv[0], target);

    kill_target_tree(target);  /* the agent and everything it spawned */
    int status = 0;
    waitpid(target, &status, 0);
    /* Relay anything the agent wrote before it died, then close the stream. */
    (void)relay_agent_stderr(agent_err_fd, true);
    close(agent_err_fd);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    /* v1.12.2: say when the agent died by a signal. Through v1.12.1 an agent
     * killed by the filter (SIGSYS) left only an exit code of 1, which is how a
     * thread-starting agent could be killed on every run without a word. Only
     * when the agent ended on its own: otherwise the SIGKILL is the Warden's. */
    if (agent_ended && WIFSIGNALED(status))
        fprintf(stderr, "[warden] agent killed by signal %d (%s)%s\n",
                WTERMSIG(status), strsignal(WTERMSIG(status)),
                WTERMSIG(status) == SIGSYS
                    ? ": most likely a hard-denied system call" : "");
    emit_run_end(rc);
    sodium_memzero(g_sk, sizeof g_sk);
    close(target_pidfd);
    close(notify_fd);
    return rc;
}
