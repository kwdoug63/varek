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
 *   4. Stateful Execution Context — per-pid state object holding a
 *      sequence number used for pathology-report correlation and whether
 *      the pid has launched. (Correction, v1.21.0: this said it tracked
 *      cwd snapshots and opened-fd lineage; it tracks neither, and nothing
 *      in the Warden tracks descriptors after it grants them.)
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
 * The calls the filter routes here are listed in warden_baseline_filter.c
 * (kMediate, add_sends): opens, lookups, connects, launches, bind, and the
 * sends that can carry a destination. The architecture extends to any
 * syscall by adding a new case to derive_intent() and policy_decide().
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
#include <grp.h>
#include <pwd.h>
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
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
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
/* v1.18.0: the v1.7 data-flow check, the v1.8.2 refusal breaker and the v1.9
 * progress-safety check, run by the --plan gate when --flow-policy is given. */
#include "plan_label_policy.h"
#include "plan_policy_config.h"
#include "plan_warden_binding.h"
#include "plan_breaker.h"
#include "plan_progress.h"
#include "warden_baseline_filter.h"
#include "smt_decide.h"            /* v1.13 SMT decision procedure */
#include "checker/vdp_checker.h"   /* v1.15 independent certificate checker */
#include "warden_lifecycle.h"   /* v1.9.3 supervisor/target lifecycle coupling */
#include "warden_resolve.h"     /* v1.24 resolution table for host name rules */
#include "shared_domains.h"     /* v1.25 wildcards over shared domains, refused at load */
#include "warden_proxy.h"       /* v1.26 the egress proxy process */
#include "proxy_parse.h"        /* v1.26 what the proxy reads (pp_kind_name) */

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

#ifndef VAREK_PIDFD_THREAD
#define VAREK_PIDFD_THREAD O_EXCL      /* PIDFD_THREAD, Linux 6.9 */
#endif

#ifndef VAREK_AT_FDCWD
#define VAREK_AT_FDCWD (-100)
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
    ACT_NET_BIND,        /* v1.21: bind, performed only for a wildcard address, port 0 */
    ACT_PROCESS_EXEC,
    ACT_FILE_STAT,       /* v1.17.0: newfstatat, statx */
    ACT_FILE_ACCESS,     /* v1.17.0: access, faccessat, faccessat2 */
    ACT_FILE_READLINK,   /* v1.17.0: readlink, readlinkat */
    ACT_NET_PROXY,       /* v1.26: a name:port the egress proxy read from a client */
    ACT_OTHER,
} action_kind_t;

/* v1.17.0: the metadata and link lookups, mediated like opens. */
static bool is_meta_kind(action_kind_t k) {
    return k == ACT_FILE_STAT || k == ACT_FILE_ACCESS || k == ACT_FILE_READLINK;
}

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
    /* v1.21: decided connections and relayed sends */
    unsigned char sa[sizeof(struct sockaddr_storage)]; /* the destination, copied once */
    int           salen;                /* connect's addrlen as the kernel reads it */
    bool          salen_bad;            /* < 0 or > sizeof(sockaddr_storage): EINVAL */
    int           sock_fd;              /* the agent's descriptor (arg 0) */
    const char   *sock_name;            /* "tcp", "udp", "unix-stream", ... (record) */
    uint64_t      dial_ns;              /* dial start to completion */
    int           send_nr;              /* sendto / sendmsg / sendmmsg */
    uint64_t      send_flags;           /* the flags register */
    uint64_t      msg_addr;             /* sendmsg: struct msghdr *; sendmmsg: mmsghdr[] */
    unsigned      mmsg_vlen;            /* sendmmsg: vlen */
    /* v1.17.0: metadata lookups */
    int           meta_nr;              /* the system call */
    uint64_t      out_addr;             /* where the answer goes in the agent */
    uint64_t      out_len;              /* readlink's buffer size */
    int           at_flags;             /* AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, ... */
    unsigned      statx_mask;
    int           access_mode;          /* F_OK/R_OK/W_OK/X_OK */
    bool          path_null;            /* a NULL path pointer */
    bool          bad_flags;            /* flags the kernel would refuse (EINVAL) */
    /* v1.24: host names (warden_names.inc.c) */
    int           ncand;                /* connect: candidate strings decided over (g_cand,
                                           warden_names.inc.c) */
    bool          special_addr;         /* connect: a special address, decided as a number */
    char          dialed[64];           /* connect: the numeric destination dialed */
    bool          proxy_handoff;        /* v1.26: a connect handed to the egress proxy */
    char          extra[4608];          /* extra record fields, trusted text, each ending in ',' */
};

/* v1.25: the candidates of the connect being decided (warden_names.inc.c) */
typedef char cand_t[WR_NAME_MAX + 8];
static cand_t *g_cand;
static size_t  g_cand_cap;
static size_t *g_cand_idx;

static const char *action_kind_name(action_kind_t k) {
    switch (k) {
        case ACT_FILE_OPEN:    return "file.open";
        case ACT_NET_CONNECT:  return "net.connect";
        case ACT_NET_SEND:     return "net.send";
        case ACT_NET_BIND:     return "net.bind";
        case ACT_PROCESS_EXEC: return "process.exec";
        case ACT_FILE_STAT:     return "file.stat";
        case ACT_FILE_ACCESS:   return "file.access";
        case ACT_FILE_READLINK: return "file.readlink";
        case ACT_NET_PROXY:     return "net.proxy";
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
    snprintf(p->version, sizeof(p->version), "1.26");
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
    /* Rule by rule, the two parses must agree: verb, kind, matcher, constant,
     * flag clause, and (v1.24) whether a host rule is a name and matches every
     * port. (A divergence could only cause denials, since an
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
            [VDP_KIND_REQUEST] = VDPC_REQUEST,
        };
        if (vdpc_rule_info(&p->c, i, &ci) < 0 || ci.allow != (r->verb == VDP_ALLOW) ||
            ci.kind != kind_to_c[r->kind] || ci.match != op_to_match[r->s.op] ||
            ci.clen != r->s.len || memcmp(ci.c, r->s.c, r->s.len) != 0 ||
            ci.mask != r->b.mask || ci.value != r->b.value || ci.line != r->line ||
            ci.portless != r->s.portless || ci.name != r->s.name || ci.wild != r->s.wild ||
            ci.names != r->names || ci.rate != r->rate || ci.max_body != r->max_body) {
            fprintf(stderr, "[warden] policy %s:%d: the decision procedure and the certificate "
                    "checker read this rule differently; refusing to start\n", path, r->line);
            return -1;
        }
    }
    /* v1.26: and the proxy directives */
    bool proxy_same = p->v.proxy == (p->c.proxy != 0) && p->v.proxy_nports == p->c.proxy_nports;
    for (size_t k = 0; proxy_same && k < p->v.proxy_nports; k++)
        proxy_same = p->v.proxy_ports[k] == p->c.proxy_ports[k];
    proxy_same = proxy_same && p->v.proxy_up_port == p->c.proxy_up_port &&
                 (!p->v.proxy_up_port || !strcmp(p->v.proxy_up_host, p->c.proxy_up_host));
    /* v1.26.1: inspecting mode and its passthrough hosts */
    proxy_same = proxy_same && p->v.proxy_inspect == (p->c.proxy_inspect != 0) &&
                 p->v.proxy_npass == p->c.proxy_npass;
    for (size_t k = 0; proxy_same && k < p->v.proxy_npass; k++)
        proxy_same = !strcmp(p->v.proxy_pass[k], p->c.proxy_pass[k]);
    if (!proxy_same) {
        fprintf(stderr, "[warden] policy %s: the decision procedure and the certificate checker read "
                "the proxy directives differently; refusing to start\n", path);
        return -1;
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
    /* v1.26.1: a request rule whose host no host rule allows on its port */
    for (size_t i = 0; i < p->v.n; i++) {
        char hw[300];
        if (vdp_request_host_refused(&p->v, i, hw, sizeof hw)) {
            dead++;
            fprintf(stderr, "[warden] policy %s:%d: WARNING: request rule can never fire: %s\n",
                    path, p->v.rules[i].line, hw);
        }
    }
    /* v1.21: host rules no connect can match (non-canonical spellings, and
     * v1.24 host names without `require warden 1.24`; each got a note above). */
    size_t hostnever = 0;
    for (size_t i = 0; i < p->v.n; i++) {
        char hw[160];
        if (p->v.rules[i].kind == VDP_KIND_HOST &&
            !vdp_host_rule_ok(&p->v.rules[i], hw, sizeof hw))
            hostnever++;
    }
    fprintf(stderr, "[warden] loaded policy %s v%s with %zu rules (%zu can never fire%s), "
            "sha256 %s\n", p->name, p->version, p->v.n, dead,
            hostnever ? "; some host rules can never match a connect, see the notes" : "",
            p->sha256);
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
    /* v1.24: the legacy open(2), which musl uses (a static musl program never
     * calls openat), is open relative to the working directory: decided and
     * answered exactly as openat(AT_FDCWD, path, flags, mode). Through v1.23 it
     * fell to the filter's default deny, so a musl agent could open nothing. */
    if (nr == __NR_open) {
        out->kind = ACT_FILE_OPEN;
        if (xproc_read_str(req->pid, req->data.args[0],
                           out->target, sizeof(out->target)) < 0)
            return -1;
        out->open_dirfd = VAREK_AT_FDCWD;
        out->resolved[0] = '\0';
        out->open_flags = (int)req->data.args[1];
        out->flags_known = true;
        out->open_mode  = (int)(req->data.args[2] & 0777);
        return 0;
    }
    if (nr == __NR_connect) {
        out->kind = ACT_NET_CONNECT;
        out->sock_fd = (int)req->data.args[0];
        /* v1.21: the kernel takes addrlen as an int and refuses one below 0 or
         * above sizeof(struct sockaddr_storage) with EINVAL. The destination is
         * copied here, once; the Warden dials this copy and never lets the
         * kernel read the agent's memory again. */
        int ilen = (int)req->data.args[2];
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        if (ilen < 0 || (size_t)ilen > sizeof(struct sockaddr_storage)) {
            out->salen_bad = true;
            snprintf(out->target, sizeof(out->target), "addrlen:%d", ilen);
            return 0;
        }
        socklen_t len = (socklen_t)ilen;
        if (len > 0 && xproc_read_bytes(req->pid, req->data.args[1], &ss, len) < 0)
            return -1;
        memcpy(out->sa, &ss, sizeof ss);
        out->salen = ilen;
        if (len < sizeof(sa_family_t)) {
            snprintf(out->target, sizeof(out->target), "addrlen:%d", ilen);
        } else if (ss.ss_family == AF_INET) {
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
            size_t pl = len > offsetof(struct sockaddr_un, sun_path)
                      ? len - offsetof(struct sockaddr_un, sun_path) : 0;
            if (pl == 0)
                snprintf(out->target, sizeof(out->target), "unix:<unnamed>");
            else if (sun->sun_path[0] == '\0')
                snprintf(out->target, sizeof(out->target), "unix:<abstract>");
            else
                snprintf(out->target, sizeof(out->target), "unix:%.*s",
                         (int)strnlen(sun->sun_path, pl), sun->sun_path);
            out->connect_family = AF_UNIX;
        } else {
            snprintf(out->target, sizeof(out->target), "family:%u",
                     (unsigned)ss.ss_family);
            out->connect_family = ss.ss_family;
        }
        return 0;
    }
    if (nr == __NR_bind) {
        /* v1.21: the address is copied once; net_bind decides and binds. */
        out->kind = ACT_NET_BIND;
        out->sock_fd = (int)req->data.args[0];
        int ilen = (int)req->data.args[2];
        if (ilen < 0 || (size_t)ilen > sizeof(struct sockaddr_storage)) {
            out->salen_bad = true;
            snprintf(out->target, sizeof(out->target), "addrlen:%d", ilen);
            return 0;
        }
        if (ilen > 0 && xproc_read_bytes(req->pid, req->data.args[1], out->sa, (size_t)ilen) < 0)
            return -1;
        out->salen = ilen;
        sa_family_t fam = 0;
        if (ilen >= (int)sizeof fam) memcpy(&fam, out->sa, sizeof fam);
        if (fam == AF_INET && (size_t)ilen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in in;
            memcpy(&in, out->sa, sizeof in);
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &in.sin_addr, ip, sizeof ip);
            snprintf(out->target, sizeof(out->target), "%s:%u", ip, ntohs(in.sin_port));
        } else if (fam == AF_INET6 && ilen >= 24) {
            struct sockaddr_in6 in6;
            memset(&in6, 0, sizeof in6);
            memcpy(&in6, out->sa, (size_t)ilen < sizeof in6 ? (size_t)ilen : sizeof in6);
            char ip[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, &in6.sin6_addr, ip, sizeof ip);
            snprintf(out->target, sizeof(out->target), "[%s]:%u", ip, ntohs(in6.sin6_port));
        } else {
            snprintf(out->target, sizeof(out->target), "family:%u", (unsigned)fam);
        }
        return 0;
    }
    if (nr == __NR_sendmmsg) {
        /* v1.21: relayed like sendmsg, one message at a time (net_send_relay). */
        out->kind = ACT_NET_SEND;
        out->send_nr = nr;
        out->sock_fd = (int)req->data.args[0];
        out->msg_addr = req->data.args[1];
        out->mmsg_vlen = (unsigned)req->data.args[2];
        out->send_flags = req->data.args[3];
        snprintf(out->target, sizeof(out->target), "<sendmmsg>");
        return 0;
    }
    if (nr == __NR_sendto || nr == __NR_sendmsg) {
        /* v1.12: extract the destination sockaddr, if any, for the record. sendto
         * passes dest_addr in arg4 / addrlen in arg5; sendmsg carries msg_name /
         * msg_namelen inside the struct msghdr in arg1. v1.21: a sendto reaches
         * here only if it names a destination or sets MSG_FASTOPEN (the filter
         * admits the rest) and is refused; a sendmsg with no destination and no
         * control data is relayed by net_send_relay, and any other send is
         * refused below. */
        out->kind = ACT_NET_SEND;
        out->send_nr = nr;
        out->sock_fd = (int)req->data.args[0];
        out->send_flags = nr == __NR_sendto ? req->data.args[3] : req->data.args[2];
        out->msg_addr = req->data.args[1];
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
                /* v1.25: the copy a send to the stub is made with */
                memcpy(out->sa, &ss, l);
                out->salen = (int)l;
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
    /* v1.17.0: metadata and link lookups. Through v1.16.3 these were admitted
     * outright and never logged, so an agent could learn that any file
     * existed, its size and owner, and read where any link (including the
     * Warden's own /proc/<pid>/fd entries) pointed, with no record. They are
     * now decided like a read-only open of the same object. */
    if (nr == __NR_newfstatat || nr == __NR_statx || nr == __NR_access ||
        nr == __NR_faccessat || nr == __NR_faccessat2 ||
        nr == __NR_readlink || nr == __NR_readlinkat) {
        uint64_t pathaddr = 0;
        int dfd = VAREK_AT_FDCWD;
        out->meta_nr = nr;
        switch (nr) {
            case __NR_newfstatat:
                out->kind = ACT_FILE_STAT;
                dfd = (int)req->data.args[0]; pathaddr = req->data.args[1];
                out->out_addr = req->data.args[2]; out->at_flags = (int)req->data.args[3];
                break;
            case __NR_statx:
                out->kind = ACT_FILE_STAT;
                dfd = (int)req->data.args[0]; pathaddr = req->data.args[1];
                out->at_flags = (int)req->data.args[2];
                out->statx_mask = (unsigned)req->data.args[3];
                out->out_addr = req->data.args[4];
                break;
            case __NR_access:
                out->kind = ACT_FILE_ACCESS;
                pathaddr = req->data.args[0]; out->access_mode = (int)req->data.args[1];
                break;
            case __NR_faccessat:
                out->kind = ACT_FILE_ACCESS;
                dfd = (int)req->data.args[0]; pathaddr = req->data.args[1];
                out->access_mode = (int)req->data.args[2];
                break;
            case __NR_faccessat2:
                out->kind = ACT_FILE_ACCESS;
                dfd = (int)req->data.args[0]; pathaddr = req->data.args[1];
                out->access_mode = (int)req->data.args[2];
                out->at_flags = (int)req->data.args[3];
                break;
            case __NR_readlink:
                out->kind = ACT_FILE_READLINK;
                pathaddr = req->data.args[0];
                out->out_addr = req->data.args[1]; out->out_len = req->data.args[2];
                break;
            default: /* __NR_readlinkat */
                out->kind = ACT_FILE_READLINK;
                dfd = (int)req->data.args[0]; pathaddr = req->data.args[1];
                out->out_addr = req->data.args[2]; out->out_len = req->data.args[3];
                break;
        }
        out->open_dirfd = dfd;
        out->bad_flags =
            (nr == __NR_newfstatat &&
             (out->at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH))) ||
            (nr == __NR_statx &&
             ((out->at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
                                 AT_STATX_SYNC_TYPE)) ||
              (out->at_flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE ||
              (out->statx_mask & STATX__RESERVED))) ||
            (nr == __NR_faccessat2 &&
             (out->at_flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))) ||
            (out->kind == ACT_FILE_ACCESS && (out->access_mode & ~(F_OK | R_OK | W_OK | X_OK)));
        if (pathaddr == 0) {
            out->path_null = true;
            out->target[0] = '\0';
        } else if (xproc_read_str(req->pid, pathaddr, out->target, sizeof(out->target)) < 0) {
            return -1;
        }
        /* Decided as the open that would reveal the same thing: a read, or
         * for access(W_OK) a write. */
        int m = out->access_mode & (R_OK | W_OK);
        out->open_flags = out->kind == ACT_FILE_ACCESS && m == W_OK ? O_WRONLY
                        : out->kind == ACT_FILE_ACCESS && m == (R_OK | W_OK) ? O_RDWR
                        : O_RDONLY;
        out->flags_known = true;
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
        case ACT_FILE_STAT:
        case ACT_FILE_ACCESS:
        case ACT_FILE_READLINK:
            kind = VDP_KIND_PATH;
            s = a->resolved;
            if (s[0] == '\0') { a->why = "no_resolved_path"; return DEC_UNKNOWN; }
            break;
        case ACT_NET_CONNECT:
        case ACT_NET_PROXY:              /* v1.26: the name:port the proxy read */
            /* v1.21: decided on the destination the Warden will dial, in its
             * canonical spelling (net_decision_string), never the agent's. */
            kind = VDP_KIND_HOST;
            s = a->resolved;
            if (s[0] == '\0') { a->why = "no_resolved_destination"; return DEC_UNKNOWN; }
            break;
        case ACT_PROCESS_EXEC: kind = VDP_KIND_EXEC; s = a->target; break;
        default:
            a->why = "not_in_fragment";
            return DEC_UNKNOWN;
    }
    int ri;
    vdp_why_t why;
    vdp_verdict_t v = vdp_decide(&p->v, kind, s, (uint32_t)a->open_flags,
                                 kind == VDP_KIND_PATH && a->flags_known,
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
        case ACT_FILE_OPEN:
        case ACT_FILE_STAT:
        case ACT_FILE_ACCESS:
        case ACT_FILE_READLINK: kind = VDPC_PATH; s = a->resolved; break;
        case ACT_NET_CONNECT:  kind = VDPC_HOST; s = a->resolved; break;   /* v1.21 */
        case ACT_NET_PROXY:    kind = VDPC_HOST; s = a->resolved; break;   /* v1.26 */
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
    bool has_flags = kind != VDPC_PATH || a->flags_known;
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
    /* v1.24: a connect decided over several candidates (the address and the
     * names it belongs to): the checker also confirms, with its own matchers,
     * that no earlier host rule holds on any other candidate. */
    if (a->kind == ACT_NET_CONNECT && a->ncand > 1) {
        for (int c = 0; c < a->ncand; c++) {
            if (!strcmp(g_cand[c], s)) continue;
            for (int i = 0; i < cc.r; i++) {
                vdpc_rule_info_t ri;
                if (vdpc_rule_info(&p->c, (size_t)i, &ri) < 0 || ri.kind != VDPC_HOST) continue;
                if (vdpc_holds(&p->c, (size_t)i, g_cand[c], strlen(g_cand[c])) == 1) {
                    snprintf(a->check_why, sizeof a->check_why,
                             "an earlier rule (line %d) holds on another candidate", ri.line);
                    return false;
                }
            }
        }
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
    /* v1.21.1: the parsed plan, so the node check can read a step's `open`
     * field (NULL: no fields). */
    const plan_parsed_t *parsed;
    const plan_spec_t   *spec;
};

/* v1.21.1: how a file_open step says it will open its file.
 *
 * A plan step has no open flags of its own, so through v1.21.0 the node check
 * decided a file_open step with the flags unknown, and a path allowed only by
 * a rule with a flag clause (`readonly`, `access=ro`, `-O_TRUNC`, ...) was
 * UNKNOWN at the gate although the runtime allowed the same open. A step may
 * now declare its flags in an `open` field:
 *
 *   open=read                      O_RDONLY, nothing else (what `readonly` allows)
 *   open=O_WRONLY|O_CREAT|O_TRUNC  an access mode (O_RDONLY, O_WRONLY or O_RDWR)
 *                                  first, then any of the flags below, each once
 *
 * A name has the value an agent's open() passes for it: O_SYNC and O_TMPFILE
 * are glibc's composites (O_SYNC includes O_DSYNC, O_TMPFILE includes
 * O_DIRECTORY), and O_LARGEFILE is the kernel's bit, which is also what the
 * name means in a policy's flag clauses.
 *
 * The step is then decided and certified with exactly those flags, as the
 * runtime decides an open with the flags the agent passes. Nothing binds the
 * agent's later opens to them (as with every declaration in a plan): an open
 * with other flags is decided on its own flags at run time. A value that is
 * not one of these forms, an `open` field on another kind of step, or a
 * repeated flag makes the step UNKNOWN, with the reason logged.
 * Returns 1 and sets *flags for a valid field, 0 when the step has no `open`
 * field, -1 (with why) when the field is present but not understood. */
static const struct { const char *name; int bits; } kPlanOpenFlags[] = {
    { "O_CREAT", O_CREAT },       { "O_EXCL", O_EXCL },           { "O_NOCTTY", O_NOCTTY },
    { "O_TRUNC", O_TRUNC },       { "O_APPEND", O_APPEND },       { "O_NONBLOCK", O_NONBLOCK },
    { "O_DSYNC", O_DSYNC },       { "O_ASYNC", O_ASYNC },         { "O_DIRECT", O_DIRECT },
    /* The kernel's bit, as the policy language names it (smt_decide.c
     * K_O_LARGEFILE): glibc defines O_LARGEFILE as 0 on x86_64, which would
     * make a declared O_LARGEFILE mean no flag at all. */
    { "O_LARGEFILE", 0100000 },   { "O_DIRECTORY", O_DIRECTORY }, { "O_NOFOLLOW", O_NOFOLLOW },
    { "O_NOATIME", O_NOATIME },   { "O_CLOEXEC", O_CLOEXEC },     { "O_SYNC", O_SYNC },
    { "O_PATH", O_PATH },         { "O_TMPFILE", O_TMPFILE },
};

static int plan_open_field(const struct warden_plan_ud *u, const plan_spec_action_t *a,
                           int *flags, char *why, size_t wn) {
    if (!u->parsed || !u->spec || a < u->spec->actions ||
        a >= u->spec->actions + u->spec->n_actions)
        return 0;
    size_t nf = 0;
    const plan_spec_field_t *fl = plan_parser_fields(u->parsed, (size_t)(a - u->spec->actions), &nf);
    const char *v = NULL;
    for (size_t k = 0; k < nf; k++)
        if (fl[k].key && !strcmp(fl[k].key, "open")) { v = fl[k].value ? fl[k].value : ""; break; }
    if (!v) return 0;
    if (!a->kind || strcmp(a->kind, "file_open")) {
        snprintf(why, wn, "an open field is only for a file_open step");
        return -1;
    }
    if (!strcmp(v, "read")) { *flags = O_RDONLY; return 1; }
    char buf[512];
    if (strlen(v) >= sizeof buf) { snprintf(why, wn, "the open field is too long"); return -1; }
    snprintf(buf, sizeof buf, "%s", v);
    int f = 0, seen = 0, first = 1;
    char *save = NULL;
    for (char *t = strtok_r(buf, "|", &save); t; t = strtok_r(NULL, "|", &save), first = 0) {
        if (first) {
            if      (!strcmp(t, "O_RDONLY")) f = O_RDONLY;
            else if (!strcmp(t, "O_WRONLY")) f = O_WRONLY;
            else if (!strcmp(t, "O_RDWR"))   f = O_RDWR;
            else {
                snprintf(why, wn, "the open field must be read, or begin with O_RDONLY, O_WRONLY or O_RDWR");
                return -1;
            }
            continue;
        }
        size_t i = 0, nn = sizeof kPlanOpenFlags / sizeof kPlanOpenFlags[0];
        while (i < nn && strcmp(t, kPlanOpenFlags[i].name)) i++;
        if (i == nn) { snprintf(why, wn, "the open field names an unknown flag"); return -1; }
        if (seen & (1 << i)) { snprintf(why, wn, "the open field repeats a flag"); return -1; }
        seen |= 1 << i;
        f |= kPlanOpenFlags[i].bits;
    }
    /* An empty value, or `|` at either end or doubled, leaves a token out:
     * refuse rather than guess what was meant. */
    if (first || v[0] == '|' || v[strlen(v) - 1] == '|' || strstr(v, "||")) {
        snprintf(why, wn, "the open field is empty or malformed");
        return -1;
    }
    *flags = f;
    return 1;
}

/* v1.21 (warden_net.inc.c): a net_connect step's destination as the runtime
 * spells it. */
static int net_plan_canon(const char *in, char *out, size_t n, char *why, size_t wn);

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
    /* v1.20.0: a target that does not fit is UNKNOWN, never cut short and
     * decided as the shorter path it would become. */
    if (a->target && strlen(a->target) >= sizeof(act.target)) return PLAN_DEC_UNKNOWN;
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
    /* v1.21.1: the flags the step declares it will open with (see
     * plan_open_field). */
    {
        char why[160];
        int of = 0, r = plan_open_field(u, a, &of, why, sizeof why);
        if (r < 0) {
            log_line_start();
            fputs("[warden] plan: ", g_log);
            json_escape(g_log, a->kind ? a->kind : "");     /* the plan's own text */
            fputs(" step \"", g_log);
            json_escape(g_log, act.target);
            fprintf(g_log, "\" is UNKNOWN: %s\n", why);
            fflush(g_log);
            return PLAN_DEC_UNKNOWN;
        }
        if (r > 0) { act.open_flags = of; act.flags_known = true; }
    }
    /* v1.18.0: the runtime refuses every launch after the first, whatever
     * the policy says, so a process_exec step is UNSATISFIED (a plan lists
     * what the agent does after it starts, so every such step is a later
     * launch). v1.21: connects are decided at runtime, so a net_connect step
     * is decided by the policy on the destination the runtime would decide
     * on (net_plan_canon); through v1.20.0 it was always UNSATISFIED. */
    if (act.kind == ACT_PROCESS_EXEC) {
        log_line_start();
        fprintf(g_log, "[warden] plan: %s step \"", a->kind);
        json_escape(g_log, act.target);
        fprintf(g_log, "\" is UNSATISFIED: the Warden refuses every launch after the first "
                "at runtime, whatever the policy says\n");
        fflush(g_log);
        return PLAN_DEC_UNSATISFIED;
    }
    if (act.kind == ACT_NET_CONNECT) {
        char why[200];
        if (net_plan_canon(act.target, act.resolved, sizeof act.resolved, why, sizeof why) < 0) {
            log_line_start();
            fputs("[warden] plan: net_connect step \"", g_log);
            json_escape(g_log, act.target);
            fprintf(g_log, "\" is UNKNOWN: %s\n", why);
            fflush(g_log);
            return PLAN_DEC_UNKNOWN;
        }
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
    struct warden_plan_ud ud = { .policy = policy, .parsed = parsed, .spec = spec };

    plan_decision_t pd = warden_adapter_verify(spec, warden_plan_decider,
                                               &ud, sink);

    /* v1.21.1: read the count before the plan is freed (spec points into it;
     * through v1.21.0 it was read after plan_parser_free). */
    size_t n_actions = spec->n_actions;
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
            n_actions);
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
static wr_table_t g_names;           /* v1.24: the resolution table (see names_setup) */
static bool       g_names_on = false;
static bool       g_any_name = false;  /* v1.24: the policy has a host name rule (allow or deny) */
static bool       g_any_wild = false;  /* v1.25: the policy has a wildcard allow rule (warden_stub.inc.c) */
static void       stub_resolved(size_t i);
static void       px_resolved(size_t i);  /* v1.26: proxied requests waiting on a lookup */
static bool       px_up_charged(const char *name);  /* v1.26 review: sent to the upstream, charged */
static void       px_handed_off(uint64_t id, unsigned port);  /* v1.26 review: a hand-off announced */
static bool       g_stub_on;           /* v1.25: the stub resolver is up (warden_stub.inc.c) */
/* v1.25 (section 4): a wildcard allow rule's budgets when it sets none */
#define STUB_DEFAULT_NAMES 256           /* distinct new names per run */
#define STUB_DEFAULT_RATE  30            /* distinct new names per minute */
#define STUB_LABEL_MAX     63            /* bytes matched by `*` */
static char       g_psl_sha[65], g_shared_sha[65];  /* v1.25: the lists wildcards were checked against */
static wp_t       g_proxy = { .ctl = -1 };          /* v1.26: the egress proxy, when `proxy on` */
static char       g_proxy_sha[65];                  /* v1.26.1: the SHA-256 of the warden-proxy that ran */
static bool       g_syn_on = false;    /* v1.26: `proxy on`: synthetic addresses (warden_synth.inc.c) */
static const struct policy *g_syn_p;   /* v1.26: the policy, for the hosts view */
/* v1.26: the stub runs with a wildcard allow rule (v1.25), or with the proxy
 * on and any host name rule (synthetic addresses) */
#define STUB_WANTED() (g_any_wild || (g_syn_on && g_names_on))
static uint64_t   g_proxy_conns = 0;   /* v1.26: connections handed to the proxy (proxy_conn ids) */
static int        g_up_entry = -1;     /* v1.26 section 5: the upstream proxy's name in g_names, or -1 */
static wr_ip_t    g_up_ip;             /* v1.26 section 5: the upstream given as an address */
#define SYN_BASE   0xc6120000u           /* 198.18.0.0 */
#define SYN_MAX    131070u               /* synthetic addresses: 198.18.0.1 .. 198.19.255.254 */
#define SYN_TTL    300u                  /* seconds, in answers (the address never changes) */
static bool       g_lists_pinned;                   /* v1.25 review: they are the release's */
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
static unsigned char *g_sk;                /* sodium_malloc: guarded, locked, not dumped */
static int           g_anchor_fd = -1;
static bool          g_anchor_fifo = false;  /* v1.16.2: held read-write; drained at exit */
static char          g_anchor_lock[PATH_MAX + 8];  /* v1.16.2: the forwarder's liveness lock */
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
    fprintf(f, "{\"event\":\"run_start\",\"run\":\"%s\",\"warden\":\"1.26.0\","
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
        fprintf(f, "\"log_pubkey\":\"%s\",", pk_hex);
    }
    if (checkpoints_on())
        fprintf(f, "\"checkpoint_every\":%" PRIu64 ",", g_ckpt_every);
    if (g_anchor_fd >= 0) fputs("\"anchored\":true,", f);
    /* v1.24: the names the Warden resolves (each gets a resolution record). */
    if (g_any_name) fputs("\"host_name_rules\":true,", f);
    /* v1.25: the lists the policy's wildcards were checked against */
    if (g_psl_sha[0]) fprintf(f, "\"psl_sha256\":\"%s\",\"shared_domains_sha256\":\"%s\","
                              "\"shared_lists_pinned\":%s,",
                              g_psl_sha, g_shared_sha, g_lists_pinned ? "true" : "false");
    if (g_names_on) fprintf(f, "\"host_names\":%zu,\"resolver\":\"%s\",", g_names.n, g_names.resolver);
    /* v1.25: where the agent's questions go (connects and sends to it are
     * records with rule dns_stub) */
    if (STUB_WANTED()) fputs("\"dns_stub\":\"127.53.53.53:53\",", f);
    /* v1.26: the egress proxy: its listener, its user, the proxied ports */
    if (g_proxy.ctl >= 0) {
        fprintf(f, "\"proxy\":{\"mode\":\"sni\",\"listen\":\"127.0.0.1:%u\",\"uid\":%u,\"gid\":%u,\"pid\":%d,\"ports\":[",
                g_proxy.port, (unsigned)g_proxy.uid, (unsigned)g_proxy.gid, (int)g_proxy.pid);
        if (p->v.proxy_nports)
            for (size_t k = 0; k < p->v.proxy_nports; k++)
                fprintf(f, "%s%u", k ? "," : "", p->v.proxy_ports[k]);
        else fputs("80,443", f);
        fputs("]", f);
        if (p->v.proxy_up_port)                  /* section 5 */
            fprintf(f, ",\"upstream\":\"%s:%u\"", p->v.proxy_up_host, p->v.proxy_up_port);
        fputs("},", f);
        /* v1.26.1: the SHA-256 of the warden-proxy binary that runs (the
         * sealed copy it was started from) */
        fprintf(f, "\"proxy_binary_sha256\":\"%s\",", g_proxy_sha);
    }
    /* v1.25 (section 4): each wildcard allow rule's budgets, defaults filled in */
    if (g_any_wild) {
        fputs("\"wildcard_budgets\":[", f);
        bool first = true;
        for (size_t i = 0; i < p->v.n; i++) {
            const vdp_rule_t *r = &p->v.rules[i];
            if (r->kind != VDP_KIND_HOST || !r->s.wild || r->verb != VDP_ALLOW) continue;
            fprintf(f, "%s{\"policy_line\":%d,\"names\":%u,\"rate\":%u,\"label\":%u}", first ? "" : ",",
                    r->line, r->names ? r->names : STUB_DEFAULT_NAMES,
                    r->rate ? r->rate : STUB_DEFAULT_RATE, STUB_LABEL_MAX);
            first = false;
        }
        fputs("],", f);
    }
    fprintf(f, "\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end("run_start");
}

/* ---- v1.24: host names (docs/security/v1.21-stage2-host-names.md) ----
 * The Warden resolves every name an allow rule names, itself, and keeps what
 * each resolved to (warden_resolve.c). Every result is a chained record. */
/* Build the table from the policy's allow name rules. 0, or -1. */
static int names_setup(const struct policy *p, const wr_config_t *cfg) {
    char why[160];
    if (wr_table_init(&g_names, cfg, why, sizeof why) < 0) {
        fprintf(stderr, "[warden] %s\n", why);
        return -1;
    }
    /* Allow rules' names first (listed in the hosts view), then deny rules'
     * names not already there (v1.24 review): resolved too, so a deny on a
     * name holds on its addresses even when no allow rule names it, but kept
     * out of the hosts view. v1.25: a wildcard names no host to resolve in
     * advance (an allow wildcard's names come from the stub). */
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < p->v.n; i++) {
            const vdp_rule_t *r = &p->v.rules[i];
            if (r->kind == VDP_KIND_HOST && r->s.name) g_any_name = true;
            if (r->kind == VDP_KIND_HOST && r->s.wild && r->verb == VDP_ALLOW) g_any_wild = true;
            if (r->kind != VDP_KIND_HOST || !r->s.name || r->s.wild) continue;
            if (r->verb != (pass == 0 ? VDP_ALLOW : VDP_DENY)) continue;
            char name[WR_NAME_MAX + 1];
            const char *colon = memchr(r->s.c, ':', r->s.len);
            size_t nl = colon ? (size_t)(colon - r->s.c) : r->s.len;
            if (nl > WR_NAME_MAX) return -1;            /* both parsers refuse it */
            memcpy(name, r->s.c, nl);
            name[nl] = '\0';
            size_t before = g_names.n;
            int ix = wr_table_add(&g_names, name);
            if (ix < 0) {
                fprintf(stderr, "[warden] out of memory for the resolution table\n");
                return -1;
            }
            if (pass == 1 && g_names.n > before) g_names.e[ix].unlisted = true;
        }
    }
    /* v1.26 section 5: the upstream proxy's name is resolved and refreshed
     * like a deny rule's (unlisted: never in the agent's views); an address
     * is dialed as it is. */
    if (p->v.proxy_up_port) {
        if (wr_ip_parse(p->v.proxy_up_host, &g_up_ip) == 0) g_up_entry = -1;
        else {
            size_t before = g_names.n;
            g_up_entry = wr_table_add(&g_names, p->v.proxy_up_host);
            if (g_up_entry < 0) {
                fprintf(stderr, "[warden] out of memory for the resolution table\n");
                return -1;
            }
            if (g_names.n > before) g_names.e[g_up_entry].unlisted = true;
        }
    }
    /* v1.25: a wildcard adds names when the agent asks (the stub) */
    g_names_on = g_names.n > 0 || g_any_wild;
    g_syn_on = p->v.proxy;               /* v1.26 */
    g_syn_p = p;
    return 0;
}

/* v1.25: an allow wildcard over a shared domain (a public suffix, an entry of
 * the Public Suffix List's private section, or the VAREK list) is refused at
 * load: anyone could register a name under it. The lists are pinned files
 * (data/); their SHA-256 goes in run_start. 0, or -1 (the Warden does not
 * start). */
static int sha256_file_hex(const char *path, char out[65]) {
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) crypto_hash_sha256_update(&st, buf, n);
    int bad = ferror(f);
    fclose(f);
    if (bad) return -1;
    unsigned char h[32];
    crypto_hash_sha256_final(&st, h);
    sodium_bin2hex(out, 65, h, sizeof h);
    return 0;
}

static int wildcards_check(const char *path, const struct policy *p, const char *psl_arg,
                           const char *shared_arg) {
    bool any = false;
    for (size_t i = 0; i < p->v.n; i++)
        if (p->v.rules[i].kind == VDP_KIND_HOST && p->v.rules[i].s.wild) any = true;
    if (!any) return 0;
    char psl[PATH_MAX], var[PATH_MAX], why[512];
    if (psl_arg) snprintf(psl, sizeof psl, "%s", psl_arg);
    else if (sd_default_path("public_suffix_list.dat", psl, sizeof psl) < 0) {
        fprintf(stderr, "[warden] the policy has wildcard host rules, and the Public Suffix List "
                "(data/public_suffix_list.dat) was not found; give --psl\n");
        return -1;
    }
    if (shared_arg) snprintf(var, sizeof var, "%s", shared_arg);
    else if (sd_default_path("varek_shared_domains.txt", var, sizeof var) < 0) {
        fprintf(stderr, "[warden] the policy has wildcard host rules, and the VAREK list of shared "
                "domains (data/varek_shared_domains.txt) was not found; give --shared-domains\n");
        return -1;
    }
    /* v1.25 review: the lists in data/ must be the ones this release ships;
     * lists named with --psl or --shared-domains may differ, which run_start
     * records (shared_lists_pinned). */
    if (sha256_file_hex(psl, g_psl_sha) < 0 || sha256_file_hex(var, g_shared_sha) < 0) {
        fprintf(stderr, "[warden] cannot read %s; refusing to start\n", g_psl_sha[0] ? var : psl);
        return -1;
    }
    bool psl_ok = !strcmp(g_psl_sha, SD_PSL_SHA256), var_ok = !strcmp(g_shared_sha, SD_VAREK_SHA256);
    if ((!psl_arg && !psl_ok) || (!shared_arg && !var_ok)) {
        const char *which = !psl_arg && !psl_ok ? psl : var;
        fprintf(stderr, "[warden] %s is not the list this release ships (SHA-256 %s); reinstall it, "
                "or name a list with %s; refusing to start\n", which,
                which == psl ? g_psl_sha : g_shared_sha, which == psl ? "--psl" : "--shared-domains");
        return -1;
    }
    g_lists_pinned = psl_ok && var_ok;
    if (!g_lists_pinned)
        fprintf(stderr, "[warden] the shared-domain lists named on the command line are not the ones "
                "this release ships; run_start records it (shared_lists_pinned false)\n");
    sd_lists_t *l = sd_load(psl, var, why, sizeof why);
    if (!l) { fprintf(stderr, "[warden] %s; refusing to start\n", why); return -1; }
    int refused = 0;
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        char suf[512];
        if (r->kind != VDP_KIND_HOST || !r->s.wild || r->verb != VDP_ALLOW) continue;
        if (sd_wildcard_suffix(r->s.c, suf, sizeof suf) == 0 && sd_refuses(l, suf, why, sizeof why)) {
            fprintf(stderr, "[warden] policy %s:%d: allow host *.%s is refused: %s; write the exact "
                    "names instead\n", path, r->line, suf, why);
            refused++;
        }
    }
    sd_free(l);
    if (refused) return -1;
    return 0;
}

static void emit_resolution(void *ctx, size_t i, const wr_result_t *r) {
    (void)ctx;
    FILE *f = rec_begin();
    wr_format_record(f, g_run_id, &g_names, i, r, wr_now_ms());
    rec_end(NULL);
    stub_resolved(i);                   /* v1.25: answer the agent's waiting questions */
    px_resolved(i);                     /* v1.26: and dial the proxy's waiting requests */
}

/* v1.25: a dynamic entry's TTL passed with no new question; its addresses
 * went into grace. A resolution record says so ("a" and "aaaa": "retired"),
 * so the audit sees the addresses leave as the Warden's table did. */
/* v1.25 review: an entry whose grace ended, written before the connect
 * decided at that time */
static void emit_grace_end(void *ctx, size_t i) {
    wr_result_t r;
    memset(&r, 0, sizeof r);
    r.st[0] = r.st[1] = WR_ST_GRACE_END;
    int64_t now = *(const int64_t *)ctx;
    FILE *f = rec_begin();
    wr_format_record(f, g_run_id, &g_names, i, &r, now);
    rec_end(NULL);
}

static void emit_retired(void *ctx, size_t i) {
    (void)ctx;
    wr_result_t r;
    memset(&r, 0, sizeof r);
    r.st[0] = r.st[1] = WR_ST_RETIRED;
    FILE *f = rec_begin();
    wr_format_record(f, g_run_id, &g_names, i, &r, wr_now_ms());
    rec_end(NULL);
}

/* Resolve every name before the agent runs. A name that does not resolve is
 * reported and retried; it does not stop the Warden. With record false (the
 * startup checks) nothing is written to the verdict stream. */
static void names_resolve_all(bool record) {
    for (size_t i = 0; i < g_names.n; i++) {
        wr_result_t r;
        /* v1.24 review: through the resolver helper, so the Warden (which
         * holds the signing key) never parses network data, at startup too */
        if (wr_async_lookup(&g_names, i, &r) < 0) {
            memset(&r, 0, sizeof r);
            r.st[0] = r.st[1] = WR_ST_FAIL;
        }
        wr_apply(&g_names, i, &r, wr_now_ms());
        if (record) emit_resolution(NULL, i, &r);
        size_t cur = 0;
        for (size_t k = 0; k < g_names.e[i].n; k++) if (g_names.e[i].addrs[k].until_ms == 0) cur++;
        if (cur == 0)
            fprintf(stderr, "[warden] host name %s did not resolve (A %s, AAAA %s); the agent "
                    "cannot reach it until it does; retrying every %u s\n", g_names.e[i].name,
                    r.st[0] == WR_ST_NXDOMAIN ? "nxdomain" : r.st[0] == WR_ST_NODATA ? "nodata" : "failed",
                    r.st[1] == WR_ST_NXDOMAIN ? "nxdomain" : r.st[1] == WR_ST_NODATA ? "nodata" : "failed",
                    g_names.cfg.ttl_min);
        else if (!record)
            fprintf(stderr, "[warden] host name %s resolves to %zu address%s\n",
                    g_names.e[i].name, cur, cur == 1 ? "" : "es");
    }
}

/* v1.25 review: a lookup on demand still out when the run ends is recorded
 * as unanswered, so the audit can require an answer for every lookup sent
 * upstream (a deleted answer is then missing, not merely late). */
static void emit_unanswered(void) {
    if (!g_names_on) return;
    for (size_t i = 0; i < g_names.n; i++) {
        if (!g_names.e[i].pending || !g_names.e[i].dynamic) continue;
        wr_result_t r;
        memset(&r, 0, sizeof r);
        r.st[0] = r.st[1] = WR_ST_UNANSWERED;
        FILE *f = rec_begin();
        wr_format_record(f, g_run_id, &g_names, i, &r, wr_now_ms());
        rec_end(NULL);
    }
}

static void px_finish(void);           /* v1.26 step 7 (warden_pxdecide.inc.c) */
static void emit_run_end(int exit_status) {
    px_finish();                        /* v1.26: every relay's proxy_close */
    emit_unanswered();
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

/* v1.18.0: the name of an errno the Warden answers a refused call with, for
 * the record's kernel_verdict. Every refusal path sends EACCES today; the
 * others are listed so a future path cannot be mislabeled silently. */
static const char *errno_label(int e) {
    switch (e) {
        case EACCES:       return "EACCES";
        case EPERM:        return "EPERM";
        case ENOENT:       return "ENOENT";
        case EINVAL:       return "EINVAL";
        case ENOSYS:       return "ENOSYS";
        case ENOTDIR:      return "ENOTDIR";
        case ELOOP:        return "ELOOP";
        case ENAMETOOLONG: return "ENAMETOOLONG";
        case EFAULT:       return "EFAULT";
        case EAFNOSUPPORT: return "EAFNOSUPPORT";   /* v1.21 */
        case ENOTSOCK:     return "ENOTSOCK";
        case EBADF:        return "EBADF";
        case EMSGSIZE:     return "EMSGSIZE";
        case ENOBUFS:      return "ENOBUFS";
        default:           return "ERRNO";
    }
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
    char flags_json[40] = "";
    if ((a->kind == ACT_FILE_OPEN || is_meta_kind(a->kind)) && a->flags_known)
        snprintf(flags_json, sizeof flags_json, "0x%x", (unsigned)a->open_flags);
    /* v1.17.0: what an access() asked, so an audit can tell F_OK/R_OK from
     * W_OK/X_OK. */
    if (a->kind == ACT_FILE_ACCESS && flags_json[0])
        snprintf(flags_json + strlen(flags_json), sizeof flags_json - strlen(flags_json),
                 "\",\"access_mode\":\"%d", a->access_mode & 7);
    /* v1.21: a connect's socket kind and how long the dial took, so the
     * Warden's own cost (latency_us minus dial_us) can be read per record. */
    char net_json[64] = "";
    if (a->kind == ACT_NET_CONNECT && a->sock_name)
        snprintf(net_json, sizeof net_json, "\"sock\":\"%s\",\"dial_us\":%" PRIu64 ",",
                 a->sock_name, (uint64_t)(a->dial_ns / 1000ULL));
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
        "%s%s"
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
        net_json, a->extra,
        /* v1.12.1: an ALLOW whose open then failed (EEXIST, ENXIO, ...)
         * delivered nothing; say so rather than reporting ALLOW.
         * v1.18.0: a refusal names the errno the agent actually received
         * (EACCES). Through v1.17.0 it said "EPERM", which the Warden never
         * sends for a mediated call. */
        /* v1.21: a connect handed over still in progress (EINPROGRESS, as the
         * agent's own non-blocking connect would say) was allowed and made. */
        d_final == DEC_ALLOW ? ((kernel_errno && !(a->kind == ACT_NET_CONNECT &&
                                                   kernel_errno == EINPROGRESS))
                                ? "ERRNO" : "ALLOW")
                             : errno_label(kernel_errno ? kernel_errno : EACCES),
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
 *   RESOLVE_NO_MAGICLINKS — the kernel's magic links (/proc/<pid>/fd/N, cwd,
 *                           exe, root, ns/, map_files/) do not resolve.
 *   /proc/self — an ordinary symlink (not a magic link: RESOLVE_NO_MAGICLINKS
 *                follows it), but resolved by the SUPERVISOR it names the
 *                supervisor's own process. So (v1.12.3) a leading /proc/self or
 *                /proc/thread-self in the agent's path is rewritten to the
 *                agent's own /proc/<tgid> before resolution; without that, the
 *                check below would refuse every /proc/self path, since it would
 *                reach the supervisor's /proc/<pid>. After resolution any object
 *                on a procfs mount must lie under /proc/<the agent's tgid>/ or be
 *                a non-process /proc entry; a numeric /proc/<pid> that is not the
 *                agent's (the supervisor's own, or another process's) fails
 *                closed. That check, check_proc_object(), is what refuses a
 *                planted symlink pointing at /proc/self/mem: it resolves to the
 *                supervisor's /proc/<pid>/mem and is refused there. (v1.21
 *                correction: through v1.20 this comment credited
 *                RESOLVE_NO_MAGICLINKS with that refusal.) An object under the
 *                agent's own /proc/<tgid>/ is decided and recorded as
 *                /proc/self/..., which is how policies name it.
 *   RESOLVE_BENEATH is deliberately NOT set: allow rules legitimately name
 *   absolute paths outside the cwd. `..` is defanged by deciding on the
 *   post-collapse canonical path.
 *   O_NOFOLLOW from the agent is honoured: it is passed to the O_PATH resolve,
 *   which then returns the trailing symlink itself, and a trailing symlink
 *   fails closed (EACCES; a normal open would say ELOOP).
 *
 * dirfd handling: only AT_FDCWD (resolved against /proc/<pid>/cwd) and
 * absolute paths are handled; any other dirfd fails closed. */

/* v1.17.0: objects the agent must never reach, identified by device and
 * inode rather than by path.
 *
 * Through v1.16.3 the Warden refused to START if the policy would let the
 * agent open the signing key, the anchor or the verdict stream by their real
 * path. A second path to the same file defeated that: with the key's
 * directory bind-mounted under an allowed tree, the agent opened
 * /tmp/varek_allowed_x/log.key, the policy said ALLOW, and it read the private
 * key. Any alias the operator or a container runtime creates (bind mount,
 * overlay lower layer, a hard link made after startup) has the same inode, so
 * the runtime check below is made on identity, after resolution, on the object
 * actually pinned, before the policy is consulted. The startup checks stay as
 * an early, clearer error.
 *
 * Raw storage and memory devices are refused the same way, whatever the policy
 * says and whatever path reaches them: block devices; /dev/mem, /dev/kmem,
 * /dev/port (character 1:1, 1:2, 1:4); the character devices that pass
 * commands to a disk (the sg, bsg, nvme and nvme-generic majors, read from
 * /proc/devices at startup); and /proc/kcore. Each reads every file on the
 * machine, the signing key included, below any path rule. */
#define MAX_PROTECTED 16
struct protected_obj { dev_t dev; ino_t ino; const char *what; };
static struct protected_obj g_protected[MAX_PROTECTED];
static int g_nprotected = 0;
static unsigned g_raw_char_majors[16];
static int g_nraw_char_majors = 0;

static void protect_fd(int fd, const char *what) {
    struct stat st;
    if (g_nprotected >= MAX_PROTECTED) {
        /* Cannot happen (at most 8 are registered); never run unprotected. */
        fprintf(stderr, "[warden] internal error: too many protected objects; stopping\n");
        abort();
    }
    if (fstat(fd, &st) == 0) {
        g_protected[g_nprotected].dev = st.st_dev;
        g_protected[g_nprotected].ino = st.st_ino;
        g_protected[g_nprotected].what = what;
        g_nprotected++;
    }
}

static void load_raw_char_majors(void) {
    FILE *f = fopen("/proc/devices", "re");
    if (!f) return;
    char line[128];
    bool chr = false;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "Character devices:", 18)) { chr = true; continue; }
        if (!strncmp(line, "Block devices:", 14)) { chr = false; continue; }
        unsigned major;
        char name[64];
        if (!chr || sscanf(line, "%u %63s", &major, name) != 2) continue;
        if ((!strcmp(name, "sg") || !strcmp(name, "bsg") || !strcmp(name, "nvme") ||
             !strcmp(name, "nvme-generic")) && g_nraw_char_majors < 16)
            g_raw_char_majors[g_nraw_char_majors++] = major;
    }
    fclose(f);
}

/* NULL if the pinned object may be decided by the policy; otherwise the
 * record's rule id for refusing it outright. */
/* v1.18.0: the breaker's state directory. Every file in it (the table, its
 * lock, a table a concurrent Warden renames in later) is refused whatever path
 * reaches it, including a bind mount of the directory into an allowed tree. */
static bool  g_pdir_set;
static dev_t g_pdir_dev;
static ino_t g_pdir_ino;

/* 1: the object is in the state directory; 0: it is not; -1: its directory
 * could not be examined (the caller refuses, as resolution_failed). The
 * directory is found from the canonical path: the agent cannot rename or
 * mount, so it cannot swap it between resolution and this check. */
static int in_protected_dir(const char *canon, int parent_fd) {
    if (!g_pdir_set) return 0;
    struct stat ds;
    if (parent_fd >= 0) {
        if (fstat(parent_fd, &ds) < 0) return -1;
    } else {
        char dir[PATH_MAX];
        const char *slash = canon ? strrchr(canon, '/') : NULL;
        if (!slash) return -1;
        size_t n = slash == canon ? 1 : (size_t)(slash - canon);
        if (n >= sizeof dir) return -1;
        memcpy(dir, canon, n);
        dir[n] = '\0';
        if (stat(dir, &ds) < 0) return -1;
    }
    return ds.st_dev == g_pdir_dev && ds.st_ino == g_pdir_ino;
}

static const char *forbidden_object(int fd, const char *canon) {
    struct stat st;
    if (fstat(fd, &st) < 0) return "resolution_failed";
    for (int i = 0; i < g_nprotected; i++)
        if (st.st_dev == g_protected[i].dev && st.st_ino == g_protected[i].ino)
            return "protected_object";
    if (g_pdir_set && st.st_dev == g_pdir_dev && st.st_ino == g_pdir_ino)
        return "protected_object";
    int pd = in_protected_dir(canon, -1);
    if (pd < 0) return "resolution_failed";
    if (pd > 0) return "protected_object";
    if (S_ISBLK(st.st_mode)) return "raw_device";
    if (S_ISCHR(st.st_mode)) {
        unsigned ma = major(st.st_rdev), mi = minor(st.st_rdev);
        if (ma == 1 && (mi == 1 || mi == 2 || mi == 4)) return "raw_device";
        for (int i = 0; i < g_nraw_char_majors; i++)
            if (ma == g_raw_char_majors[i]) return "raw_device";
    }
    if (!strcmp(canon, "/proc/kcore")) return "raw_device";
    return NULL;
}

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

/* ---------------- v1.17.0: metadata and link lookups ---------------- */

/* The directories that lead to what an allow rule names: for `allow path
 * /usr/lib/python3/`, the directories /, /usr, /usr/lib and /usr/lib/python3.
 * A path rule's literal start is its constant (prefix, exact) or the part of a
 * glob before its first wildcard; suffix and contains rules have none. The
 * policy already says these exist, so a read-type lookup on one of them
 * (stat, access(F_OK/R_OK), and readlink, which on a directory only says
 * EINVAL) is answered without a policy decision. Without
 * this, realpath() and the like fail on every allowed path, because each
 * component's lstat/readlink would be refused. */
#define MAX_ANCESTORS 2048
static char  *g_ancestors[MAX_ANCESTORS];
static size_t g_nancestors = 0;

static void add_ancestor(const char *s, size_t n) {
    if (n == 0) { s = "/"; n = 1; }
    for (size_t i = 0; i < g_nancestors; i++)
        if (strlen(g_ancestors[i]) == n && !memcmp(g_ancestors[i], s, n)) return;
    if (g_nancestors < MAX_ANCESTORS) {
        char *c = strndup(s, n);
        if (c) g_ancestors[g_nancestors++] = c;
    }
}

static void load_ancestors(const struct policy *p) {
    for (size_t r = 0; r < p->v.n; r++) {
        const vdp_rule_t *ru = &p->v.rules[r];
        if (ru->verb != VDP_ALLOW || ru->kind != VDP_KIND_PATH) continue;
        size_t lit = 0;
        if (ru->s.op == VDP_STR_PREFIX || ru->s.op == VDP_STR_EQ) lit = ru->s.len;
        else if (ru->s.op == VDP_STR_GLOB)
            while (lit < ru->s.len && !strchr("*?[\\", ru->s.c[lit])) lit++;
        else continue;
        if (lit == 0 || ru->s.c[0] != '/') continue;
        /* Every directory strictly before the last '/' of the literal part,
         * plus the literal itself when it ends in '/' (the named directory). */
        for (size_t i = 1; i <= lit; i++)
            if (i == lit ? ru->s.c[i - 1] == '/' : ru->s.c[i] == '/')
                add_ancestor(ru->s.c, i == lit ? i - 1 : i);
        add_ancestor("/", 1);
    }
}

static bool is_ancestor(const char *canon) {
    for (size_t i = 0; i < g_nancestors; i++)
        if (!strcmp(g_ancestors[i], canon)) return true;
    return false;
}

/* An ancestor a deny rule covers (the directory, or what is inside it) is not
 * answered: `deny path /home/` before `allow path /home/bob/work/` leaves
 * /home and /home/bob to the policy, which refuses them. */
static bool ancestor_denied(const struct policy *p, const char *dir) {
    char withslash[PATH_LIMIT];
    const char *cands[2] = { dir, withslash };
    int nc = 1;
    if (strcmp(dir, "/") && (size_t)snprintf(withslash, sizeof withslash, "%s/", dir) < sizeof withslash)
        nc = 2;
    for (int k = 0; k < nc; k++) {
        int ri;
        vdp_why_t why;
        if (vdp_decide(&p->v, VDP_KIND_PATH, cands[k], O_RDONLY, true, &ri, &why) == VDP_UNSATISFIED)
            return true;
    }
    return false;
}


static void send_value(int notify_fd, uint64_t id, int64_t val) {
    struct seccomp_notif_resp resp = { .id = id, .val = val, .error = 0, .flags = 0 };
    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

/* Write an answer into the agent's memory. /proc/<pid>/mem is opened first
 * and the notification checked second, so the descriptor cannot belong to a
 * process that reused the pid of one that died. Returns 0 or -errno. */
static int xproc_write(pid_t pid, int notify_fd, uint64_t id,
                       uint64_t addr, const void *buf, size_t len) {
    if (addr == 0) return -EFAULT;
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -EFAULT;
    if (!notif_id_valid(notify_fd, id)) { close(fd); return -ESRCH; }
    ssize_t n = pwrite(fd, buf, len, (off_t)addr);
    close(fd);
    return n == (ssize_t)len ? 0 : -EFAULT;
}

/* One of the agent's own descriptors, duplicated into the supervisor (the
 * supervisor is not under the agent's filter, so pidfd_getfd is open to it).
 * AT_FDCWD is the agent's working directory. Returns a descriptor or -errno. */
static int agent_fd(pid_t tid, int fd) {
    if (fd == VAREK_AT_FDCWD) {
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/cwd", tid);
        int r = open(p, O_PATH | O_DIRECTORY | O_CLOEXEC);
        return r < 0 ? -EBADF : r;
    }
    if (fd < 0) return -EBADF;
    /* v1.21: the requesting task's own descriptor table, through a pidfd for
     * that thread (PIDFD_THREAD, Linux 6.9). A task the agent started without
     * CLONE_FILES has a table of its own, and the thread-group leader's
     * descriptor N may be another object. Older kernels refuse the flag
     * (EINVAL); they get the thread group's pidfd, as through v1.20. */
    int pfd = (int)syscall(__NR_pidfd_open, tid, VAREK_PIDFD_THREAD);
    if (pfd < 0 && errno == EINVAL) {
        pid_t tgid = task_tgid(tid);
        if (tgid < 0) return -ESRCH;
        pfd = (int)syscall(__NR_pidfd_open, tgid, 0);
    }
    if (pfd < 0) return -ESRCH;
    int r = (int)syscall(__NR_pidfd_getfd, pfd, fd, 0);
    int e = errno;
    close(pfd);
    (void)e;
    return r < 0 ? -EBADF : r;
}

/* Answer the lookup on an object the supervisor holds. Returns the system
 * call's return value (>= 0) or -errno. */
static int64_t meta_answer(pid_t tid, int notify_fd, uint64_t id,
                           const struct action *a, int ofd, bool ancestor) {
    if (a->kind == ACT_FILE_STAT) {
        if (a->meta_nr == __NR_statx) {
            struct statx stx;
            memset(&stx, 0, sizeof stx);
            /* The sync type is not passed on: a forced sync on a network
             * filesystem would stall the single-threaded supervisor. */
            if (syscall(__NR_statx, ofd, "", AT_EMPTY_PATH, a->statx_mask, &stx) < 0)
                return -errno;
            if (ancestor) {                  /* existence and type only */
                memset(&stx.stx_atime, 0, sizeof stx.stx_atime);
                memset(&stx.stx_btime, 0, sizeof stx.stx_btime);
                memset(&stx.stx_ctime, 0, sizeof stx.stx_ctime);
                memset(&stx.stx_mtime, 0, sizeof stx.stx_mtime);
                stx.stx_nlink = 1;
            }
            int w = xproc_write(tid, notify_fd, id, a->out_addr, &stx, sizeof stx);
            return w < 0 ? w : 0;
        }
        struct stat st;
        if (fstatat(ofd, "", &st, AT_EMPTY_PATH) < 0) return -errno;
        if (ancestor) {
            memset(&st.st_atim, 0, sizeof st.st_atim);
            memset(&st.st_mtim, 0, sizeof st.st_mtim);
            memset(&st.st_ctim, 0, sizeof st.st_ctim);
            st.st_nlink = 1;
        }
        int w = xproc_write(tid, notify_fd, id, a->out_addr, &st, sizeof st);
        return w < 0 ? w : 0;
    }
    if (a->kind == ACT_FILE_ACCESS) {
        /* What the agent may do is what the policy lets the Warden do on its
         * behalf (decided above). Nothing may be executed after the launch
         * (deny-only), so X_OK is refused. */
        if (a->access_mode & ~(F_OK | R_OK | W_OK | X_OK)) return -EINVAL;
        if (a->access_mode & X_OK) return -EACCES;
        return 0;
    }
    /* readlink: the kernel takes the size as an int. */
    int bufsiz = (int)(uint32_t)a->out_len;
    if (bufsiz <= 0) return -EINVAL;
    struct stat lst;
    if (fstat(ofd, &lst) < 0) return -errno;
    if (!S_ISLNK(lst.st_mode)) return -EINVAL;     /* what readlink says of a non-link */
    char buf[PATH_LIMIT];
    size_t want = (size_t)bufsiz < sizeof buf ? (size_t)bufsiz : sizeof buf;
    ssize_t n = readlinkat(ofd, "", buf, want);
    if (n < 0) return -errno;
    int w = xproc_write(tid, notify_fd, id, a->out_addr, buf, (size_t)n);
    return w < 0 ? w : n;
}

/* A lookup with an empty path names a descriptor, not a path: the agent's
 * dirfd (with AT_EMPTY_PATH), or readlinkat(fd, ""). Returns:
 *   1  answered here (stat/statx of a descriptor the agent already holds, like
 *      read() on it: no decision, not recorded; or an error);
 *   2  the object is *held_ofd and must be decided like a named one: the
 *      working directory (AT_FDCWD), whose rights the agent never acquired
 *      through the Warden, and access()/readlink(), which ask what the agent
 *      may do or see rather than what it already holds;
 *   0  not an empty path. */
static int meta_on_held_fd(pid_t tid, int notify_fd, uint64_t id, const struct action *a,
                           int *held_ofd) {
    *held_ofd = -1;
    bool empty_ok = (a->kind == ACT_FILE_STAT || a->meta_nr == __NR_faccessat2)
                        ? (a->at_flags & AT_EMPTY_PATH) != 0
                        : a->meta_nr == __NR_readlinkat;
    if (a->target[0] != '\0') return 0;
    if (!empty_ok) {                         /* an empty path names nothing */
        send_errno(notify_fd, id, a->path_null ? EFAULT : ENOENT);
        return 1;
    }
    int ofd = agent_fd(tid, a->open_dirfd);
    if (ofd < 0) { send_errno(notify_fd, id, (int)-ofd); return 1; }
    if (a->kind != ACT_FILE_STAT || a->open_dirfd == VAREK_AT_FDCWD) {
        *held_ofd = ofd;
        return 2;
    }
    int64_t r = meta_answer(tid, notify_fd, id, a, ofd, false);
    close(ofd);
    if (r < 0) send_errno(notify_fd, id, (int)-r);
    else       send_value(notify_fd, id, r);
    return 1;
}

/* Resolve the object a lookup names, without following a trailing symlink
 * when the call says not to (lstat, readlink). On success *ofd is an O_PATH
 * descriptor and a->resolved its canonical path. When the object does not
 * exist, *ofd is -1, a->resolved is <canonical parent>/<name> and *missing is
 * the errno the agent's own call would have seen, so the decision is made on
 * where it would be. Returns 0, or -1 to fail closed. */
static int resolve_meta(pid_t tid, struct action *a, int held, int *ofd, int *missing) {
    *ofd = -1;
    *missing = 0;
    a->resolved[0] = '\0';
    pid_t tgid = -1;
    if (held >= 0) {                     /* an empty path: the descriptor itself */
        if (fd_canonical_path(held, a->resolved, sizeof(a->resolved)) < 0 ||
            check_proc_object(held, tid, &tgid, a->resolved, sizeof(a->resolved)) < 0) {
            a->resolved[0] = '\0';
            close(held);
            return -1;
        }
        *ofd = held;
        return 0;
    }
    char path[PATH_LIMIT];
    bool thread_self = false;
    if (path_is_proc_self(a->target, &thread_self)) {
        tgid = task_tgid(tid);
        if (tgid < 0 || rewrite_proc_self(a->target, thread_self, tgid, tid,
                                          path, sizeof(path)) < 0)
            return -1;
    } else if ((size_t)snprintf(path, sizeof(path), "%s", a->target) >= sizeof(path)) {
        return -1;
    }
    int base = agent_fd(tid, path[0] == '/' ? VAREK_AT_FDCWD : a->open_dirfd);
    if (base < 0) return -1;
    bool nofollow = a->kind == ACT_FILE_READLINK ||
                    (a->kind == ACT_FILE_STAT && (a->at_flags & AT_SYMLINK_NOFOLLOW)) ||
                    (a->kind == ACT_FILE_ACCESS && (a->at_flags & AT_SYMLINK_NOFOLLOW));
    int fd = openat2_path(base, path, nofollow ? (uint64_t)O_NOFOLLOW : 0);
    if (fd >= 0) {
        close(base);
        if (fd_canonical_path(fd, a->resolved, sizeof(a->resolved)) < 0 ||
            check_proc_object(fd, tid, &tgid, a->resolved, sizeof(a->resolved)) < 0) {
            a->resolved[0] = '\0';
            close(fd);
            return -1;
        }
        *ofd = fd;
        return 0;
    }
    int e = errno;
    if (e != ENOENT && e != ENOTDIR) { close(base); return -1; }
    /* Not there: decide on where it would be. */
    size_t tl = strlen(path);
    while (tl > 1 && path[tl - 1] == '/') path[--tl] = '\0';
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) { close(base); return -1; }
    char dir[PATH_LIMIT];
    if (!slash)             snprintf(dir, sizeof(dir), ".");
    else if (slash == path) snprintf(dir, sizeof(dir), "/");
    else                    snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
    int pfd = openat2_path(base, dir, (uint64_t)O_DIRECTORY);
    close(base);
    if (pfd < 0) return -1;              /* the parent is missing too: fail closed */
    /* Only a name that truly does not exist is decided on where it would be.
     * If it exists (a trailing slash on a file, ENOTDIR; or a symlink whose
     * target is missing), failing here would answer for an object the
     * identity check never saw, or tell the agent whether a link's target
     * outside the policy exists: fail closed instead. */
    struct stat nst;
    if (fstatat(pfd, name, &nst, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        close(pfd);
        return -1;
    }
    char parent[PATH_LIMIT];
    int rc = -1;
    if (fd_canonical_path(pfd, parent, sizeof(parent)) == 0 &&
        check_proc_object(pfd, tid, &tgid, parent, sizeof(parent)) == 0) {
        int n = snprintf(a->resolved, sizeof(a->resolved), "%s%s%s",
                         parent, strcmp(parent, "/") ? "/" : "", name);
        if (n > 0 && (size_t)n < sizeof(a->resolved)) { *missing = e; rc = 0; }
        else a->resolved[0] = '\0';
    }
    close(pfd);
    return rc;
}

/* v1.26 (warden_synth.inc.c): synthetic addresses, used by the views, the
 * connects and the stub */
static bool syn_is_addr(const wr_ip_t *ip);
static bool syn_qualifies(const struct policy *p, const char *name);
static int  syn_assign(const char *name, int line, wr_ip_t *out);
static void syn_hosts_view(const struct policy *p, FILE *f);
#include "warden_names.inc.c"        /* v1.24: host-name views and candidates */
#include "warden_net.inc.c"          /* v1.21: decided connections */
#include "warden_stub.inc.c"         /* v1.25: the stub resolver for wildcard names */
#include "warden_synth.inc.c"        /* v1.26: synthetic addresses with the proxy on */
#include "warden_pxdecide.inc.c"     /* v1.26: the Warden's decisions on what the proxy reads */

/* ---------------- receive loop ---------------- */

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_child_exited = 0;
static void on_term(int sig) { if (sig == SIGCHLD) g_child_exited = 1; g_stop = 1; }

/* Returns true when the agent went away on its own (its pidfd fired, or no
 * task is left under the filter), false when the Warden stopped supervising for
 * another reason and is about to kill it. */
static bool supervise(int notify_fd, int target_pidfd, int agent_err_fd,
                      const struct policy *p, const char *bootstrap_path,
                      pid_t bootstrap_pid) {
    bool bootstrap_done = false;
    while (!g_stop && !g_log_broken) {
        /* v1.9.3: wait on the listener AND the target's pidfd. Blocking in
         * NOTIF_RECV alone can hang forever if the target exits between the
         * g_stop check and the ioctl (the SIGCHLD is already spent).
         * v1.12.1: also on the agent's stderr pipe, which is relayed. A
         * negative fd is ignored by poll(). */
        /* v1.21: also on the sockets of connects and sends still being
         * finished for the agent (warden_net.inc.c). */
        /* v1.24: also on the resolver helper's results. */
        /* v1.25: and on the stub resolver's sockets (warden_stub.inc.c). */
        struct pollfd pfds[4 + MAX_PENDING + 2 + STUB_MAX_CONN + 1 + PX_MAX_DIAL] = {
            { .fd = notify_fd,    .events = POLLIN },
            { .fd = target_pidfd, .events = POLLIN },
            { .fd = agent_err_fd, .events = POLLIN },
            { .fd = wr_async_fd(&g_names), .events = POLLIN },
        };
        int npoll = g_npend;
        for (int i = 0; i < npoll; i++) {
            pfds[4 + i].fd = g_pend[i]->kind == PEND_UNIX_RETRY ? -1 : g_pend[i]->sock;
            pfds[4 + i].events = POLLOUT;
            pfds[4 + i].revents = 0;
        }
        /* v1.16: checkpoints are written here, between notifications, so
         * signing never delays an answer the agent is waiting for. v1.24:
         * likewise, refreshes are handed to the resolver helper here and
         * their results applied here; the lookups themselves never run in
         * the Warden. */
        int nstub = stub_poll_fill(&pfds[4 + npoll]);
        /* v1.26 (step 5): and on the egress proxy's reports */
        int pxi = 4 + npoll + nstub;
        pfds[pxi] = (struct pollfd){ .fd = g_proxy.ctl, .events = POLLIN };
        int npx = px_poll_fill(&pfds[pxi + 1]);
        int to = maybe_checkpoint(), pto = pend_timeout_ms();
        if (pto >= 0 && (to < 0 || pto < to)) to = pto;
        if (g_names_on) {
            wr_retire_due(&g_names, wr_now_ms(), emit_retired, NULL);
            wr_async_schedule(&g_names, wr_now_ms());
            int dto = wr_next_due_ms(&g_names, wr_now_ms());
            if (dto >= 0 && (to < 0 || dto < to)) to = dto;
        }
        int xto = px_timeout_ms();
        if (xto >= 0 && (to < 0 || xto < to)) to = xto;
        int pr = poll(pfds, (nfds_t)(pxi + 1 + npx), to);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (npoll > 0) {
            short rev[MAX_PENDING];
            for (int i = 0; i < npoll; i++) rev[i] = pfds[4 + i].revents;
            pend_service(notify_fd, rev, npoll);
        }
        stub_service(p, &pfds[4 + npoll], nstub);
        px_service(p, &pfds[pxi + 1], npx);
        if (g_proxy.ctl >= 0 && (pfds[pxi].revents & (POLLIN | POLLHUP | POLLERR)) && proxy_service(p) < 0) {
            /* fail closed, as for the resolver helper */
            fprintf(stderr, "[warden] the egress proxy exited or sent a malformed report; stopping the run\n");
            return false;
        }
        if (g_names_on && (pfds[3].revents & (POLLIN | POLLHUP | POLLERR))) {
            wr_async_collect(&g_names, wr_now_ms(), emit_resolution, NULL);
            /* v1.24: without the helper the table would go stale; stop
             * (fail closed: the agent is killed, as for a broken stream). */
            if (!wr_async_alive(&g_names)) {
                fprintf(stderr, "[warden] the resolver helper exited; host names can no longer be "
                        "refreshed, stopping the run\n");
                return false;
            }
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
            emit_pathology(g_report_seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY,
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
        /* v1.17.0: the launch is execveat(fd, "", AT_EMPTY_PATH) on the
         * program the Warden's own code opened before dropping privileges (or
         * execve of its path, for a script). The descriptor is in a register,
         * not memory, and the launching process runs only Warden code until
         * the exec, so CONTINUE stays as sound as before. */
        bool boot_by_fd = act.kind == ACT_PROCESS_EXEC && req.data.nr == __NR_execveat &&
                          act.target[0] == '\0' && (req.data.args[4] & AT_EMPTY_PATH);
        if (act.kind == ACT_PROCESS_EXEC && !bootstrap_done &&
            (pid_t)req.pid == bootstrap_pid && bootstrap_path &&
            (boot_by_fd || strcmp(act.target, bootstrap_path) == 0)) {
            if (boot_by_fd)
                snprintf(act.target, sizeof act.target, "%s", bootstrap_path);
            bootstrap_done = true;
            if (ctx) ctx->launched = true;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_b = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,
                           "bootstrap_exec_allow", lat_b, 0);
            send_simple(notify_fd, req.id, DEC_ALLOW);
            continue;
        }

        /* v1.17.0: metadata and link lookups (stat, statx, access, readlink):
         * resolved like an open, refused by identity if protected, decided as
         * a read-only open of the same object (access(W_OK) as a write),
         * certified, recorded, and answered by the Warden itself. A lookup on
         * a descriptor the agent already holds is answered without a
         * decision, like read() on it. A name that does not exist is decided
         * on where it would be: ENOENT inside the policy, EACCES outside, so
         * the lookup no longer tells the agent what exists elsewhere. */
        if (is_meta_kind(act.kind)) {
            if (act.bad_flags) { send_errno(notify_fd, req.id, EINVAL); continue; }
            int held = -1;
            if (meta_on_held_fd(req.pid, notify_fd, req.id, &act, &held) == 1) continue;
            int mfd = -1, missing = 0;
            const char *mforbid = NULL;
            if (resolve_meta(req.pid, &act, held, &mfd, &missing) < 0) {
                mforbid = "resolution_failed";
            } else if (mfd >= 0) {
                const char *f = forbidden_object(mfd, act.resolved);
                if (f && strcmp(f, "raw_device") != 0) mforbid = f;   /* stat of a disk is harmless */
            }
            if (mforbid) {
                if (mfd >= 0) close(mfd);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat_m = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(g_report_seq++, req.pid, &act,
                               strcmp(mforbid, "resolution_failed") ? DEC_DENY : DEC_UNKNOWN,
                               DEC_DENY, mforbid, lat_m, EACCES);
                send_simple(notify_fd, req.id, DEC_DENY);
                continue;
            }
            /* A directory the policy's allow rules lead to: a read-type
             * lookup is answered without a decision (see load_ancestors). */
            if (mfd >= 0 &&
                !(act.kind == ACT_FILE_ACCESS && (act.access_mode & (W_OK | X_OK)))) {
                struct stat ast;
                if (fstat(mfd, &ast) == 0 && S_ISDIR(ast.st_mode) && is_ancestor(act.resolved) &&
                    !ancestor_denied(p, act.resolved)) {
                    int64_t r = meta_answer(req.pid, notify_fd, req.id, &act, mfd, true);
                    close(mfd);
                    if (r < 0) send_errno(notify_fd, req.id, (int)-r);
                    else       send_value(notify_fd, req.id, r);
                    clock_gettime(CLOCK_MONOTONIC, &t1);
                    uint64_t lat_a = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                                   + (t1.tv_nsec - t0.tv_nsec);
                    emit_pathology(g_report_seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,
                                   "metadata_ancestor", lat_a, r < 0 ? (int)-r : 0);
                    continue;
                }
            }
            decision_t m_raw   = policy_decide(p, &act);
            decision_t m_final = (m_raw == DEC_ALLOW) ? DEC_ALLOW : DEC_DENY;
            bool m_cert_refused = false;
            if (m_final == DEC_ALLOW && !certify(p, &act)) {
                m_final = DEC_DENY;
                m_cert_refused = true;
                log_line_start();
                fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n",
                        g_records, act.check_why);
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (m_final != DEC_ALLOW) {
                if (mfd >= 0) close(mfd);
                uint64_t lat_m = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(g_report_seq++, req.pid, &act, m_raw, m_final,
                               m_cert_refused ? "certificate_refused" : decision_rule_id(&act, m_raw),
                               lat_m, EACCES);
                send_simple(notify_fd, req.id, DEC_DENY);
                continue;
            }
            int64_t r;
            const char *rule;
            if (mfd < 0) {
                r = -missing;
                rule = "metadata_not_found";
            } else {
                r = meta_answer(req.pid, notify_fd, req.id, &act, mfd, false);
                close(mfd);
                rule = r < 0 ? "metadata_failed" : "metadata_answered";
            }
            if (r < 0) send_errno(notify_fd, req.id, (int)-r);
            else       send_value(notify_fd, req.id, r);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_m = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, m_raw, m_final, rule, lat_m,
                           r < 0 ? (int)-r : 0);
            continue;
        }

        /* v1.21: connects are decided on the destination the Warden will
         * dial, dialed by the Warden and handed over (warden_net.inc.c).
         * Sends with no destination of their own on a TCP or UDP socket are
         * relayed; the rest fall through to the refusal below. */
        if (act.kind == ACT_NET_CONNECT) {
            net_connect(notify_fd, &req, &act, p, &t0);
            continue;
        }
        if (act.kind == ACT_NET_SEND && net_send_relay(notify_fd, &req, &act, &t0))
            continue;
        if (act.kind == ACT_NET_SEND && stub_sendto(notify_fd, &req, &act, &t0))   /* v1.25 */
            continue;
        if (act.kind == ACT_NET_BIND) {
            net_bind(notify_fd, &req, &act, &t0);
            continue;
        }

        /* v1.12.1: resolve-then-decide-then-open for file opens. The object
         * is pinned with O_PATH (no side effect), canonicalized, matched
         * against policy, and only on ALLOW opened with the agent's flags
         * through the pinned descriptor. Resolution failure (symlink
         * component, untracked dirfd, over-long path, deleted inode, missing
         * parent) is a hard deny before any policy match. */
        struct resolved_target rt = { .path_fd = -1, .parent_fd = -1 };
        /* v1.24: /etc/hosts, /etc/resolv.conf, /etc/nsswitch.conf and
         * /etc/host.conf, named as such, are answered with the Warden's views
         * while the policy has a host name rule (warden_names.inc.c), whether
         * or not the host has the file. */
        if (g_any_name && act.kind == ACT_FILE_OPEN && view_open_readonly(&act) &&
            view_by_target(act.target) >= 0) {
            view_serve(notify_fd, &req, &act, p, view_by_target(act.target), &t0);
            continue;
        }
        /* v1.24 review: an open of those files that could write is refused,
         * whatever the policy says. The Warden's resolver helper reads the
         * host's resolv.conf on every lookup, so an agent that could write it
         * would choose where allowed names lead. */
        if (g_any_name && act.kind == ACT_FILE_OPEN && !view_open_readonly(&act) &&
            view_by_target(act.target) >= 0) {
            snprintf(act.resolved, sizeof act.resolved, "%s", act.target);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_DENY, DEC_DENY, "view_write_refused",
                           (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec), EACCES);
            send_simple(notify_fd, req.id, DEC_DENY);
            continue;
        }
        if (act.kind == ACT_FILE_OPEN) {
            if (resolve_target(req.pid, &act, &rt) < 0) {
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat_r = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(g_report_seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY,
                               "resolution_failed", lat_r, EACCES);
                send_simple(notify_fd, req.id, DEC_DENY);
                continue;
            }
            /* v1.17.0: the signing key, the anchor, the verdict stream and raw
             * storage are refused by identity, before the policy is asked. */
            const char *forbid = rt.path_fd >= 0 ? forbidden_object(rt.path_fd, act.resolved)
                               : in_protected_dir(NULL, rt.parent_fd) < 0 ? "resolution_failed"
                               : in_protected_dir(NULL, rt.parent_fd) > 0 ? "protected_object" : NULL;
            if (forbid) {
                resolved_target_close(&rt);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                uint64_t lat_f = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                emit_pathology(g_report_seq++, req.pid, &act, DEC_DENY, DEC_DENY, forbid, lat_f, EACCES);
                send_simple(notify_fd, req.id, DEC_DENY);
                continue;
            }
            /* v1.24: the same views, reached by another spelling (a symlink,
             * "..", /etc/resolv.conf's own target). */
            if (g_any_name && view_open_readonly(&act) && view_by_canonical(act.resolved) >= 0) {
                int v = view_by_canonical(act.resolved);
                resolved_target_close(&rt);
                view_serve(notify_fd, &req, &act, p, v, &t0);
                continue;
            }
            if (g_any_name && !view_open_readonly(&act) && view_by_canonical(act.resolved) >= 0) {
                resolved_target_close(&rt);
                clock_gettime(CLOCK_MONOTONIC, &t1);
                emit_pathology(g_report_seq++, req.pid, &act, DEC_DENY, DEC_DENY, "view_write_refused",
                               (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec), EACCES);
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
                emit_pathology(g_report_seq++, req.pid, &act, d_raw, d_final, rule, lat, err);
                continue;
            }
            /* Denied by policy: the pinned object was never opened. */
            resolved_target_close(&rt);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_d = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, d_raw, d_final,
                           cert_refused ? "certificate_refused" : decision_rule_id(&act, d_raw),
                           lat_d, EACCES);
            send_simple(notify_fd, req.id, d_final);
            continue;
        }

        /* v1.9.1: deny-only mediation of what remains: a launch after the
         * first (an execve allow cannot be enforced via CONTINUE without a
         * TOCTOU race on its pointer argument). v1.21: connects no longer
         * reach here; the Warden dials them (net_connect above). */
        if (d_final == DEC_ALLOW && act.kind != ACT_FILE_OPEN) {
            d_final = DEC_DENY;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_dn = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                            + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, d_raw, d_final,
                           "deny_only_nonfile_v191", lat_dn, EACCES);
            send_simple(notify_fd, req.id, d_final);
            continue;
        }

        send_simple(notify_fd, req.id, d_final);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                     + (t1.tv_nsec - t0.tv_nsec);
        emit_pathology(g_report_seq++, req.pid, &act, d_raw, d_final,
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

/* The canonical path of an open descriptor, as the kernel resolved it (no
 * second lookup that could race with a rename). */
static int fd_path(int fd, char *out, size_t n) {
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t k = readlink(link, out, n - 1);
    if (k <= 0 || (size_t)k >= n - 1 || out[0] != '/') return -1;
    out[k] = '\0';
    return 0;
}

/* The policy must not let the agent open the file behind fd (with any flags):
 * decided by the certificate checker, which every authorization needs. A
 * regular file must have exactly one name, or the agent could reach it through
 * another (a hard link in an allowed directory). */
static int refuse_if_agent_can_open(const struct policy *p, int fd, const char *path,
                                    const char *what) {
    struct stat st;
    char rp[PATH_MAX];
    if (fstat(fd, &st) < 0 || fd_path(fd, rp, sizeof rp) < 0) {
        fprintf(stderr, "[warden] %s %s: cannot determine its path\n", what, path);
        return -1;
    }
    if (S_ISREG(st.st_mode) && st.st_nlink != 1) {
        fprintf(stderr, "[warden] the %s %s has %lu names (hard links); the agent could reach "
                "it through another. Refusing to start.\n", what, rp, (unsigned long)st.st_nlink);
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

/* Raw access to a disk reads (or writes) every file on it, whatever the path
 * rules say: with a signing key or an anchor, refuse a policy that would let
 * the agent open any block device under /dev, /dev/mem, /dev/kmem, /dev/port,
 * /proc/kcore, or a disk's command device (/dev/sg*, /dev/nvme*, /dev/bsg/).
 * Only nodes that exist are checked; the agent cannot create one (mknod is not
 * in its allowlist). Other drivers that expose storage are not recognized. */
static int raw_device_scan(const struct policy *p, const char *dir, int depth) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char path[PATH_MAX];
        if ((size_t)snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= sizeof path) continue;
        struct stat st;
        if (lstat(path, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth < 4) rc = raw_device_scan(p, path, depth + 1);
            continue;
        }
        /* Block devices; memory; and the character devices that pass commands
         * to a disk (SCSI generic, NVMe, block SCSI generic). */
        bool raw = S_ISBLK(st.st_mode) ||
                   (S_ISCHR(st.st_mode) &&
                    ((depth == 0 && (!strcmp(e->d_name, "mem") || !strcmp(e->d_name, "kmem") ||
                                     !strcmp(e->d_name, "port") ||
                                     !strncmp(e->d_name, "sg", 2) ||
                                     !strncmp(e->d_name, "nvme", 4))) ||
                     !strcmp(dir, "/dev/bsg") || !strncmp(dir, "/dev/bsg/", 9)));
        if (raw && vdpc_path_openable(&p->c, path, strlen(path))) {
            fprintf(stderr, "[warden] the policy would let the agent open %s, which gives raw "
                    "access to storage (including the signing key or the anchor); deny it. "
                    "Refusing to start.\n", path);
            rc = -1;
        }
    }
    closedir(d);
    return rc;
}

static int refuse_raw_devices(const struct policy *p) {
    if (raw_device_scan(p, "/dev", 0) < 0) return -1;
    struct stat st;
    if (stat("/proc/kcore", &st) == 0 && vdpc_path_openable(&p->c, "/proc/kcore", 11)) {
        fprintf(stderr, "[warden] the policy would let the agent open /proc/kcore; deny it. "
                "Refusing to start.\n");
        return -1;
    }
    return 0;
}

/* --sign-key FILE: an Ed25519 seed, 64 hex characters (tools/varek_keygen
 * makes one), in a regular file with one name that no one but its owner can
 * read or write. */
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
    if (refuse_if_agent_can_open(p, fd, path, "signing key") < 0) { close(fd); return -1; }
    protect_fd(fd, "signing key");          /* v1.17.0: refused by identity at runtime too */
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
    g_sk = sodium_malloc(crypto_sign_SECRETKEYBYTES);
    if (!g_sk) {
        sodium_memzero(seed, sizeof seed);
        fprintf(stderr, "[warden] cannot allocate protected memory for the signing key\n");
        return -1;
    }
    crypto_sign_seed_keypair(g_pk, g_sk, seed);
    sodium_memzero(seed, sizeof seed);
    g_signing = true;
    return 0;
}

/* v1.16.2: tools/varek_anchor_forward.py holds an exclusive lock on
 * FIFO.lock while it runs. 1: a forwarder holds it; 0: the lock file exists
 * and is free (no forwarder, even if the FIFO is held open by another
 * Warden); -1: no lock file (another kind of reader; only the reader check
 * applies). */
static int forwarder_alive(const char *fifo) {
    char lp[PATH_MAX + 8];
    if ((size_t)snprintf(lp, sizeof lp, "%s.lock", fifo) >= sizeof lp) return -1;
    int fd = open(lp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    snprintf(g_anchor_lock, sizeof g_anchor_lock, "%s", lp);
    /* A shared probe: it conflicts only with the forwarder's exclusive lock,
     * never with another probe. */
    int r = flock(fd, LOCK_SH | LOCK_NB) == 0 ? 0 : (errno == EWOULDBLOCK ? 1 : -1);
    close(fd);                                   /* releases it if we took it */
    return r;
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
    if (refuse_if_agent_can_open(p, fd, path, "anchor") < 0) { close(fd); return -1; }
    if (S_ISFIFO(st.st_mode) && forwarder_alive(path) == 0) {
        fprintf(stderr, "[warden] anchor %s: the forwarder is not running (%s.lock is free; the FIFO "
                "may only be held open by another Warden). Start it first.\n", path, path);
        close(fd);
        return -1;
    }
    if (S_ISFIFO(st.st_mode)) {
        /* v1.16.2: the open above proved a reader (the forwarder) is there.
         * Now hold the FIFO read-write through the same inode, so that if the
         * forwarder restarts mid-run, records written meanwhile wait in the
         * pipe (64 KiB) instead of failing with EPIPE. The Warden never reads
         * from it. */
        char self[64];
        snprintf(self, sizeof self, "/proc/self/fd/%d", fd);
        int rw = open(self, O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (rw < 0) {
            fprintf(stderr, "[warden] anchor %s: cannot hold the FIFO open (%s)\n", path, strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
        fd = rw;
        g_anchor_fifo = true;
    }
    protect_fd(fd, "anchor");               /* v1.17.0 */
    g_anchor_fd = fd;
    return 0;
}

/* The verdict stream itself: if it is a regular file the agent could open, the
 * agent could truncate or read it (and learn the run id). v1.16 refuses. */
static int refuse_exposed_stream(const struct policy *p) {
    struct stat st;
    if (fstat(STDERR_FILENO, &st) < 0) return 0;
    /* v1.17.0: a file or FIFO holding the stream is refused by identity at
     * runtime whatever path reaches it; a regular file is also checked by
     * path here, for a clear error at startup. */
    if (S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode)) protect_fd(STDERR_FILENO, "verdict stream");
    if (!S_ISREG(st.st_mode)) return 0;
    return refuse_if_agent_can_open(p, STDERR_FILENO, "(stderr)", "verdict stream");
}

/* v1.16.2: a FIFO anchor's unread records vanish when its last descriptor
 * closes. Before exiting, give the forwarder up to 10 s to read what is still
 * in the pipe (it may be restarting), and say so if it does not. */
static void anchor_drain(void) {
    if (g_anchor_fd < 0 || !g_anchor_fifo) return;
    int left = 0;
    for (int i = 0; i < 200; i++) {
        if (ioctl(g_anchor_fd, FIONREAD, &left) < 0 || left == 0) return;
        /* A live forwarder holds the pipe itself: what is left is safe with
         * it (it may just be busy sending). */
        if (g_anchor_lock[0]) {
            int fd = open(g_anchor_lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd >= 0) {
                int busy = flock(fd, LOCK_SH | LOCK_NB) != 0 && errno == EWOULDBLOCK;
                close(fd);
                if (busy) return;
            }
        }
        struct timespec ts = { 0, 50 * 1000000L };
        nanosleep(&ts, NULL);
    }
    log_line_start();
    fprintf(g_log, "[warden] anchor: %d byte(s) of records in the FIFO were not read within 10 s of "
            "the run's end and no forwarder is running; unless another process keeps the FIFO open "
            "until one starts, they are lost (the audit reports them as never anchored)\n", left);
    fflush(g_log);
}

/* ---------------- v1.17.0: the agent runs unprivileged ---------------- */

/* Through v1.16.3 the agent ran as root with every capability; only the
 * seccomp filter held it back. It now runs as an unprivileged user (--run-as,
 * default nobody) with an empty capability bounding set. File access does not
 * depend on the agent's own rights: the Warden opens (and looks up) files on
 * its behalf, as root, and only after the policy allows it. What changes is
 * what the agent could do with any call the filter admits, and with any kernel
 * bug it reaches: as nobody, with no capabilities, far less. */
struct run_as { bool drop; uid_t uid; gid_t gid; };

static int parse_run_as(const char *v, struct run_as *ra) {
    ra->drop = true;
    if (!strcmp(v, "root")) { ra->drop = false; ra->uid = 0; ra->gid = 0; return 0; }
    if (v[0] >= '0' && v[0] <= '9') {
        char *end;
        unsigned long u = strtoul(v, &end, 10), g = u;
        if (*end == ':') {
            const char *gs = end + 1;
            if (*gs < '0' || *gs > '9') return -1;  /* "1000:" is not group 0 */
            g = strtoul(gs, &end, 10);
        }
        if (*end || u > 0x7fffffffUL || g > 0x7fffffffUL) return -1;
        ra->uid = (uid_t)u;
        ra->gid = (gid_t)g;
    } else {
        struct passwd *pw = getpwnam(v);
        if (!pw) {
            if (strcmp(v, "nobody") != 0) return -1;
            ra->uid = 65534; ra->gid = 65534;       /* nobody, where not in passwd */
        } else {
            ra->uid = pw->pw_uid; ra->gid = pw->pw_gid;
        }
    }
    if (ra->uid == 0) ra->drop = false;            /* uid 0 is root */
    if (ra->drop && ra->gid == 0) return -2;       /* group root for an unprivileged user */
    return 0;
}

/* In the child, before the filter: no supplementary groups, an empty
 * capability bounding and ambient set, then the unprivileged user and group
 * (which clears the permitted and effective sets). Verified afterwards. */
static int drop_privileges(const struct run_as *ra) {
    if (setgroups(0, NULL) < 0) return -errno;
    for (int cap = 0; cap <= 63; cap++)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) return -errno;
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    if (setresgid(ra->gid, ra->gid, ra->gid) < 0) return -errno;
    if (setresuid(ra->uid, ra->uid, ra->uid) < 0) return -errno;
    struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capget, &hdr, data) != 0) return -errno;
    for (int i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) return -EPERM;
    if (getuid() != ra->uid || geteuid() != ra->uid || getgid() != ra->gid) return -EPERM;
    return 0;
}

/* The program to launch, as execvp would find it (PATH search for a bare
 * name). Returns 0 with out filled, or -1. */
static int find_program(const char *name, char *out, size_t n) {
    if (strchr(name, '/')) {
        struct stat st;
        if ((size_t)snprintf(out, n, "%s", name) >= n) return -1;
        return stat(out, &st) == 0 && S_ISREG(st.st_mode) ? 0 : -1;
    }
    const char *path = getenv("PATH");
    if (!path || !*path) path = "/usr/local/bin:/usr/bin:/bin";
    while (*path) {
        const char *c = strchr(path, ':');
        size_t len = c ? (size_t)(c - path) : strlen(path);
        int w = len ? snprintf(out, n, "%.*s/%s", (int)len, path, name)
                    : snprintf(out, n, "./%s", name);
        struct stat st;
        if (w > 0 && (size_t)w < n && stat(out, &st) == 0 && S_ISREG(st.st_mode) &&
            (st.st_mode & 0111))
            return 0;
        if (!c) break;
        path = c + 1;
    }
    return -1;
}

/* ---------------- main ---------------- */

/* ---------------- v1.18.0: the full plan gate (--flow-policy) ----------------
 *
 * Through v1.17.0 the --plan gate ran only the v1.6 check (every step allowed
 * by the policy). The v1.7 data-flow check, the v1.8.2 refusal breaker and the
 * v1.9 progress-safety check existed as a library with tests, and the README
 * described them as part of the runtime, but the Warden never called them.
 * With --flow-policy <cfg> (the v1.7.3 label-policy format) the gate now runs:
 *
 *   at startup  the v1.9 progress-safety check on <cfg>: the Warden refuses to
 *               start unless every refusal ends in an automated outcome. It
 *               also requires a refusal_budget, since the Warden's own policy
 *               can always refuse a step even when <cfg> cannot, and (v1.19.0)
 *               a session_refusal_budget: refusal_budget bounds resubmissions
 *               of one plan, so a planner that changed one step each time
 *               started a new count every time.
 *   per plan    the v1.6 node check and the v1.7 flow check (plan_warden_verify),
 *               then the breaker, keyed by (--session, the plan's signature),
 *               with its counts kept in --breaker-state across runs.
 *
 * Plan steps reach the flow policy as actions named by their kind (file_open,
 * net_connect, process_exec) with the argument "target" and (v1.20.0) every
 * field the step declares (key=value after the target in the plan file), in
 * key order. A file_open target is the lexically canonical path the node check
 * decides on, so a flow rule on a secret directory (match target on
 * /srv/secret/ followed by a star) cannot be stepped around with "..". Fields
 * reach the flow policy; the node check reads only a file_open step's `open`
 * field (v1.21.1, plan_open_field), the runtime none, and nothing compares
 * the agent's later calls with its fields.
 *
 * The outcome: PASS runs the agent, and the Warden then exits with the agent's
 * status. Otherwise the agent never runs and the Warden exits 3
 * (REFUSED_RETRYABLE: the host may submit a different plan), 4 (TERMINAL_DENY)
 * or 5 (TERMINAL_ACTION: the message names the pre-authorized action the host
 * must run), or 1 on an error, including a breaker state it cannot read or
 * write. An agent can exit 3, 4 or 5 itself, so a host that acts on the outcome
 * reads --gate-status <file> (one line, written before the agent starts) or the
 * plan_gate record in the verdict stream (chained, and sealed by the next
 * signed checkpoint), not the exit status alone.
 *
 * The breaker state: <dir>/<name> (default /var/lib/varek/breaker.state). <dir>
 * must be owned by the Warden's user and writable by no one else; it is opened
 * once and every later step works relative to it. <name>.lock is locked for
 * the gate only (not the agent's run). The table is written to <name>.tmp,
 * synced and renamed over <name>, so an interrupted write (a crash, a full
 * disk, a file-size limit) leaves the previous table in place. A missing
 * <name> is an empty table; one that does not read back (empty, cut short,
 * malformed) is an error and the plan is refused. The lock file and the
 * table are protected from the agent by identity, like the signing key. */

#define BREAKER_DEFAULT_DIR  "/var/lib/varek"
#define BREAKER_DEFAULT_NAME "breaker.state"

static plan_label_policy_config_t *g_flow_cfg;
static int  g_state_dir = -1;           /* the state directory, pinned */
static int  g_state_lock = -1;          /* <name>.lock, flock()ed during the gate */
static char g_state_name[NAME_MAX + 1];
static char g_state_tmp[NAME_MAX + 1];
static const char *g_breaker_path;      /* for messages */
static const char *g_session = "default";
static bool g_check_only = false;       /* v1.21: --check-startup */
static int  g_gate_status_fd = -1;      /* --gate-status */

enum { GATE_PASS = 0, GATE_ERROR = 1, GATE_RETRYABLE = 3, GATE_TERMINAL_DENY = 4,
       GATE_TERMINAL_ACTION = 5 };

/* The Warden's own file: regular, owned by its user, writable by no one else. */
static bool own_private_file(const struct stat *st) {
    return S_ISREG(st->st_mode) && st->st_uid == geteuid() && !(st->st_mode & 022);
}

/* Load and certify the flow policy; open and check the state directory, the
 * lock file and (if it exists) the table; open --gate-status. Returns 0, or -1
 * after saying why. */
static int flow_setup(const struct policy *pol, const char *cfg_path, const char *state_path,
                      const char *session, const char *gate_status_path) {
    int line = 0;
    const char *msg = NULL;
    if (plan_label_policy_config_load(cfg_path, &g_flow_cfg, &line, &msg) != 0) {
        fprintf(stderr, "[warden] --flow-policy %s: line %d: %s\n", cfg_path, line,
                msg ? msg : "cannot load");
        return -1;
    }
    plan_progress_finding_t f;
    if (plan_progress_verify(g_flow_cfg, &f) != 0 || !plan_progress_certified(&f)) {
        fprintf(stderr, "[warden] --flow-policy %s is not progress-safe (P%d, %s): %s%s%s; "
                "refusing to start\n", cfg_path, f.obligation, plan_decision_name(f.verdict),
                f.reason ? f.reason : "?", f.detail[0] ? ": " : "", f.detail);
        return -1;
    }
    if (!plan_label_policy_config_breaker_enabled(g_flow_cfg)) {
        fprintf(stderr, "[warden] --flow-policy %s declares no refusal_budget. The Warden's "
                "policy can refuse a plan step even when the flow policy cannot, so a "
                "budget is required to bound resubmissions (add, e.g., refusal_budget 3 "
                "and on_exhaustion deny); refusing to start\n", cfg_path);
        return -1;
    }
    const char *fr_action = NULL, *fr_key = NULL;
    if (plan_label_policy_config_field_rule(g_flow_cfg, &fr_action, &fr_key) &&
        !plan_label_policy_config_trusts_declared_fields(g_flow_cfg)) {
        fprintf(stderr, "[warden] --flow-policy %s: a rule for %s matches '%s', a field the plan "
                "step declares. The agent writes its plan, so declaring or omitting a field "
                "changes which rule applies: a rule that permits on a field is unlocked by "
                "declaring it, one that refuses on a field is avoided by leaving it out, and a "
                "field rule placed before a stricter one skips it. Add trust_declared_fields "
                "to the flow policy to accept that; refusing to start\n", cfg_path,
                fr_action ? fr_action : "?", fr_key ? fr_key : "?");
        return -1;
    }
    if (plan_label_policy_config_session_refusal_budget(g_flow_cfg) == 0) {
        fprintf(stderr, "[warden] --flow-policy %s declares no session_refusal_budget. "
                "refusal_budget bounds resubmissions of one plan; without a session limit "
                "a planner that changes one step each time is never stopped (add, e.g., "
                "session_refusal_budget 10); refusing to start\n", cfg_path);
        return -1;
    }
    if (session) {
        size_t n = strlen(session);
        bool ok = n >= 1 && n <= 128;
        for (size_t i = 0; ok && i < n; i++)
            ok = session[i] > 0x20 && session[i] < 0x7f;
        if (!ok) {
            fprintf(stderr, "[warden] --session: 1 to 128 printable characters, no spaces\n");
            return -1;
        }
        g_session = session;
    }

    /* The directory: pinned by descriptor, so the checks hold for every later
     * step. */
    char dir[PATH_MAX];
    const char *name;
    if (!state_path) {
        if (mkdir(BREAKER_DEFAULT_DIR, 0700) < 0 && errno != EEXIST) {
            fprintf(stderr, "[warden] cannot create %s for the breaker state: %s\n",
                    BREAKER_DEFAULT_DIR, strerror(errno));
            return -1;
        }
        snprintf(dir, sizeof dir, "%s", BREAKER_DEFAULT_DIR);
        name = BREAKER_DEFAULT_NAME;
        g_breaker_path = BREAKER_DEFAULT_DIR "/" BREAKER_DEFAULT_NAME;
    } else {
        g_breaker_path = state_path;
        const char *slash = strrchr(state_path, '/');
        name = slash ? slash + 1 : state_path;
        size_t dl = slash ? (size_t)(slash - state_path) : 0;
        if (slash && dl == 0) dl = 1;                       /* "/name" */
        if (dl >= sizeof dir) { fprintf(stderr, "[warden] --breaker-state: path too long\n"); return -1; }
        if (slash) memcpy(dir, state_path, dl); else dir[dl++] = '.';
        dir[dl] = '\0';
    }
    if (!*name || strlen(name) + 5 > NAME_MAX || !strcmp(name, ".") || !strcmp(name, "..")) {
        fprintf(stderr, "[warden] --breaker-state %s: not a file name\n", g_breaker_path);
        return -1;
    }
    snprintf(g_state_name, sizeof g_state_name, "%s", name);
    snprintf(g_state_tmp, sizeof g_state_tmp, "%s.tmp", name);
    char lockname[NAME_MAX + 1];
    snprintf(lockname, sizeof lockname, "%s.lock", name);

    struct stat st;
    g_state_dir = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_state_dir < 0 || fstat(g_state_dir, &st) < 0) {
        fprintf(stderr, "[warden] breaker state directory %s: %s\n", dir, strerror(errno));
        return -1;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 022)) {
        fprintf(stderr, "[warden] breaker state directory %s must be owned by the Warden's "
                "user and writable by no one else (whoever can write it can delete the "
                "table and reset every count); refusing to start\n", dir);
        return -1;
    }
    g_state_lock = openat(g_state_dir, lockname, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (g_state_lock < 0 || fstat(g_state_lock, &st) < 0 || !own_private_file(&st)) {
        fprintf(stderr, "[warden] breaker lock %s/%s: %s; refusing to start\n", dir, lockname,
                g_state_lock < 0 ? strerror(errno)
                                 : "must be a regular file owned by the Warden's user and "
                                   "writable by no one else");
        return -1;
    }
    if (fstatat(g_state_dir, g_state_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && !own_private_file(&st)) {
        fprintf(stderr, "[warden] breaker state %s must be a regular file (not a symlink) owned "
                "by the Warden's user and writable by no one else; refusing to start\n",
                g_breaker_path);
        return -1;
    }
    /* The identity check covers the table inodes this Warden sees; a table that
     * another Warden renames into place later is a new inode. So, as for the
     * verdict stream, refuse a policy that would let the agent open anything
     * the breaker writes in that directory. */
    char rdir[PATH_MAX];
    if (fd_path(g_state_dir, rdir, sizeof rdir) < 0) {
        fprintf(stderr, "[warden] breaker state directory %s: cannot determine its path\n", dir);
        return -1;
    }
    const char *names[3] = { g_state_name, g_state_tmp, lockname };
    for (int i = 0; i < 3; i++) {
        char full[PATH_MAX];
        int fl = snprintf(full, sizeof full, "%s%s%s", rdir, strcmp(rdir, "/") ? "/" : "", names[i]);
        if (fl < 0 || (size_t)fl >= sizeof full || vdpc_path_openable(&pol->c, full, (size_t)fl)) {
            fprintf(stderr, "[warden] the policy would let the agent open the breaker state (%s); "
                    "deny that path or keep the state outside every path the policy allows. "
                    "Refusing to start.\n", full);
            return -1;
        }
    }
    protect_fd(g_state_lock, "breaker_state");
    int sfd = openat(g_state_dir, g_state_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd >= 0) { protect_fd(sfd, "breaker_state"); close(sfd); }
    struct stat dst;
    if (fstat(g_state_dir, &dst) == 0) {
        g_pdir_dev = dst.st_dev;
        g_pdir_ino = dst.st_ino;
        g_pdir_set = true;
    }

    if (gate_status_path) {
        /* A host acts on this file, so it gets the state files' checks: a
         * private directory and file of the Warden's user that the agent cannot
         * reach. Opened non-blocking (a FIFO does not stall startup) and
         * truncated only once it has passed. Empty until the gate decides. */
        char gdir[PATH_MAX];
        const char *gslash = strrchr(gate_status_path, '/');
        const char *gname = gslash ? gslash + 1 : gate_status_path;
        size_t gl = gslash ? (size_t)(gslash - gate_status_path) : 0;
        if (gslash && gl == 0) gl = 1;
        if (!*gname || gl >= sizeof gdir) {
            fprintf(stderr, "[warden] --gate-status %s: not a file name\n", gate_status_path);
            return -1;
        }
        if (gslash) memcpy(gdir, gate_status_path, gl); else gdir[gl++] = '.';
        gdir[gl] = '\0';
        int gd = open(gdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        struct stat gs;
        if (gd < 0 || fstat(gd, &gs) < 0 || gs.st_uid != geteuid() || (gs.st_mode & 022)) {
            fprintf(stderr, "[warden] --gate-status %s: its directory must be owned by the Warden's "
                    "user and writable by no one else; refusing to start\n", gate_status_path);
            if (gd >= 0) close(gd);
            return -1;
        }
        char gdr[PATH_MAX], gfull[PATH_MAX];
        int gfl = fd_path(gd, gdr, sizeof gdr) < 0 ? -1
                : snprintf(gfull, sizeof gfull, "%s%s%s", gdr, strcmp(gdr, "/") ? "/" : "", gname);
        if (gfl < 0 || (size_t)gfl >= sizeof gfull || vdpc_path_openable(&pol->c, gfull, (size_t)gfl)) {
            fprintf(stderr, "[warden] --gate-status %s: the policy would let the agent open it; "
                    "refusing to start\n", gate_status_path);
            close(gd);
            return -1;
        }
        g_gate_status_fd = openat(gd, gname,
                                  O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
        close(gd);
        if (g_gate_status_fd < 0 || fstat(g_gate_status_fd, &gs) < 0 || !own_private_file(&gs) ||
            (!g_check_only && ftruncate(g_gate_status_fd, 0) != 0)) {
            fprintf(stderr, "[warden] --gate-status %s: %s; refusing to start\n", gate_status_path,
                    g_gate_status_fd < 0 ? strerror(errno)
                                         : "must be a regular file owned by the Warden's user and "
                                           "writable by no one else");
            return -1;
        }
        protect_fd(g_gate_status_fd, "gate_status");
    }
    return 0;
}

/* Read the breaker table (under the lock), or fail closed: a table that cannot
 * be read back would otherwise start every count again from zero. */
static plan_breaker_t *breaker_load(void) {
    plan_breaker_t *b = plan_breaker_new();
    if (!b) return NULL;
    int fd = openat(g_state_dir, g_state_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) return b;             /* first use: an empty table */
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !own_private_file(&st)) {
        fprintf(stderr, "[warden] breaker state %s: %s\n", g_breaker_path,
                fd < 0 ? strerror(errno) : "not a private regular file of the Warden's user");
        if (fd >= 0) close(fd);
        plan_breaker_free(b);
        return NULL;
    }
    FILE *in = fdopen(fd, "r");
    if (!in) { close(fd); plan_breaker_free(b); return NULL; }
    int rc = plan_breaker_load(b, in, g_flow_cfg);
    fclose(in);
    if (rc != 0) {
        fprintf(stderr, "[warden] breaker state %s does not read back as a VAREK breaker table "
                "(empty, cut short or altered); refusing the plan. Inspect it; removing it "
                "resets every count.\n", g_breaker_path);
        plan_breaker_free(b);
        return NULL;
    }
    return b;
}

/* Write the table to <name>.tmp, sync it, rename it over <name>, sync the
 * directory. Returns 0 or -1 (errno set). */
static int breaker_store(const plan_breaker_t *b) {
    char *buf = NULL;
    size_t len = 0;
    FILE *m = open_memstream(&buf, &len);
    if (!m) return -1;
    int rc = plan_breaker_save(b, m);
    fclose(m);
    if (rc != 0) { free(buf); errno = EIO; return -1; }
    (void)unlinkat(g_state_dir, g_state_tmp, 0);         /* a leftover from a crash */
    int fd = openat(g_state_dir, g_state_tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { free(buf); return -1; }
    size_t off = 0;
    while (rc == 0 && off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) rc = -1; else off += (size_t)w;
    }
    free(buf);
    if (rc == 0) rc = fsync(fd);
    int e = errno;
    if (close(fd) != 0 && rc == 0) { rc = -1; e = errno; }
    if (rc == 0 && renameat(g_state_dir, g_state_tmp, g_state_dir, g_state_name) != 0) {
        rc = -1; e = errno;
    }
    if (rc != 0) { (void)unlinkat(g_state_dir, g_state_tmp, 0); errno = e; return -1; }
    (void)fsync(g_state_dir);
    /* The new table is a new inode: protect it too. */
    int sfd = openat(g_state_dir, g_state_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd >= 0) { protect_fd(sfd, "breaker_state"); close(sfd); }
    return 0;
}

/* --gate-status: one line, before the agent starts. */
static void gate_status(const char *line) {
    if (g_gate_status_fd < 0) return;
    size_t n = strlen(line);
    if (write(g_gate_status_fd, line, n) != (ssize_t)n || fsync(g_gate_status_fd) != 0)
        fprintf(stderr, "[warden] --gate-status: write failed: %s\n", strerror(errno));
    close(g_gate_status_fd);
    g_gate_status_fd = -1;
}

static int cmp_arg_key(const void *x, const void *y) {
    return strcmp(((const plan_action_arg_t *)x)->key, ((const plan_action_arg_t *)y)->key);
}

static int warden_gate_plan_flow(const char *plan_path, const struct policy *policy) {
    char err[256] = {0};
    plan_parsed_t *parsed = plan_parser_load(plan_path, err, sizeof(err));
    if (!parsed) {
        fprintf(stderr, "[warden] plan load failed: %s\n", err);
        return GATE_ERROR;
    }
    const plan_spec_t *spec = plan_parser_spec(parsed);
    size_t n = spec->n_actions;
    int result = GATE_ERROR;
    exec_plan_t *plan = NULL;
    plan_action_desc_t *acts = NULL;
    plan_action_arg_t *args = NULL;     /* per step: target, then its fields */
    const size_t per_step = 1 + PLAN_FIELDS_MAX;
    char (*canon)[PATH_LIMIT] = NULL;
    plan_breaker_t *br = NULL;

    if (n == 0 || n > PLAN_MAX_NODES || spec->n_edges > PLAN_MAX_EDGES) {
        fprintf(stderr, "[warden] plan rejected: %zu actions and %zu edges (1 to %u actions, "
                "at most %u edges)\n", n, spec->n_edges, PLAN_MAX_NODES, PLAN_MAX_EDGES);
        goto out;
    }
    plan  = exec_plan_new();
    acts  = calloc(n, sizeof *acts);
    args  = calloc(n * per_step, sizeof *args);
    canon = calloc(n, sizeof *canon);
    if (!plan || !acts || !args || !canon) goto out;

    struct warden_plan_ud ud = { .policy = policy, .parsed = parsed, .spec = spec };
    for (size_t i = 0; i < n; i++) {
        const plan_spec_action_t *sa = &spec->actions[i];
        plan_decision_t d = warden_plan_decider(sa, &ud);
        if (exec_plan_add_node(plan, sa->label, d) == PLAN_NODE_ID_INVALID) goto out;
        const char *tgt = sa->target ? sa->target : "";
        char nwhy[200];
        if (sa->kind && strcmp(sa->kind, "file_open") == 0 &&
            plan_lexical_canon(tgt, canon[i], sizeof canon[i]) == 0)
            tgt = canon[i];
        /* v1.21: a connect step's destination in the spelling the node check
         * and the runtime decide on. */
        else if (sa->kind && strcmp(sa->kind, "net_connect") == 0 &&
                 net_plan_canon(tgt, canon[i], sizeof canon[i], nwhy, sizeof nwhy) == 0)
            tgt = canon[i];
        plan_action_arg_t *a = &args[i * per_step];
        a[0].key = "target";
        a[0].value = tgt;
        size_t nf = 0;
        const plan_spec_field_t *fl = plan_parser_fields(parsed, i, &nf);
        if (nf > PLAN_FIELDS_MAX) goto out;
        for (size_t k = 0; k < nf; k++) {
            a[1 + k].key = fl[k].key;
            a[1 + k].value = fl[k].value;
        }
        /* Key order (keys are unique), so declaring the same fields in
         * another order is the same step, and the same breaker signature. */
        qsort(&a[1], nf, sizeof *a, cmp_arg_key);
        acts[i].name = sa->kind ? sa->kind : "";
        acts[i].named_args = a;
        acts[i].n_named_args = 1 + nf;
    }
    for (size_t i = 0; i < spec->n_edges; i++)
        if (exec_plan_add_edge(plan, spec->edges[i].from_idx, spec->edges[i].to_idx) != 0) {
            fprintf(stderr, "[warden] plan rejected: edge %zu is invalid\n", i);
            goto out;
        }

    plan_pathology_opts_t popts = plan_label_policy_config_pathology_opts(g_flow_cfg);
    char pbuf[8192];
    plan_warden_request_t req = {
        .plan = plan, .actions = acts, .n_actions = n,
        .policy = plan_label_policy_config_policy(g_flow_cfg),
        .path_opts = &popts, .pathology_buf = pbuf, .pathology_buf_sz = sizeof pbuf,
    };
    plan_warden_response_t resp;
    if (plan_warden_verify(&req, &resp) != 0)
        resp.verdict = resp.node_axis = resp.flow_axis = PLAN_DEC_UNKNOWN;  /* fail closed */
    if (resp.pathology_emitted) {
        /* Prefixed, so no reader takes it for a verdict record. */
        log_line_start();
        fputs("[warden] plan flow pathology: ", g_log);
        fwrite(pbuf, 1, resp.pathology_len, g_log);
        if (resp.pathology_len && pbuf[resp.pathology_len - 1] != '\n') fputc('\n', g_log);
        fflush(g_log);
    }

    uint32_t *efrom = calloc(spec->n_edges + 1, sizeof *efrom);
    uint32_t *eto   = calloc(spec->n_edges + 1, sizeof *eto);
    if (!efrom || !eto) { free(efrom); free(eto); goto out; }
    for (size_t i = 0; i < spec->n_edges; i++) {
        efrom[i] = spec->edges[i].from_idx;
        eto[i]   = spec->edges[i].to_idx;
    }
    uint64_t sig = plan_breaker_signature_graph(acts, n, efrom, eto, spec->n_edges);
    free(efrom);
    free(eto);
    /* The lock covers read, step and write, and only those: two Wardens
     * gating at once cannot both count from the same table, and neither waits
     * for the other's agent to finish. */
    plan_breaker_result_t r;
    memset(&r, 0, sizeof r);
    r.budget = plan_label_policy_config_refusal_budget(g_flow_cfg);
    r.session_budget = plan_label_policy_config_session_refusal_budget(g_flow_cfg);
    bool state_error = false;
    if (flock(g_state_lock, LOCK_EX) != 0) {
        fprintf(stderr, "[warden] cannot lock the breaker state %s: %s\n", g_breaker_path,
                strerror(errno));
        state_error = true;
    } else {
        br = breaker_load();
        if (!br) {
            state_error = true;
        } else {
            r = plan_breaker_step(br, g_session, sig, resp.verdict, g_flow_cfg);
            if (breaker_store(br) != 0) {
                fprintf(stderr, "[warden] cannot write the breaker state %s (%s); the previous "
                        "table is unchanged; refusing the plan\n", g_breaker_path, strerror(errno));
                state_error = true;
            }
        }
        (void)flock(g_state_lock, LOCK_UN);
    }
    close(g_state_lock);
    g_state_lock = -1;

    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"plan_gate\",\"run\":\"%s\",\"plan\":\"", g_run_id);
    json_escape(f, plan_path);
    fprintf(f, "\",\"actions\":%zu,\"edges\":%zu,\"node_axis\":\"%s\",\"flow_axis\":\"%s\","
               "\"verdict\":\"%s\",\"session\":\"", n, spec->n_edges,
            plan_decision_name(resp.node_axis), plan_decision_name(resp.flow_axis),
            plan_decision_name(resp.verdict));
    json_escape(f, g_session);
    fprintf(f, "\",\"signature\":\"%016" PRIx64 "\",\"breaker\":\"%s\",\"refusals\":%u,"
               "\"budget\":%u,\"session_refusals\":%u,\"session_budget\":%u,"
               "\"session_exhausted\":%s,\"terminal_action\":\"", sig,
            state_error ? "STATE_ERROR" : plan_breaker_outcome_name(r.outcome),
            r.refusals, r.budget, r.session_refusals, r.session_budget,
            r.session_exhausted ? "true" : "false");
    json_escape(f, r.terminal_action ? r.terminal_action : "");
    fprintf(f, "\",\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);

    char st_line[320];
    if (state_error) {
        fprintf(stderr, "[warden] plan refused: the breaker state could not be used (a state "
                "fault, not a verdict on the plan)\n");
        snprintf(st_line, sizeof st_line, "ERROR breaker_state\n");
        result = GATE_ERROR;
        gate_status(st_line);
        goto out;
    }
    switch (r.outcome) {
    case PLAN_BREAKER_PASS:
        fprintf(stderr, "[warden] plan authorized (%zu actions; node %s, flow %s); "
                "proceeding to supervise\n", n, plan_decision_name(resp.node_axis),
                plan_decision_name(resp.flow_axis));
        snprintf(st_line, sizeof st_line, "PASS\n");
        result = GATE_PASS;
        break;
    case PLAN_BREAKER_REFUSED_RETRYABLE:
        fprintf(stderr, "[warden] plan rejected (%s; node %s, flow %s); refusal %u of %u for "
                "this plan and %u of %u in session %s; the host may submit a different plan\n",
                plan_decision_name(resp.verdict), plan_decision_name(resp.node_axis),
                plan_decision_name(resp.flow_axis), r.refusals, r.budget,
                r.session_refusals, r.session_budget, g_session);
        snprintf(st_line, sizeof st_line, "REFUSED_RETRYABLE %u/%u session %u/%u\n",
                 r.refusals, r.budget, r.session_refusals, r.session_budget);
        result = GATE_RETRYABLE;
        break;
    case PLAN_BREAKER_TERMINAL_ACTION:
        fprintf(stderr, "[warden] plan rejected (%s); terminal%s: the host must run the "
                "pre-authorized action %s\n", plan_decision_name(resp.verdict),
                r.session_exhausted ? " (session refusal limit reached)" : "",
                r.terminal_action ? r.terminal_action : "?");
        snprintf(st_line, sizeof st_line, "TERMINAL_ACTION %.256s\n",
                 r.terminal_action ? r.terminal_action : "?");
        result = GATE_TERMINAL_ACTION;
        break;
    default:
        if (r.session_exhausted)
            fprintf(stderr, "[warden] plan rejected (%s); terminal: deny (session %s has "
                    "reached its refusal limit, %u of %u; no further refused plan in it "
                    "may be resubmitted)\n", plan_decision_name(resp.verdict), g_session,
                    r.session_refusals, r.session_budget);
        else
            fprintf(stderr, "[warden] plan rejected (%s); terminal: deny (no further "
                    "submission of this plan in session %s will run)\n",
                    plan_decision_name(resp.verdict), g_session);
        snprintf(st_line, sizeof st_line, "TERMINAL_DENY\n");
        result = GATE_TERMINAL_DENY;
        break;
    }
    gate_status(st_line);

out:
    if (result == GATE_ERROR) gate_status("ERROR\n");     /* no-op once written */
    if (g_state_lock >= 0) { close(g_state_lock); g_state_lock = -1; }
    plan_breaker_free(br);
    free(canon);
    free(args);
    free(acts);
    if (plan) exec_plan_free(plan);
    plan_parser_free(parsed);
    return result;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <policy.txt> [--plan <plan.txt> [--flow-policy <cfg>\n"
        "              [--session <id>] [--breaker-state <file>] [--gate-status <file>]]]\n"
        "              [--sign-key <key>]\n"
        "              [--anchor <path>] [--checkpoint-every <n>] [--run-as <user>]\n"
        "              [--dns-server <a.b.c.d[:port]>] [--dns-ttl-min <s>] [--dns-ttl-max <s>]\n"
        "              [--dns-grace-max <s>] [--psl <file>] [--shared-domains <file>]\n              [--proxy-as <user>] [--proxy-bin <warden-proxy>]\n"
        "              -- <target> [args...]\n"
        "       %s <policy.txt> [the options above] --check-startup   (v1.21)\n"
        "\n"
        "  Privileged seccomp-unotify supervisor (VAREK Warden v1.4).\n"
        "  --check-startup runs the startup checks and exits (0: would start).\n"
        "\n"
        "  Requires CAP_SYS_ADMIN (run as root or via sudo): the target runs\n"
        "  as init of its own PID namespace so it, and everything it spawns,\n"
        "  dies with the Warden. VAREK_WARDEN_NO_PIDNS=1 skips the namespace\n"
        "  and the requirement; processes the agent spawns may then outlive\n"
        "  a crashed Warden.\n"
        "\n"
        "  Optional --plan <plan.txt> enables v1.6 pre-execution plan\n"
        "  verification. The target is not forked unless the plan\n"
        "  verifies as SATISFIED against the loaded policy. A process_exec\n"
        "  step is UNSATISFIED: the runtime refuses launches (v1.18). v1.21: a\n"
        "  net_connect step is decided like the connect it names (a.b.c.d:port,\n"
        "  [IPv6]:port or unix:/path; a host name is UNKNOWN until stage 2).\n"
        "  v1.20: a step may declare key=value fields after its target; they\n"
        "  reach the --flow-policy's rules (see v1_6/plan_parser.h), and a\n"
        "  flow policy whose rules match them must declare trust_declared_fields.\n"
        "  v1.21.1: a file_open step may declare how it opens its file,\n"
        "  open=read or open=O_WRONLY|O_CREAT|O_TRUNC (an access mode, then O_\n"
        "  flags); the node check decides the step with those flags, so a path\n"
        "  allowed only read-only is SATISFIED for a declared read.\n"
        "\n"
        "  v1.18 --flow-policy <cfg> (v1.7 label policy) adds the data-flow check\n"
        "  and the refusal breaker to the gate. At startup <cfg> must pass the v1.9\n"
        "  progress-safety check and declare a refusal_budget and (v1.19) a\n"
        "  session_refusal_budget. Each refused plan counts against that plan and\n"
        "  against its session (--session <id>, default \"default\"), whatever the\n"
        "  plan; reaching either limit is terminal. The counts are\n"
        "  kept in --breaker-state <file> (default /var/lib/varek/breaker.state).\n"
        "  Refused: the agent never runs; exit 3 (the host may re-plan), 4 (terminal\n"
        "  deny) or 5 (terminal: run the pre-authorized action the message names);\n"
        "  1 on an error. Authorized: the exit status is the agent's, which may be\n"
        "  3, 4 or 5 too, so read --gate-status <file> (one line: PASS,\n"
        "  REFUSED_RETRYABLE n/budget session m/limit, TERMINAL_DENY,\n"
        "  TERMINAL_ACTION <name>, ERROR).\n"
        "\n"
        "  v1.16 log integrity: every record is hash-chained. --sign-key <key>\n"
        "  (from tools/varek_keygen) signs run_start, a checkpoint every <n>\n"
        "  records (default 64, and at least once a second) and run_end with\n"
        "  Ed25519; --anchor <path> also appends each checkpoint to <path>\n"
        "  (append-only or off-host storage). tools/varek_audit.py verifies both.\n"
        "\n"
        "  v1.21 decided connections: each connect is decided on the destination\n"
        "  the Warden will dial (host rules; the checker confirms any ALLOW),\n"
        "  dialed by the Warden outside the agent's empty network namespace, and\n"
        "  handed over in place of the agent's socket (SECCOMP_IOCTL_NOTIF_ADDFD).\n"
        "  TCP and UDP over IPv4 and IPv6, and Unix sockets named by a path.\n"
        "  Refused whatever the policy says: sends that name a destination,\n"
        "  abstract Unix addresses, listen and accept, any bind other than a\n"
        "  TCP or UDP socket to the wildcard address and port 0 (which the\n"
        "  Warden performs), other socket kinds.\n"
        "\n"
        , argv0, argv0);
    fputs(
        "  v1.24 host names (with `require warden 1.24`): the Warden resolves\n"
        "  every name an allow rule names, A and AAAA, before the agent runs, and\n"
        "  refreshes each at its TTL clamped to [--dns-ttl-min, --dns-ttl-max]\n"
        "  (default 30 and 3600 s) in a resolver helper; an address that drops\n"
        "  out of an answer stays valid for the old TTL, at most --dns-grace-max\n"
        "  (default 300 s). Each result is a resolution record. --dns-server\n"
        "  resolves through that server instead of the host's resolv.conf (a\n"
        "  validating resolver, or a test server).\n"
        "\n"
        , stderr);
    fputs(
        "  v1.17: the agent runs as an unprivileged user with no capabilities.\n"
        "  --run-as <user|uid[:gid]> picks the user (default nobody); --run-as root\n"
        "  keeps the pre-v1.17 behaviour and prints a warning. The Warden still\n"
        "  opens allowed files for the agent, so the user needs no file access of\n"
        "  its own; it must be able to execute the program (a script's directories\n"
        "  must also be searchable by it).\n"
        "\n"
        "  Policy file format (one rule per line):\n"
        "    allow path /tmp/safe/\n"
        "    deny  path /etc/\n"
        "    allow host 127.0.0.1:8080          (v1.21: the Warden dials it and\n"
        "    allow host [::1]                    hands over the socket; a numeric\n"
        "    allow host unix:/run/app.sock       address, [IPv6] or unix:/path;\n"
        "    deny  host 203.0.113.7              host names: see v1.24 above)\n"
        "    allow host api.example.com:443     (v1.24, after `require warden 1.24`)\n"
        "    allow exec /usr/bin/env\n"
        "    allow path /var/log/ readonly     (v1.13: access=ro -O_CREAT -O_TRUNC)\n"
        "    deny  path suffix .pem            (v1.14 matchers: exact, prefix,\n"
        "    deny  path glob /home/*/.ssh/**    suffix, contains, glob; path and exec)\n"
        "  Path rules also take access=ro|wo|rw, +O_NAME, -O_NAME. Begin a policy\n"
        "  that uses flag clauses with require warden 1.13, matchers with 1.14.\n"
        "  Check a policy with: tools/vdp_check <policy> lint\n"
        "\n"
        "  Plan file format (see varek/v1_6/sample_plan.txt):\n"
        "    action <label> <kind> <target> [key=value | key=\"quoted value\" ...]\n"
        "    edge   <from_label> <to_label>\n"
        "  Fields (v1.20) are declarations: the node check reads only open=\n"
        "  (v1.21.1), and nothing compares the agent's later calls with them.\n"
        "  A file_open target is verified against the policy on its lexically\n"
        "  canonical path (. and .. collapsed); it must be absolute. Symlinks\n"
        "  are not followed at plan time (there is no agent yet), so the gate is\n"
        "  an advisory pre-check and every open is still mediated at runtime.\n",
        stderr);
}

int main(int argc, char **argv) {
    /* v1.24: the resolver helper is this program re-executed (a clean address
     * space, without the signing key); see warden_resolve.h. */
    if (argc >= 2 && !strcmp(argv[1], "--resolver-helper")) return wr_helper_exec_main(argc, argv);
    /* v1.26.1: the egress proxy is its own program, warden-proxy (see
     * proxy_bin below); this binary no longer has a --proxy-helper mode. */
    /* Positional parse with optional --plan between policy_path and --.
     * Accepted forms:
     *   warden policy.txt -- target [args...]
     *   warden policy.txt --plan plan.txt -- target [args...] */
    /* v1.21: `warden <policy> [options] --check-startup` runs every check the
     * Warden makes before it starts an agent (the policy in both parsers, the
     * verdict stream, --sign-key, --anchor, raw devices, and with
     * --flow-policy the flow policy's progress safety and budgets, the breaker
     * state directory, lock and table, and --gate-status), then exits: 0 if
     * the Warden would start, 1 with the reason otherwise. No agent runs and
     * no verdict stream is written. tools/varek_preflight.sh uses it. */
    for (int i = 2; i < argc && strcmp(argv[i], "--"); i++)
        if (!strcmp(argv[i], "--check-startup")) g_check_only = true;
    if (argc < (g_check_only ? 3 : 4)) { usage(argv[0]); return 2; }

    const char *policy_path = argv[1];
    const char *plan_path   = NULL;
    const char *key_path    = NULL;     /* v1.16 */
    const char *anchor_path = NULL;     /* v1.16 */
    const char *run_as_arg  = NULL;     /* v1.17.0 */
    const char *proxy_as_arg = NULL;    /* v1.26: the egress proxy's user */
    const char *proxy_bin_arg = NULL;   /* v1.26.1: the warden-proxy binary */
    const char *flow_path   = NULL;     /* v1.18.0 */
    const char *session_arg = NULL;     /* v1.18.0 */
    const char *state_arg   = NULL;     /* v1.18.0 */
    const char *gstatus_arg = NULL;     /* v1.18.0 */
    wr_config_t dns_cfg;                /* v1.24 */
    const char *psl_arg = NULL, *shared_arg = NULL;   /* v1.25 */
    wr_config_default(&dns_cfg);
    int sep_idx = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep_idx = i; break; }
        if (strcmp(argv[i], "--check-startup") == 0) continue;
        if (i + 1 >= argc) { usage(argv[0]); return 2; }
        if (strcmp(argv[i], "--plan") == 0 && !plan_path) {
            plan_path = argv[++i];
        } else if (strcmp(argv[i], "--flow-policy") == 0 && !flow_path) {
            flow_path = argv[++i];
        } else if (strcmp(argv[i], "--session") == 0 && !session_arg) {
            session_arg = argv[++i];
        } else if (strcmp(argv[i], "--breaker-state") == 0 && !state_arg) {
            state_arg = argv[++i];
        } else if (strcmp(argv[i], "--gate-status") == 0 && !gstatus_arg) {
            gstatus_arg = argv[++i];
        } else if (strcmp(argv[i], "--sign-key") == 0 && !key_path) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--anchor") == 0 && !anchor_path) {
            anchor_path = argv[++i];
        } else if (strcmp(argv[i], "--run-as") == 0 && !run_as_arg) {
            run_as_arg = argv[++i];
        } else if (strcmp(argv[i], "--proxy-as") == 0 && !proxy_as_arg) {   /* v1.26 */
            proxy_as_arg = argv[++i];
        } else if (strcmp(argv[i], "--proxy-bin") == 0 && !proxy_bin_arg) { /* v1.26.1 */
            proxy_bin_arg = argv[++i];
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
        } else if (strcmp(argv[i], "--psl") == 0 && !psl_arg) {
            psl_arg = argv[++i];                                            /* v1.25 */
        } else if (strcmp(argv[i], "--shared-domains") == 0 && !shared_arg) {
            shared_arg = argv[++i];                                         /* v1.25 */
        } else if (strcmp(argv[i], "--dns-server") == 0 && !dns_cfg.server) {
            dns_cfg.server = argv[++i];                                     /* v1.24 */
        } else if (strcmp(argv[i], "--dns-ttl-min") == 0 || strcmp(argv[i], "--dns-ttl-max") == 0 ||
                   strcmp(argv[i], "--dns-grace-max") == 0) {
            const char *opt = argv[i], *v = argv[++i];
            uint32_t n = 0;
            size_t k = 0;
            for (; v[k] >= '0' && v[k] <= '9' && k < 6; k++) n = n * 10 + (uint32_t)(v[k] - '0');
            if (k == 0 || v[k] || n > 86400 || (n < 1 && strcmp(opt, "--dns-grace-max"))) {
                fprintf(stderr, "[warden] %s takes %s to 86400 (seconds)\n", opt,
                        strcmp(opt, "--dns-grace-max") ? "1" : "0");
                return 2;
            }
            if (!strcmp(opt, "--dns-ttl-min")) dns_cfg.ttl_min = n;
            else if (!strcmp(opt, "--dns-ttl-max")) dns_cfg.ttl_max = n;
            else dns_cfg.grace_max = n;
        } else {
            usage(argv[0]); return 2;
        }
    }

    if (!g_check_only && (sep_idx < 0 || sep_idx + 1 >= argc)) { usage(argv[0]); return 2; }
    if (flow_path && !plan_path && !g_check_only) {
        fprintf(stderr, "[warden] --flow-policy checks a plan; give --plan too\n");
        return 2;
    }
    if ((session_arg || state_arg || gstatus_arg) && !flow_path) {
        fprintf(stderr, "[warden] --session, --breaker-state and --gate-status need --flow-policy\n");
        return 2;
    }
    char *const *target_argv = sep_idx >= 0 && sep_idx + 1 < argc ? &argv[sep_idx + 1] : NULL;

    /* v1.17.0: who the agent runs as, and the program it launches. */
    struct run_as ra;
    int prc = parse_run_as(run_as_arg ? run_as_arg : "nobody", &ra);
    if (prc == -2) {
        fprintf(stderr, "[warden] --run-as %s: an unprivileged user in group 0 (root) is refused; "
                "name a non-root group\n", run_as_arg ? run_as_arg : "nobody");
        return 2;
    }
    if (prc < 0) {
        fprintf(stderr, "[warden] --run-as %s: no such user (give a name, uid or uid:gid)\n",
                run_as_arg ? run_as_arg : "nobody");
        return 2;
    }
    if (!ra.drop)
        fprintf(stderr, "[warden] WARNING: --run-as root: the agent runs as root with every "
                "capability (the pre-v1.17 behaviour); only the seccomp filter holds it back\n");
    static char boot_path[PATH_MAX];
    if (target_argv && find_program(target_argv[0], boot_path, sizeof boot_path) < 0) {
        fprintf(stderr, "[warden] %s: program not found (or not a regular file)\n", target_argv[0]);
        return 127;
    }

    const int pidns = getenv("VAREK_WARDEN_NO_PIDNS") == NULL;
    if (pidns && !have_cap_sys_admin() && !g_check_only) {
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
    load_raw_char_majors();                 /* v1.17.0 */
    load_ancestors(&p);                     /* v1.17.0 */
    if (refuse_exposed_stream(&p) < 0) return 1;
    if (key_path && load_sign_key(key_path, &p) < 0) return 1;
    if (anchor_path && open_anchor(anchor_path, &p) < 0) return 1;
    if ((key_path || anchor_path) && refuse_raw_devices(&p) < 0) return 1;
    if (flow_path && flow_setup(&p, flow_path, state_arg, session_arg, gstatus_arg) < 0)
        return 1;                                                           /* v1.18.0 */
    if (names_setup(&p, &dns_cfg) < 0) return 1;                            /* v1.24 */
    if (wildcards_check(policy_path, &p, psl_arg, shared_arg) < 0) return 1;            /* v1.25 */
    if (g_any_name) views_setup();
    /* v1.26: the egress proxy runs as its own user, never the agent's: the
     * default is varek-proxy where that user exists, else 65532:65532. */
    struct run_as pxa = { .drop = false };
    if (p.v.proxy) {
        const char *pas = proxy_as_arg ? proxy_as_arg : getpwnam("varek-proxy") ? "varek-proxy" : "65532:65532";
        if (parse_run_as(pas, &pxa) < 0 || !pxa.drop) {
            fprintf(stderr, "[warden] --proxy-as %s: give an unprivileged user (name, uid or uid:gid) "
                    "with a non-root group\n", pas);
            return 2;
        }
        if (pxa.uid == ra.uid) {
            fprintf(stderr, "[warden] --proxy-as %s: the proxy may not run as the agent's user "
                    "(--run-as); give it its own\n", pas);
            return 2;
        }
    }
    /* v1.26.1 (step 1): inspecting mode is parsed and checked, but this
     * Warden cannot yet terminate TLS or decide requests, so it does not run
     * such a policy as SNI mode, which would allow requests the request rules
     * refuse; nor does --check-startup say it would (`vdp_check <policy>
     * lint` checks such a policy). */
    if (p.v.proxy_inspect) {
        fprintf(stderr, "[warden] `proxy inspect`: inspecting mode is not built into this Warden yet "
                "(v1.26.1 in progress); refusing to start\n");
        if (g_sk) sodium_free(g_sk);
        return 2;
    }
    /* v1.26 (step 8): with `proxy on`, names reach proxied ports only through
     * the proxy, which needs root to start as its own user: a Warden that
     * cannot start it does not run the policy without it. */
    if (p.v.proxy && geteuid() != 0 && !g_check_only) {
        fprintf(stderr, "[warden] `proxy on` needs the Warden to run as root (the proxy runs as its "
                "own user); refusing to start\n");
        if (g_sk) sodium_free(g_sk);
        return 2;
    }
    /* v1.26.1: the proxy is warden-proxy, beside this binary unless
     * --proxy-bin names it. It is copied into a sealed memfd and hashed, and
     * that copy is what runs, so run_start's hash is of what ran. */
    int proxy_fd = -1;
    if (p.v.proxy) {
        char pb[PATH_MAX], why[PATH_MAX + 128];
        if (proxy_bin_arg) snprintf(pb, sizeof pb, "%s", proxy_bin_arg);
        else {
            ssize_t n = readlink("/proc/self/exe", pb, sizeof pb - 16);
            if (n <= 0) { fprintf(stderr, "[warden] cannot find this binary's directory\n"); return 1; }
            pb[n] = '\0';
            char *sl = strrchr(pb, '/');
            snprintf(sl ? sl + 1 : pb, sizeof pb - (size_t)(sl ? sl + 1 - pb : 0), "warden-proxy");
        }
        proxy_fd = wp_load(pb, g_proxy_sha, why, sizeof why);
        if (proxy_fd < 0) {
            fprintf(stderr, "[warden] the egress proxy: %s; build it (make warden-proxy) or name it with "
                    "--proxy-bin; refusing to start\n", why);
            if (g_sk) sodium_free(g_sk);
            return 1;
        }
        fprintf(stderr, "[warden] egress proxy binary %s, SHA-256 %s\n", pb, g_proxy_sha);
    }
    if (p.v.proxy && geteuid() == 0) {
        if (wp_start(&g_proxy, proxy_fd, pxa.uid, pxa.gid) < 0) {
            fprintf(stderr, "[warden] cannot start the egress proxy (%s); refusing to start\n",
                    strerror(errno));
            if (g_sk) sodium_free(g_sk);
            return 1;
        }
        fprintf(stderr, "[warden] egress proxy (SNI mode) on 127.0.0.1:%u as %u:%u\n",
                g_proxy.port, (unsigned)g_proxy.uid, (unsigned)g_proxy.gid);
    }
    if (proxy_fd >= 0) close(proxy_fd);
    if (g_check_only) {
        /* v1.24: resolve each allowed name and report the ones that fail (a
         * name that does not resolve does not stop the Warden). */
        if (g_names_on) {
            if (wr_async_start(&g_names, "/proc/self/exe") < 0) {
                fprintf(stderr, "[warden] cannot start the resolver helper (%s)\n", strerror(errno));
                return 1;
            }
            names_resolve_all(false);
            wr_async_stop(&g_names);
        }
        fprintf(stderr, "[warden] startup checks passed: the policy%s%s%s%s would be accepted%s\n",
                key_path ? ", the signing key" : "", anchor_path ? ", the anchor" : "",
                flow_path ? ", the flow policy, the breaker state" : "",
                gstatus_arg ? ", --gate-status" : "",
                pidns && !have_cap_sys_admin() ? " (but this user lacks CAP_SYS_ADMIN, which "
                "a run needs)" : "");
        if (g_sk) sodium_free(g_sk);
        return 0;
    }
    if (!target_argv) { usage(argv[0]); return 2; }
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
    /* v1.24: every allowed host name is resolved before the agent runs.
     * Refreshes then run in a resolver helper process (warden_resolve.c),
     * started now: while the Warden is single-threaded and before the agent's
     * PID namespace exists. Without it the table would go stale, so a failure
     * to start it stops the run. */
    if (g_names_on) {
        if (wr_async_start(&g_names, "/proc/self/exe") < 0) {
            fprintf(stderr, "[warden] cannot start the resolver helper (%s); refusing to start\n",
                    strerror(errno));
            emit_run_end(1);
            if (g_sk) sodium_free(g_sk);
            return 1;
        }
        names_resolve_all(true);
    }

    /* v1.6 pre-execution plan verification. Fires before fork; on
     * any non-SATISFIED result the target is not started. */
    if (plan_path && g_flow_cfg) {
        /* v1.18.0: node + flow check, refusal breaker (exit 3, 4 or 5). */
        int gate = warden_gate_plan_flow(plan_path, &p);
        if (gate != GATE_PASS) {
            emit_run_end(gate);
            if (g_sk) sodium_free(g_sk);
            return gate;
        }
    } else if (plan_path && warden_verify_plan(plan_path, &p) != 0) {
        emit_run_end(1);                    /* v1.16: a closed (and signed) stream */
        if (g_sk) sodium_free(g_sk);
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
        /* v1.12.1 network namespace: needs CAP_SYS_ADMIN, so before the drop. */
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
        /* v1.17.0: open the program while still root, so the unprivileged
         * user needs only execute permission on the file itself, not on every
         * directory above it. A script (#!) is launched by its path instead:
         * its interpreter must open it by name. */
        int exec_fd = open(boot_path, O_RDONLY | O_CLOEXEC);
        if (exec_fd < 0) {
            fprintf(stderr, "[warden-target] %s: %s\n", boot_path, strerror(errno));
            _exit(127);
        }
        char magic[2] = {0, 0};
        bool is_script = pread(exec_fd, magic, 2, 0) == 2 && magic[0] == '#' && magic[1] == '!';
        if (ra.drop) {
            int drc = drop_privileges(&ra);
            if (drc < 0) {
                fprintf(stderr, "[warden-target] cannot drop to uid %u gid %u (%s); "
                                "refusing to run\n", (unsigned)ra.uid, (unsigned)ra.gid,
                                strerror(-drc));
                _exit(1);
            }
        }
        /* After the credential change: PR_SET_PDEATHSIG is cleared by one. */
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
        extern char **environ;
        if (is_script) {
            close(exec_fd);
            execv(boot_path, target_argv);
        } else {
            syscall(__NR_execveat, exec_fd, "", target_argv, environ, AT_EMPTY_PATH);
        }
        fprintf(stderr, "[warden-target] cannot execute %s as uid %u: %s%s\n", boot_path,
                (unsigned)getuid(), strerror(errno),
                errno == EACCES ? " (the user --run-as names must be able to execute it; "
                                  "for a script, every directory above it must be "
                                  "searchable too)" : "");
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
        close(sv[0]); kill_target_tree(target); waitpid(target, NULL, 0);
        (void)relay_agent_stderr(agent_err_fd, true);   /* v1.17.0: the child's reason */
        fprintf(stderr, "[warden] the agent's setup failed before supervision began "
                        "(see the [agent] lines above)\n");
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
        /* v1.21: both namespaces, held open: a connect's socket options are
         * compared with a socket made in the agent's (warden_net.inc.c). */
        g_host_netns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        g_agent_netns = open(path, O_RDONLY | O_CLOEXEC);
        g_netns_separate = !strcmp(netns, "on");
        if (g_netns_separate && (g_host_netns < 0 || g_agent_netns < 0)) {
            fprintf(stderr, "[warden] cannot hold the network namespaces (%s); refusing to "
                    "supervise\n", strerror(errno));
            kill_target_tree(target);
            waitpid(target, NULL, 0);
            return 1;
        }
        sockref_warm();
        stub_setup();                   /* v1.25 */
    }
    /* v1.21: up to MAX_PENDING connects and sends can wait in the Warden, each
     * holding a socket: raise the Warden's own descriptor limit (after the
     * fork, so the agent keeps its own). */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max < 65536 ? rl.rlim_max : 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
    fprintf(stderr,
        "[warden] supervising pid=%d  notify_fd=%d  policy=%s (%zu rules)  pidns=%s  netns=%s"
        "  uid=%u%s\n",
        target, notify_fd, p.name, p.v.n, pidns ? "on" : "off", netns,
        (unsigned)ra.uid, ra.drop ? " caps=none" : " caps=all");

    bool agent_ended = supervise(notify_fd, target_pidfd, agent_err_fd, &p,
                                 boot_path, target);
    agent_ended = agent_ended || g_child_exited;   /* before the Warden's own SIGKILL */

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
    /* v1.16: SIGCHLD also stops the loop, and then the agent ended on its own
     * (agent_ended above; through v1.15 that race lost this report about one
     * run in four). */
    if (agent_ended && WIFSIGNALED(status))
        fprintf(stderr, "[warden] agent killed by signal %d (%s)%s\n",
                WTERMSIG(status), strsignal(WTERMSIG(status)),
                WTERMSIG(status) == SIGSYS
                    ? ": most likely a hard-denied system call" : "");
    if (g_names_on) wr_async_stop(&g_names);    /* v1.24 */
    emit_run_end(rc);
    anchor_drain();
    if (g_sk) sodium_free(g_sk);             /* zeroes it */
    close(target_pidfd);
    close(notify_fd);
    return rc;
}
