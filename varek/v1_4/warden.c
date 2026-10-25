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
 * Requires: Linux kernel >= 5.14, x86_64 or aarch64 (BPF arch check).
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
#include <sys/mount.h>     /* v1.27.1: writable directories mounted noexec */
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <openssl/crypto.h>   /* v1.29: SHA-256 of the launch set (warden_exec.inc.c) */
#include <openssl/evp.h>
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
#include "warden_oci.h"                 /* v1.34 step 3 */
#include "smt_decide.h"            /* v1.13 SMT decision procedure */
#include "checker/vdp_checker.h"   /* v1.15 independent certificate checker */
#include "warden_lifecycle.h"   /* v1.9.3 supervisor/target lifecycle coupling */
#include "warden_resolve.h"     /* v1.24 resolution table for host name rules */
#include "shared_domains.h"     /* v1.25 wildcards over shared domains, refused at load */
#include "warden_proxy.h"       /* v1.26 the egress proxy process */
#include "warden_secrets.h"     /* v1.28 the credentials' helper, warden-secrets */
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

#if defined(__x86_64__)
#define ARCH_NR     AUDIT_ARCH_X86_64
#define WARDEN_ARCH "x86_64"            /* run_start's arch (v1.30) */
#define WARDEN_O_LARGEFILE 0100000      /* the kernel's bit (glibc's O_LARGEFILE is 0) */
#elif defined(__aarch64__)
#define ARCH_NR     AUDIT_ARCH_AARCH64
#define WARDEN_ARCH "aarch64"
#define WARDEN_O_LARGEFILE 0400000
#else
#error "VAREK Warden supports x86_64 and aarch64"
#endif
/* v1.30: arm64 has only the *at forms of these calls. A number no call
 * carries stands in for each, so the comparisons below never match there. */
#ifndef __NR_open
#define __NR_open     (-101)
#endif
#ifndef __NR_stat
#define __NR_stat     (-102)
#endif
#ifndef __NR_lstat
#define __NR_lstat    (-103)
#endif
#ifndef __NR_access
#define __NR_access   (-104)
#endif
#ifndef __NR_readlink
#define __NR_readlink (-105)
#endif
#ifndef __NR_unlink
#define __NR_unlink   (-106)
#endif
#ifndef __NR_rmdir
#define __NR_rmdir    (-107)
#endif
#ifndef __NR_mkdir
#define __NR_mkdir    (-108)
#endif
#ifndef __NR_rename
#define __NR_rename   (-109)
#endif
#ifndef __NR_chmod
#define __NR_chmod    (-110)
#endif
#define PATH_LIMIT  4096
#define MAX_RULES    512
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
    ACT_NET_REQUEST,     /* v1.26.1: a request of an inspected connection (its object) */
    ACT_FILE_CHANGE,     /* v1.29: a change by name (warden_change.inc.c): chg_op says which */
    ACT_NET_MCP,         /* v1.31: an MCP call over HTTP (warden_pxdecide.inc.c): its object */
    ACT_OTHER,
} action_kind_t;

/* v1.29 (warden_change.inc.c): the changes by name */
enum { CHG_UNLINK = 1, CHG_RMDIR, CHG_MKDIR, CHG_RENAME_FROM, CHG_RENAME_TO, CHG_CHMOD,
       CHG_UTIME, CHG_TRUNCATE, CHG_CHDIR };

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
    int           subject;              /* v1.28.1: who the call is for (warden_subagent.inc.c): 0 the
                                           agent, a sub-agent, or -1 (in no group of the run) */
    int           plan_psubj;           /* v1.35 (D6): a plan step's policy subject, plus 1 (0: none,
                                           the subject is the call's attribution, as at run time) */
    /* v1.29: a change by name (warden_change.inc.c) */
    int           chg_op;               /* CHG_* */
    char          target2[PATH_LIMIT];  /* a rename's new name */
    int           chg_dirfd, chg_dirfd2;
    unsigned      chg_flags;            /* unlinkat's, renameat2's, utimensat's */
    unsigned      chg_mode;
    int64_t       chg_len;
    int           chg_fd;               /* the descriptor of ftruncate, fchmod, futimens */
    struct timespec chg_times[2];
    bool          chg_times_null;
    bool          dry;                  /* v1.29: a refusal a dry run let through (not enforced) */
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
        case ACT_NET_REQUEST:   return "net.request";
        case ACT_FILE_CHANGE:   return "file.change";
        case ACT_NET_MCP:       return "net.mcp";
        case ACT_OTHER:        return "other";
    }
    return "invalid";
}

/* ---------------- v1.29: the dry run (docs/security/v1.29-varek-run.md, section 3) ----------------
 *
 * `--dry-run`, given per run on the command line only (D3): every call is
 * decided, certified and recorded as when enforcing; a call the POLICY
 * refuses is then let through (D1) and its record says "enforced":false:
 * a file open, lookup, change or launch goes to the kernel as the agent's own
 * user (CONTINUE), a connect is dialed by the Warden as an allowed one is, the
 * stub answers a name no rule reaches, the proxy relays a request no rule
 * allows (with no credential), and a system call outside the allowlist,
 * which the filter then sends here, goes to the kernel. Refused all the same
 * (D2), recorded as enforced: the hard-denied system calls (the filter), the
 * protected objects, raw devices, the views, kernel filesystems, anything the
 * Warden could not resolve, the sub-agents' attribution, and every call after
 * `varek revoke` or the user token's expiry. */
static bool     g_dry = false;
static uint64_t g_dry_unenforced = 0;

/* the record rules of a refusal the policy made (a dry run lets those through) */
static bool dry_policy_rule(const char *rule) {
    static const char *const kLet[] = {
        "policy_match", "default_deny_unknown", "fragment_escape_flags", "fragment_escape_length",
        "certificate_refused", "exec_not_in_ruleset", "exec_no_landlock", "syscall_not_admitted",
        "rename_to_refused", "rename_from_refused", "max_body", NULL };
    for (int i = 0; rule && kLet[i]; i++) if (!strcmp(rule, kLet[i])) return true;
    return false;
}

/* In a dry run, a refusal by rule is let through: mark a, true. */
static bool dry_let(struct action *a, const char *rule) {
    if (!g_dry || !dry_policy_rule(rule)) return false;
    a->dry = true;
    return true;
}

/* ---------------- Policy ---------------- */

/* v1.13: the policy is parsed and decided by the SMT decision procedure in
 * smt_decide.c. See smt_decide.h for the fragment (bounded strings for the
 * path/host/exec constant, a 32-bit bitvector for open flags), the verdict
 * semantics, and the soundness obligations. v1.14 adds the bounded string
 * fragment: exact, prefix, suffix, contains and glob matchers. */
/* v1.29 (docs/security/v1.29-varek-run.md, section 2): a baseline `varek
 * run` wrote says, in its first lines, what it was made for:
 *   #@ varek baseline 1
 *   #@ profile NAME SHA256        (or: #@ profile none -)
 *   #@ cwd PATH   #@ home PATH   #@ user NAME   #@ tmp PATH
 * Comments to the parsers; the Warden reads them from the same bytes it
 * hashes and copies them into run_start's `baseline`. */
struct baseline_hdr {
    bool on;
    char profile[33], profile_sha[65];
    char cwd[PATH_MAX], home[PATH_MAX], user[64], tmp[PATH_MAX];
};

struct policy {
    char          name[64];
    char          version[16];
    vdp_policy_t  v;
    vdpc_policy_t c;                    /* v1.15: the checker's own parse */
    char          sha256[65];           /* v1.15: of the policy bytes both parsed */
    struct baseline_hdr base;           /* v1.29 */
};

/* v1.29: 0 (b->on says whether the policy is a baseline), or -1 with why */
static int baseline_parse(const char *buf, size_t len, struct baseline_hdr *b, char *why, size_t wn) {
    static const char kHead[] = "#@ varek baseline ";
    memset(b, 0, sizeof *b);
    if (len < sizeof kHead - 1 || memcmp(buf, kHead, sizeof kHead - 1)) return 0;
    size_t pos = 0;
    int line = 0;
    bool seen[5] = { false };
    while (pos < len && len - pos >= 3 && !memcmp(buf + pos, "#@ ", 3)) {
        const char *nl = memchr(buf + pos, '\n', len - pos);
        size_t ll = nl ? (size_t)(nl - (buf + pos)) : len - pos;
        char l[PATH_MAX + 32];
        if (ll >= sizeof l) { snprintf(why, wn, "baseline header line %d is too long", line + 1); return -1; }
        memcpy(l, buf + pos, ll);
        l[ll] = '\0';
        pos += ll + (nl ? 1 : 0);
        line++;
        for (size_t i = 3; i < ll; i++)
            if ((unsigned char)l[i] < 0x20 || (unsigned char)l[i] > 0x7e) {
                snprintf(why, wn, "baseline header line %d holds a byte outside printable ASCII", line);
                return -1;
            }
        if (line == 1) {
            if (strcmp(l, "#@ varek baseline 1")) {
                snprintf(why, wn, "a baseline of a format this Warden does not know (%.40s)", l + 3);
                return -1;
            }
            continue;
        }
        char *key = l + 3, *val = strchr(key, ' ');
        if (!val || !val[1]) { snprintf(why, wn, "baseline header line %d has no value", line); return -1; }
        *val++ = '\0';
        static const char *const kKeys[] = { "profile", "cwd", "home", "user", "tmp" };
        int k = -1;
        for (int i = 0; i < 5; i++) if (!strcmp(key, kKeys[i])) k = i;
        if (k < 0) { snprintf(why, wn, "baseline header line %d: unknown key %.32s", line, key); return -1; }
        if (seen[k]) { snprintf(why, wn, "baseline header: %.16s given twice", key); return -1; }
        seen[k] = true;
        if (k == 0) {
            char nm[64], sh[80];
            if (sscanf(val, "%63s %79s", nm, sh) != 2 || strlen(nm) > 32 || strlen(sh) > 64 ||
                (strcmp(nm, "none") && strlen(sh) != 64) || (!strcmp(nm, "none") && strcmp(sh, "-"))) {
                snprintf(why, wn, "baseline header: need `#@ profile NAME SHA256` or `#@ profile none -`");
                return -1;
            }
            snprintf(b->profile, sizeof b->profile, "%s", nm);
            snprintf(b->profile_sha, sizeof b->profile_sha, "%s", strcmp(nm, "none") ? sh : "");
        } else if (k == 3) {
            if (strlen(val) >= sizeof b->user) { snprintf(why, wn, "baseline header: user too long"); return -1; }
            snprintf(b->user, sizeof b->user, "%s", val);
        } else {
            if (val[0] != '/') { snprintf(why, wn, "baseline header: %.16s is not an absolute path", key); return -1; }
            char *dst = k == 1 ? b->cwd : k == 2 ? b->home : b->tmp;
            snprintf(dst, PATH_MAX, "%s", val);
        }
    }
    for (int i = 0; i < 5; i++)
        if (!seen[i]) { snprintf(why, wn, "baseline header: a line is missing (profile, cwd, home, user, tmp)"); return -1; }
    b->on = true;
    return 0;
}

#define POLICY_MAX_BYTES (16u << 20)

static int policy_load(const char *path, struct policy *p) {
    memset(p, 0, sizeof(*p));
#ifdef VDP_FAULT_INJECT
    fprintf(stderr, "[warden] WARNING: TEST BUILD with a planted decision-procedure bug "
            "(warden_faultinject); never use it to supervise a real agent\n");
#endif
    snprintf(p->name,    sizeof(p->name),    "default");
    /* the grammar this Warden implements (v1.27: from smt_decide.h, not a copy) */
    snprintf(p->version, sizeof(p->version), "%d.%d", VDP_WARDEN_MAJOR, VDP_WARDEN_MINOR);
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
    if (baseline_parse(buf, len, &p->base, err, sizeof err) < 0) {     /* v1.29 */
        fprintf(stderr, "[warden] policy %s: %s; refusing to start\n", path, err);
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
            [VDP_KIND_REQUEST] = VDPC_REQUEST, [VDP_KIND_MCP] = VDPC_MCP,
        };
        if (vdpc_rule_info(&p->c, i, &ci) < 0 || ci.allow != (r->verb == VDP_ALLOW) ||
            ci.kind != kind_to_c[r->kind] || ci.match != op_to_match[r->s.op] ||
            ci.clen != r->s.len || memcmp(ci.c, r->s.c, r->s.len) != 0 ||
            ci.mask != r->b.mask || ci.value != r->b.value || ci.line != r->line ||
            ci.portless != r->s.portless || ci.name != r->s.name || ci.wild != r->s.wild ||
            ci.names != r->names || ci.rate != r->rate || ci.max_body != r->max_body ||
            /* v1.28: the credential a request rule carries, and where */
            ci.cred != r->cred || strcmp(ci.cred_hdr, r->cred_hdr) || strcmp(ci.cred_scheme, r->cred_scheme) ||
            /* v1.28.1: the sub-agent an exec rule names */
            strcmp(ci.subagent, r->subagent) ||
            /* v1.31: the subject a rule decides for, the confined subject it launches, an mcp server's pin */
            ci.subj != r->subj || ci.confined_subj != r->confined_subj || ci.mcp_server != r->mcp_server ||
            strcmp(ci.sha256, r->sha256)) {
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
    /* v1.27 review: and whether launches after the first are decided, so the
     * checker's own reading gates them too (exec_launch requires it) */
    if (p->v.launches != (p->c.launches != 0)) {
        fprintf(stderr, "[warden] policy %s: the decision procedure and the certificate checker read "
                "require warden differently (launches %s and %s); refusing to start\n", path,
                p->v.launches ? "on" : "off", p->c.launches ? "on" : "off");
        return -1;
    }
    /* v1.29: and whether files are opened as the agent */
    if (p->v.open_as_agent != (p->c.open_as_agent != 0)) {
        fprintf(stderr, "[warden] policy %s: the decision procedure and the certificate checker read "
                "require warden differently (opening as the agent %s and %s); refusing to start\n", path,
                p->v.open_as_agent ? "on" : "off", p->c.open_as_agent ? "on" : "off");
        return -1;
    }
    /* v1.28: and the credentials (name, store, reference), in order */
    bool creds_same = p->v.ncreds == p->c.ncreds;
    for (size_t k = 0; creds_same && k < p->v.ncreds; k++)
        creds_same = !strcmp(p->v.creds[k].name, p->c.creds[k].name) &&
                     p->v.creds[k].store == p->c.creds[k].store &&
                     !strcmp(p->v.creds[k].ref, p->c.creds[k].ref) && p->v.creds[k].line == p->c.creds[k].line &&
                     /* v1.31: an MCP access token's audience */
                     !strcmp(p->v.creds[k].audience, p->c.creds[k].audience) &&
                     p->v.creds[k].opaque == (p->c.creds[k].opaque != 0);
    if (!creds_same) {
        fprintf(stderr, "[warden] policy %s: the decision procedure and the certificate checker read "
                "the credentials differently; refusing to start\n", path);
        return -1;
    }
    /* v1.28.1: and the identities the run trusts */
    bool id_same = p->v.nissuers == p->c.nissuers && p->v.nspiffe == p->c.nspiffe &&
                   p->v.require_obo == (p->c.require_obo != 0);
    for (size_t k = 0; id_same && k < p->v.nissuers; k++)
        id_same = !strcmp(p->v.issuers[k].iss, p->c.issuers[k].iss) && !strcmp(p->v.issuers[k].aud, p->c.issuers[k].aud) &&
                  !strcmp(p->v.issuers[k].jwks, p->c.issuers[k].jwks) && p->v.issuers[k].line == p->c.issuers[k].line;
    for (size_t k = 0; id_same && k < p->v.nspiffe; k++)
        id_same = !strcmp(p->v.spiffe[k].domain, p->c.spiffe[k].domain) &&
                  !strcmp(p->v.spiffe[k].bundle, p->c.spiffe[k].bundle) && p->v.spiffe[k].line == p->c.spiffe[k].line;
    /* v1.31: the MCP resources trusted for the user's token, and the confined subjects */
    id_same = id_same && p->v.nmcpres == p->c.nmcpres && p->v.nsubjects == p->c.nsubjects;
    for (size_t k = 0; id_same && k < p->v.nmcpres; k++)
        id_same = !strcmp(p->v.mcpres[k].url, p->c.mcpres[k].url) && !strcmp(p->v.mcpres[k].aud, p->c.mcpres[k].aud) &&
                  p->v.mcpres[k].line == p->c.mcpres[k].line;
    for (size_t k = 0; id_same && k < p->v.nsubjects; k++)
        id_same = !strcmp(p->v.subjects[k].name, p->c.subjects[k].name) &&
                  p->v.subjects[k].rule == p->c.subjects[k].rule &&
                  p->v.subjects[k].mcp == (p->c.subjects[k].mcp != 0) && p->v.subjects[k].line == p->c.subjects[k].line;
    if (!id_same) {
        fprintf(stderr, "[warden] policy %s: the decision procedure and the certificate checker read "
                "the trusted identities or the confined subjects differently; refusing to start\n", path);
        return -1;
    }
    /* v1.31 (docs/security/v1.31-standards.md): every new line is enforced:
     * confined subjects (step 3), MCP calls over HTTP (step 4), MCP tokens and
     * trust mcp-resource (step 5). An audience= URL the helper is sent is at
     * most 1024 bytes. */
    for (size_t k = 0; k < p->v.ncreds; k++)
        if (strlen(p->v.creds[k].audience) > 1024) {
            fprintf(stderr, "[warden] policy %s: credential %s's audience is over 1024 bytes; refusing to start\n",
                    path, p->v.creds[k].name);
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
        /* v1.27: an interpreter or shell allowed to launch, a file both
         * launched and written */
        if (vdp_exec_advisory(&p->v, i, adv, sizeof adv))
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
    /* v1.27: exec rules without the opt-in decide only the agent's own launch */
    for (size_t i = 0; !p->v.launches && i < p->v.n; i++)
        if (p->v.rules[i].kind == VDP_KIND_EXEC && p->v.rules[i].verb == VDP_ALLOW) {
            fprintf(stderr, "[warden] policy %s:%d: note: exec rules take effect for launches after "
                    "the first only with `require warden 1.27`; without it every later launch is "
                    "refused\n", path, p->v.rules[i].line);
            break;
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

/* ---------------- v1.34: the node's /proc ----------------
 * Every read of a process's state, the agent's or the Warden's own
 * (/proc/<pid>/mem, /proc/self/fd/N, ...), goes through a descriptor on the
 * /proc the Warden started with. Under the node agent the supervisor enters
 * the container's mount namespace, where /proc is the container's: another
 * PID namespace, in which the supervisor has no entry (docs/security/
 * v1.34-kubernetes.md, step 2). Names the agent asks for (its own
 * /proc/self) are still resolved in its view. proc_dir() is first called
 * before any namespace is entered. */
static int g_procfd = -1;
static int proc_dir(void) {
    /* opened once, at the start (main), never again: a later open could be
     * the container's /proc, once in its mount namespace */
    static bool tried = false;
    if (!tried) { tried = true; g_procfd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC); }
    if (g_procfd < 0) errno = ENOENT;
    return g_procfd;
}

/* The name below that /proc ("<pid>/..." or "self/..."), or -1 */
static int proc_rel(char *rel, size_t n, const char *fmt, va_list ap) {
    int k = vsnprintf(rel, n, fmt, ap);
    if (k < 0 || (size_t)k >= n) { errno = ENAMETOOLONG; return -1; }
    if (proc_dir() < 0) return -1;
    return 0;
}

__attribute__((format(printf, 3, 4)))
static int proc_openf(int flags, mode_t mode, const char *fmt, ...) {
    char rel[128];
    va_list ap;
    va_start(ap, fmt);
    int r = proc_rel(rel, sizeof rel, fmt, ap);
    va_end(ap);
    return r < 0 ? -1 : openat(g_procfd, rel, flags | O_CLOEXEC, mode);
}

__attribute__((format(printf, 1, 2)))
static FILE *proc_fopenf(const char *fmt, ...) {
    char rel[128];
    va_list ap;
    va_start(ap, fmt);
    int r = proc_rel(rel, sizeof rel, fmt, ap);
    va_end(ap);
    int fd = r < 0 ? -1 : openat(g_procfd, rel, O_RDONLY | O_CLOEXEC);
    FILE *f = fd < 0 ? NULL : fdopen(fd, "re");
    if (fd >= 0 && !f) close(fd);
    return f;
}

/* as readlink(2): the length, not terminated */
__attribute__((format(printf, 3, 4)))
static ssize_t proc_readlinkf(char *out, size_t n, const char *fmt, ...) {
    char rel[128];
    va_list ap;
    va_start(ap, fmt);
    int r = proc_rel(rel, sizeof rel, fmt, ap);
    va_end(ap);
    return r < 0 ? -1 : readlinkat(g_procfd, rel, out, n);
}

__attribute__((format(printf, 2, 3)))
static int proc_statf(struct stat *st, const char *fmt, ...) {
    char rel[128];
    va_list ap;
    va_start(ap, fmt);
    int r = proc_rel(rel, sizeof rel, fmt, ap);
    va_end(ap);
    return r < 0 ? -1 : fstatat(g_procfd, rel, st, 0);
}

/* v1.34 step 2: the container a node agent's supervisor supervises
 * (warden_node.inc.c); off in a run the Warden starts itself */
struct node_run {
    bool   on;                  /* this process supervises a container a runtime started */
    int    notify_fd;
    pid_t  pid;                 /* the container's init, as the node numbers it */
    int    pidfd;               /* that process itself, opened as the state arrived */
    char   id[128];             /* the container's id */
    char   bundle[PATH_MAX];
    char   meta[256];           /* the profile's listenerMetadata */
    char   pod_ns[256], pod_name[256], pod_uid[128], ctr[256];
    char   argv0[PATH_MAX];     /* the container's command: its first launch */
    uid_t  uid;                 /* the agent's, read from its process */
    gid_t  gid;
    gid_t  groups[256];         /* its supplementary groups, from its process too */
    int    ngroups;
    long   before_exec;         /* the runtime's own calls before that launch, let through */
    /* v1.34 step 3 */
    char   policy[64];          /* the pod's policy, by name (varek.dev/policy), or "" */
    bool   launcher;            /* the command is /varek/init -- COMMAND (the NRI plugin's) */
    bool   in_launcher;         /* the runtime has launched /varek/init; the launcher runs */
    long   launcher_calls;      /* the launcher's own calls before the command, let through */
    int    set_view;            /* the launch set the launcher reads, a sealed memfd */
    char  *set_text;            /* its text, one path a line */
    char   policy_sha[65];      /* v1.34 step 5: the plugin's SHA-256 of the policy it wrote the filter for, or "" */
    char   plan[64];            /* v1.35 step 4c (D11): the pod's plan, by name (varek.dev/plan), or "" */
    char   plan_sha[65];        /* the plugin's SHA-256 of the plan it checked the policy with, or "" */
    char   dns[80];             /* v1.34 step 4: the pod's DNS server, "a.b.c.d:53" (its resolv.conf), or "" */
    struct sock_filter *bpf;    /* the Warden's own filter for the policy, compiled */
    unsigned nbpf;
    long   not_admitted;        /* calls it refuses, which the pod's filter notifies */
};
static struct node_run g_nr = { .notify_fd = -1, .pidfd = -1, .set_view = -1 };
static void node_run_start(FILE *f);
static void node_fail(const char *why) __attribute__((noreturn));
static bool node_launcher_open(int notify_fd, const struct seccomp_notif *req);
static int node_launcher_exec(int notify_fd, const struct seccomp_notif *req, const struct action *a,
                              const char *bootstrap_path, bool by_fd);

/* ---------------- cross-process memory ---------------- */

static int xproc_read_str(pid_t pid, uint64_t addr, char *out, size_t outlen) {
    int fd = proc_openf(O_RDONLY, 0, "%d/mem", pid);
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
    int fd = proc_openf(O_RDONLY, 0, "%d/mem", pid);
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

static int change_derive(const struct seccomp_notif *req, struct action *out);   /* v1.29 */
/* v1.29: the policy says `require warden 1.29`, so the filter sends the
 * changes by name and stat/lstat here. Otherwise (a dry run of an earlier
 * policy sends every unlisted call) they are derived as other calls, recorded
 * syscall_not_admitted, as enforcing refuses them. */
static bool g_changes_on;
static const char *change_op_name(int op);
static int derive_intent(const struct seccomp_notif *req,
                         struct action *out)
{
    memset(out, 0, sizeof(*out));
    out->policy_line = -1;
    int nr = (int)req->data.nr;
    /* v1.33: a negative number is no system call (the legacy calls arm64
     * lacks are given such numbers here, and the filter notifies none):
     * never derived as one */
    if (nr < 0) { out->kind = ACT_OTHER; snprintf(out->target, sizeof out->target, "syscall:%d", nr); return 0; }
    /* v1.29: the changes by name (warden_change.inc.c) */
    int cr = g_changes_on ? change_derive(req, out) : 0;
    if (cr) return cr < 0 ? -1 : 0;

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
    /* v1.29 (step 6): under `require warden 1.29` the legacy stat(2) and
     * lstat(2) come here too (the filter sends them only then): musl calls
     * them, and with them a statically linked agent (the Codex CLI) looked
     * nothing up. Each is newfstatat(AT_FDCWD, path, buf, 0 or
     * AT_SYMLINK_NOFOLLOW), answered with the same struct stat. */
    if (g_changes_on && (nr == __NR_stat || nr == __NR_lstat)) {
        out->kind = ACT_FILE_STAT;
        out->meta_nr = __NR_newfstatat;
        out->open_dirfd = VAREK_AT_FDCWD;
        out->out_addr = req->data.args[1];
        out->at_flags = nr == __NR_lstat ? AT_SYMLINK_NOFOLLOW : 0;
        if (req->data.args[0] == 0) {
            out->path_null = true;
            out->target[0] = '\0';
        } else if (xproc_read_str(req->pid, req->data.args[0], out->target, sizeof(out->target)) < 0) {
            return -1;
        }
        out->open_flags = O_RDONLY;
        out->flags_known = true;
        return 0;
    }
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
    snprintf(out->target, sizeof out->target, "syscall:%d", nr);   /* v1.29: named in the record */
    return 0;
}

/* ---------------- Policy Decision ---------------- */

static bool g_revoked;               /* v1.28 step 4: warden_revoke.inc.c */
static int sub_policy_subject(int s);  /* v1.31: warden_subagent.inc.c */
/* v1.35 (D6): the policy subject an action is decided as: a plan step's own
 * (as=NAME), else the calling process's attribution */
static int act_policy_subject(const struct action *a) {
    return a->plan_psubj > 0 ? a->plan_psubj - 1 : sub_policy_subject(a->subject);
}
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
    /* v1.28 step 4: after `varek revoke`, nothing more is allowed */
    if (g_revoked) { a->why = "revoked"; return DEC_DENY; }
    vdp_kind_t kind;
    const char *s;
    switch (a->kind) {
        case ACT_FILE_OPEN:
        case ACT_FILE_STAT:
        case ACT_FILE_ACCESS:
        case ACT_FILE_READLINK:
        case ACT_FILE_CHANGE:            /* v1.29: as a write (or chdir: a read) */
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
        /* v1.27: on the name exec_name made (absolute), when launches are
         * decided; before 1.27, on the path as written */
        case ACT_PROCESS_EXEC: kind = VDP_KIND_EXEC; s = a->resolved[0] ? a->resolved : a->target; break;
        case ACT_NET_REQUEST: kind = VDP_KIND_REQUEST; s = a->resolved; break;      /* v1.26.1 */
        case ACT_NET_MCP:                /* v1.31: an object vdp_mcp_object built, or none */
            kind = VDP_KIND_MCP;
            s = a->resolved;
            if (s[0] == '\0') { a->why = "not_in_fragment"; return DEC_UNKNOWN; }
            break;
        default:
            a->why = "not_in_fragment";
            return DEC_UNKNOWN;
    }
    int ri;
    vdp_why_t why;
    /* v1.31: by the calling subject's rules (the Warden's attribution) */
    vdp_verdict_t v = vdp_decide_subj(&p->v, act_policy_subject(a), kind, s, vdp_oflags_from_native((uint32_t)a->open_flags),
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
    if (a->why && !strcmp(a->why, "revoked")) return "revoked";          /* v1.28 step 4 */
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
static void exec_ruleset_record(FILE *f);     /* v1.27: warden_exec.inc.c */
static void noexec_record(FILE *f);           /* v1.27.1: warden_noexec.inc.c */
static bool noexec_breach(const char *resolved, int fd);
struct action;
static int exec_access_x(int ofd, const struct action *a);   /* v1.27: warden_exec.inc.c */

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
        case ACT_FILE_READLINK:
        case ACT_FILE_CHANGE:  kind = VDPC_PATH; s = a->resolved; break;   /* v1.29 */
        case ACT_NET_CONNECT:  kind = VDPC_HOST; s = a->resolved; break;   /* v1.21 */
        case ACT_NET_PROXY:    kind = VDPC_HOST; s = a->resolved; break;   /* v1.26 */
        case ACT_NET_REQUEST:  kind = VDPC_REQUEST; s = a->resolved; break; /* v1.26.1 */
        case ACT_NET_MCP:      kind = VDPC_MCP; s = a->resolved; break;     /* v1.31 */
        case ACT_PROCESS_EXEC: kind = VDPC_EXEC; s = a->resolved[0] ? a->resolved : a->target; break;
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
    if ((size_t)n < sizeof a->cert) n += snprintf(a->cert + n, sizeof a->cert - (size_t)n, "\"");
    /* v1.31: the subject the certificate is checked as, from the Warden's own
     * attribution (not the procedure's), recorded when it is not the agent */
    int subj = act_policy_subject(a);
    if (subj && (size_t)n < sizeof a->cert) snprintf(a->cert + n, sizeof a->cert - (size_t)n, ",\"cert_subject\":%d", subj);
    if (!vdpc_check_subj(&p->c, subj, kind, s, strlen(s), vdp_oflags_from_native((uint32_t)a->open_flags), has_flags, &cc,
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
                if (vdpc_rule_info(&p->c, (size_t)i, &ri) < 0 || ri.kind != VDPC_HOST || ri.subj != subj) continue;
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
    /* v1.35 step 2 (D9): the plan file, for the plan_step records (NULL:
     * none written). */
    const char          *plan_path;
};

/* v1.35 step 2 (D9): why a step was not SATISFIED, for its plan_step record.
 * Filled by plan_step_decide; the deciding rule's line when a rule decided. */
struct plan_step_note {
    char why[320];
    int  policy_line;
    char resolved[PATH_MAX];
    char mcp_host[PATH_MAX];    /* v1.35 step 4: an mcp_call step's server, host:port */
};

#include "warden_hold.inc.c"         /* v1.35 step 4: a run held to its plan */

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
     * K_O_LARGEFILE): glibc defines O_LARGEFILE as 0 on 64-bit systems, which
     * would make a declared O_LARGEFILE mean no flag at all. v1.30: the
     * kernel's own bit on this architecture, as every flag here (the
     * Warden keeps an action's flags as the kernel's, and translates them
     * where they are decided and recorded). */
    { "O_LARGEFILE", WARDEN_O_LARGEFILE }, { "O_DIRECTORY", O_DIRECTORY }, { "O_NOFOLLOW", O_NOFOLLOW },
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
static plan_decision_t plan_exec_decide(const struct policy *p, struct action *a, const char **why);  /* warden_exec.inc.c */

/* v1.35 (D3, D4, D6; docs/security/v1.35-frameworks.md): the steps a plan
 * in format 1.35 (`plan 1.35` its first line) may name besides file_open,
 * net_connect and process_exec, and the subject a step is decided as.
 *
 *   mcp_call URL [method=METHOD] [name=NAME]
 *       an MCP call over HTTP, decided as v1.31 decides one: on the object
 *       <canonical URL>#<METHOD>#<NAME> (vdp_mcp_object), by the mcp rules,
 *       and certified. METHOD defaults to tools/call. Without name= the step
 *       is the server (its tools found when it is connected): decided on the
 *       empty name, so SATISFIED only where a rule allows any name. A server
 *       that is not an http:// or https:// URL (a stdio server) is UNKNOWN:
 *       its calls are not decided (its launch is a subagent step).
 *   subagent NAME [exec=PATH]
 *       a sub-agent, or a confined MCP server, decided as its launch: by the
 *       exec rules, as a process_exec step is, and SATISFIED only when the
 *       rule that allows the program is one with subagent=NAME. Without
 *       exec= the program is the one exact rule with subagent=NAME names.
 *   credential NAME
 *       a credential the policy names (`credential NAME from ...`) and an
 *       allow request or mcp rule of the step's subject releases
 *       (credential=NAME); the requests that carry it are decided when made.
 *   as=NAME   on any step: decided under the rules of NAME, a confined
 *       subject (`mcp server NAME`, `subagent=NAME confined`), as its calls
 *       are; for an unconfined sub-agent, the rules of the subject that
 *       launches it, as its calls are. A name the policy does not give is
 *       UNKNOWN.
 *
 * A plan without `plan 1.35` is read as through v1.34: these kinds, and an
 * as= field, are UNKNOWN there. */
static const char *plan_field(const struct warden_plan_ud *u, const plan_spec_action_t *a, const char *key) {
    if (!u->parsed || !u->spec || a < u->spec->actions || a >= u->spec->actions + u->spec->n_actions)
        return NULL;
    size_t nf = 0;
    const plan_spec_field_t *fl = plan_parser_fields(u->parsed, (size_t)(a - u->spec->actions), &nf);
    for (size_t k = 0; k < nf; k++)
        if (fl[k].key && !strcmp(fl[k].key, key)) return fl[k].value ? fl[k].value : "";
    return NULL;
}

/* as=NAME: 1 + the policy subject its calls are decided as (1: the agent's
 * rules), or 0 with why */
static int plan_subject(const struct policy *p, const char *name, const char **why) {
    for (size_t k = 0; k < p->v.nsubjects; k++)
        if (!strcmp(p->v.subjects[k].name, name)) return (int)k + 2;
    int subj = -1;
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind != VDP_KIND_EXEC || r->verb != VDP_ALLOW || strcmp(r->subagent, name)) continue;
        if (subj >= 0 && subj != r->subj) { *why = "the sub-agent is launched by rules of two subjects"; return 0; }
        subj = r->subj;
    }
    if (subj < 0) { *why = "the policy names no sub-agent or MCP server by that name"; return 0; }
    return subj + 1;
}

/* a subagent step: its launch, as a process_exec step's (plan_exec_decide),
 * then the deciding rule's subagent= */
static plan_decision_t plan_subagent_decide(const struct warden_plan_ud *u, const plan_spec_action_t *a,
                                            struct action *act, const char **why) {
    const struct policy *p = u->policy;
    const char *name = a->target ? a->target : "";
    int subj = act->plan_psubj > 0 ? act->plan_psubj - 1 : 0;
    const vdp_rule_t *only = NULL;
    size_t n = 0;
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind == VDP_KIND_EXEC && r->verb == VDP_ALLOW && r->subj == subj && !strcmp(r->subagent, name)) {
            only = r;
            n++;
        }
    }
    if (!n) { *why = "no rule of the policy launches a sub-agent by that name"; return PLAN_DEC_UNKNOWN; }
    const char *path = plan_field(u, a, "exec");
    if (!path) {
        if (n != 1 || only->s.op != VDP_STR_EQ) {
            *why = "name the sub-agent's program with exec=PATH (no one exact rule names it)";
            return PLAN_DEC_UNKNOWN;
        }
        path = only->s.c;
    }
    if (strlen(path) >= sizeof act->target) { *why = "the program's path is too long"; return PLAN_DEC_UNKNOWN; }
    snprintf(act->target, sizeof act->target, "%s", path);
    act->kind = ACT_PROCESS_EXEC;
    if (!p->v.launches) {
        *why = "the Warden refuses every launch after the first at runtime, as the policy does not decide "
               "launches (require warden 1.27)";
        return PLAN_DEC_UNSATISFIED;
    }
    plan_decision_t pd = plan_exec_decide(p, act, why);
    if (pd == PLAN_DEC_SATISFIED &&
        (act->rule_index < 0 || strcmp(p->v.rules[act->rule_index].subagent, name))) {
        *why = "the program is allowed, but by a rule that does not launch it as this sub-agent";
        return PLAN_DEC_UNKNOWN;
    }
    return pd;
}

/* a credential step: named, and released by an allow rule of the subject */
static plan_decision_t plan_cred_decide(const struct policy *p, const plan_spec_action_t *a,
                                        struct action *act, const char **why) {
    const char *name = a->target ? a->target : "";
    int subj = act->plan_psubj > 0 ? act->plan_psubj - 1 : 0;
    size_t c = 0;
    while (c < p->v.ncreds && strcmp(p->v.creds[c].name, name)) c++;
    if (c == p->v.ncreds) { *why = "the policy names no credential by that name"; return PLAN_DEC_UNKNOWN; }
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->verb == VDP_ALLOW && (r->kind == VDP_KIND_REQUEST || r->kind == VDP_KIND_MCP) &&
            r->cred == (int)c + 1 && r->subj == subj) {
            act->policy_line = r->line;
            return PLAN_DEC_SATISFIED;
        }
    }
    *why = "no rule of the policy releases it (credential=) to this subject";
    return PLAN_DEC_UNKNOWN;
}

/* an mcp_call step's server: its host and port decided (and certified) as the
 * connection the proxy reads is (ACT_NET_PROXY), before the call. At run time
 * the call is decided only on a connection the host rules allow, so a step
 * whose host they do not is not SATISFIED either. url is canonical
 * (vdp_mcp_url): scheme://host:port/path. */
static plan_decision_t plan_mcp_host(const struct policy *p, const struct action *call, const char *url,
                                     char *host, size_t hn, const char **why) {
    struct action h;
    memset(&h, 0, sizeof h);
    h.kind = ACT_NET_PROXY;
    h.policy_line = -1;
    h.plan_psubj = call->plan_psubj;
    const char *b = strstr(url, "://");
    const char *e = b ? strchr(b + 3, '/') : NULL;
    if (!b || !e || (size_t)(e - b - 3) >= sizeof h.resolved) { *why = "the server's URL has no host"; return PLAN_DEC_UNKNOWN; }
    memcpy(h.resolved, b + 3, (size_t)(e - b - 3));
    snprintf(h.target, sizeof h.target, "%s", h.resolved);
    decision_t d = policy_decide(p, &h);
    if (d == DEC_ALLOW && certify(p, &h)) { snprintf(host, hn, "%s", h.resolved); return PLAN_DEC_SATISFIED; }
    *why = d == DEC_DENY ? "the connection to its server's host and port is refused by a host rule"
         : d == DEC_ALLOW ? "the connection to its server's host and port: certificate refused"
                          : "no host rule allows the connection to its server's host and port";
    return d == DEC_DENY ? PLAN_DEC_UNSATISFIED : PLAN_DEC_UNKNOWN;
}

static void plan_step_log(const plan_spec_action_t *a, const char *target, plan_decision_t pd, const char *why) {
    log_line_start();
    fputs("[warden] plan: ", g_log);
    json_escape(g_log, a->kind ? a->kind : "");
    fputs(" step \"", g_log);
    json_escape(g_log, target);
    fprintf(g_log, "\" is %s: %s\n", plan_decision_name(pd), why);
    fflush(g_log);
}

static plan_decision_t plan_step_decide(const struct warden_plan_ud *u, const plan_spec_action_t *a,
                                        struct plan_step_note *nt)
{
    struct action act;
    memset(&act, 0, sizeof(act));
    act.policy_line = -1;
    act.kind = kind_from_string(a->kind);
    /* v1.20.0: a target that does not fit is UNKNOWN, never cut short and
     * decided as the shorter path it would become. */
    if (a->target && strlen(a->target) >= sizeof(act.target)) {
        snprintf(nt->why, sizeof nt->why, "the target is too long");
        return PLAN_DEC_UNKNOWN;
    }
    if (a->target) {
        snprintf(act.target, sizeof(act.target), "%s", a->target);
    }
    /* v1.35 (D3, D4, D6): the subject, then the kinds of plan 1.35 */
    {
        int ver = plan_parser_version(u->parsed);
        const char *why = NULL;
        plan_decision_t pd = PLAN_DEC_UNKNOWN;
        bool newkind = a->kind && (!strcmp(a->kind, "mcp_call") || !strcmp(a->kind, "subagent") ||
                                   !strcmp(a->kind, "credential"));
        const char *as = plan_field(u, a, "as");
        if (as && ver < 135) why = "an as= field needs `plan 1.35` as the plan's first line";
        else if (as && !(act.plan_psubj = plan_subject(u->policy, as, &why))) { }
        else if (newkind && ver < 135) why = "this kind of step needs `plan 1.35` as the plan's first line";
        else if (newkind && g_nr.on)                                    /* v1.35 step 4c (D11) */
            why = "the node agent does not carry this kind of step yet (v1.36)";
        else if (newkind && !strcmp(a->kind, "credential")) pd = plan_cred_decide(u->policy, a, &act, &why);
        else if (newkind && !strcmp(a->kind, "subagent")) pd = plan_subagent_decide(u, a, &act, &why);
        else if (newkind) {                                             /* mcp_call */
            char url[VDP_STR_MAX + 1];
            const char *method = plan_field(u, a, "method"), *name = plan_field(u, a, "name");
            const char *bad = strstr(act.target, "://") ? vdp_mcp_url(act.target, false, url, sizeof url)
                                                        : "not an http:// or https:// URL";
            if (bad && !strstr(act.target, "://"))
                why = "a stdio MCP server's calls are not decided (the Warden decides MCP calls over HTTP); "
                      "its launch is a subagent step";
            else if (bad) why = bad;
            else if (vdp_mcp_object(url, method ? method : "tools/call", name ? name : "", act.resolved,
                                    sizeof act.resolved) < 0)
                why = "the method or name is outside what the Warden decides";
            else if ((pd = plan_mcp_host(u->policy, &act, url, nt->mcp_host, sizeof nt->mcp_host, &why)) ==
                     PLAN_DEC_SATISFIED) {
                pd = PLAN_DEC_UNKNOWN;
                act.kind = ACT_NET_MCP;                                 /* decided below, as a call */
            }
        }
        if (why || pd != PLAN_DEC_UNKNOWN) {
            if (!why) {                                                 /* a credential or subagent step SATISFIED */
                if (g_hold_collect) hold_from_step(a, &act, nt);
                return pd;
            }
            plan_step_log(a, act.target, pd, why);
            snprintf(nt->why, sizeof nt->why, "%s", why);
            nt->policy_line = act.policy_line;
            snprintf(nt->resolved, sizeof nt->resolved, "%s", act.resolved[0] ? act.resolved : act.target);
            return pd;
        }
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
        /* v1.35 step 4: a directory step (its target ending in '/') is decided
         * on the directory's name with its '/', as a prefix rule names it;
         * each call beneath it is decided by the policy when it is made */
        size_t tl = strlen(act.target), rl = strlen(act.resolved);
        if (tl > 1 && act.target[tl - 1] == '/' && rl > 1 && act.resolved[rl - 1] != '/' &&
            rl + 1 < sizeof act.resolved) {
            act.resolved[rl] = '/';
            act.resolved[rl + 1] = '\0';
        }
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
            snprintf(nt->why, sizeof nt->why, "%s", why);
            return PLAN_DEC_UNKNOWN;
        }
        if (r > 0) { act.open_flags = of; act.flags_known = true; }
    }
    /* v1.18.0: the runtime refuses every launch after the first, whatever
     * the policy says, so a process_exec step is UNSATISFIED (a plan lists
     * what the agent does after it starts, so every such step is a later
     * launch). v1.35 step 2 (D9): unless the policy decides launches
     * (require warden 1.27): then the step is decided as the launch would be
     * (plan_exec_decide). v1.21: connects are decided at runtime, so a
     * net_connect step is decided by the policy on the destination the
     * runtime would decide on (net_plan_canon); through v1.20.0 it was always
     * UNSATISFIED. */
    if (act.kind == ACT_PROCESS_EXEC) {
        const char *why = "the Warden refuses every launch after the first at runtime, "
                          "as the policy does not decide launches (require warden 1.27)";
        plan_decision_t pd = PLAN_DEC_UNSATISFIED;
        if (u->policy->v.launches) pd = plan_exec_decide(u->policy, &act, &why);
        if (pd != PLAN_DEC_SATISFIED) {
            log_line_start();
            fprintf(g_log, "[warden] plan: %s step \"", a->kind);
            json_escape(g_log, act.target);
            fprintf(g_log, "\" is %s: %s\n", plan_decision_name(pd), why);
            fflush(g_log);
            snprintf(nt->why, sizeof nt->why, "%s", why);
            nt->policy_line = act.policy_line;
            snprintf(nt->resolved, sizeof nt->resolved, "%s", act.resolved);
        } else if (g_hold_collect) hold_from_step(a, &act, nt);
        return pd;
    }
    if (act.kind == ACT_NET_CONNECT) {
        char why[200];
        if (net_plan_canon(act.target, act.resolved, sizeof act.resolved, why, sizeof why) < 0) {
            log_line_start();
            fputs("[warden] plan: net_connect step \"", g_log);
            json_escape(g_log, act.target);
            fprintf(g_log, "\" is UNKNOWN: %s\n", why);
            fflush(g_log);
            snprintf(nt->why, sizeof nt->why, "%s", why);
            return PLAN_DEC_UNKNOWN;
        }
    }
    decision_t d = policy_decide(u->policy, &act);
    nt->policy_line = act.policy_line;
    snprintf(nt->resolved, sizeof nt->resolved, "%s", act.resolved);
    if (d == DEC_ALLOW && !certify(u->policy, &act)) {
        /* v1.15: the plan gate authorizes only what the checker confirms. */
        log_line_start();
        fputs("[warden] plan: certificate refused for \"", g_log);
        json_escape(g_log, act.target);
        fprintf(g_log, "\": %s\n", act.check_why);
        fflush(g_log);
        snprintf(nt->why, sizeof nt->why, "its certificate is refused: %s", act.check_why);
        return PLAN_DEC_UNKNOWN;
    }
    /* v1.35 step 3: a step the policy decides is logged with its reason too,
     * as every other is (through step 2 only its record said why, and
     * `varek policy check --plan`, which writes no record, showed nothing) */
    plan_decision_t pd = PLAN_DEC_UNKNOWN;
    switch (d) {
        case DEC_ALLOW:
            if (g_hold_collect) hold_from_step(a, &act, nt);
            return PLAN_DEC_SATISFIED;
        case DEC_DENY:
            snprintf(nt->why, sizeof nt->why, "the policy refuses it");
            pd = PLAN_DEC_UNSATISFIED;
            break;
        case DEC_UNKNOWN:
            snprintf(nt->why, sizeof nt->why, "%s", act.kind == ACT_OTHER ? "the Warden decides no step of this kind"
                                                                      : "no rule of the policy allows it");
            break;
    }
    plan_step_log(a, act.kind == ACT_NET_MCP && act.resolved[0] ? act.resolved : act.target, pd, nt->why);
    return pd;
}

/* v1.35 step 2 (D9): the plan gate's chained records (defined after the
 * record writer). */
static void emit_plan_step(const char *plan_path, const plan_spec_action_t *a,
                           plan_decision_t pd, const struct plan_step_note *nt);
static void emit_plan_gate_basic(const char *plan_path, size_t n_actions, size_t n_edges,
                                 plan_decision_t pd, const char *error);

static plan_decision_t warden_plan_decider(const plan_spec_action_t *a,
                                           void *ud)
{
    const struct warden_plan_ud *u = (const struct warden_plan_ud *)ud;
    if (!u || !u->policy || !a) return PLAN_DEC_UNKNOWN;
    struct plan_step_note nt = { .policy_line = -1 };
    plan_decision_t pd = plan_step_decide(u, a, &nt);
    if (pd != PLAN_DEC_SATISFIED && u->plan_path) emit_plan_step(u->plan_path, a, pd, &nt);
    return pd;
}

/* Verify an agent's declared plan against the current policy, ahead
 * of any execution. Returns 0 if the plan is authorized, non-zero
 * otherwise. Emits a plan-level pathology record to stderr. v1.35 step 2
 * (D9): and chained plan_step and plan_gate records, unless `records` is
 * false (--check-startup, which opens no stream). */
/* v1.35 step 4c: a plan read already (parsed, or NULL with err): under the
 * node agent it is read in the node's view and decided in the container's
 * (node_supervise); it is freed here */
static int warden_verify_plan_parsed(plan_parsed_t *parsed, const char *err, const char *plan_path,
                                     const struct policy *policy, bool records)
{
    if (!parsed) {
        fprintf(stderr, "[warden] plan load failed: %s\n", err);
        if (records) emit_plan_gate_basic(plan_path, 0, 0, PLAN_DEC_UNKNOWN, err);
        return 1;
    }

    const plan_spec_t *spec = plan_parser_spec(parsed);
    pathology_sink_t *sink = pathology_sink_new(stderr);
    struct warden_plan_ud ud = { .policy = policy, .parsed = parsed, .spec = spec,
                                 .plan_path = records ? plan_path : NULL };

    plan_decision_t pd = warden_adapter_verify(spec, warden_plan_decider,
                                               &ud, sink);

    /* v1.21.1: read the count before the plan is freed (spec points into it;
     * through v1.21.0 it was read after plan_parser_free). */
    size_t n_actions = spec->n_actions, n_edges = spec->n_edges;
    pathology_sink_free(sink);
    plan_parser_free(parsed);
    if (records) emit_plan_gate_basic(plan_path, n_actions, n_edges, pd, NULL);

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

static int warden_verify_plan(const char *plan_path,
                              const struct policy *policy, bool records)
{
    char err[256] = {0};
    plan_parsed_t *parsed = plan_parser_load(plan_path, err, sizeof(err));
    return warden_verify_plan_parsed(parsed, err, plan_path, policy, records);
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
static bool       g_policy_any_name = false;  /* v1.29: so, before a dry run's views */
static bool       g_any_wild = false;  /* v1.25: the policy has a wildcard allow rule (warden_stub.inc.c) */
static void       stub_resolved(size_t i);
static void       px_resolved(size_t i);  /* v1.26: proxied requests waiting on a lookup */
static bool       px_up_charged(const char *name);  /* v1.26 review: sent to the upstream, charged */
static void       px_handed_off(uint64_t id, unsigned port, int subject);  /* v1.26 review: a hand-off announced */
static bool       g_stub_on;           /* v1.25: the stub resolver is up (warden_stub.inc.c) */
/* v1.25: the stub's address; v1.34 step 4: under the node agent, the first of
 * 127.53.53.53 to 127.53.53.254 free in the pod's network namespace (which
 * the pod's containers share) */
static char       g_stub_text[16] = "127.53.53.53";
/* v1.25 (section 4): a wildcard allow rule's budgets when it sets none */
#define STUB_DEFAULT_NAMES 256           /* distinct new names per run */
#define STUB_DEFAULT_RATE  30            /* distinct new names per minute */
#define STUB_LABEL_MAX     63            /* bytes matched by `*` */
static char       g_psl_sha[65], g_shared_sha[65];  /* v1.25: the lists wildcards were checked against */
static wp_t       g_proxy = { .ctl = -1 };          /* v1.26: the egress proxy, when `proxy on` */
static ws_t       g_secrets = { .ctl = -1 };        /* v1.28: warden-secrets, when the policy names credentials */
static char       g_secrets_sha[65];                /* v1.28: the SHA-256 of the warden-secrets that ran */
static ws_meta_t  g_cred_meta[WS_MAX_CREDS];        /* v1.28: each credential's version and length (never its value) */
static struct ws_identity g_identity;               /* v1.28.1: the verified user and agent (has_user, has_svid) */
static int g_obo_on_expiry;                         /* v1.28.1 step 4: 0 revoke the run when the token expires, 1 record only */
/* v1.28.1 step 3: sub-agents (warden_subagent.inc.c) */
static bool g_sub_on;                               /* the policy names a sub-agent */
static char g_cg_self[PATH_MAX];                    /* the run's group as /proc/<pid>/cgroup shows it */
static void sub_obo(FILE *f, int s);
static bool sub_cgroup_write(int fd, int flags);
static char       g_cred_ph[WS_MAX_CREDS][WP_PH_MAX]; /* v1.28: each credential's placeholder (not a secret) */
static char       g_cred_ph_sha[WS_MAX_CREDS][65];  /* v1.28: its SHA-256, for the record */
static char       g_proxy_sha[65];                  /* v1.26.1: the SHA-256 of the warden-proxy that ran */
/* v1.26.1, inspecting mode: the run's CA and the trust views (warden_trust.inc.c) */
static bool       g_inspect_on = false;
static unsigned char *g_trust_bundle, *g_ca_pem, *g_trust_p12;
static size_t     g_trust_bundle_len, g_ca_pem_len, g_trust_p12_len;
static char       g_trust_host_bundle[PATH_MAX];    /* the host's bundle the views start with */
static const char *g_trust_bundle_arg;              /* v1.26.1: --trust-bundle, in its place */
static char       g_trust_host_sha[65], g_ca_sha[65], g_trust_p12_sha[65];
static int        g_trust_secure_heap, g_trust_nroots;
static size_t     g_trust_nnames;
static bool       g_syn_on = false;    /* v1.26: `proxy on`: synthetic addresses (warden_synth.inc.c) */
static const struct policy *g_syn_p;   /* v1.26: the policy, for the hosts view */
/* v1.26: the stub runs with a wildcard allow rule (v1.25), or with the proxy
 * on and any host name rule (synthetic addresses) */
#define STUB_WANTED() (g_any_wild || (g_syn_on && g_names_on) || g_dry)   /* v1.29: a dry run */
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
static int           g_anchor_lock_dir = -1;        /* v1.34 review: its directory, held (the node's) */
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

#define WARDEN_VSTR_(x) #x
#define WARDEN_VSTR(x) WARDEN_VSTR_(x)
#define WARDEN_VERSION WARDEN_VSTR(VDP_WARDEN_MAJOR) "." WARDEN_VSTR(VDP_WARDEN_REL_MINOR) "." \
                       WARDEN_VSTR(VDP_WARDEN_PATCH)

/* v1.28.1: run_start's on_behalf_of and operator */
static void emit_on_behalf_of(FILE *f, const struct policy *p) {
    const struct ws_identity *id = &g_identity;
    fputs("\"on_behalf_of\":{", f);
    if (id->has_user) {
        /* v1.31: the issuer is the policy's, or found through a trusted MCP resource */
        const vdp_issuer_t *is = id->mcp_resource ? NULL : &p->v.issuers[id->issuer];
        const vdp_mcpres_t *mr = id->mcp_resource ? &p->v.mcpres[id->mcp_resource - 1] : NULL;
        fputs("\"user\":{\"issuer\":\"", f);
        json_escape(f, is ? is->iss : id->found_iss);
        fputs("\",\"audience\":\"", f);
        json_escape(f, is ? is->aud : id->found_aud);
        if (mr) {
            fputs("\",\"mcp_resource\":\"", f);
            json_escape(f, mr->url);
        }
        fputs("\",\"subject\":\"", f);
        json_escape(f, id->sub);
        fprintf(f, "\",\"expires\":%lld,", (long long)id->exp);
        if (id->iat >= 0) fprintf(f, "\"issued_at\":%lld,", (long long)id->iat);
        if (id->nbf >= 0) fprintf(f, "\"not_before\":%lld,", (long long)id->nbf);
        if (id->jti[0]) { fputs("\"jti\":\"", f); json_escape(f, id->jti); fputs("\",", f); }
        fputs("\"algorithm\":\"", f);
        json_escape(f, id->alg);
        fputs("\",", f);
        if (id->kid[0]) { fputs("\"key_id\":\"", f); json_escape(f, id->kid); fputs("\",", f); }
        fprintf(f, "\"token_sha256\":\"%s\",\"policy_line\":%d,\"verified\":true,\"on_expiry\":\"%s\"},",
                id->token_sha256, is ? is->line : mr->line, g_obo_on_expiry ? "record" : "revoke");
        if (id->nact) {
            fputs("\"actors\":[", f);
            for (uint32_t k = 0; k < id->nact; k++) {
                fputs(k ? ",{\"subject\":\"" : "{\"subject\":\"", f);
                json_escape(f, id->act[k].sub);
                fputs("\"", f);
                if (id->act[k].iss[0]) { fputs(",\"issuer\":\"", f); json_escape(f, id->act[k].iss); fputs("\"", f); }
                fputs("}", f);
            }
            fputs("],", f);
        }
    }
    fprintf(f, "\"agent\":{\"run\":\"%s\"", g_run_id);
    if (g_sub_on) { fputs(",\"cgroup\":\"", f); json_escape(f, g_cg_self); fputs("\"", f); }
    if (id->has_svid) {
        const vdp_spiffe_t *sp = &p->v.spiffe[id->spiffe];
        fputs(",\"spiffe_id\":\"", f);
        json_escape(f, id->spiffe_id);
        fputs("\",\"trust_domain\":\"", f);
        json_escape(f, sp->domain);
        fprintf(f, "\",\"svid_sha256\":\"%s\",\"svid_not_after\":%lld,\"policy_line\":%d,\"verified\":true",
                id->svid_sha256, (long long)id->svid_not_after, sp->line);
    }
    fputs("}},", f);
    /* the operator: the user sudo names, when root was reached through it */
    uid_t ou = getuid();
    const char *login = NULL, *src = "process";
    const char *su = getenv("SUDO_UID"), *sn = getenv("SUDO_USER");
    if (ou == 0 && su && *su && strspn(su, "0123456789") == strlen(su) && strlen(su) < 11) {
        ou = (uid_t)strtoul(su, NULL, 10);
        login = sn;
        src = "sudo";
    } else {
        struct passwd *pw = getpwuid(ou);
        login = pw ? pw->pw_name : NULL;
    }
    fprintf(f, "\"operator\":{\"uid\":%u,", (unsigned)ou);
    if (login && *login && strlen(login) <= 64) {
        bool ok = true;
        for (const char *c = login; *c; c++) ok &= *c > 0x20 && *c < 0x7f;
        if (ok) { fputs("\"login\":\"", f); json_escape(f, login); fputs("\",", f); }
    }
    fprintf(f, "\"source\":\"%s\",\"verified\":false},", src);
}

static void as_agent_record(FILE *f);   /* v1.29: warden_asagent.inc.c */
static void emit_run_start(const char *policy_path, const struct policy *p) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    /* the version is one literal, so `varek version` can read it from the binary */
    fprintf(f, "{\"event\":\"run_start\",\"run\":\"%s\",\"warden\":\"" WARDEN_VERSION "\","
               "\"arch\":\"" WARDEN_ARCH "\","        /* v1.30 */
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
    /* v1.35 step 4: the run is held to this plan (if it passes the gate) */
    if (g_hold_req) fprintf(f, "\"hold\":{\"plan\":\"%s\",\"plan_sha256\":\"%s\"},", g_hold_plan_json, g_hold_plan_sha);
    if (g_signing) {
        char pk_hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
        sodium_bin2hex(pk_hex, sizeof pk_hex, g_pk, sizeof g_pk);
        fprintf(f, "\"log_pubkey\":\"%s\",", pk_hex);
    }
    if (checkpoints_on())
        fprintf(f, "\"checkpoint_every\":%" PRIu64 ",", g_ckpt_every);
    if (g_anchor_fd >= 0) fputs("\"anchored\":true,", f);
    /* v1.24: the names the Warden resolves (each gets a resolution record). */
    node_run_start(f);                                                   /* v1.34 step 2 */
    if (g_policy_any_name) fputs("\"host_name_rules\":true,", f);
    /* v1.25: the lists the policy's wildcards were checked against */
    if (g_psl_sha[0]) fprintf(f, "\"psl_sha256\":\"%s\",\"shared_domains_sha256\":\"%s\","
                              "\"shared_lists_pinned\":%s,",
                              g_psl_sha, g_shared_sha, g_lists_pinned ? "true" : "false");
    if (g_names_on) fprintf(f, "\"host_names\":%zu,\"resolver\":\"%s\",", g_names.n, g_names.resolver);
    /* v1.25: where the agent's questions go (connects and sends to it are
     * records with rule dns_stub) */
    if (STUB_WANTED()) fprintf(f, "\"dns_stub\":\"%s:53\",", g_stub_text);
    /* v1.26: the egress proxy: its listener, its user, the proxied ports */
    if (g_proxy.ctl >= 0) {
        fprintf(f, "\"proxy\":{\"mode\":\"%s\",\"listen\":\"127.0.0.1:%u\",\"uid\":%u,\"gid\":%u,\"pid\":%d,\"ports\":[",
                g_inspect_on ? "inspect" : "sni",
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
        /* v1.26.1: inspecting mode's trust: the host's bundle, the run's CA
         * (the SHA-256 of its DER), the trust store, the passthrough hosts */
        if (g_inspect_on) {
            fprintf(f, "\"trust\":{\"host_bundle\":\"");
            json_escape(f, g_trust_host_bundle);
            fprintf(f, "\",\"host_bundle_sha256\":\"%s\",\"host_roots\":%d,\"ca_sha256\":\"%s\","
                    "\"ca_names\":%zu,\"trust_store_sha256\":\"%s\",\"ca_key_locked\":%s,\"passthrough\":[",
                    g_trust_host_sha, g_trust_nroots, g_ca_sha, g_trust_nnames, g_trust_p12_sha,
                    g_trust_secure_heap ? "true" : "false");
            for (size_t k = 0; k < p->v.proxy_npass; k++) fprintf(f, "%s\"%s\"", k ? "," : "", p->v.proxy_pass[k]);
            fputs("]},", f);
        }
    }
    /* v1.27: Landlock and the launch set (require warden 1.27) */
    if (p->v.launches || g_nr.launcher) { exec_ruleset_record(f); noexec_record(f); }   /* v1.27, v1.27.1; v1.34 */
    as_agent_record(f);                  /* v1.29: who files are opened as */
    if (g_dry) fputs("\"mode\":\"dry_run\",", f);   /* v1.29: not enforcing (section 3) */
    /* v1.29: the baseline this policy is (section 2), and the names (never
     * the values) of the agent's environment, under require warden 1.29 */
    if (p->base.on) {
        fputs("\"baseline\":{\"format\":1,\"profile\":\"", f);
        json_escape(f, p->base.profile);
        fprintf(f, "\",\"profile_sha256\":\"%s\",\"cwd\":\"", p->base.profile_sha);
        json_escape(f, p->base.cwd);
        fputs("\",\"home\":\"", f);
        json_escape(f, p->base.home);
        fputs("\",\"user\":\"", f);
        json_escape(f, p->base.user);
        fputs("\",\"tmp\":\"", f);
        json_escape(f, p->base.tmp);
        fputs("\"},", f);
    }
    if (p->v.open_as_agent) {
        extern char **environ;
        fputs("\"agent_env\":[", f);
        bool first = true;
        for (char **e = environ; e && *e; e++) {
            const char *eq = strchr(*e, '=');
            if (!eq || eq == *e || (size_t)(eq - *e) > 255) continue;
            char nm[256];
            memcpy(nm, *e, (size_t)(eq - *e));
            nm[eq - *e] = '\0';
            fputs(first ? "\"" : ",\"", f);
            json_escape(f, nm);
            fputs("\"", f);
            first = false;
        }
        fputs("],", f);
    }
    /* v1.28.1: who the run acts for (docs/security/v1.28.1-delegation-chain.md,
     * section 4): the user a trusted issuer vouched for, the actors of a
     * delegation, the agent; with no token, the agent alone. Then the
     * operator who started it, as the host says (not verified: D1). */
    emit_on_behalf_of(f, p);
    /* v1.28: the credentials the proxy holds for this run: where each came
     * from, its version and length, its placeholder's SHA-256 (never a
     * value, never a placeholder), and the warden-secrets that fetched them */
    if (g_secrets_sha[0] && !p->v.ncreds) fprintf(f, "\"secrets_binary_sha256\":\"%s\",", g_secrets_sha);
    if (p->v.ncreds && g_secrets_sha[0]) {
        static const char *const kSt[] = { "", "file", "vault", "aws-sm" };
        fprintf(f, "\"secrets_binary_sha256\":\"%s\",\"credentials\":[", g_secrets_sha);
        for (size_t k = 0; k < p->v.ncreds; k++) {
            const vdp_cred_t *c = &p->v.creds[k];
            fprintf(f, "%s{\"name\":\"%s\",\"policy_line\":%d,\"store\":\"%s\",\"ref\":\"", k ? "," : "", c->name,
                    c->line, kSt[c->store]);
            json_escape(f, c->ref);
            fputs("\",\"version\":\"", f);
            json_escape(f, g_cred_meta[k].version);
            fprintf(f, "\",\"length\":%u,\"placeholder_sha256\":\"%s\"", g_cred_meta[k].len, g_cred_ph_sha[k]);
            if (c->audience[0]) {                       /* v1.31: an MCP token, for this server */
                fputs(",\"audience\":\"", f);
                json_escape(f, c->audience);
                fputc('"', f);
                if (c->opaque) fputs(",\"opaque\":true", f);
                else fprintf(f, ",\"expires\":%lld", (long long)g_cred_meta[k].exp);
            }
            fputc('}', f);
        }
        fputs("],", f);
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
    g_policy_any_name = g_any_name;
    /* v1.29: a dry run serves the agent the name views and the stub, which
     * answers every name (warden_stub.inc.c), whatever the policy names */
    if (g_dry) { g_any_name = true; g_names_on = true; }
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
static void revoked_proxy_record(uint32_t held); /* v1.28 step 4 (warden_revoke.inc.c) */
static bool g_px_failed;               /* v1.26.1 review: the proxy misbehaved while flushing */
static unsigned g_exec_mismatch;       /* v1.27: processes killed by the identity check */
static void exec_finish(void);         /* v1.27: warden_exec.inc.c */
static void ctl_close(void);
static void emit_run_end(int exit_status) {
    ctl_close();                        /* v1.28 step 4: no revocation after the end */
    px_finish();                        /* v1.26: every relay's proxy_close */
    exec_finish();                      /* v1.27: launches never seen */
    emit_unanswered();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char dry_count[160] = "";
    if (g_dry) snprintf(dry_count, sizeof dry_count, "\"not_enforced\":%" PRIu64 ",", g_dry_unenforced);
    else if (g_nr.on)                     /* v1.34 step 2: the runtime's own, let through */
        snprintf(dry_count, sizeof dry_count, "\"runtime_calls_before_exec\":%ld,\"launcher_calls_before_exec\":%ld,"
                 "\"calls_not_admitted\":%ld,", g_nr.before_exec, g_nr.launcher_calls, g_nr.not_admitted);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"run_end\",\"run\":\"%s\",\"records\":%" PRIu64 ","
               "\"exit_status\":%d,%s%s%s%s%s\"timestamp_ns\":%lld}\n",
            g_run_id, g_records, exit_status, dry_count,
            g_dry ? "\"mode\":\"dry_run\"," : "",
            g_anchor_errors ? "\"anchor_errors_seen\":true," : "",
            g_px_failed ? "\"proxy_failed\":true," : "",
            g_exec_mismatch ? "\"exec_identity_mismatch\":true," : "",
            (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end("run_end");
    if (g_dry) {                                                           /* v1.29 */
        log_line_start();
        fprintf(g_log, "[warden] DRY RUN: NOT ENFORCING: %" PRIu64 " call(s) the policy refuses were let "
                "through (\"enforced\":false)\n", g_dry_unenforced);
    }
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
    bool held = rule_id && !strcmp(rule_id, "outside_plan");   /* v1.35 step 4 */
    if (!g_log) return;
    /* v1.31 (the shared soak): a checkpoint seals at most checkpoint_every
     * decision records. It is written between notifications
     * (maybe_checkpoint), but one notification or one pass over the proxy's
     * reports can write several records (a rename's two names, a batch of
     * requests); when this record would pass the bound, the checkpoint comes
     * first, here. */
    if (checkpoints_on() && g_since_ckpt >= g_ckpt_every) emit_checkpoint();
    if (a->dry) d_final = DEC_DENY;      /* v1.29: a call a dry run let through was refused by the policy */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char flags_json[40] = "";
    if ((a->kind == ACT_FILE_OPEN || is_meta_kind(a->kind) || a->kind == ACT_FILE_CHANGE) && a->flags_known)
        snprintf(flags_json, sizeof flags_json, "0x%x",           /* v1.30: VAREK's encoding */
                 (unsigned)vdp_oflags_from_native((uint32_t)a->open_flags));
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
        "\"agent_pid\":%d,",
        (long)ts.tv_sec, ts.tv_nsec, seq,
        g_run_id, g_records,
        (int)pid);
    /* v1.28.1: who it was for */
    sub_obo(f, a->subject);
    if (a->dry) { fputs("\"enforced\":false,", f); g_dry_unenforced++; }   /* v1.29 */
    fprintf(f, "\"action\":\"%s\",\"target\":\"",
            a->kind == ACT_FILE_CHANGE ? change_op_name(a->chg_op) : action_kind_name(a->kind));
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
        "%s%s%s%s%s"
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
        /* v1.35 step 4: an outside_plan refusal names the plan the run is held to */
        held ? "\"plan\":\"" : "", held ? g_hold_plan_json : "", held ? "\"," : "",
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
    int  agent_err;        /* v1.29: the walk as the agent failed with this errno (the
                            * object was then pinned as root, for the decision only) */
};

static void resolved_target_close(struct resolved_target *r) {
    if (r->path_fd   >= 0) close(r->path_fd);
    if (r->parent_fd >= 0) close(r->parent_fd);
    r->path_fd = r->parent_fd = -1;
}

/* Canonical path of a descriptor the supervisor holds. Fails closed on a
 * deleted or anonymous inode (readlink does not start with '/'). */
static int fd_canonical_path(int fd, char *out, size_t outlen) {
    ssize_t rl = proc_readlinkf(out, outlen - 1, "self/fd/%d", fd);
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
    char line[128];
    FILE *f = proc_fopenf("%d/status", tid);
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

/* v1.34: the supervisor resolves names in a container's view (its mount
 * namespace, and so its /proc, of the container's PID namespace), set once it
 * has entered it under the node agent; the pids the kernel gives the Warden
 * are the node's. */
static bool g_view_container = false;
/* the container's PID namespace's place in a process's NSpid (0, the node's,
 * first): its /proc numbers processes by that entry, the agent's included,
 * however deep the agent's own namespace is */
static int g_view_depth = 0;


/* A process's pid as the /proc of the Warden's view numbers it: the node's
 * own, or in a container's view its NSpid entry for the container's PID
 * namespace (g_view_depth). -1 if unknown, or if the process is not in that
 * namespace. */
static pid_t view_pid(pid_t pid) {
    if (!g_view_container) return pid;
    char line[256];
    FILE *f = proc_fopenf("%d/status", pid);
    if (!f) return -1;
    pid_t v = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "NSpid:", 6)) continue;
        char *s = line + 6, *e;
        int k = 0;
        for (long x; (x = strtol(s, &e, 10)), e != s; s = e, k++)
            if (k == g_view_depth) { v = (pid_t)x; break; }
        break;
    }
    fclose(f);
    return v > 0 ? v : -1;
}

/* How deep a process's PID namespace is below the node's: its NSpid's
 * entries less one. -1 if unknown. */
static int pidns_depth(pid_t pid) {
    char line[256];
    FILE *f = proc_fopenf("%d/status", pid);
    if (!f) return -1;
    int n = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "NSpid:", 6)) continue;
        char *s = line + 6, *e;
        n = 0;
        for (; strtol(s, &e, 10), e != s; s = e) n++;
        break;
    }
    fclose(f);
    return n > 0 ? n - 1 : -1;
}

/* Rewrite a leading /proc/self or /proc/thread-self (already matched) to the
 * agent's own /proc/<tgid>[/task/<tid>], so the supervisor does not resolve it
 * to itself. Returns 0 (out filled), or -1 if it does not fit. */
static int rewrite_proc_self(const char *in, bool thread_self,
                             pid_t tgid, pid_t tid, char *out, size_t outlen) {
    static const char kSelf[] = "/proc/self", kThread[] = "/proc/thread-self";
    int n;
    tgid = view_pid(tgid);                      /* v1.34 */
    if (thread_self) tid = view_pid(tid);
    if (tgid < 0 || tid < 0) return -1;
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
    if (n != (long)view_pid(*tgid_cache)) return -1;   /* the supervisor's, or another process's */
    char tmp[PATH_LIMIT];
    int w = snprintf(tmp, sizeof(tmp), "/proc/self%s", end);
    if (w < 0 || (size_t)w >= sizeof(tmp) || (size_t)w >= canonlen) return -1;
    memcpy(canon, tmp, (size_t)w + 1);
    return 0;
}

#include "warden_asagent.inc.c"      /* v1.29 step 1 */
static int agent_fd(pid_t tid, int fd);   /* v1.21: the agent's descriptor, or -errno */

/* v1.29: a step of the resolution's walk, as the agent when opening as the
 * agent. A walk the agent's user may not make (EACCES, EPERM: a directory it
 * cannot search) is made again as root, so the decision is still made on the
 * object, and the agent's error is kept for the open (materialize_target
 * returns it): an allowed open the agent's user could not make fails as the
 * kernel would have failed it. */
static int resolve_openat2(int dirfd, const char *path, uint64_t extra, int *agent_err) {
    if (!g_as.on) return openat2_path(dirfd, path, extra);
    int fd = openat2_path_agent(dirfd, path, extra);
    if (fd < 0 && (errno == EACCES || errno == EPERM)) {
        int e = errno;
        fd = openat2_path(dirfd, path, extra);   /* root's errno when it fails too */
        if (fd >= 0) *agent_err = e;
    }
    return fd;
}

/* Returns 0 with r filled and a->resolved set, or -1 (fail closed). Nothing
 * on the filesystem is opened, created or modified. */
static int resolve_target(pid_t target_pid, struct action *a,
                          struct resolved_target *r)
{
    a->resolved[0] = '\0';
    r->path_fd = r->parent_fd = -1;
    r->name[0] = '\0';
    r->agent_err = 0;

    /* a relative open against a directory descriptor: from v1.29 (require
     * warden 1.29), resolved from the agent's own descriptor (agent_fd, the
     * caller's table), as lookups are; before, refused */
    if (a->open_dirfd != VAREK_AT_FDCWD && a->target[0] != '/' && !g_as.policy)
        return -1;

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

    int cwd_fd = agent_fd(target_pid, path[0] == '/' ? VAREK_AT_FDCWD : a->open_dirfd);
    if (cwd_fd < 0) return -1;

    int fd = resolve_openat2(cwd_fd, path,
                             (uint64_t)a->open_flags &
                             ((uint64_t)O_DIRECTORY | (uint64_t)O_NOFOLLOW), &r->agent_err);
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

    r->agent_err = 0;
    int pfd = resolve_openat2(cwd_fd, dir, (uint64_t)O_DIRECTORY, &r->agent_err);
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
    char line[128];
    FILE *f = proc_fopenf("%d/status", pid);
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

    /* v1.29: the agent's user could not walk to it: its error, as the
     * kernel would have given it */
    if (r->agent_err) return -r->agent_err;
    if (r->path_fd >= 0) {
        if (want & O_PATH) {
            fd = fcntl(r->path_fd, F_DUPFD_CLOEXEC, 0);
            return fd < 0 ? -errno : fd;
        }
        /* Through the pinned descriptor: same inode that was decided on.
         * O_NOFOLLOW is dropped here only because /proc/self/fd/N is itself a
         * link; the agent's O_NOFOLLOW was already honoured at resolution
         * (a trailing symlink fails closed there). */
        int flags = (want & ~O_NOFOLLOW) | O_NONBLOCK | O_CLOEXEC;
        if ((want & O_TMPFILE) == O_TMPFILE) {
            /* O_TMPFILE creates an unnamed file in the pinned directory:
             * apply the agent's mode and umask, as for O_CREAT. */
            mode_t old = umask(target_umask(target_pid));
            if (as_agent_enter() < 0) { umask(old); return -EACCES; }
            fd = proc_openf(flags, (mode_t)(a->open_mode & 07777), "self/fd/%d", r->path_fd);
            as_agent_leave();
            int saved = errno;
            umask(old);
            errno = saved;
        } else {
            if (as_agent_enter() < 0) return -EACCES;    /* v1.29: as the agent */
            fd = proc_openf(flags, 0, "self/fd/%d", r->path_fd);
            as_agent_leave();
        }
    } else if (r->parent_fd >= 0) {
        if (want & O_PATH) return -ENOENT;
        int flags = want | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
        mode_t old = umask(target_umask(target_pid));
        if (as_agent_enter() < 0) { umask(old); return -EACCES; }
        fd = openat(r->parent_fd, r->name, flags, (mode_t)(a->open_mode & 07777));
        as_agent_leave();
        int saved = errno;
        umask(old);
        errno = saved;
    } else {
        return -EACCES;
    }
    if (fd < 0) return -errno;
    if (noexec_breach(a->resolved, fd)) {          /* v1.27.1 review: fail closed */
        close(fd);
        log_line_start();
        fprintf(g_log, "[warden] noexec: %s is under a writable directory but was reached through a "
                "mount that is not noexec; refused\n", a->resolved);
        return -EACCES;
    }
    if (sub_cgroup_write(fd, want)) {              /* v1.28.1: the control groups stay out of reach */
        close(fd);
        log_line_start();
        fprintf(g_log, "[warden] sub-agents: %s is on a control group filesystem; opening it to write is "
                "refused\n", a->resolved);
        return -EACCES;
    }

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
static int    g_ancestor_subj[MAX_ANCESTORS];   /* v1.31: the subject whose rule leads there */
static size_t g_nancestors = 0;

static void add_ancestor(const char *s, size_t n, int subj) {
    if (n == 0) { s = "/"; n = 1; }
    for (size_t i = 0; i < g_nancestors; i++)
        if (g_ancestor_subj[i] == subj && strlen(g_ancestors[i]) == n && !memcmp(g_ancestors[i], s, n)) return;
    if (g_nancestors < MAX_ANCESTORS) {
        char *c = strndup(s, n);
        if (c) { g_ancestor_subj[g_nancestors] = subj; g_ancestors[g_nancestors++] = c; }
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
                add_ancestor(ru->s.c, i == lit ? i - 1 : i, ru->subj);
        add_ancestor("/", 1, ru->subj);
    }
}

/* v1.31: of subj's rules (a directory one subject's rules lead to is not
 * answered to another without a decision) */
static bool is_ancestor(const char *canon, int subj) {
    for (size_t i = 0; i < g_nancestors; i++)
        if (g_ancestor_subj[i] == subj && !strcmp(g_ancestors[i], canon)) return true;
    return false;
}

/* An ancestor a deny rule covers (the directory, or what is inside it) is not
 * answered: `deny path /home/` before `allow path /home/bob/work/` leaves
 * /home and /home/bob to the policy, which refuses them. */
static bool ancestor_denied(const struct policy *p, const char *dir, int subj) {
    char withslash[PATH_LIMIT];
    const char *cands[2] = { dir, withslash };
    int nc = 1;
    if (strcmp(dir, "/") && (size_t)snprintf(withslash, sizeof withslash, "%s/", dir) < sizeof withslash)
        nc = 2;
    for (int k = 0; k < nc; k++) {
        int ri;
        vdp_why_t why;
        if (vdp_decide_subj(&p->v, subj, VDP_KIND_PATH, cands[k], O_RDONLY, true, &ri, &why) == VDP_UNSATISFIED)
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
    int fd = proc_openf(O_WRONLY, 0, "%d/mem", pid);
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
        int r = proc_openf(O_PATH | O_DIRECTORY, 0, "%d/cwd", tid);
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
        /* v1.27: with launches decided, X_OK says whether a launch of it would
         * be allowed (a file), or grants search like a read (a directory) */
        if (a->access_mode & X_OK) return exec_access_x(ofd, a);
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
/* v1.27: a lookup whose path leaves the filesystem before its last name
 * (a parent is missing too). Walk it one name at a time, as the kernel does
 * ("." skipped, ".." to the real parent, symlinks followed, no magic links),
 * to the first name that does not exist: that is where the kernel's lookup
 * stops with ENOENT. 0 with *pfd (its directory) and name, or -1. */
static const struct policy *g_exec_policy;   /* set with launches decided (warden_exec.inc.c) */
/* v1.29 (step 6): rest, when given, gets the names after the missing one,
 * joined by single slashes, or stays empty if one of them is "." or "..",
 * where the name the kernel would reach is not the path written. */
static int meta_first_missing(int base, const char *path, int *pfd, char *name, size_t nn,
                              char *rest, size_t rn) {
    if (rest && rn) rest[0] = '\0';
    int cur = path[0] == '/' ? open("/", O_PATH | O_DIRECTORY | O_CLOEXEC) : dup(base);
    if (cur < 0) return -1;
    char buf[PATH_LIMIT];
    snprintf(buf, sizeof buf, "%s", path);
    char *save = NULL;
    for (char *c = strtok_r(buf, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
        if (!strcmp(c, ".")) continue;
        int nx = openat2_path(cur, c, 0);
        if (nx < 0) {
            struct stat st;
            if (errno == ENOENT && strcmp(c, "..") && strlen(c) < nn &&
                fstatat(cur, c, &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT) {
                snprintf(name, nn, "%s", c);
                *pfd = cur;
                if (rest && rn) {
                    size_t k = 0;
                    bool ok = true;
                    for (char *d = strtok_r(NULL, "/", &save); d && ok; d = strtok_r(NULL, "/", &save)) {
                        if (!strcmp(d, ".") || !strcmp(d, "..")) { ok = false; break; }
                        int w = snprintf(rest + k, rn - k, "%s%s", k ? "/" : "", d);
                        if (w < 0 || (size_t)w >= rn - k) { ok = false; break; }
                        k += (size_t)w;
                    }
                    if (!ok) rest[0] = '\0';
                }
                return 0;
            }
            break;                         /* a dangling link, a refusal: fail closed */
        }
        struct stat st;
        if (fstat(nx, &st) < 0 || !S_ISDIR(st.st_mode)) { close(nx); break; }
        close(cur);
        cur = nx;
    }
    close(cur);
    return -1;
}

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
    /* the parent is missing too: fail closed, as before 1.27; with launches
     * decided (a coding agent's compiler looks up include directories under
     * missing ones), decide on where the kernel's lookup stops */
    char tail[PATH_LIMIT] = "";
    if (pfd < 0 && errno == ENOENT && g_exec_policy && g_exec_policy->v.launches) {
        static char nm[256];
        int q = -1;
        /* v1.29 (step 6): under `require warden 1.29`, decided on the whole
         * name asked for (~/.config/git/config, ~/.config missing), not on
         * the first missing directory: the answer is ENOENT either way,
         * and where the policy allows that name nothing outside it is told */
        if (meta_first_missing(base, path, &q, nm, sizeof nm, g_changes_on ? tail : NULL, sizeof tail) == 0) {
            pfd = q; name = nm;
        }
    }
    close(base);
    if (pfd < 0) return -1;
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
        int n = snprintf(a->resolved, sizeof(a->resolved), "%s%s%s%s%s",
                         parent, strcmp(parent, "/") ? "/" : "", name, tail[0] ? "/" : "", tail);
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
#include "mcp_aud.h"                /* v1.31 step 5 */
#include "warden_pxdecide.inc.c"     /* v1.26: the Warden's decisions on what the proxy reads */
#include "warden_revoke.inc.c"       /* v1.28 step 4: revoking a run */
#include "warden_trust.inc.c"        /* v1.26.1: the run's CA and the trust views */
#include "warden_subagent.inc.c"     /* v1.28.1: sub-agents' control groups and attribution */
#include "warden_exec.inc.c"         /* v1.27: the launch set and its Landlock ruleset */
#include "warden_noexec.inc.c"       /* v1.27.1: writable directories mounted noexec */
#include "warden_change.inc.c"       /* v1.29: changes by name */

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
        struct pollfd pfds[4 + MAX_PENDING + 2 + STUB_MAX_CONN + 1 + PX_MAX_DIAL + 3] = {
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
        /* v1.28 step 4: the run's control socket, and warden-secrets' reports */
        int rvi = pxi + 1 + npx;
        pfds[rvi] = (struct pollfd){ .fd = g_ctl_listen, .events = POLLIN };
        pfds[rvi + 1] = (struct pollfd){ .fd = g_secrets.ctl, .events = POLLIN };
        pfds[rvi + 2] = (struct pollfd){ .fd = g_cn, .events = POLLIN };     /* v1.28.1 review: process events */
        /* v1.28.1 step 4: and the user's token's expiry */
        int oto = obo_timeout_ms();
        if (oto >= 0 && (to < 0 || oto < to)) to = oto;
        int pr = poll(pfds, (nfds_t)(rvi + 3), to);
        if (pr >= 0) obo_check(notify_fd);
        if (pr > 0 && (pfds[rvi + 2].revents & POLLIN)) sub_cn_drain();
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
        if (g_ctl_listen >= 0 && (pfds[rvi].revents & POLLIN)) ctl_service(notify_fd);   /* v1.28 step 4 */
        if (g_secrets.ctl >= 0 && (pfds[rvi + 1].revents & (POLLIN | POLLHUP | POLLERR)) && secrets_service(p) < 0) {
            log_line_start();
            fprintf(g_log, "[warden] warden-secrets has gone: leased secrets will not be renewed or revoked\n");
            ws_stop(&g_secrets);
        }
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

        /* v1.34 step 2: under the node agent, until the container's first
         * launch, the calls of the container's init are the runtime's own
         * (its checks of /proc before it executes the command), made before
         * any of the container's code runs: let through and counted, as the
         * calls of the Warden's own child before its exec are on a host */
        /* v1.34 step 3: then the launcher's (the NRI plugin's /varek/init),
         * once the runtime has launched it: the launch set it reads is a view
         * the Warden serves, and its other calls (Landlock, its own filter)
         * are let through, until it launches the container's command */
        if (g_nr.on && !bootstrap_done && req.data.nr != __NR_execve && req.data.nr != __NR_execveat &&
            task_tgid((pid_t)req.pid) == bootstrap_pid && notif_id_valid(notify_fd, req.id)) {
            if (g_nr.in_launcher && node_launcher_open(notify_fd, &req)) continue;
            if (g_nr.in_launcher) g_nr.launcher_calls++;
            else g_nr.before_exec++;
            send_simple(notify_fd, req.id, DEC_ALLOW);
            continue;
        }
        /* review: before the container's first launch only its init calls
         * (the runtime's init, before it executes the command; the runtime's
         * hooks run outside the filter): a call from another process then
         * is not the runtime's, and the container is ended */
        if (g_nr.on && !bootstrap_done) {
            pid_t tg = task_tgid((pid_t)req.pid);
            if (tg > 0 && tg != bootstrap_pid)
                node_fail("a process other than the container's init made a call before the container's command ran");
        }
        /* v1.34 step 3: from the command's launch, a call the Warden's own
         * filter for this policy refuses (the pod's filter notifies each call
         * that filter names no rule for, for the runtime's last steps) is
         * answered as that filter answers it, without a record, as on a host */
        if (g_nr.on && bootstrap_done && g_nr.bpf) {
            uint32_t fa = wd_bpf_run(g_nr.bpf, g_nr.nbpf, &req.data);
            if ((fa & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_USER_NOTIF) {
                g_nr.not_admitted++;
                send_errno(notify_fd, req.id, (fa & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO && (fa & SECCOMP_RET_DATA)
                                              ? (int)(fa & SECCOMP_RET_DATA) : EPERM);
                continue;
            }
        }

        struct exec_ctx *ctx = ctx_get(req.pid);
        if (ctx) ctx->seq++;

        /* v1.28.1: who the call is for, read before it is decided (the id
         * is checked valid below: the thread read was the caller) */
        g_sub_froze = false;
        int subj = sub_attribute((pid_t)req.pid);
        struct action act;
        int dr = derive_intent(&req, &act);
        act.subject = subj;
        /* a failed sub-agent's group was frozen to move its processes back:
         * that interrupts the caller's call, which the kernel restarts (and
         * notifies again); this one is void, and not a decision */
        if (g_sub_froze && !notif_id_valid(notify_fd, req.id)) continue;
        /* a call interrupted while it waited is restarted by the kernel and
         * notified again: this one is void, not a decision */
        if (!notif_id_valid(notify_fd, req.id)) continue;
        if (dr < 0) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                         + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY,
                           "intent_derivation_failed", lat, EACCES);
            send_simple(notify_fd, req.id, DEC_DENY);
            continue;
        }

        /* v1.27 (step 4): with launches decided, before anything is
         * answered, the calling process must run a program the Warden
         * decided to run (warden_exec.inc.c) */
        if (exec_identity(notify_fd, &req, &act, &t0)) continue;
        /* v1.28.1: a launch settled there may have failed: its processes are the launcher's */
        if (act.subject > 0) act.subject = sub_effective(act.subject);
        if (g_sub_on && act.subject < 0) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_DENY, DEC_DENY, "subagent_unattributed",
                           (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec), EACCES);
            send_simple(notify_fd, req.id, DEC_DENY);
            continue;
        }

        /* v1.28 step 4: after `varek revoke`, every call is refused */
        if (g_revoked) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_DENY, DEC_DENY, "revoked",
                           (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec), EACCES);
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
        /* v1.34 step 3: under the node agent with the launcher, the runtime
         * launches /varek/init first, and the launcher the container's
         * command, which is then the bootstrap below */
        if (g_nr.on && g_nr.launcher && !bootstrap_done && act.kind == ACT_PROCESS_EXEC &&
            node_launcher_exec(notify_fd, &req, &act, bootstrap_path, boot_by_fd))
            continue;
        if (act.kind == ACT_PROCESS_EXEC && !bootstrap_done &&
            (pid_t)req.pid == bootstrap_pid && bootstrap_path &&
            (boot_by_fd || strcmp(act.target, bootstrap_path) == 0)) {
            if (boot_by_fd)
                snprintf(act.target, sizeof act.target, "%s", bootstrap_path);
            /* v1.34 review: the allowance is spent only once the kernel takes
             * the answer. A signal can interrupt the exec while it waits (the
             * Go runtime's preemption signals, in a container's runc init):
             * the answer then reaches no one, the kernel restarts the call,
             * and the restarted exec is the same launch, still the first */
            struct seccomp_notif_resp br = { .id = req.id, .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE };
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &br) < 0) continue;
            bootstrap_done = true;
            g_exec_checking = p->v.launches;   /* v1.27 step 4: from here on */
            if (ctx) ctx->launched = true;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            uint64_t lat_b = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                           + (t1.tv_nsec - t0.tv_nsec);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_ALLOW, DEC_ALLOW,
                           "bootstrap_exec_allow", lat_b, 0);
            continue;
        }

        /* v1.27: with `require warden 1.27`, a launch after the first is
         * decided on its name and allowed only onto a file of the launch set,
         * which Landlock holds the agent to (warden_exec.inc.c) */
        if (act.kind == ACT_PROCESS_EXEC && p->v.launches) {
            exec_launch(notify_fd, &req, &act, p, &t0);
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
        /* v1.29: a change by name (unlink, rename, mkdir, chmod, ...): decided
         * as a write on each path, carried out as the agent */
        if (act.kind == ACT_FILE_CHANGE) {
            change_handle(notify_fd, &req, &act, p, &t0);
            continue;
        }
        if (is_meta_kind(act.kind)) {
            if (act.bad_flags) { send_errno(notify_fd, req.id, EINVAL); continue; }
            /* v1.26.1: a trust view's metadata, from the view */
            if (g_inspect_on && (act.kind == ACT_FILE_STAT ||
                                 (act.kind == ACT_FILE_ACCESS && !(act.access_mode & (W_OK | X_OK)))) &&
                view_by_target(act.target) >= VIEW_TRUST0) {
                view_meta(notify_fd, &req, &act, p, view_by_target(act.target), &t0);
                continue;
            }
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
                if (fstat(mfd, &ast) == 0 && S_ISDIR(ast.st_mode) &&
                    is_ancestor(act.resolved, sub_policy_subject(act.subject)) &&
                    !ancestor_denied(p, act.resolved, sub_policy_subject(act.subject)) &&
                    (!g_hold_on || hold_covers(&act))) {                    /* v1.35 step 4 */
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
            bool m_cert_refused = false, m_held = false;
            if (m_final == DEC_ALLOW && !certify(p, &act)) {
                m_final = DEC_DENY;
                m_cert_refused = true;
                log_line_start();
                fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n",
                        g_records, act.check_why);
            }
            if (m_final == DEC_ALLOW && hold_refuses(&act)) { m_final = DEC_DENY; m_held = true; }   /* v1.35 */
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if (m_final != DEC_ALLOW) {
                if (mfd >= 0) close(mfd);
                uint64_t lat_m = (t1.tv_sec - t0.tv_sec) * 1000000000ULL
                               + (t1.tv_nsec - t0.tv_nsec);
                const char *mrule = m_held ? "outside_plan" : m_cert_refused ? "certificate_refused"
                                                                             : decision_rule_id(&act, m_raw);
                bool mlet = dry_let(&act, mrule);                   /* v1.29: to the kernel */
                emit_pathology(g_report_seq++, req.pid, &act, m_raw, m_final, mrule, lat_m, mlet ? 0 : EACCES);
                send_simple(notify_fd, req.id, mlet ? DEC_ALLOW : DEC_DENY);
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
        if ((g_any_name || g_inspect_on) && act.kind == ACT_FILE_OPEN && view_open_readonly(&act) &&
            view_by_target(act.target) >= 0) {
            view_serve(notify_fd, &req, &act, p, view_by_target(act.target), &t0);
            continue;
        }
        /* v1.24 review: an open of those files that could write is refused,
         * whatever the policy says. The Warden's resolver helper reads the
         * host's resolv.conf on every lookup, so an agent that could write it
         * would choose where allowed names lead. */
        if ((g_any_name || g_inspect_on) && act.kind == ACT_FILE_OPEN && !view_open_readonly(&act) &&
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
                /* v1.27: with launches decided, an open (not creating) of a
                 * name that does not exist is decided on where it would be,
                 * as a lookup is (v1.17): ENOENT where the policy allows the
                 * read, EACCES elsewhere. Before 1.27, refused as before. */
                int mofd = -1, miss = 0;
                if (g_exec_policy && g_exec_policy->v.launches &&
                    (!(act.open_flags & O_CREAT) || p->v.open_as_agent) &&   /* v1.29: creates too */
                    resolve_meta(req.pid, &act, -1, &mofd, &miss) == 0 && mofd < 0 && miss == ENOENT &&
                    in_protected_dir(act.resolved, -1) == 0) {
                    decision_t nr = policy_decide(p, &act);
                    bool nok = nr == DEC_ALLOW && certify(p, &act);
                    bool nheld = nok && hold_refuses(&act);                 /* v1.35 step 4 */
                    if (nheld) nok = false;
                    clock_gettime(CLOCK_MONOTONIC, &t1);
                    const char *nrule = nok ? "open_not_found" : nheld ? "outside_plan"
                                      : nr == DEC_ALLOW ? "certificate_refused" : decision_rule_id(&act, nr);
                    bool nlet = !nok && dry_let(&act, nrule);          /* v1.29: to the kernel */
                    emit_pathology(g_report_seq++, req.pid, &act, nr, nok ? DEC_ALLOW : DEC_DENY, nrule,
                                   (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec),
                                   nok ? ENOENT : nlet ? 0 : EACCES);
                    if (nlet) send_simple(notify_fd, req.id, DEC_ALLOW);
                    else send_errno(notify_fd, req.id, nok ? ENOENT : EACCES);
                    continue;
                }
                if (mofd >= 0) close(mofd);
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
            if ((g_any_name || g_inspect_on) && view_open_readonly(&act) && view_by_canonical(act.resolved) >= 0) {
                int v = view_by_canonical(act.resolved);
                resolved_target_close(&rt);
                view_serve(notify_fd, &req, &act, p, v, &t0);
                continue;
            }
            if ((g_any_name || g_inspect_on) && !view_open_readonly(&act) && view_by_canonical(act.resolved) >= 0) {
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
        bool cert_refused = false, held = false;
        if (d_final == DEC_ALLOW && act.kind == ACT_FILE_OPEN && !certify(p, &act)) {
            d_final = DEC_DENY;
            cert_refused = true;
            /* No agent-controlled byte here: the path is in the record. */
            log_line_start();
            fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n",
                    g_records, act.check_why);
        }
        /* v1.35 step 4: allowed and certified, but outside the run's plan */
        if (d_final == DEC_ALLOW && act.kind == ACT_FILE_OPEN && hold_refuses(&act)) {
            d_final = DEC_DENY;
            held = true;
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
            const char *orule = held ? "outside_plan" : cert_refused ? "certificate_refused"
                                                                     : decision_rule_id(&act, d_raw);
            bool olet = dry_let(&act, orule);       /* v1.29: to the kernel, as the agent */
            emit_pathology(g_report_seq++, req.pid, &act, d_raw, d_final, orule, lat_d, olet ? 0 : EACCES);
            send_simple(notify_fd, req.id, olet ? DEC_ALLOW : d_final);
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

        /* v1.29: in a dry run the filter sends a system call outside its
         * allowlist here (when enforcing it is refused there, EPERM): the
         * kernel carries it out, recorded as not enforced */
        if (act.kind == ACT_OTHER && g_dry) {
            act.dry = true;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            emit_pathology(g_report_seq++, req.pid, &act, DEC_UNKNOWN, DEC_DENY, "syscall_not_admitted",
                           (t1.tv_sec - t0.tv_sec) * 1000000000ULL + (t1.tv_nsec - t0.tv_nsec), 0);
            send_simple(notify_fd, req.id, DEC_ALLOW);
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
    ssize_t k = proc_readlinkf(out, n - 1, "self/fd/%d", fd);
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

/* v1.28 review: a file warden-secrets read must have one name only (as the
 * signing key), and no other name the agent could open through another mount
 * of its filesystem: a bind mount of the file, or of a directory above it,
 * shows it at a second path, which the agent's allowed opens (made by the
 * Warden, as root) would reach. Every mount of the file's filesystem
 * (/proc/self/mountinfo, the same device) whose root holds the file gives
 * that path; each is asked of the checker. 0, or -1 with the reason printed.
 * v1.28.1: trusted (a SPIFFE trust bundle, which the agent may read): the
 * same, for opens that write. */
static int refuse_secret_reachable(const struct policy *p, const char *path, bool trusted) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[warden] credentials: cannot open %s to check it (%s); refusing to start\n", path,
                strerror(errno));
        return -1;
    }
    struct stat st;
    char rp[PATH_MAX];
    int rc = 0;
    #define REACH(s_) (trusted ? vdpc_path_writable(&p->c, (s_), strlen(s_)) : vdpc_path_openable(&p->c, (s_), strlen(s_)))
    if (!trusted) rc = refuse_if_agent_can_open(p, fd, path, "file warden-secrets read");
    else if (fstat(fd, &st) < 0 || fd_path(fd, rp, sizeof rp) < 0) {
        fprintf(stderr, "[warden] trust bundle %s: cannot determine its path; refusing to start\n", path);
        rc = -1;
    } else if (S_ISREG(st.st_mode) && st.st_nlink != 1) {
        fprintf(stderr, "[warden] the trust bundle %s has %lu names (hard links); the agent could write it "
                "through another. Refusing to start.\n", rp, (unsigned long)st.st_nlink);
        rc = -1;
    } else if (REACH(rp)) {
        fprintf(stderr, "[warden] the policy lets the agent write %s, the trust bundle warden-secrets checks the "
                "agent's SVID against; refusing to start\n", rp);
        rc = -1;
    }
    if (rc == 0 && (fstat(fd, &st) < 0 || fd_path(fd, rp, sizeof rp) < 0)) rc = -1;
    close(fd);
    if (rc < 0) return -1;
    FILE *mi = proc_fopenf("self/mountinfo");
    if (!mi) {
        fprintf(stderr, "[warden] credentials: cannot read the mounts (%s); refusing to start\n", strerror(errno));
        return -1;
    }
    struct mnt { unsigned maj, min; char *root, *mp; } *m = NULL;
    size_t n = 0, cap = 0;
    char *line = NULL;
    size_t lc = 0;
    while (getline(&line, &lc, mi) > 0) {
        /* id parent major:minor root mountpoint ... */
        char *save = NULL, *f[5];
        int k = 0;
        for (char *t = strtok_r(line, " ", &save); t && k < 5; t = strtok_r(NULL, " ", &save)) f[k++] = t;
        unsigned maj, min;
        if (k < 5 || sscanf(f[2], "%u:%u", &maj, &min) != 2) continue;
        if (maj != major(st.st_dev) || min != minor(st.st_dev)) continue;
        if (n == cap) {
            cap = cap ? 2 * cap : 16;
            struct mnt *nm = realloc(m, cap * sizeof *m);
            if (!nm) break;
            m = nm;
        }
        noexec_unescape(f[3]);
        noexec_unescape(f[4]);
        m[n].maj = maj;
        m[n].min = min;
        m[n].root = strdup(f[3]);
        m[n].mp = strdup(f[4]);
        if (!m[n].root || !m[n].mp) { free(m[n].root); free(m[n].mp); break; }
        n++;
    }
    free(line);
    fclose(mi);
    /* the mount the file was reached through: the longest mount point above it */
    #define UNDER(a, b) (!strcmp(b, "/") || (!strncmp(a, b, strlen(b)) && (a[strlen(b)] == '/' || !a[strlen(b)])))
    size_t own = n, best = 0;
    for (size_t i = 0; i < n; i++)
        if (UNDER(rp, m[i].mp) && strlen(m[i].mp) >= best) { own = i; best = strlen(m[i].mp); }
    if (own < n) {
        /* the file's path inside its filesystem */
        char rel[PATH_MAX];
        const char *tail = !strcmp(m[own].mp, "/") ? rp : rp + strlen(m[own].mp);
        snprintf(rel, sizeof rel, "%s%s", !strcmp(m[own].root, "/") ? "" : m[own].root, tail);
        if (!rel[0]) snprintf(rel, sizeof rel, "/");
        for (size_t i = 0; rc == 0 && i < n; i++) {
            if (i == own || !UNDER(rel, m[i].root)) continue;
            char alt[PATH_MAX];
            const char *rest = !strcmp(m[i].root, "/") ? rel : rel + strlen(m[i].root);
            if (snprintf(alt, sizeof alt, "%s%s", !strcmp(m[i].mp, "/") ? "" : m[i].mp, rest) >= (int)sizeof alt)
                continue;
            if (strcmp(alt, rp) && REACH(alt)) {
                fprintf(stderr, "[warden] credentials: %s, which warden-secrets reads, is also mounted at %s, "
                        "which the policy lets the agent %s; refusing to start\n", rp, alt, trusted ? "write" : "open");
                rc = -1;
            }
        }
    }
    #undef UNDER
    #undef REACH
    for (size_t i = 0; i < n; i++) { free(m[i].root); free(m[i].mp); }
    free(m);
    return rc;
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
    if (g_anchor_lock_dir < 0) {
        /* the lock is opened again at the end through its directory, held
         * from here: under the node agent the Warden is in the container's
         * mount namespace by then, where the name is the container's */
        char d[PATH_MAX + 8];
        snprintf(d, sizeof d, "%s", lp);
        char *sl = strrchr(d, '/');
        if (sl == d) d[1] = '\0'; else if (sl) *sl = '\0'; else snprintf(d, sizeof d, ".");
        g_anchor_lock_dir = open(d, O_PATH | O_DIRECTORY | O_CLOEXEC);
    }
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
        int rw = proc_openf(O_RDWR | O_NONBLOCK, 0, "self/fd/%d", fd);
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
            const char *base = strrchr(g_anchor_lock, '/');
            int fd = g_anchor_lock_dir >= 0 ? openat(g_anchor_lock_dir, base ? base + 1 : g_anchor_lock,
                                                     O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
                                            : open(g_anchor_lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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

/* v1.35 step 2 (D9): each step the plan gate does not find SATISFIED is a
 * chained plan_step record, so `varek refusals` and the audit read why a plan
 * was refused from the stream itself (through v1.34 the basic gate's reasons
 * were lines on standard error only). The plan's own text (label, kind,
 * target) is escaped, as a path is. */
static void emit_plan_step(const char *plan_path, const plan_spec_action_t *a,
                           plan_decision_t pd, const struct plan_step_note *nt) {
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"plan_step\",\"run\":\"%s\",\"plan\":\"", g_run_id);
    json_escape(f, plan_path);
    fputs("\",\"label\":\"", f);
    json_escape(f, a->label ? a->label : "");
    fputs("\",\"kind\":\"", f);
    json_escape(f, a->kind ? a->kind : "");
    fputs("\",\"target\":\"", f);
    json_escape(f, a->target ? a->target : "");
    fputs("\",\"resolved\":\"", f);
    json_escape(f, nt->resolved);
    fprintf(f, "\",\"decision\":\"%s\",\"policy_line\":%d,\"why\":\"", plan_decision_name(pd),
            nt->policy_line);
    json_escape(f, nt->why);
    fprintf(f, "\",\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);
}

/* v1.35 step 2 (D9): the basic gate's outcome as a chained plan_gate record
 * (the flow gate writes its own, with the breaker's fields): the plan, its
 * size, the verdict, and why it could not be read when it could not. Through
 * v1.34 the outcome was a line on standard error only. */
static void emit_plan_gate_basic(const char *plan_path, size_t n_actions, size_t n_edges,
                                 plan_decision_t pd, const char *error) {
    FILE *f = rec_begin();
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f, "{\"event\":\"plan_gate\",\"run\":\"%s\",\"gate\":\"plan\",\"plan\":\"", g_run_id);
    json_escape(f, plan_path);
    fprintf(f, "\",\"actions\":%zu,\"edges\":%zu,\"verdict\":\"%s\"", n_actions, n_edges,
            plan_decision_name(pd));
    if (error) {
        fputs(",\"error\":\"", f);
        json_escape(f, error);
        fputc('"', f);
    }
    fprintf(f, ",\"timestamp_ns\":%lld}\n", (long long)(ts.tv_sec * 1000000000LL + ts.tv_nsec));
    rec_end(NULL);
}

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
static bool g_check_creds = false;      /* v1.28: --check-credentials (fetch each, then stop) */
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

    struct warden_plan_ud ud = { .policy = policy, .parsed = parsed, .spec = spec,
                                 .plan_path = plan_path };
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
    fprintf(f, "{\"event\":\"plan_gate\",\"run\":\"%s\",\"gate\":\"flow\",\"plan\":\"", g_run_id);
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
        "usage: %s <policy.txt> [--plan <plan.txt> [--hold-to-plan] [--flow-policy <cfg>\n"
        "              [--session <id>] [--breaker-state <file>] [--gate-status <file>]]]\n"
        "              [--sign-key <key>]\n"
        "              [--anchor <path>] [--checkpoint-every <n>] [--run-as <user>]\n"
        "              [--dns-server <a.b.c.d[:port]>] [--dns-ttl-min <s>] [--dns-ttl-max <s>]\n"
        "              [--dns-grace-max <s>] [--psl <file>] [--shared-domains <file>]\n              [--proxy-as <user>] [--proxy-bin <warden-proxy>] [--trust-bundle <pem>]\n"
        "              [--secrets-as <user>] [--secrets-bin <warden-secrets>] [--secrets-conf <file>]\n"
        "              [--on-behalf-of <token file> [--on-behalf-of-expiry revoke|record]]\n"
        "              [--agent-svid <svid file>]\n"
        "              [--writable-exec]\n"
        "              -- <target> [args...]\n"
        "       %s <policy.txt> [the options above] --check-startup   (v1.21)\n"
        "       %s <policies dir | policy.txt> --node-agent <socket> --node-streams <dir>\n"
        "              [--node-launcher <varek-init>]   (v1.34: the node agent, one supervisor a container)\n"
        "       %s <policy.txt> --oci-filter [--plan PLAN | --no-plan]   (v1.34: the policy's filter in OCI's form, for the\n"
        "              NRI plugin; v1.35: with the pod's plan, or for a pod that names none)\n"
        , argv0, argv0, argv0, argv0);
    fprintf(stderr,
        "\n"
        "  Privileged seccomp-unotify supervisor (VAREK Warden v1.4).\n"
        "  --check-startup runs the startup checks and exits (0: would start).\n"
        "  --check-credentials (v1.28, root) does too, and fetches each credential the policy names\n"
        "      with warden-secrets (versions and lengths only; a Vault lease it makes is revoked).\n"

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
        );
    fputs(
        "  --on-behalf-of (v1.28.1, root): the user's token (a JWT in a root-owned file) the run acts\n"
        "      for, verified by warden-secrets against an issuer the policy trusts (`trust issuer`);\n"
        "      --agent-svid: the agent's X.509-SVID and key, verified against `trust spiffe`'s bundle.\n"
        "      run_start records what was verified (never the token). When the token expires during\n"
        "      the run it is recorded (on_behalf_of_expired) and the run revoked, as by varek revoke;\n"
        "      --on-behalf-of-expiry record lets the run go on.\n"
        "\n"
        , stderr);
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

#include "warden_node.inc.c"         /* v1.34 step 2: the node agent */

int main(int argc, char **argv) {
    /* v1.24: the resolver helper is this program re-executed (a clean address
     * space, without the signing key); see warden_resolve.h. */
    if (argc >= 2 && !strcmp(argv[1], "--resolver-helper")) return wr_helper_exec_main(argc, argv);
    /* v1.34: the node's /proc, held from the start (proc_dir) */
    if (proc_dir() < 0) { fprintf(stderr, "[warden] cannot open /proc: %s\n", strerror(errno)); return 2; }
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
    bool oci_only = false, oci_no_plan = false;
    for (int i = 2; i < argc && strcmp(argv[i], "--"); i++)
        if (!strcmp(argv[i], "--check-startup")) g_check_only = true;
        else if (!strcmp(argv[i], "--check-credentials")) g_check_only = g_check_creds = true;   /* v1.28 */
        else if (!strcmp(argv[i], "--oci-filter")) oci_only = true;                             /* v1.34 step 3 */
        else if (!strcmp(argv[i], "--no-plan")) oci_no_plan = true;                             /* v1.35 step 4c */
    if (argc < (g_check_only || oci_only ? 3 : 4)) { usage(argv[0]); return 2; }

    const char *policy_path = argv[1];
    const char *plan_path   = NULL;
    const char *key_path    = NULL;     /* v1.16 */
    const char *anchor_path = NULL;     /* v1.16 */
    const char *run_as_arg  = NULL;     /* v1.17.0 */
    const char *proxy_as_arg = NULL;    /* v1.26: the egress proxy's user */
    const char *proxy_bin_arg = NULL;   /* v1.26.1: the warden-proxy binary */
    const char *secrets_bin_arg = NULL, *secrets_as_arg = NULL, *secrets_conf_arg = NULL;   /* v1.28 */
    const char *obo_arg = NULL, *svid_arg = NULL, *obo_exp_arg = NULL;                  /* v1.28.1 */
    const char *flow_path   = NULL;     /* v1.18.0 */
    const char *session_arg = NULL;     /* v1.18.0 */
    const char *state_arg   = NULL;     /* v1.18.0 */
    const char *gstatus_arg = NULL;     /* v1.18.0 */
    wr_config_t dns_cfg;                /* v1.24 */
    const char *psl_arg = NULL, *shared_arg = NULL;   /* v1.25 */
    wr_config_default(&dns_cfg);
    int sep_idx = -1;
    const char *node_sock = NULL, *node_streams = NULL;                     /* v1.34 step 2 */
    const char *node_launcher = NULL;                                       /* v1.34 step 3 */

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep_idx = i; break; }
        if (strcmp(argv[i], "--check-startup") == 0 || strcmp(argv[i], "--check-credentials") == 0 ||
            strcmp(argv[i], "--oci-filter") == 0 || strcmp(argv[i], "--no-plan") == 0) continue;
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
        } else if (strcmp(argv[i], "--dry-run") == 0) {                  /* v1.29 */
            g_dry = true;
        } else if (strcmp(argv[i], "--hold-to-plan") == 0) {             /* v1.35 step 4 */
            g_hold_req = true;
        } else if (strcmp(argv[i], "--node-agent") == 0 && !node_sock && i + 1 < argc) {   /* v1.34 step 2 */
            node_sock = argv[++i];
        } else if (strcmp(argv[i], "--node-streams") == 0 && !node_streams && i + 1 < argc) {
            node_streams = argv[++i];
        } else if (strcmp(argv[i], "--node-launcher") == 0 && !node_launcher && i + 1 < argc) {   /* v1.34 step 3 */
            node_launcher = argv[++i];
        } else if (strcmp(argv[i], "--writable-exec") == 0) {            /* v1.27.1 */
            g_writable_exec = true;
        } else if (strcmp(argv[i], "--run-as") == 0 && !run_as_arg) {
            run_as_arg = argv[++i];
        } else if (strcmp(argv[i], "--proxy-as") == 0 && !proxy_as_arg) {   /* v1.26 */
            proxy_as_arg = argv[++i];
        } else if (strcmp(argv[i], "--proxy-bin") == 0 && !proxy_bin_arg) { /* v1.26.1 */
            proxy_bin_arg = argv[++i];
        } else if (strcmp(argv[i], "--secrets-bin") == 0 && !secrets_bin_arg) { /* v1.28 */
            secrets_bin_arg = argv[++i];
        } else if (strcmp(argv[i], "--secrets-as") == 0 && !secrets_as_arg) {   /* v1.28 */
            secrets_as_arg = argv[++i];
        } else if (strcmp(argv[i], "--secrets-conf") == 0 && !secrets_conf_arg) { /* v1.28 */
            secrets_conf_arg = argv[++i];
        } else if (strcmp(argv[i], "--on-behalf-of") == 0 && !obo_arg) {      /* v1.28.1 */
            obo_arg = argv[++i];
        } else if (strcmp(argv[i], "--agent-svid") == 0 && !svid_arg) {       /* v1.28.1 */
            svid_arg = argv[++i];
        } else if (strcmp(argv[i], "--on-behalf-of-expiry") == 0 && !obo_exp_arg) {   /* v1.28.1 step 4 */
            obo_exp_arg = argv[++i];
            if (strcmp(obo_exp_arg, "revoke") && strcmp(obo_exp_arg, "record")) {
                fprintf(stderr, "[warden] --on-behalf-of-expiry takes revoke (the default) or record\n");
                return 2;
            }
            g_obo_on_expiry = !strcmp(obo_exp_arg, "record");
        } else if (strcmp(argv[i], "--trust-bundle") == 0 && !g_trust_bundle_arg) { /* v1.26.1 */
            g_trust_bundle_arg = argv[++i];
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

    /* v1.34 step 3: the filter in OCI's form, for the NRI plugin */
    if (oci_only) {
        if (sep_idx >= 0 || g_check_only || node_sock || g_dry || flow_path || g_hold_req ||
            (plan_path && oci_no_plan)) {
            fprintf(stderr, "[warden] --oci-filter takes the policy, and the pod's plan (--plan PLAN) or "
                    "--no-plan\n");
            return 2;
        }
        static struct policy op;
        if (policy_load(policy_path, &op) < 0) return 1;
        /* v1.34 step 5: written only for a policy the node agent carries
         * (the plugin's, and the admission check's, test) */
        const char *no = node_policy_why(&op);
        if (no) {
            fprintf(stderr, "[warden] --oci-filter: the node agent does not carry %s yet\n", no);
            return 1;
        }
        /* v1.35 step 4c (D11): with the pod's plan (--plan), or for a pod
         * that names none (--no-plan), which a policy that says `require
         * plan` refuses; the policy alone (a VarekPolicy) is checked as before */
        char why[200];
        if (oci_no_plan && op.v.require_plan) {
            fprintf(stderr, "[warden] --oci-filter: the policy says `require plan`: a pod under it names its plan "
                    "(varek.dev/plan)\n");
            return 1;
        }
        if (plan_path && node_plan_carried(plan_path, why, sizeof why) < 0) {
            fprintf(stderr, "[warden] --oci-filter: the plan %s: %s\n", plan_path, why);
            return 1;
        }
        if (wd_oci_filter_write(stdout, op.v.open_as_agent ? WD_FILTER_CHANGES : 0, why, sizeof why) < 0 ||
            fflush(stdout) != 0) {
            fprintf(stderr, "[warden] --oci-filter: %s\n", why);
            return 1;
        }
        return 0;
    }
    if ((node_sock && (sep_idx >= 0 || g_check_only || !node_streams || g_writable_exec || plan_path ||
                       flow_path || g_hold_req)) ||
        (node_launcher && !node_sock) || (oci_no_plan && !oci_only)) {     /* v1.34 step 2 */
        fprintf(stderr, "[warden] --node-agent takes --node-streams DIR, and no agent (\"--\"), check, plan (each "
                "pod names its own, v1.35) or --writable-exec (a pod's mounts are checked, D4); --node-launcher "
                "goes with --node-agent, --no-plan with --oci-filter\n");
        return 2;
    }
    if (node_sock && node_listen(node_sock, node_streams, node_launcher, &policy_path, &plan_path) < 0) return 1;
    /* from here, under the node agent, the supervisor of one container */
    if (!g_check_only && !g_nr.on && (sep_idx < 0 || sep_idx + 1 >= argc)) { usage(argv[0]); return 2; }
    /* v1.35 step 4: the hold needs a plan to hold to; its path and hash are
     * read now, for run_start and every outside_plan record */
    if (g_hold_req) {
        if (!plan_path) {
            fprintf(stderr, "[warden] --hold-to-plan holds a run to its plan; give --plan too\n");
            return 2;
        }
        if (sha256_file_hex(plan_path, g_hold_plan_sha) < 0) {
            fprintf(stderr, "[warden] cannot read the plan %s (%s)\n", plan_path, strerror(errno));
            return 1;
        }
        char *jb = NULL;
        size_t jn = 0;
        FILE *jf = open_memstream(&jb, &jn);
        if (!jf) return 1;
        json_escape(jf, plan_path);
        fclose(jf);
        snprintf(g_hold_plan_json, sizeof g_hold_plan_json, "%s", jb ? jb : "");
        free(jb);
    }
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
    if (g_nr.on) {                                                       /* v1.34 step 2 */
        ra.uid = g_nr.uid;
        ra.gid = g_nr.gid;
        ra.drop = g_nr.uid != 0;
        if (ra.drop && ra.gid == 0) node_fail("an unprivileged user in group 0 (root)");
    }
    if (!ra.drop)
        fprintf(stderr, "[warden] WARNING: --run-as root: the agent runs as root with every "
                "capability (the pre-v1.17 behaviour); only the seccomp filter holds it back\n");
    static char boot_path[PATH_MAX];
    if (g_nr.on) snprintf(boot_path, sizeof boot_path, "%s", g_nr.argv0);   /* v1.34: in the container's view */
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

    /* ~2 MB (512 rules x 4 KB constants): static, not on the stack. */
    static struct policy p;
    if (policy_load(policy_path, &p) < 0) return 1;
    /* v1.29: a dry run (section 3), on the command line only (D3). Not with
     * a plan (the plan gate refuses before the agent starts; no command
     * checks a plan without starting the agent: v1.35), with credentials (it would hand the
     * proxy real values for an agent whose policy is not settled: D2), or
     * with sub-agents (their attribution rests on launches being held). */
    if (g_dry) {
        bool subs = false;
        for (size_t i = 0; i < p.v.n; i++) if (p.v.rules[i].subagent[0]) subs = true;
        const char *no = plan_path ? "--plan" : p.v.ncreds ? "a policy that names credentials"
                       : subs ? "a policy that names sub-agents (subagent=)" : NULL;
        if (no) {
            fprintf(stderr, "[warden] --dry-run with %s is refused\n", no);
            return 2;
        }
        fprintf(stderr, "[warden] DRY RUN: NOT ENFORCING. Every call is decided and recorded; a call the "
                "policy refuses is let through (\"enforced\":false). The protected objects, the hard-denied "
                "system calls and revocation still refuse.\n");
        g_writable_exec = true;          /* no noexec mounts: launches are not held */
    }

    /* v1.16: log integrity. */
    /* v1.29 (step 9): libcrypto only hashes the launch set; it reads no
     * configuration file, so no module or provider one names is loaded */
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
        fprintf(stderr, "[warden] libcrypto failed to initialize\n");
        return 1;
    }
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
    /* v1.34 step 4: in a pod, names are resolved from the pod's network
     * through the pod's DNS server (the kubelet's resolv.conf: the cluster's
     * DNS), unless --dns-server names one; the node's own may be on its
     * loopback, which the pod's network does not reach */
    if (g_nr.on && !dns_cfg.server && g_nr.dns[0]) dns_cfg.server = g_nr.dns;
    if (names_setup(&p, &dns_cfg) < 0) return 1;                            /* v1.24 */
    if (g_nr.on && g_names_on && !dns_cfg.server)
        node_fail("the policy names hosts, and the pod's /etc/resolv.conf names no IPv4 nameserver to resolve "
                  "them through (give the node agent --dns-server)");
    if (g_nr.on) {                                                         /* v1.34 step 2 */
        const char *no = node_unsupported(&p, g_dry, plan_path, flow_path, obo_arg, svid_arg, g_trust_bundle_arg);
        if (no) {
            char why[256];
            snprintf(why, sizeof why, "%s is not carried under the node agent yet", no);
            node_fail(why);
        }
    }
    /* v1.35 step 4 (D7): a policy that says `require plan` runs an agent only
     * with a plan it is held to */
    if (p.v.require_plan && g_nr.on && !plan_path)                       /* v1.35 step 4c (D11) */
        node_fail("its policy says `require plan`, and its pod names no plan (varek.dev/plan)");
    if (p.v.require_plan && !g_nr.on && (!plan_path || !g_hold_req)) {
        if (g_check_only) {
            fprintf(stderr, "[warden] note: the policy says `require plan`: a run needs a plan it is held to "
                    "(--plan PLAN --hold-to-plan)\n");
        } else {
            fprintf(stderr, "[warden] the policy says `require plan`: a run needs a plan it is held to "
                    "(--plan PLAN --hold-to-plan); refusing to start\n");
            return 1;
        }
    }
    if (wildcards_check(policy_path, &p, psl_arg, shared_arg) < 0) return 1;            /* v1.25 */
    g_inspect_on = p.v.proxy_inspect;                                      /* v1.26.1 */
    if (g_any_name || g_inspect_on) views_setup();
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
            ssize_t n = proc_readlinkf(pb, sizeof pb - 16, "self/exe");
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
        fprintf(stderr, "[warden] egress proxy (%s) on 127.0.0.1:%u as %u:%u\n",
                p.v.proxy_inspect ? "inspecting mode" : "SNI mode", g_proxy.port, (unsigned)g_proxy.uid, (unsigned)g_proxy.gid);
    }
    if (proxy_fd >= 0) close(proxy_fd);
    /* v1.28: the credentials (docs/security/v1.28-credential-release.md,
     * section 2). warden-secrets, from a sealed copy hashed for run_start,
     * as its own user, fetches each one; the Warden learns each one's
     * version and length and the local files the helper read, never a
     * value. A fetch that fails, or a file the policy would let the agent
     * open, refuses the start.
     * v1.28.1: the same helper verifies the user's token and the agent's
     * SVID (docs/security/v1.28.1-delegation-chain.md, section 2), first. */
    if (p.v.require_obo && !obo_arg) {
        fprintf(stderr, "[warden] the policy has `require on-behalf-of`: give the user's token with "
                "--on-behalf-of FILE; refusing to start\n");
        return 2;
    }
    if (obo_exp_arg && !obo_arg) {
        fprintf(stderr, "[warden] --on-behalf-of-expiry: there is no user's token (--on-behalf-of) to expire\n");
        return 2;
    }
    if (obo_arg && !p.v.nissuers && !p.v.nmcpres) {         /* v1.31: or an MCP resource's servers */
        fprintf(stderr, "[warden] --on-behalf-of: the policy trusts no issuer (`trust issuer URL audience AUD` or "
                "`trust mcp-resource URL`), so no token can be verified; refusing to start\n");
        return 2;
    }
    if (svid_arg && !p.v.nspiffe) {
        fprintf(stderr, "[warden] --agent-svid: the policy trusts no SPIFFE trust domain (`trust spiffe DOMAIN "
                "bundle PATH`), so no SVID can be verified; refusing to start\n");
        return 2;
    }
    /* v1.28.1 review: every bundle the policy trusts, whether this run checks
     * an SVID against it or not, is out of the agent's reach for writing (by
     * its name, its resolved name, or a second one): a bundle changed in one
     * run is trusted in the next */
    for (size_t k = 0; k < p.v.nspiffe; k++) {
        const char *b = p.v.spiffe[k].bundle;
        char rb[PATH_MAX];
        if (vdpc_path_writable(&p.c, b, strlen(b)) ||
            (realpath(b, rb) && vdpc_path_writable(&p.c, rb, strlen(rb)))) {
            fprintf(stderr, "[warden] the policy lets the agent write %s, the trust bundle for %s (line %d); "
                    "refusing to start\n", b, p.v.spiffe[k].domain, p.v.spiffe[k].line);
            return 1;
        }
        if (access(b, F_OK) == 0 && refuse_secret_reachable(&p, b, true) < 0) return 1;
    }
    if (p.v.ncreds || obo_arg || svid_arg) {
        static const char *const kStore[] = { "", "file", "vault", "aws-sm" };
        const char *conf = secrets_conf_arg ? secrets_conf_arg : "/etc/varek/secrets.conf";
        /* v1.28 review: the helper reads absolute paths only */
        static char conf_abs[PATH_MAX], obo_abs[PATH_MAX], svid_abs[PATH_MAX];
        if (conf[0] != '/' && realpath(conf, conf_abs)) conf = conf_abs;
        char cwd[PATH_MAX];
        if (obo_arg && obo_arg[0] != '/' && getcwd(cwd, sizeof cwd) &&
            (size_t)snprintf(obo_abs, sizeof obo_abs, "%s/%s", cwd, obo_arg) < sizeof obo_abs)
            obo_arg = obo_abs;
        if (svid_arg && svid_arg[0] != '/' && getcwd(cwd, sizeof cwd) &&
            (size_t)snprintf(svid_abs, sizeof svid_abs, "%s/%s", cwd, svid_arg) < sizeof svid_abs)
            svid_arg = svid_abs;
        if (g_check_only && !g_check_creds) {
            for (size_t k = 0; k < p.v.ncreds; k++)
                fprintf(stderr, "[warden]   credential %s from %s:%s (line %d)\n", p.v.creds[k].name,
                        kStore[p.v.creds[k].store], p.v.creds[k].ref, p.v.creds[k].line);
            if (obo_arg) fprintf(stderr, "[warden]   the user's token %s (--check-credentials verifies it); when it "
                                 "expires: %s\n", obo_arg, g_obo_on_expiry ? "recorded, the run goes on" : "the run is revoked");
            if (svid_arg) fprintf(stderr, "[warden]   the agent's SVID %s (--check-credentials verifies it)\n", svid_arg);
        } else {
            if (geteuid() != 0) {
                fprintf(stderr, "[warden] %s need the Warden to run as root (warden-secrets runs as "
                        "its own user); refusing to start\n",
                        p.v.ncreds ? "credentials" : "the user's token and the agent's SVID");
                return 2;
            }
            struct run_as sca = { .drop = false };
            const char *sas = secrets_as_arg ? secrets_as_arg : getpwnam("varek-secrets") ? "varek-secrets" : "65531:65531";
            if (parse_run_as(sas, &sca) < 0 || !sca.drop) {
                fprintf(stderr, "[warden] --secrets-as %s: give an unprivileged user (name, uid or uid:gid) "
                        "with a non-root group\n", sas);
                return 2;
            }
            if (sca.uid == ra.uid || (p.v.proxy && sca.uid == pxa.uid)) {
                fprintf(stderr, "[warden] --secrets-as %s: warden-secrets may not run as the agent's user or "
                        "the proxy's; give it its own\n", sas);
                return 2;
            }
            char sb[PATH_MAX], why[PATH_MAX + 256];
            if (secrets_bin_arg) snprintf(sb, sizeof sb, "%s", secrets_bin_arg);
            else {
                ssize_t n = proc_readlinkf(sb, sizeof sb - 16, "self/exe");
                if (n <= 0) { fprintf(stderr, "[warden] cannot find this binary's directory\n"); return 1; }
                sb[n] = '\0';
                char *sl = strrchr(sb, '/');
                snprintf(sl ? sl + 1 : sb, sizeof sb - (size_t)(sl ? sl + 1 - sb : 0), "warden-secrets");
            }
            int sfd = wp_load(sb, g_secrets_sha, why, sizeof why);
            if (sfd < 0) {
                fprintf(stderr, "[warden] warden-secrets: %s; build it (make warden-secrets) or name it with "
                        "--secrets-bin; refusing to start\n", why);
                return 1;
            }
            fprintf(stderr, "[warden] credentials' helper %s, SHA-256 %s\n", sb, g_secrets_sha);
            if (ws_start(&g_secrets, sfd, sca.uid, sca.gid) < 0) {
                close(sfd);
                fprintf(stderr, "[warden] cannot start warden-secrets (%s); refusing to start\n", strerror(errno));
                return 1;
            }
            close(sfd);
            int store[WS_MAX_CREDS];
            const char *ref[WS_MAX_CREDS];
            for (size_t k = 0; k < p.v.ncreds; k++) { store[k] = p.v.creds[k].store; ref[k] = p.v.creds[k].ref; }
            static char files[WS_MAX_FILES][4096];
            static uint32_t fkind[WS_MAX_FILES];
            size_t nfiles = 0;
            /* v1.28.1: the identities, with the policy's issuers and domains */
            static struct ws_issuer wiss[VDP_MAX_ISSUERS];
            static struct ws_spiffe wspf[VDP_MAX_SPIFFE];
            for (size_t k = 0; k < p.v.nissuers; k++) {
                memcpy(wiss[k].iss, p.v.issuers[k].iss, sizeof wiss[k].iss);
                memcpy(wiss[k].aud, p.v.issuers[k].aud, sizeof wiss[k].aud);
                memcpy(wiss[k].jwks, p.v.issuers[k].jwks, sizeof wiss[k].jwks);
            }
            for (size_t k = 0; k < p.v.nspiffe; k++) {
                memcpy(wspf[k].domain, p.v.spiffe[k].domain, sizeof wspf[k].domain);
                memcpy(wspf[k].bundle, p.v.spiffe[k].bundle, sizeof wspf[k].bundle);
            }
            /* v1.31: each credential's audience=, and the MCP resources trusted */
            static const char *caud[WS_MAX_CREDS];
            static bool copq[WS_MAX_CREDS];
            for (size_t k = 0; k < p.v.ncreds; k++) { caud[k] = p.v.creds[k].audience; copq[k] = p.v.creds[k].opaque; }
            static struct ws_mcpres wmr[VDP_MAX_MCPRES];
            for (size_t k = 0; k < p.v.nmcpres; k++) {
                memcpy(wmr[k].url, p.v.mcpres[k].url, sizeof wmr[k].url);
                memcpy(wmr[k].aud, p.v.mcpres[k].aud, sizeof wmr[k].aud);
            }
            ws_idreq_t idr = { .token = obo_arg, .svid = svid_arg, .issuers = wiss, .nissuers = p.v.nissuers,
                               .spiffe = wspf, .nspiffe = p.v.nspiffe, .id = &g_identity, .kinds = fkind,
                               .audience = caud, .opaque = copq, .mcpres = wmr, .nmcpres = p.v.nmcpres };
            int fr = ws_fetch_id(&g_secrets, conf, p.v.ncreds, store, ref, g_cred_meta, files, &nfiles, &idr, 30000,
                                 why, sizeof why);
            /* every local file the helper read, whatever came of it: the
             * agent must not be able to open one (v1.28.1: a trust bundle,
             * to write one) */
            for (size_t k = 0; k < nfiles; k++) {
                char real[PATH_MAX];
                const char *f = realpath(files[k], real) ? real : files[k];
                if (fkind[k] == WS_FILE_TRUSTED) {
                    /* one the helper could not find: its own refusal says so */
                    if (fr < 0 && access(files[k], F_OK) < 0 && errno == ENOENT) continue;
                    if (refuse_secret_reachable(&p, files[k], true) < 0) {
                        ws_stop(&g_secrets);
                        return 1;
                    }
                    continue;
                }
                if (vdpc_path_openable(&p.c, f, strlen(f))) {
                    fprintf(stderr, "[warden] credentials: the policy lets the agent open %s, which warden-secrets "
                            "reads; refusing to start\n", f);
                    ws_stop(&g_secrets);
                    return 1;
                }
                /* v1.28 review: nor through a second name (a hard link, a bind mount) */
                if (refuse_secret_reachable(&p, files[k], false) < 0) {
                    ws_stop(&g_secrets);
                    return 1;
                }
            }
            if (fr < 0) {
                /* name the credential, not its index */
                unsigned idx;
                const char *rest = why;
                if (sscanf(why, "credential %u: ", &idx) == 1 && idx < p.v.ncreds && (rest = strchr(why, ':')))
                    fprintf(stderr, "[warden] credential %s (line %d): %s; refusing to start\n",
                            p.v.creds[idx].name, p.v.creds[idx].line, rest + 2);
                else if (!strncmp(why, "the user's token: ", 18) || !strncmp(why, "the agent's SVID: ", 18))
                    fprintf(stderr, "[warden] %s; refusing to start\n", why);
                else
                    fprintf(stderr, "[warden] credentials: %s; refusing to start\n", why);
                ws_stop(&g_secrets);
                return 1;
            }
            if (g_identity.has_user) {
                const struct ws_identity *id = &g_identity;
                fprintf(stderr, "[warden] on behalf of %s (issuer %s, line %d): token verified (%s%s%s), expires in "
                        "%lld s (then %s), SHA-256 %s\n", id->sub,
                        id->mcp_resource ? id->found_iss : p.v.issuers[id->issuer].iss,       /* v1.31 */
                        id->mcp_resource ? p.v.mcpres[id->mcp_resource - 1].line : p.v.issuers[id->issuer].line,
                        id->alg, id->kid[0] ? ", key " : "", id->kid, (long long)(id->exp - time(NULL)),
                        g_obo_on_expiry ? "recorded" : "the run is revoked", id->token_sha256);
                for (uint32_t k = 0; k < id->nact; k++)
                    fprintf(stderr, "[warden]   actor %u: %s%s%s\n", k + 1, id->act[k].sub,
                            id->act[k].iss[0] ? ", issuer " : "", id->act[k].iss);
            }
            if (g_identity.has_svid)
                fprintf(stderr, "[warden] agent %s: SVID verified against the bundle for %s (line %d), SHA-256 %s\n",
                        g_identity.spiffe_id, p.v.spiffe[g_identity.spiffe].domain, p.v.spiffe[g_identity.spiffe].line,
                        g_identity.svid_sha256);
            for (size_t k = 0; k < p.v.ncreds; k++)
                fprintf(stderr, "[warden] credential %s from %s:%s: fetched, %u bytes, version %s\n",
                        p.v.creds[k].name, kStore[p.v.creds[k].store], p.v.creds[k].ref,
                        g_cred_meta[k].len, g_cred_meta[k].version);
            if (!p.v.ncreds) {
                /* identities only: the helper's work is done */
                ws_stop(&g_secrets);
                if (g_check_creds) fprintf(stderr, "[warden] identities: verified\n");
            } else if (g_check_creds) {
                /* v1.28: a check fetches and hands nothing on: the leases it
                 * made are revoked, the helper clears the values and ends */
                struct ws_revoked rv = { 0 };
                struct pollfd pf = { .fd = g_secrets.ctl, .events = POLLIN };
                bool answered = false;
                if (ws_revoke(&g_secrets) == 0) {
                    /* review: a renewal due at once may be reported first */
                    union { struct ws_revoked r; struct ws_renewed n; uint32_t type; } m;
                    while (!answered && poll(&pf, 1, 15000) == 1) {
                        ssize_t k = recv(g_secrets.ctl, &m, sizeof m, 0);
                        if (k == (ssize_t)sizeof m.n && m.type == WS_MSG_RENEWED) continue;
                        if (k != (ssize_t)sizeof m.r || m.type != WS_MSG_REVOKED) break;
                        rv = m.r;
                        answered = true;
                    }
                }
                ws_stop(&g_secrets);
                if (!answered || rv.failed) {
                    fprintf(stderr, "[warden] credentials: fetched, but %s; refusing to start\n",
                            answered ? "a Vault lease the check made could not be revoked" :
                            "warden-secrets did not answer the check's revocation");
                    return 1;
                }
                if (rv.revoked)
                    fprintf(stderr, "[warden] credentials: the %u Vault lease(s) the check made are revoked\n",
                            rv.revoked);
                fprintf(stderr, "[warden] credentials: each one fetched (its value not kept)\n");
            } else {
                /* step 3: a placeholder for each, made for this run (32 random
                 * bytes), in the agent's environment as VAREK_CRED_<NAME>; the
                 * proxy gets the placeholders from the Warden and the values from
                 * warden-secrets, over a socket the Warden only passes on */
                for (size_t k = 0; k < p.v.ncreds; k++) {
                    unsigned char rnd[32], dg[32];
                    char b64[64], env[48];
                    randombytes_buf(rnd, sizeof rnd);
                    sodium_bin2base64(b64, sizeof b64, rnd, sizeof rnd, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
                    snprintf(g_cred_ph[k], sizeof g_cred_ph[k], "varek_ph_%s_%s", p.v.creds[k].name, b64);
                    crypto_hash_sha256(dg, (const unsigned char *)g_cred_ph[k], strlen(g_cred_ph[k]));
                    sodium_bin2hex(g_cred_ph_sha[k], sizeof g_cred_ph_sha[k], dg, sizeof dg);
                    int el = snprintf(env, sizeof env, "VAREK_CRED_%s", p.v.creds[k].name);
                    for (int q = 11; q < el; q++) env[q] = (char)toupper((unsigned char)env[q]);
                    if (setenv(env, g_cred_ph[k], 1) < 0) {
                        fprintf(stderr, "[warden] cannot set %s (%s); refusing to start\n", env, strerror(errno));
                        ws_stop(&g_secrets);
                        return 1;
                    }
                    sodium_memzero(rnd, sizeof rnd);
                }
                int vs[2];
                if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, vs) < 0 || ws_hand_to(&g_secrets, vs[0]) < 0 ||
                    wp_creds(&g_proxy, p.v.ncreds, g_cred_ph, vs[1], 10000, why, sizeof why) < 0) {
                    fprintf(stderr, "[warden] credentials: %s; refusing to start\n",
                            g_proxy.ctl < 0 ? "the proxy is not running" : why);
                    ws_stop(&g_secrets);
                    return 1;
                }
                close(vs[0]);
                close(vs[1]);
                fprintf(stderr, "[warden] credentials: %zu held by the proxy; the agent has placeholders "
                        "(VAREK_CRED_<NAME>)\n", p.v.ncreds);
            }
        }
    }
    /* v1.27: with `require warden 1.27`, the files the agent may launch and
     * the Landlock ruleset that holds it to them (warden_exec.inc.c). v1.34
     * step 3: under the node agent, in the container's view (node_supervise) */
    if (p.v.launches && !g_nr.on) {
        if (exec_ruleset_build(&p, target_argv ? boot_path : NULL) < 0 ||
            exec_confined_checks(&p) < 0) {              /* v1.31 */
            if (g_sk) sodium_free(g_sk);
            return 1;
        }
        fprintf(stderr, "[warden] launch set: %zu files, %s\n", g_exec_n,
                g_dry ? "not held (dry run)" :
                g_ll_abi >= 1 ? "held by Landlock" : "no Landlock: later launches refused");
        if (g_check_only)
            for (size_t k = 0; k < g_exec_n; k++) {
                const struct exec_file *e = &g_exec_rs[k];
                bool same = !strcmp(e->name, e->path);
                fprintf(stderr, "[warden]   %s%s%s, sha256 %.16s..., %s", e->name, same ? "" : " -> ",
                        same ? "" : e->path, e->sha, e->why);
                if (e->line) fprintf(stderr, " (line %d)", e->line);
                fputc('\n', stderr);
            }
        /* v1.27.1: the directories the agent may write, mounted noexec */
        if (g_writable_exec) {
            fprintf(stderr, "[warden] noexec: off (--writable-exec): files the agent writes may be "
                    "mapped executable\n");
        } else {
            if (noexec_build(&p, target_argv ? boot_path : NULL) < 0) {
                if (g_sk) sodium_free(g_sk);
                return 1;
            }
            if (!g_check_only && noexec_mount() < 0) {      /* step 2: before the agent is forked */
                if (g_sk) sodium_free(g_sk);
                return 1;
            }
            size_t gone = 0;
            for (size_t k = 0; k < g_nx_n; k++) gone += g_nx[k].missing;
            fprintf(stderr, "[warden] noexec: %zu writable director%s %s noexec", g_nx_n - gone,
                    g_nx_n - gone == 1 ? "y" : "ies", g_check_only ? "to mount" : "mounted");
            if (gone) fprintf(stderr, ", %zu not there (opens under %s refused if it appears)", gone,
                              gone == 1 ? "it" : "one");
            fputc('\n', stderr);
            if (g_check_only)
                for (size_t k = 0; k < g_nx_n; k++)
                    fprintf(stderr, "[warden]   noexec %s%s (line %d)\n", g_nx[k].path,
                            g_nx[k].missing ? " (not there; opens under it refused if it appears)"
                            : g_nx[k].file ? " (a file)" : "", g_nx[k].line);
        }
    }
    /* v1.29 step 1: files opened as the agent (require warden 1.29) */
    g_changes_on = p.v.open_as_agent;                                /* v1.29 */
    if (as_agent_setup(p.v.open_as_agent, ra.drop, ra.uid, ra.gid,
                       g_nr.on ? NULL : run_as_arg ? run_as_arg : "nobody") < 0)
        return 1;
    if (g_nr.on) node_as_agent();                                         /* v1.34 step 2 (review) */
    /* v1.28.1 step 3: sub-agents need cgroup v2 (a check makes no group) */
    if (g_check_only && sub_setup(&p, true, !ra.drop) < 0) return 1;
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
        /* v1.35 step 2 (D9): a plan is decided as the run would decide it
         * (after the launch set is built), with each step's reason, and no
         * record written: `varek policy check --plan`. The flow policy and
         * the breaker are not stepped by a check. */
        if (plan_path) {
            if (!g_log) g_log = stderr;             /* the decider's reasons, with no stream */
            if (flow_path)
                fprintf(stderr, "[warden] the plan's steps are decided (the node check); a check does not "
                        "step the flow policy or the breaker\n");
            if (warden_verify_plan(plan_path, &p, false) != 0) {
                if (g_sk) sodium_free(g_sk);
                return 1;
            }
        }
        fprintf(stderr, "[warden] startup checks passed: the policy%s%s%s%s%s would be accepted%s\n",
                key_path ? ", the signing key" : "", anchor_path ? ", the anchor" : "",
                flow_path ? ", the flow policy, the breaker state" : "",
                plan_path ? ", the plan" : "",
                gstatus_arg ? ", --gate-status" : "",
                pidns && !have_cap_sys_admin() ? " (but this user lacks CAP_SYS_ADMIN, which "
                "a run needs)" : "");
        if (g_sk) sodium_free(g_sk);
        return 0;
    }
    if (!target_argv && !g_nr.on) { usage(argv[0]); return 2; }
    /* A FIFO anchor whose reader went away must fail the write (EPIPE, then
     * an anchor_error record), not kill the Warden. The agent gets the
     * default disposition back before it runs (see the child below). */
    if (anchor_path) signal(SIGPIPE, SIG_IGN);

    if (log_init() < 0) {
        fprintf(stderr, "[warden] cannot open the verdict stream or create a run id (%s)\n",
                strerror(errno));
        return 1;
    }
    /* v1.28.1 step 3: the run's control group, named after the run */
    if (sub_setup(&p, false, !ra.drop) < 0) return 1;
    if (g_sub_on) atexit(sub_finish);
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
    /* v1.26.1: inspecting mode: the run's CA, made by the proxy, and the
     * trust views, before run_start records them */
    if (g_inspect_on && trust_setup(&p) < 0) {
        if (g_sk) sodium_free(g_sk);
        return 1;
    }
    if (!g_nr.on) emit_run_start(policy_path, &p);     /* v1.34 step 3: node_supervise's, after the launch set */
    ctl_open();                                                            /* v1.28 step 4 */
    /* v1.24: every allowed host name is resolved before the agent runs.
     * Refreshes then run in a resolver helper process (warden_resolve.c),
     * started now: while the Warden is single-threaded and before the agent's
     * PID namespace exists. Without it the table would go stale, so a failure
     * to start it stops the run. */
    if (g_names_on) {
        if (wr_async_start(&g_names, "/proc/self/exe") < 0) {
            if (g_nr.on) node_fail("cannot start the resolver helper");
            fprintf(stderr, "[warden] cannot start the resolver helper (%s); refusing to start\n",
                    strerror(errno));
            emit_run_end(1);
            if (g_sk) sodium_free(g_sk);
            return 1;
        }
        /* v1.34 step 4: under the node agent, after run_start (node_supervise);
         * the helper is started here, where this binary is the node's */
        if (!g_nr.on) names_resolve_all(true);
    }

    /* v1.6 pre-execution plan verification. Fires before fork; on
     * any non-SATISFIED result the target is not started. */
    g_hold_collect = g_hold_req && !g_nr.on;      /* v1.35 step 4: each step that passes */
    if (g_nr.on) {
        /* v1.35 step 4c: the pod's plan is decided in node_supervise, in the
         * container's view, after run_start */
    } else if (plan_path && g_flow_cfg) {
        /* v1.18.0: node + flow check, refusal breaker (exit 3, 4 or 5). */
        int gate = warden_gate_plan_flow(plan_path, &p);
        if (gate != GATE_PASS) {
            emit_run_end(gate);
            if (g_sk) sodium_free(g_sk);
            return gate;
        }
    } else if (plan_path && warden_verify_plan(plan_path, &p, true) != 0) {
        emit_run_end(1);                    /* v1.16: a closed (and signed) stream */
        if (g_sk) sodium_free(g_sk);
        return 1;
    }
    if (g_hold_req && !g_nr.on) {                                          /* v1.35 step 4 */
        g_hold_collect = false;
        g_hold_on = true;
        fprintf(stderr, "[warden] the run is held to its plan: %zu entries; a call the policy allows "
                "outside them is refused (outside_plan)\n", g_nhold);
    }

    struct sigaction sa = { .sa_handler = on_term };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* no SA_RESTART: we want EINTR to break ioctl */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    if (g_nr.on) {                                                         /* v1.34 step 2 */
        /* v1.35 step 4c: the pod's plan read here, in the node's view (its
         * copy beside the stream), decided in the container's */
        static char perr[256];
        plan_parsed_t *pp = plan_path ? plan_parser_load(plan_path, perr, sizeof perr) : NULL;
        return node_supervise(&p, boot_path, policy_path, plan_path, pp, perr);
    }

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
    if (target > 0 && g_ll_fd >= 0) { close(g_ll_fd); g_ll_fd = -1; }   /* v1.27: the agent holds it */

    if (target == 0) {
        signal(SIGPIPE, SIG_DFL);       /* v1.16: an ignored signal survives execve */
        /* v1.28.1: into the run's control group, while still root */
        if (sub_enter_run() < 0) {
            fprintf(stderr, "[warden-target] cannot enter the run's control group (%s); refusing to run\n",
                    strerror(errno));
            _exit(1);
        }
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
        /* v1.27: the agent enters the launch set's Landlock domain before
         * its filter is installed (the filter does not admit the call) and
         * before its own launch, which the set holds */
        if (!g_dry && exec_ruleset_apply() < 0) {      /* v1.29: a dry run holds no launch */
            fprintf(stderr, "[warden-target] cannot enter the Landlock domain (%s); refusing to run\n",
                    strerror(errno));
            _exit(1);
        }
        int notify_fd =
            install_baseline_user_notif_filter_ex(getenv("VAREK_WARDEN_OBSERVE") != NULL,
                                                  (p.v.open_as_agent ? WD_FILTER_CHANGES : 0) |
                                                  (g_dry ? WD_FILTER_DRY : 0));   /* v1.29 */
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
    if (g_px_failed && rc == 0) rc = 1;      /* v1.26.1 review: the run did not end cleanly */
    if (g_exec_mismatch && rc == 0) rc = 1;  /* v1.27: a process ran what was not decided */
    return rc;
}
