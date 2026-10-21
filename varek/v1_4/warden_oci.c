// SPDX-License-Identifier: MIT
// warden_oci.c — v1.34 step 3 (docs/security/v1.34-kubernetes.md): the
// Warden's filter in OCI's form (the runtime specification's linux.seccomp),
// for a pod the node agent supervises:
//
//   warden POLICY --oci-filter
//
// writes it to standard output; the NRI plugin (k8s/cmd/varek-nri) gives it to the
// runtime as the container's seccomp policy, with the node agent's socket as
// its listenerPath. The Warden's own builder (warden_baseline_filter.c,
// included here) is run with every libseccomp call recorded, and the rules
// are written in the order it made them, as step 1's converter did
// (tests/v1340_oci_filter.c), so the plugin carries no copy of the filter
// that could drift from the Warden's: every native call is decided the same
// (step 1's first measurement, compared call by call).
//
// What a pod needs besides:
//   - the runtime loads the filter before its own last steps (runc reopens
//     its exec FIFO, which calls fstatfs, admitted only from 1.29): every
//     call the Warden's filter names no rule for is notified, not refused,
//     so the node agent can let the runtime's and the launcher's through
//     before the container's command, and from the command's launch it
//     answers each as the Warden's own filter for that policy would
//     (wd_bpf_run on wd_filter_bpf: EPERM). runc refuses a filter whose
//     default action notifies, so each is named;
//   - the Warden kills the whole process for a call from another
//     architecture (i386, x32); OCI's profile has no field for that action,
//     and a runtime's filter kills only the calling thread. The launcher
//     (varek_init.c) adds a filter of its own whose only effect is that
//     action: the kernel takes the stricter of the two;
//   - the launcher applies the launch set with Landlock under this filter,
//     which the runtime loads before the launcher runs (on a host the Warden
//     applies Landlock before it loads the filter): the three landlock_*
//     calls are admitted (each can only narrow what the caller may do), and
//     seccomp() is notified (the launcher's own filter is let through before
//     the container's command runs; an agent's is refused, since a filter
//     of its own with a listener would take the Warden's notifications).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <seccomp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "warden_oci.h"

#define OCI_REC_MAX 2048
static struct { uint32_t action; int nr; unsigned argc; struct scmp_arg_cmp a[6]; } g_rec[OCI_REC_MAX];
static size_t g_nrec;
static int g_rec_over;
static uint32_t g_rec_default;

static scmp_filter_ctx oci_rec_init(uint32_t def) {
    g_rec_default = def;
    g_nrec = 0;
    g_rec_over = 0;
    return seccomp_init(def);
}
static int oci_rec_rule_add(scmp_filter_ctx ctx, uint32_t action, int nr, unsigned argc, ...) {
    struct scmp_arg_cmp a[6];
    memset(a, 0, sizeof a);
    va_list ap;
    va_start(ap, argc);
    for (unsigned i = 0; i < argc && i < 6; i++) a[i] = va_arg(ap, struct scmp_arg_cmp);
    va_end(ap);
    if (argc > 6) return -EINVAL;
    int rc = seccomp_rule_add_array(ctx, action, nr, argc, a);
    if (rc == 0) {
        if (g_nrec == OCI_REC_MAX) g_rec_over = 1;
        else {
            g_rec[g_nrec].action = action;
            g_rec[g_nrec].nr = nr;
            g_rec[g_nrec].argc = argc;
            memcpy(g_rec[g_nrec].a, a, sizeof a);
            g_nrec++;
        }
    }
    return rc;
}

#define seccomp_init oci_rec_init
#define seccomp_rule_add oci_rec_rule_add
#define install_baseline_user_notif_filter oci_unused_install
#define install_baseline_user_notif_filter_ex oci_unused_install_ex
#include "warden_baseline_filter.c"
#undef seccomp_init
#undef seccomp_rule_add

static const char *oci_action(uint32_t a, unsigned *eno) {
    *eno = 0;
    if (a == SCMP_ACT_ALLOW) return "SCMP_ACT_ALLOW";
    if (a == SCMP_ACT_NOTIFY) return "SCMP_ACT_NOTIFY";
    if (a == SCMP_ACT_LOG) return "SCMP_ACT_LOG";
    if (a == SCMP_ACT_KILL_PROCESS) return "SCMP_ACT_KILL_PROCESS";
    if (a == SCMP_ACT_KILL_THREAD) return "SCMP_ACT_KILL_THREAD";
    if ((a & 0xffff0000U) == SCMP_ACT_ERRNO(0)) { *eno = a & 0xffff; return "SCMP_ACT_ERRNO"; }
    return NULL;
}

static const char *oci_op(enum scmp_compare op) {
    switch (op) {
    case SCMP_CMP_NE: return "SCMP_CMP_NE";
    case SCMP_CMP_LT: return "SCMP_CMP_LT";
    case SCMP_CMP_LE: return "SCMP_CMP_LE";
    case SCMP_CMP_EQ: return "SCMP_CMP_EQ";
    case SCMP_CMP_GE: return "SCMP_CMP_GE";
    case SCMP_CMP_GT: return "SCMP_CMP_GT";
    case SCMP_CMP_MASKED_EQ: return "SCMP_CMP_MASKED_EQ";
    default: return NULL;
    }
}

int wd_oci_filter_write(FILE *f, int flags, char *why, size_t wn) {
#if defined(__x86_64__)
    const char *arch = "SCMP_ARCH_X86_64";
#elif defined(__aarch64__)
    const char *arch = "SCMP_ARCH_AARCH64";
#else
    snprintf(why, wn, "the filter in OCI's form is written for x86_64 and aarch64 only");
    return -1;
#endif
    scmp_filter_ctx ctx;
    if (build(&ctx, 0, flags) < 0) { snprintf(why, wn, "the Warden's filter builder failed"); return -1; }
    seccomp_release(ctx);
    if (g_rec_over) { snprintf(why, wn, "more than %d rules", OCI_REC_MAX); return -1; }
    unsigned deno;
    const char *dn = oci_action(g_rec_default, &deno);
    if (!dn) { snprintf(why, wn, "the default action has no OCI name"); return -1; }
    fprintf(f, "{\"defaultAction\":\"%s\",\"defaultErrnoRet\":%u,\"architectures\":[\"%s\"],\"syscalls\":[\n",
            dn, deno, arch);
    for (size_t i = 0; i < g_nrec; i++) {
        unsigned eno;
        const char *an = oci_action(g_rec[i].action, &eno);
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, g_rec[i].nr);
        if (!an || !name) {
            snprintf(why, wn, "rule %zu (call %d) has no OCI name for its %s", i, g_rec[i].nr, an ? "call" : "action");
            free(name);
            return -1;
        }
        fprintf(f, "{\"names\":[\"%s\"],\"action\":\"%s\"", name, an);
        free(name);
        if (eno) fprintf(f, ",\"errnoRet\":%u", eno);
        fputs(",\"args\":[", f);
        for (unsigned k = 0; k < g_rec[i].argc; k++) {
            const char *op = oci_op(g_rec[i].a[k].op);
            if (!op) { snprintf(why, wn, "rule %zu compares with an operator OCI has no name for", i); return -1; }
            fprintf(f, "%s{\"index\":%u,\"value\":%llu,\"valueTwo\":%llu,\"op\":\"%s\"}", k ? "," : "",
                    g_rec[i].a[k].arg, (unsigned long long)g_rec[i].a[k].datum_a,
                    (unsigned long long)g_rec[i].a[k].datum_b, op);
        }
        fputs("]},\n", f);
    }
    /* the pod's: the launcher's Landlock; then every call with no rule
     * notified (seccomp among them: the launcher's filter, above) */
    static const char *const kLandlock[] = { "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self" };
    fputs("{\"names\":[\"landlock_create_ruleset\",\"landlock_add_rule\",\"landlock_restrict_self\"],"
          "\"action\":\"SCMP_ACT_ALLOW\",\"args\":[]}", f);
    for (int nr = 0; nr < 1024; nr++) {
        bool ruled = false;
        for (size_t i = 0; i < g_nrec && !ruled; i++) ruled = g_rec[i].nr == nr;
        char *name = ruled ? NULL : seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
        if (!name) continue;
        bool ll = false;
        for (size_t k = 0; k < sizeof kLandlock / sizeof kLandlock[0]; k++) ll |= !strcmp(name, kLandlock[k]);
        if (!ll) fprintf(f, ",\n{\"names\":[\"%s\"],\"action\":\"SCMP_ACT_NOTIFY\",\"args\":[]}", name);
        free(name);
    }
    fputs("\n]}\n", f);
    return ferror(f) ? (snprintf(why, wn, "cannot write the profile"), -1) : 0;
}

int wd_filter_bpf(int flags, struct sock_filter **out, unsigned *n) {
    scmp_filter_ctx ctx;
    if (build(&ctx, 0, flags) < 0) return -1;
    int fd = memfd_create("warden_filter", MFD_CLOEXEC);
    int rc = fd < 0 || seccomp_export_bpf(ctx, fd) < 0 ? -1 : 0;
    seccomp_release(ctx);
    off_t len = rc == 0 ? lseek(fd, 0, SEEK_END) : -1;
    if (len <= 0 || len % (off_t)sizeof(struct sock_filter) || len > 65536 * (off_t)sizeof(struct sock_filter)) rc = -1;
    *out = rc == 0 ? malloc((size_t)len) : NULL;
    if (rc == 0 && (!*out || pread(fd, *out, (size_t)len, 0) != (ssize_t)len)) rc = -1;
    if (fd >= 0) close(fd);
    if (rc < 0) { free(*out); *out = NULL; return -1; }
    *n = (unsigned)(len / (off_t)sizeof(struct sock_filter));
    return 0;
}

/* Classic BPF as the kernel runs a seccomp filter: loads from seccomp_data
 * (aligned words), the scratch memory, ALU, forward jumps, return. Anything
 * else, or a load or jump out of bounds, is a malformed program: kill. */
uint32_t wd_bpf_run(const struct sock_filter *f, unsigned n, const struct seccomp_data *d) {
    uint32_t A = 0, X = 0, M[BPF_MEMWORDS] = { 0 };
    const unsigned char *data = (const unsigned char *)d;
    for (unsigned pc = 0; pc < n; pc++) {
        const struct sock_filter *i = &f[pc];
        uint32_t k = i->k;
        switch (BPF_CLASS(i->code)) {
        case BPF_LD:
            if (i->code == (BPF_LD | BPF_W | BPF_ABS)) {
                if (k % 4 || k + 4 > sizeof *d) return SECCOMP_RET_KILL_PROCESS;
                memcpy(&A, data + k, 4);
            } else if (i->code == (BPF_LD | BPF_W | BPF_LEN)) A = sizeof *d;
            else if (i->code == (BPF_LD | BPF_IMM)) A = k;
            else if (i->code == (BPF_LD | BPF_MEM) && k < BPF_MEMWORDS) A = M[k];
            else return SECCOMP_RET_KILL_PROCESS;
            break;
        case BPF_LDX:
            if (i->code == (BPF_LDX | BPF_W | BPF_LEN)) X = sizeof *d;
            else if (i->code == (BPF_LDX | BPF_IMM)) X = k;
            else if (i->code == (BPF_LDX | BPF_MEM) && k < BPF_MEMWORDS) X = M[k];
            else return SECCOMP_RET_KILL_PROCESS;
            break;
        case BPF_ST:
            if (k >= BPF_MEMWORDS) return SECCOMP_RET_KILL_PROCESS;
            M[k] = A;
            break;
        case BPF_STX:
            if (k >= BPF_MEMWORDS) return SECCOMP_RET_KILL_PROCESS;
            M[k] = X;
            break;
        case BPF_ALU: {
            uint32_t v = BPF_SRC(i->code) == BPF_X ? X : k;
            switch (BPF_OP(i->code)) {
            case BPF_ADD: A += v; break;
            case BPF_SUB: A -= v; break;
            case BPF_MUL: A *= v; break;
            case BPF_DIV: if (!v) return SECCOMP_RET_KILL_PROCESS; A /= v; break;
            case BPF_MOD: if (!v) return SECCOMP_RET_KILL_PROCESS; A %= v; break;
            case BPF_AND: A &= v; break;
            case BPF_OR:  A |= v; break;
            case BPF_XOR: A ^= v; break;
            case BPF_LSH: A = v < 32 ? A << v : 0; break;
            case BPF_RSH: A = v < 32 ? A >> v : 0; break;
            case BPF_NEG: A = -A; break;
            default: return SECCOMP_RET_KILL_PROCESS;
            }
            break;
        }
        case BPF_JMP: {
            uint32_t v = BPF_SRC(i->code) == BPF_X ? X : k, off;
            bool c;
            switch (BPF_OP(i->code)) {
            case BPF_JA:   off = k; goto jump;
            case BPF_JEQ:  c = A == v; break;
            case BPF_JGT:  c = A > v; break;
            case BPF_JGE:  c = A >= v; break;
            case BPF_JSET: c = (A & v) != 0; break;
            default: return SECCOMP_RET_KILL_PROCESS;
            }
            off = c ? i->jt : i->jf;
        jump:
            if ((uint64_t)pc + 1 + off >= n) return SECCOMP_RET_KILL_PROCESS;
            pc += off;
            break;
        }
        case BPF_RET:
            if (i->code == (BPF_RET | BPF_K)) return k;
            if (i->code == (BPF_RET | BPF_A)) return A;
            return SECCOMP_RET_KILL_PROCESS;
        case BPF_MISC:
            if (i->code == (BPF_MISC | BPF_TAX)) X = A;
            else if (i->code == (BPF_MISC | BPF_TXA)) A = X;
            else return SECCOMP_RET_KILL_PROCESS;
            break;
        default:
            return SECCOMP_RET_KILL_PROCESS;
        }
    }
    return SECCOMP_RET_KILL_PROCESS;             /* fell off the end */
}
