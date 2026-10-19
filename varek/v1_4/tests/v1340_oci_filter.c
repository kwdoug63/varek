// SPDX-License-Identifier: MIT
//
// v1340_oci_filter.c — v1.34 step 1 (docs/security/v1.34-kubernetes.md): can
// the Warden's filter be given to a container runtime in OCI's form
// (linux.seccomp in the runtime spec) without loss? The Warden's own builder
// (warden_baseline_filter.c, included) is run with every libseccomp call
// recorded; the rules are written as an OCI seccomp profile (JSON), and the
// filter is built again from that profile as runc builds one (the default
// action, the architectures, one rule per entry, in order). Both filters are
// exported as BPF for tests/v1340_bpf_compare.py to compare call by call.
//
//   v1340_oci_filter FLAGS OUTDIR    FLAGS: 0, 1 (changes, 1.29) or 3 (dry run)
//   writes OUTDIR/{warden.bpf,oci.json,oci.bpf,points.json}
#define _GNU_SOURCE
#include <seccomp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define REC_MAX 2048
static struct { uint32_t action; int nr; unsigned argc; struct scmp_arg_cmp a[6]; } rec[REC_MAX];
static size_t nrec;
static uint32_t rec_default, rec_badarch;
static int rec_badarch_set;

static scmp_filter_ctx rec_init(uint32_t def) { rec_default = def; nrec = 0; rec_badarch_set = 0; return seccomp_init(def); }
static int rec_attr_set(scmp_filter_ctx ctx, enum scmp_filter_attr attr, uint32_t v) {
    if (attr == SCMP_FLTATR_ACT_BADARCH) { rec_badarch = v; rec_badarch_set = 1; }
    return seccomp_attr_set(ctx, attr, v);
}
static int rec_rule_add(scmp_filter_ctx ctx, uint32_t action, int nr, unsigned argc, ...) {
    struct scmp_arg_cmp a[6];
    va_list ap;
    va_start(ap, argc);
    for (unsigned i = 0; i < argc && i < 6; i++) a[i] = va_arg(ap, struct scmp_arg_cmp);
    va_end(ap);
    int rc = seccomp_rule_add_array(ctx, action, nr, argc, a);
    if (rc == 0 && nrec < REC_MAX) {
        rec[nrec].action = action; rec[nrec].nr = nr; rec[nrec].argc = argc;
        memcpy(rec[nrec].a, a, sizeof a);
        nrec++;
    }
    return rc;
}
#define seccomp_init rec_init
#define seccomp_attr_set rec_attr_set
#define seccomp_rule_add rec_rule_add
#include "../warden_baseline_filter.c"
#undef seccomp_init
#undef seccomp_attr_set
#undef seccomp_rule_add

static const char *act_name(uint32_t a, unsigned *eno) {
    *eno = 0;
    if (a == SCMP_ACT_ALLOW) return "SCMP_ACT_ALLOW";
    if (a == SCMP_ACT_NOTIFY) return "SCMP_ACT_NOTIFY";
    if (a == SCMP_ACT_LOG) return "SCMP_ACT_LOG";
    if (a == SCMP_ACT_KILL_PROCESS) return "SCMP_ACT_KILL_PROCESS";
    if (a == SCMP_ACT_KILL_THREAD) return "SCMP_ACT_KILL_THREAD";
    if ((a & 0xffff0000U) == SCMP_ACT_ERRNO(0)) { *eno = a & 0xffff; return "SCMP_ACT_ERRNO"; }
    return "UNKNOWN";
}
static const char *op_name(enum scmp_compare op) {
    switch (op) {
    case SCMP_CMP_NE: return "SCMP_CMP_NE";
    case SCMP_CMP_LT: return "SCMP_CMP_LT";
    case SCMP_CMP_LE: return "SCMP_CMP_LE";
    case SCMP_CMP_EQ: return "SCMP_CMP_EQ";
    case SCMP_CMP_GE: return "SCMP_CMP_GE";
    case SCMP_CMP_GT: return "SCMP_CMP_GT";
    case SCMP_CMP_MASKED_EQ: return "SCMP_CMP_MASKED_EQ";
    default: return "UNKNOWN";
    }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: v1340_oci_filter FLAGS OUTDIR\n"); return 2; }
    int flags = atoi(argv[1]);
    char p[4096];
    scmp_filter_ctx w;
    if (build(&w, 0, flags) < 0) { fprintf(stderr, "the Warden's builder failed\n"); return 1; }
    snprintf(p, sizeof p, "%s/warden.bpf", argv[2]);
    FILE *f = fopen(p, "wb");
    if (!f || seccomp_export_bpf(w, fileno(f)) < 0) { perror(p); return 1; }
    fclose(f);

    // the OCI profile, from what the builder did
    // (each action named into its own errno: one shared between the default's
    // and the bad-architecture action's lookups, in one call's arguments,
    // printed the default's as 0, found by runc building the profile)
    unsigned eno, deno, beno;
    snprintf(p, sizeof p, "%s/oci.json", argv[2]);
    f = fopen(p, "w");
    const char *dn = act_name(rec_default, &deno);
    const char *bn = rec_badarch_set ? act_name(rec_badarch, &beno) : "(libseccomp's default)";
    fprintf(f, "{\"defaultAction\":\"%s\",\"defaultErrnoRet\":%u,\"architectures\":[\"SCMP_ARCH_NATIVE\"],"
               "\"warden_badarch\":\"%s\",\"syscalls\":[\n", dn, deno, bn);
    for (size_t i = 0; i < nrec; i++) {
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, rec[i].nr);
        const char *an = act_name(rec[i].action, &eno);
        fprintf(f, "%s{\"names\":[\"%s\"],\"nr\":%d,\"action\":\"%s\"", i ? ",\n" : "", name ? name : "?",
                rec[i].nr, an);
        if (!strcmp(an, "SCMP_ACT_ERRNO")) fprintf(f, ",\"errnoRet\":%u", eno);
        fprintf(f, ",\"args\":[");
        for (unsigned k = 0; k < rec[i].argc; k++)
            fprintf(f, "%s{\"index\":%u,\"value\":%llu,\"valueTwo\":%llu,\"op\":\"%s\"}", k ? "," : "",
                    rec[i].a[k].arg, (unsigned long long)rec[i].a[k].datum_a,
                    (unsigned long long)rec[i].a[k].datum_b, op_name(rec[i].a[k].op));
        fprintf(f, "]}");
        free(name);
    }
    fprintf(f, "\n]}\n");
    fclose(f);

    // the filter built again from the profile, as runc builds one: the
    // default action, the native architecture, each entry's rule in order
    // (runc sets no bad-architecture action: libseccomp's default stays)
    scmp_filter_ctx o = seccomp_init(rec_default);
    for (size_t i = 0; i < nrec; i++)
        if (seccomp_rule_add_array(o, rec[i].action, rec[i].nr, rec[i].argc, rec[i].a) < 0) {
            fprintf(stderr, "the profile's entry %zu does not build\n", i); return 1;
        }
    snprintf(p, sizeof p, "%s/oci.bpf", argv[2]);
    f = fopen(p, "wb");
    if (!f || seccomp_export_bpf(o, fileno(f)) < 0) { perror(p); return 1; }
    fclose(f);
    printf("%zu rules; the Warden's bad-architecture action %s\n", nrec,
           rec_badarch_set ? act_name(rec_badarch, &eno) : "libseccomp's default");
    return 0;
}
