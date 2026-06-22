// SPDX-License-Identifier: MIT
// warden_seccomp_baseline.c — v1.9.2 baseline hardening
//
// v1.9.1 closed io_uring with a denylist entry. v1.9.2 inverts the model: the
// baseline is now DEFAULT-DENY ALLOWLIST, not allow-plus-denylist. This is the
// single highest-leverage change in the patch. It converts every "bypass I did
// not enumerate" into "denied because I did not admit it," which collapses most
// of the bypass-class catalog (alternate ABI, variant syscalls, off-path
// dispatch, direct-kernel/device access) at once.
//
// Three invariants this file establishes, in order of importance:
//
//   1. DEFAULT ACTION DENIES. seccomp_init() is seeded with a deny action, so
//      any syscall not explicitly admitted is refused. A new kernel syscall, a
//      clone3 where you blocked clone, an openat2 where you blocked openat — all
//      denied by construction, with no policy edit required.
//
//   2. NATIVE ABI ONLY. The default action applies across EVERY architecture,
//      including the 32-bit compat ABI (int 0x80) and the x32 ABI
//      (__X32_SYSCALL_BIT, 0x40000000). Because we never add a secondary
//      architecture and never admit syscalls under one, a process that re-issues
//      the same operation under a different ABI hits the deny default. The 32-bit
//      multiplexers (socketcall, ipc) that hide their sub-operation from BPF are
//      unreachable for the same reason. This is the bypass most filters miss;
//      default-deny + native-only is what closes it. test_v192_abi_lockdown.c
//      MUST pass on the target kernel to claim this.
//
//   3. SCALAR-ARG FILTERING IS SOUND; POINTER-ARG IS NOT. seccomp snapshots
//      register (scalar) arguments, so filtering clone()/unshare() on the
//      CLONE_NEWUSER bit is race-free and done here. Anything whose decision
//      depends on pointer-referenced memory (paths, struct args) is NOT decided
//      here — it is routed to the unotify supervisor's performs-and-ADDFD path
//      (warden_notify_hardening, v1.9.1). clone3() takes a pointer struct whose
//      flags we cannot inspect at this layer, so clone3 is denied outright.
//
// This file compiles against libseccomp and its tests pass standalone on a Linux
// x86_64 kernel. It has NOT yet been integrated with / built against your live
// v1_7 Warden source (that source is not in this environment). Wire it into the
// init path, build, and run `make check` on your target kernel BEFORE tagging.
// The allowlist below is a MINIMAL baseline; tighten the ADMIT set to the
// syscalls your workload actually issues.
//
// Build: links libseccomp >= 2.5 (KILL_PROCESS needs >= 2.4 and kernel >= 4.14).

#define _GNU_SOURCE     // expose CLONE_NEW* in <sched.h>
#include "warden_seccomp_baseline.h"

#include <seccomp.h>
#include <sched.h>      // CLONE_NEWUSER and friends
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Action policy
//
// default        : EPERM. A benign dependency that probes an un-admitted syscall
//                  degrades gracefully instead of being killed. "A refusal is a
//                  safe outcome."
// hard-deny set  : KILL_PROCESS. A mediated agent has no legitimate reason to
//                  call ptrace/bpf/userfaultfd/etc.; reaching one is an attack,
//                  not a probe, so it is fatal. Flip WD_BASELINE_STRICT off to
//                  demote these to EPERM if a customer needs non-fatal denial.
// mediate set    : NOTIFY. Routed to the unotify supervisor for pointer/path
//                  inspection (open, connect, exec, ...). The supervisor decides
//                  via the v1.9.1 performs-and-ADDFD path.
// ---------------------------------------------------------------------------

#ifndef WD_BASELINE_STRICT
#define WD_BASELINE_STRICT 1
#endif

#if WD_BASELINE_STRICT
#define WD_HARD_DENY  SCMP_ACT_KILL_PROCESS
#else
#define WD_HARD_DENY  SCMP_ACT_ERRNO(EPERM)
#endif

#define WD_DEFAULT    SCMP_ACT_ERRNO(EPERM)
#define WD_ALLOW      SCMP_ACT_ALLOW
#define WD_MEDIATE    SCMP_ACT_NOTIFY

// Helper: add a simple allow rule, accumulating the first failure.
static int admit(scmp_filter_ctx ctx, int sysnr) {
    if (sysnr < 0) return 0;            // syscall unknown on this build; skip
    return seccomp_rule_add(ctx, WD_ALLOW, sysnr, 0);
}
static int mediate(scmp_filter_ctx ctx, int sysnr) {
    if (sysnr < 0) return 0;
    return seccomp_rule_add(ctx, WD_MEDIATE, sysnr, 0);
}
static int hard_deny(scmp_filter_ctx ctx, int sysnr) {
    if (sysnr < 0) return 0;
    return seccomp_rule_add(ctx, WD_HARD_DENY, sysnr, 0);
}

// ---------------------------------------------------------------------------
// ADMIT: the minimal set a mediated workload needs. TIGHTEN PER WORKLOAD.
// Deliberately excludes anything that opens a capability (those are MEDIATE)
// and anything in the hard-deny set below.
// ---------------------------------------------------------------------------
static const char *kAdmit[] = {
    // memory / process basics
    "brk", "mmap", "mprotect", "munmap", "mremap", "madvise",
    "exit", "exit_group", "rseq", "set_robust_list", "get_robust_list",
    // fd I/O on ALREADY-AUTHORIZED descriptors (provenance enforced in Warden;
    // see fd-provenance invariant in bypass-classes.md). read/write are NOT
    // mediated per-call by design — only acquisition is. mmap-after-open is
    // contained the same way: the open was mediated, so the fd is authorized.
    "read", "write", "readv", "writev", "pread64", "pwrite64",
    "close", "close_range", "lseek", "fstat", "newfstatat", "fsync", "fdatasync",
    "dup", "dup3", "fcntl", "pipe2", "eventfd2",
    // poll / wait
    "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "select", "pselect6",
    // time / sched / random
    "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday",
    "getpid", "gettid", "getppid", "sched_yield", "sched_getaffinity",
    "getrandom", "getuid", "geteuid", "getgid", "getegid",
    // signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait",
    "sigaltstack", "tgkill",
    // sync
    "futex",
    // limits (read-only use; prlimit64 with a non-NULL new_limit is still
    // scalar-undecidable for the resource, so keep narrow or mediate if needed)
    "prlimit64",
    NULL
};

// MEDIATE: capability-acquisition syscalls. The supervisor inspects the
// pointer/path argument on a copied, validated value and performs-and-ADDFDs.
// Note: openat2 is admitted to MEDIATE precisely so the supervisor can require
// RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS on resolution
// (closes the symlink/magic-link race, class 4). Prefer openat2 over openat.
static const char *kMediate[] = {
    "openat", "openat2",
    "execve", "execveat",        // supervisor enforces an exec-target allowlist
    "connect", "bind", "socket", // socket domain/type is scalar; supervisor narrows
    "sendto", "recvfrom", "sendmsg", "recvmsg", // see SCM_RIGHTS note below
    NULL
};

// HARD-DENY: never admissible for a mediated agent. KILL_PROCESS in strict mode.
// Each entry maps to a bypass class in bypass-classes.md.
static const char *kHardDeny[] = {
    // class 3 — off-path I/O dispatch
    "io_uring_setup", "io_uring_enter", "io_uring_register",  // (v1.9.1, retained)
    "process_vm_readv", "process_vm_writev",                  // lateral mem path
    "pidfd_getfd",                                            // fd theft across procs
    // class 4 — deterministic TOCTOU primitives
    "userfaultfd",                                            // turns races deterministic
    "mount", "umount2", "fsopen", "fsconfig", "fsmount",
    "move_mount", "open_tree",                               // FUSE / attacker mounts
    // class 5 — new-execution-context / privilege surface
    "ptrace",                                                // sibling mem/reg control
    "setns",                                                 // enter foreign namespace
    "clone3",                                                // pointer-flags; uninspectable
    // class 6 — direct kernel / memory / device access
    "bpf",                                                   // load eBPF, read kmem
    "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load",
    "perf_event_open",                                       // info leak / escalation
    "keyctl", "add_key", "request_key",
    "modify_ldt",
    // class 3 (DoS-relevant) / lateral — admit explicitly only if needed
    "memfd_create",                                          // co-resident lateral path
    NULL
};

static int admit_all(scmp_filter_ctx ctx, const char **names, int kind) {
    for (size_t i = 0; names[i]; ++i) {
        int nr = seccomp_syscall_resolve_name(names[i]);
        // SCMP returns __NR_SCMP_ERROR (a large negative pseudo) for unknown
        // names; admit()/hard_deny() skip negatives so an older libseccomp that
        // does not know a name simply leaves it to the DEFAULT (deny). Failing
        // safe: an unknown dangerous name is still denied by default action.
        int rc = 0;
        if (kind == 0) rc = admit(ctx, nr);
        else if (kind == 1) rc = mediate(ctx, nr);
        else rc = hard_deny(ctx, nr);
        if (rc < 0 && rc != -EEXIST) return rc;
    }
    return 0;
}

// clone(): admitted for thread creation, but DENIED when any new-namespace flag
// is requested — CLONE_NEWUSER above all, which grants CAP_SYS_ADMIN inside the
// new namespace and is the root of a large fraction of container escapes
// (class 5). flags is a SCALAR register argument, so this is race-free.
//
// We add ONE deny rule per namespace bit, each "(flags & BIT) == BIT" — i.e.
// deny if that bit is set at all, regardless of the other bits. This is the
// robust idiom; a single combined MASKED_EQ is fragile because it only matches
// an exact bit pattern. On x86_64 flags is arg0 of the raw clone() syscall;
// verify the arg index for any other native arch you support.
static const unsigned long kCloneNsBits[] = {
    CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWPID,
    CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWCGROUP,
};

static int deny_ns_bits(scmp_filter_ctx ctx, int sysnr) {
    for (size_t i = 0; i < sizeof kCloneNsBits / sizeof kCloneNsBits[0]; ++i) {
        scmp_datum_t bit = (scmp_datum_t)kCloneNsBits[i];
        int rc = seccomp_rule_add(ctx, WD_HARD_DENY, sysnr, 1,
                                  SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit));
        if (rc < 0) return rc;
    }
    return 0;
}

static int restrict_clone(scmp_filter_ctx ctx) {
    int rc = deny_ns_bits(ctx, SCMP_SYS(clone));
    if (rc < 0) return rc;
    // Admit clone ONLY when no namespace bit is set. A *conditional* allow is
    // required here: an unconditional ALLOW for the syscall collapses the
    // conditional denies above (libseccomp lets the unconditional action win),
    // which silently reopens CLONE_NEWUSER. Build the full ns mask and allow
    // when (flags & ns_mask) == 0.
    scmp_datum_t ns_mask = 0;
    for (size_t i = 0; i < sizeof kCloneNsBits / sizeof kCloneNsBits[0]; ++i)
        ns_mask |= (scmp_datum_t)kCloneNsBits[i];
    return seccomp_rule_add(ctx, WD_ALLOW, SCMP_SYS(clone), 1,
                            SCMP_A0(SCMP_CMP_MASKED_EQ, ns_mask, (scmp_datum_t)0));
}

// unshare(): unshare(CLONE_NEWUSER) is the no-clone path to the same escalation.
// Deny every namespace bit; leave plain unshare to the DEFAULT (deny) unless a
// workload demonstrably needs it.
static int restrict_unshare(scmp_filter_ctx ctx) {
    return deny_ns_bits(ctx, SCMP_SYS(unshare));
}

// ioctl(): a wildcard ioctl admit is a hole (arbitrary device control). Keep it
// out of kAdmit and narrow to the specific request codes your runtime needs.
// Example shape (uncomment and set WD_IOCTL_* to your codes):
// static int restrict_ioctl(scmp_filter_ctx ctx) {
//     return seccomp_rule_add(ctx, WD_ALLOW, SCMP_SYS(ioctl), 1,
//                             SCMP_A1(SCMP_CMP_EQ, WD_IOCTL_ALLOWED));
// }

// ---------------------------------------------------------------------------
// Public entry point. Build the filter, DO NOT load it here — the caller loads
// after prctl(PR_SET_NO_NEW_PRIVS, 1) and after registering the unotify fd, so
// that SCMP_ACT_NOTIFY rules have a listener. Returns 0 on success.
// ---------------------------------------------------------------------------
int wd_seccomp_build_baseline(scmp_filter_ctx *out_ctx) {
    if (!out_ctx) return -EINVAL;

    // INVARIANT 1 + 2: default denies, and applies to all architectures. We add
    // NO secondary architecture, so compat/x32 syscalls hit this default.
    scmp_filter_ctx ctx = seccomp_init(WD_DEFAULT);
    if (!ctx) return -ENOMEM;

    int rc;

    // INVARIANT 2 (explicit): ensure no secondary ABI is reachable. By default
    // libseccomp carries only the native arch; we remove the common secondaries
    // defensively in case a caller pre-populated them. Errors are ignored when
    // the arch was not present (-EEXIST/-ENOENT semantics vary by version).
    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X86);     // 32-bit int 0x80
    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X32);     // x32 ABI
    // Note: removing SCMP_ARCH_X32 is what makes the __X32_SYSCALL_BIT path
    // fall to the default deny. test_v192_abi_lockdown.c asserts an x32 call is
    // refused on the live kernel; treat a failure there as release-blocking.

    if ((rc = admit_all(ctx, kAdmit, 0)) < 0) goto fail;
    if ((rc = admit_all(ctx, kMediate, 1)) < 0) goto fail;
    if ((rc = admit_all(ctx, kHardDeny, 2)) < 0) goto fail;
    if ((rc = restrict_clone(ctx)) < 0) goto fail;
    if ((rc = restrict_unshare(ctx)) < 0) goto fail;
    // if ((rc = restrict_ioctl(ctx)) < 0) goto fail;  // enable once codes set

    *out_ctx = ctx;
    return 0;

fail:
    seccomp_release(ctx);
    return rc;
}

// Convenience: build + load in one shot for callers that have already set
// PR_SET_NO_NEW_PRIVS and (if any NOTIFY rules are present) attached a listener.
int wd_seccomp_install_baseline(int *out_notify_fd) {
    scmp_filter_ctx ctx;
    int rc = wd_seccomp_build_baseline(&ctx);
    if (rc < 0) return rc;

    rc = seccomp_load(ctx);
    if (rc < 0) { seccomp_release(ctx); return rc; }

    if (out_notify_fd) {
        // -1 if the kernel/libseccomp build has no listener for our NOTIFY rules
        *out_notify_fd = seccomp_notify_fd(ctx);
    }
    // ctx may be released after load; the kernel holds the installed program.
    seccomp_release(ctx);
    return 0;
}
