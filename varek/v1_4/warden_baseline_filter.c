// SPDX-License-Identifier: MIT
// warden_baseline_filter.c — v1.9.2 enforcement wiring for the v1.4 Warden
//
// Replaces the allow-by-default raw-BPF filter in warden.c's
// install_user_notif_filter() with a DEFAULT-DENY libseccomp filter, while
// preserving this supervisor's exact mediation surface.
//
// Why a v1.4-specific builder and not wd_seccomp_build_baseline() directly:
// the generic baseline routes socket/bind/sendmsg/recvmsg/openat2/... to
// SCMP_ACT_NOTIFY on the assumption of a supervisor that can decide them. The
// v1.4 supervise()/derive_intent() models ONLY openat, connect, execve,
// execveat; any other NOTIFY becomes ACT_OTHER -> deny. So here the mediate set
// is exactly those four, and the syscalls the supervisor does not mediate
// (networking, message I/O) are ADMITTED — otherwise default-deny would break
// every target. Same hard-deny set, same scalar-flag CLONE_NEWUSER denial, same
// native-ABI lockdown (which is what closes the x32 hole the raw filter has).
//
// Contract matches the function it replaces: sets PR_SET_NO_NEW_PRIVS, installs
// the filter in the CURRENT process, returns the unotify listener fd (>=0) or
// -1. Caller (child branch of main) then send_fd()s it to the supervisor and
// execvp()s the target, exactly as before.
//
// observe != 0 puts the filter in OBSERVE MODE: the default action becomes
// SCMP_ACT_LOG (allow-and-log) instead of EPERM, so an un-admitted ordinary
// syscall is logged to the audit log rather than blocked. Hard-deny rules still
// KILL and the four mediated syscalls still NOTIFY even in observe mode. Run
// your real targets with VAREK_WARDEN_OBSERVE=1, harvest the logged syscalls
// (ausearch -m SECCOMP / dmesg), fold the genuinely-needed ones into kAdmit,
// then ship with observe off. This is how you flip a live target to default-deny
// without stranding it.

#define _GNU_SOURCE
#include "warden_baseline_filter.h"

#include <seccomp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifndef WD_BASELINE_STRICT
#define WD_BASELINE_STRICT 1
#endif
#if WD_BASELINE_STRICT
#define WD_HARD_DENY  SCMP_ACT_KILL_PROCESS
#else
#define WD_HARD_DENY  SCMP_ACT_ERRNO(EPERM)
#endif

// ADMIT: what a target process needs to run, MINUS anything that opens a
// mediated capability. Networking and message I/O are here (NOT mediated by the
// v1.4 supervisor). Tighten per workload; grow via observe mode. This is a
// starting allowlist for a typical dynamically-linked Linux target.
static const char *kAdmit[] = {
    // loader / process startup
    "arch_prctl", "set_tid_address", "set_robust_list", "get_robust_list",
    "rseq", "brk", "membarrier", "getrandom",
    // memory
    "mmap", "mprotect", "munmap", "mremap", "madvise",
    // file I/O on already-authorized fds (provenance enforced by the supervisor
    // via fd injection; openat itself is mediated below)
    "read", "write", "readv", "writev", "pread64", "pwrite64", "preadv2",
    "pwritev2", "close", "close_range", "lseek", "fstat", "newfstatat", "statx",
    "fsync", "fdatasync", "dup", "dup3", "fcntl", "pipe2", "eventfd2",
    "getdents64", "getcwd", "readlink", "readlinkat",
    "access", "faccessat", "faccessat2",
    // poll / wait
    "ppoll", "poll", "pselect6", "select",
    "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2",
    // time / sched / ids
    "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday", "time",
    "getpid", "gettid", "getppid", "sched_yield", "sched_getaffinity",
    "getuid", "geteuid", "getgid", "getegid", "uname", "sysinfo", "prlimit64",
    // signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait",
    "sigaltstack", "tgkill",
    // sync
    "futex",
    // networking — the v1.4 supervisor does NOT mediate these; targets need them.
    // connect IS mediated (below). sendto/recvfrom on a connectionless socket can
    // reach the network without connect — a known gap inherited from the
    // allow-by-default model, documented in bypass-classes.md; tighten when the
    // supervisor learns to mediate the message path.
    "socket", "socketpair", "bind", "listen", "accept", "accept4",
    "getsockname", "getpeername", "getsockopt", "setsockopt",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
    // termination
    "exit", "exit_group",
    NULL
};

// MEDIATE -> NOTIFY: EXACTLY the four supervise()/derive_intent() handles.
static const char *kMediate[] = {
    "openat", "connect", "execve", "execveat", NULL
};

// HARD-DENY: never admissible (classes 3-6). KILL in strict mode, even in
// observe mode.
static const char *kHardDeny[] = {
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "process_vm_readv", "process_vm_writev", "pidfd_getfd",
    "userfaultfd",
    "mount", "umount2", "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree",
    "ptrace", "setns", "clone3",
    "bpf", "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load",
    "perf_event_open", "keyctl", "add_key", "request_key", "modify_ldt",
    "memfd_create",
    NULL
};

static const unsigned long kCloneNsBits[] = {
    CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWPID,
    CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWCGROUP,
};

static int add_list(scmp_filter_ctx ctx, const char **names, uint32_t action) {
    for (size_t i = 0; names[i]; ++i) {
        int nr = seccomp_syscall_resolve_name(names[i]);
        if (nr == __NR_SCMP_ERROR) continue;   // unknown here -> left to default
        int rc = seccomp_rule_add(ctx, action, nr, 0);
        if (rc < 0 && rc != -EEXIST) return rc;
    }
    return 0;
}

static int deny_ns_bits(scmp_filter_ctx ctx, int sysnr) {
    for (size_t i = 0; i < sizeof kCloneNsBits / sizeof kCloneNsBits[0]; ++i) {
        scmp_datum_t bit = (scmp_datum_t)kCloneNsBits[i];
        int rc = seccomp_rule_add(ctx, WD_HARD_DENY, sysnr, 1,
                                  SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit));
        if (rc < 0) return rc;
    }
    return 0;
}

// Build the filter. default_action is EPERM (enforce) or LOG (observe).
static int build(scmp_filter_ctx *out_ctx, int observe) {
    uint32_t def = observe ? SCMP_ACT_LOG : SCMP_ACT_ERRNO(EPERM);
    scmp_filter_ctx ctx = seccomp_init(def);
    if (!ctx) return -ENOMEM;

    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X86);   // no 32-bit compat ABI
    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X32);   // x32 falls to default/kill

    int rc;
    if ((rc = add_list(ctx, kHardDeny, WD_HARD_DENY)) < 0) goto fail;  // most severe first
    if ((rc = add_list(ctx, kMediate, SCMP_ACT_NOTIFY)) < 0) goto fail;
    if ((rc = add_list(ctx, kAdmit, SCMP_ACT_ALLOW)) < 0) goto fail;
    if ((rc = deny_ns_bits(ctx, SCMP_SYS(clone))) < 0) goto fail;
    if ((rc = deny_ns_bits(ctx, SCMP_SYS(unshare))) < 0) goto fail;

    // clone admitted only when no namespace bit is set (conditional allow; an
    // unconditional allow would collapse the ns-bit denies above).
    scmp_datum_t ns_mask = 0;
    for (size_t i = 0; i < sizeof kCloneNsBits / sizeof kCloneNsBits[0]; ++i)
        ns_mask |= (scmp_datum_t)kCloneNsBits[i];
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                          SCMP_A0(SCMP_CMP_MASKED_EQ, ns_mask, (scmp_datum_t)0));
    if (rc < 0) goto fail;

    *out_ctx = ctx;
    return 0;
fail:
    seccomp_release(ctx);
    return rc;
}

int install_baseline_user_notif_filter(int observe) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;

    scmp_filter_ctx ctx;
    if (build(&ctx, observe) < 0) return -1;

    if (seccomp_load(ctx) < 0) { seccomp_release(ctx); return -1; }

    // libseccomp installs with SECCOMP_FILTER_FLAG_NEW_LISTENER because the
    // filter contains NOTIFY rules; retrieve the listener fd to hand to the
    // supervisor. The fd outlives ctx.
    int notify_fd = seccomp_notify_fd(ctx);
    seccomp_release(ctx);
    return notify_fd;   // >=0 on success, -1 if no listener was created
}
