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
// is exactly those four (plus the v1.12 sends), and the outbound-neutral
// syscalls the supervisor does not mediate (socket creation, receive) are
// ADMITTED — otherwise default-deny would break every target. The inbound
// calls (bind/listen/accept) are not admitted as of v1.12.1. Same hard-deny
// set (minus clone3, which answers ENOSYS from v1.12.2), same scalar-flag
// CLONE_NEWUSER denial, same native-ABI lockdown (which is what closes the x32
// hole the raw filter has).
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "warden_baseline_filter.h"

#include <seccomp.h>
#include <sched.h>
#include <sys/ioctl.h>
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
    "pwritev2", "close", "close_range", "lseek", "fstat",
    "fsync", "fdatasync", "dup", "dup3", "fcntl", "pipe2", "eventfd2",
    "getdents64", "getcwd",
    // v1.17.0: newfstatat, statx, readlink, readlinkat, access, faccessat and
    // faccessat2 are NO LONGER admitted. They reveal whether any file exists,
    // its size, owner and times, and where any link points (including the
    // Warden's own /proc/<pid>/fd entries), and they were never logged. They
    // are mediated below and decided like a read-only open.
    // poll / wait
    "ppoll", "poll", "pselect6", "select",
    // v1.12.2: collecting a child's exit status. Through v1.12.1 an agent could
    // start a child (fork/clone are admitted) but never wait for it: wait4 and
    // waitid fell to the default EPERM, so waitpid(), subprocess.run() and
    // os.system() failed after the child had already run. Both only reap
    // children of the caller; neither reaches outside the agent's own tree.
    "wait4", "waitid",
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
    // networking — socket creation and socket options stay admitted so targets
    // start normally; connect and the egress-capable sends are mediated (below).
    // v1.12.1: bind, listen, accept and accept4 are NO LONGER admitted. They are
    // the inbound half of networking (a TCP listener, a bound UDP receiver, an
    // abstract unix socket the host can reach) and the deny-only network posture
    // had left them open to a root agent. They fall to the default EPERM. bind
    // on a pathname unix socket also created a file outside open() mediation;
    // that is closed with it. The Warden also runs the agent in its own, empty
    // network namespace (warden.c), so no interface is reachable either way.
    "socket", "socketpair",
    "getsockname", "getpeername", "getsockopt", "setsockopt",
    // v1.12: sendto/sendmsg are NO LONGER admitted here — they can reach the
    // network without connect (a datagram send with an explicit destination),
    // which bypassed the deny-only connect posture. They are mediated below.
    // Inbound-only recv stays admitted.
    "recvfrom", "recvmsg", "shutdown",
    // termination
    "exit", "exit_group",
    NULL
};

// MEDIATE -> NOTIFY: exactly what supervise()/derive_intent() handles.
static const char *kMediate[] = {
    "openat", "connect", "execve", "execveat",
    // v1.12: egress-capable datagram/message sends. Routed to the supervisor
    // so a send carrying an inet destination is subject to the same deny-only
    // network posture as connect, closing the sendto/sendmsg egress bypass
    // (bypass-classes.md class 3).
    "sendto", "sendmsg",
    // v1.17.0: metadata and link lookups, decided like a read-only open and
    // answered by the supervisor (warden.c: meta_answer).
    "newfstatat", "statx", "readlink", "readlinkat",
    "access", "faccessat", "faccessat2", NULL
};

// HARD-DENY: never admissible (classes 3-6). KILL in strict mode, even in
// observe mode.
static const char *kHardDeny[] = {
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "process_vm_readv", "process_vm_writev", "pidfd_getfd",
    "userfaultfd",
    "mount", "umount2", "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree",
    "ptrace", "setns",
    "bpf", "init_module", "finit_module", "delete_module",
    "kexec_load", "kexec_file_load",
    "perf_event_open", "keyctl", "add_key", "request_key", "modify_ldt",
    "memfd_create",
    NULL
};

// v1.12.2: ioctl, admitted for these request numbers only. Through v1.12.1
// ioctl was not admitted at all, so isatty() failed with EPERM instead of
// ENOTTY, and ioctl(FIOCLEX), which CPython uses when it makes a descriptor
// non-inheritable and treats as fatal on EPERM, failed: under v1.12.1 CPython
// could not open its own script.
// Each request below only reads state or changes a flag on the caller's own
// descriptor that fcntl (already admitted) can change too. Every other request
// stays refused, TIOCSTI (pushing input into a terminal the operator may be
// sitting at) and TIOCSETD above all. The comparison is on the full 64-bit
// argument, so a request with junk in the upper bits matches nothing here and
// is refused, even though the kernel would truncate it to 32 bits.
static const unsigned long kIoctlAdmit[] = {
    TCGETS,       // isatty(), tcgetattr()
    TIOCGWINSZ,   // terminal size
    FIOCLEX,      // set close-on-exec   (= fcntl F_SETFD FD_CLOEXEC)
    FIONCLEX,     // clear close-on-exec (= fcntl F_SETFD 0)
    FIONBIO,      // set/clear O_NONBLOCK (= fcntl F_SETFL)
    FIONREAD,     // bytes ready to read
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

// v1.12.2: clone3 answers ENOSYS instead of killing the process.
//
// clone3 takes its flags inside a struct in the caller's memory, which a
// seccomp filter cannot read, so the namespace-bit checks applied to clone and
// unshare cannot be applied to it; it must never run. Through v1.12.1 it was on
// the kill list. But glibc >= 2.34 creates every thread with clone3 (and
// recent glibc, 2.39 here, uses it for posix_spawn too), so an agent that
// started a single thread was killed on the spot.
//
// ENOSYS is the answer the C library is written to handle: it means "this
// kernel has no clone3", and glibc and Rust's standard library then retry with
// clone(), whose flags are a register argument the filter does check (musl
// never uses clone3; Go's runtime threads use clone). It has to be ENOSYS: glibc falls back on
// ENOSYS only, so the default EPERM would still break every thread. With it,
// threads and posix_spawn work, every clone the agent makes still goes through
// the namespace-bit denials below, and clone3 itself still never executes.
// Docker's default profile (for containers without CAP_SYS_ADMIN), systemd,
// Chromium and Flatpak answer clone3 the same way for the same reason.
//
// No other rule names clone3, and this one is the same in enforce, observe and
// non-strict builds.
#ifndef __NR_clone3
#define __NR_clone3 435   // x86_64; the Warden supports x86_64 only
#endif
static int add_clone3(scmp_filter_ctx ctx) {
    int nr = seccomp_syscall_resolve_name("clone3");
    if (nr == __NR_SCMP_ERROR) nr = __NR_clone3;   // libseccomp older than clone3
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr, 0);
    return (rc < 0 && rc != -EEXIST) ? rc : 0;
}

// Build the filter. default_action is EPERM (enforce) or LOG (observe).
static int build(scmp_filter_ctx *out_ctx, int observe) {
    uint32_t def = observe ? SCMP_ACT_LOG : SCMP_ACT_ERRNO(EPERM);
    scmp_filter_ctx ctx = seccomp_init(def);
    if (!ctx) return -ENOMEM;
    int rc;

    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X86);   // no 32-bit compat ABI
    (void)seccomp_arch_remove(ctx, SCMP_ARCH_X32);   // x32 falls to default/kill
#if WD_BASELINE_STRICT
    // v1.12.2: a call from a removed ABI (i386, x32) kills the whole process,
    // not just the calling thread. libseccomp's default is KILL_THREAD, which
    // was equivalent while agents could not start threads; with threads it
    // would leave the rest of the process running, possibly holding locks.
    if ((rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH,
                               SCMP_ACT_KILL_PROCESS)) < 0) goto fail;
#endif

    if ((rc = add_list(ctx, kHardDeny, WD_HARD_DENY)) < 0) goto fail;  // most severe first
    if ((rc = add_clone3(ctx)) < 0) goto fail;
    for (size_t i = 0; i < sizeof kIoctlAdmit / sizeof kIoctlAdmit[0]; ++i) {
        rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                              SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)kIoctlAdmit[i]));
        if (rc < 0) goto fail;
    }
    if ((rc = add_list(ctx, kMediate, SCMP_ACT_NOTIFY)) < 0) goto fail;
    if ((rc = add_list(ctx, kAdmit, SCMP_ACT_ALLOW)) < 0) goto fail;
    if ((rc = deny_ns_bits(ctx, SCMP_SYS(clone))) < 0) goto fail;
    if ((rc = deny_ns_bits(ctx, SCMP_SYS(unshare))) < 0) goto fail;
    // v1.12.2: unshare(CLONE_NEWTIME) was missing from the namespace set
    // (it only mattered in observe mode, whose default action admits). clone()
    // cannot take CLONE_NEWTIME: that bit sits in its exit-signal field.
    rc = seccomp_rule_add(ctx, WD_HARD_DENY, SCMP_SYS(unshare), 1,
                          SCMP_A0(SCMP_CMP_MASKED_EQ, (scmp_datum_t)CLONE_NEWTIME,
                                  (scmp_datum_t)CLONE_NEWTIME));
    if (rc < 0) goto fail;

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
