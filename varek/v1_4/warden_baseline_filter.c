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
// v1.4 supervise()/derive_intent() models ONLY the calls in kMediate below;
// any other NOTIFY becomes ACT_OTHER -> deny. So here the mediate set is exactly
// those (openat, connect, execve, execveat, the v1.12 sends, the v1.17 lookups,
// and from v1.21 bind and sendmmsg), and the outbound-neutral syscalls the
// supervisor does not mediate (socket creation, receive) are ADMITTED —
// otherwise default-deny would break every target. The inbound
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <seccomp.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

// Older glibc <sched.h> (Amazon Linux 2023 and RHEL 9 ship glibc 2.34) lacks
// CLONE_NEWTIME although their kernels support time namespaces.
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080   // linux/sched.h, since Linux 5.6
#endif

#ifndef WD_BASELINE_STRICT
#define WD_BASELINE_STRICT 1
#endif
#if WD_BASELINE_STRICT
#define WD_HARD_DENY  SCMP_ACT_KILL_PROCESS
#else
#define WD_HARD_DENY  SCMP_ACT_ERRNO(EPERM)
#endif

// ADMIT: what a target process needs to run, MINUS anything that opens a
// mediated capability. Socket creation, receive and socket options are here;
// connect, bind and the sends that can carry a destination are mediated
// (kMediate, add_sends), and setsockopt is admitted by conditional rules
// (add_setsockopt, v1.21). Tighten per workload; grow via observe mode. This is a
// starting allowlist for a typical dynamically-linked Linux target.
static const char *kAdmit[] = {
    // loader / process startup
    "arch_prctl", "set_tid_address", "set_robust_list", "get_robust_list",
    "rseq", "brk", "membarrier", "getrandom",
    // memory
    "mmap", "mprotect", "munmap", "mremap", "madvise",
    // file I/O on descriptors the agent holds (openat itself is mediated
    // below, and an allowed open is delivered by fd injection; nothing tracks
    // a descriptor afterwards: bypass-classes.md, "Descriptor provenance")
    "read", "write", "readv", "writev", "pread64", "pwrite64", "preadv2",
    "pwritev2", "close", "close_range", "lseek", "fstat",
    "fsync", "fdatasync", "dup", "dup3", "fcntl", "pipe2", "eventfd2",
    // v1.27: dup2, which glibc calls for dup2() on x86_64 and every launcher
    // uses to give a child its stdin/stdout/stderr; it does what dup3 does
    "dup2",
    // v1.31.1 (found by the RHEL 9 sweep): pipe, which glibc before 2.37
    // calls for pipe() on x86_64 (later ones call pipe2 with no flags); it
    // does what pipe2 does
    "pipe",
    // v1.31.1 (the RHEL 9 sweep): getpgrp, the caller's own process group,
    // under every policy (from 1.29 it was admitted with the rest of
    // kAdmit129): bash, RHEL's /bin/sh, exits at its start when it fails
    // ("getpgrp failed"), so a shell agent under an earlier pack could not
    // start
    "getpgrp",
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
    // v1.27 (decided launches): vfork, which CPython's subprocess and
    // posix_spawn use; it is clone(CLONE_VM|CLONE_VFORK|SIGCHLD), and can set
    // no namespace bit. kill is admitted below for a pid above 0 only.
    "vfork",
    "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_pwait2",
    // v1.31.1: epoll_wait and epoll_create, which glibc on x86_64 calls for
    // epoll_wait() and epoll_create() (arm64 has neither and uses the two
    // above). Without them Python's select.epoll, and so asyncio's default
    // event loop, failed with EPERM under every policy. They do what
    // epoll_pwait with no signal mask and epoll_create1 with no flags do.
    "epoll_wait", "epoll_create",
    // time / sched / ids
    "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday", "time",
    "getpid", "gettid", "getppid", "sched_yield", "sched_getaffinity",
    "getuid", "geteuid", "getgid", "getegid", "uname", "sysinfo", "prlimit64",
    // signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait",
    "sigaltstack", "tgkill",
    // sync
    "futex",
    // networking — socket creation stays admitted so targets start normally,
    // and socket options are admitted by add_setsockopt except the routing
    // ones; connect, bind and the egress-capable sends are mediated (below).
    // v1.12.1: bind, listen, accept and accept4 are NO LONGER admitted. They are
    // the inbound half of networking (a TCP listener, a bound UDP receiver, an
    // abstract unix socket the host can reach) and the deny-only network posture
    // had left them open to a root agent. They fall to the default EPERM. bind
    // on a pathname unix socket also created a file outside open() mediation;
    // that is closed with it. The Warden also runs the agent in its own, empty
    // network namespace (warden.c), so no interface is reachable either way.
    "socket", "socketpair",
    "getsockname", "getpeername", "getsockopt",
    // v1.21: setsockopt is admitted by conditional rules (add_setsockopt).
    // v1.12: sendto/sendmsg are NO LONGER admitted here — they can reach the
    // network without connect (a datagram send with an explicit destination),
    // which bypassed the deny-only connect posture. They are mediated below.
    // v1.21: sendto with NO destination is admitted by a conditional rule
    // (add_sends); sendmsg and sendmmsg are relayed by the Warden.
    // Inbound-only recv stays admitted.
    "recvfrom", "recvmsg", "shutdown",
    // termination
    "exit", "exit_group",
    NULL
};

// MEDIATE -> NOTIFY: exactly what supervise()/derive_intent() handles.
static const char *kMediate[] = {
    "openat", "connect", "execve", "execveat",
    // v1.24: the legacy open(2) (musl), decided as openat(AT_FDCWD, ...).
    "open",
    // v1.12: egress-capable datagram/message sends. Routed to the supervisor
    // so a send carrying an inet destination was refused, like every connect
    // then (the deny-only posture of v1.9.1 to v1.20.0), closing the
    // sendto/sendmsg egress bypass (bypass-classes.md class 3). v1.21: sendmsg and sendmmsg carry their
    // destination in the agent's memory, so the Warden reads each message
    // once and sends it itself (net_send_relay) when it names no destination
    // and carries no control data, and refuses it otherwise. sendto is
    // routed here only when it names a destination or asks for TCP Fast Open
    // (add_sends); every other sendto is admitted.
    "sendmsg", "sendmmsg",
    // v1.21: bind is performed by the Warden for a TCP or UDP socket and the
    // wildcard address with port 0 only (libuv binds so before every UDP
    // connect); every other bind is refused (net_bind in warden_net.inc.c).
    "bind",
    // v1.17.0: metadata and link lookups, decided like a read-only open and
    // answered by the supervisor (warden.c: meta_answer).
    "newfstatat", "statx", "readlink", "readlinkat",
    "access", "faccessat", "faccessat2", NULL
};

// v1.29 (docs/security/v1.29-varek-run.md, D12): under `require warden 1.29`
// the changes by name go to the supervisor, which decides each as a write on
// every path it names and carries it out as the agent (warden_change.inc.c).
// Without it they fall to the default refusal, as before. link, linkat,
// symlink and symlinkat are in neither list: a second name for a file is how
// a deny rule would be escaped.
static const char *kChange[] = {
    "unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "rename", "renameat", "renameat2",
    "chmod", "fchmod", "fchmodat", "fchmodat2", "utimensat", "truncate", "ftruncate", "chdir",
    NULL
};
// fchdir: the agent's working directory becomes a directory it already holds
// (an open the Warden decided); its later relative names are each decided.
static const char *kChangeAdmit[] = { "fchdir", NULL };

// v1.29 (step 6: dry runs of the coding agents' CLIs, then the same runs
// enforcing): what they need that the lists above lack, under `require
// warden 1.29` only (before it, refused as before).
// stat and lstat, which musl calls (a statically linked agent, the Codex
// CLI, looked nothing up), decided as newfstatat (warden.c).
static const char *kMediate129[] = { "stat", "lstat", NULL };
// Each acts on the caller, its own descriptors, or processes of its own PID
// namespace (the agent runs as its init): its resource use (getrusage), a
// system call the kernel restarts after a signal (restart_syscall), its
// capabilities, read (capget), process groups and sessions (setpgid,
// getpgid, getpgrp, getsid, setsid: shells and job control), a read-ahead
// hint and an advisory lock on a descriptor it holds (fadvise64, flock), the
// filesystem of a descriptor it holds (fstatfs), its timers (getitimer,
// setitimer, alarm), its file creation mask (umask: the Warden reads it from
// /proc when it creates a file for the agent), its own memory's NUMA policy
// (mbind), and a descriptor for one of its processes (pidfd_open: the
// descriptor can be waited on; pidfd_getfd is hard-denied and
// pidfd_send_signal is not admitted).
static const char *kAdmit129[] = {
    "getrusage", "restart_syscall", "capget", "setpgid", "getpgid", "getsid", "setsid",
    "fadvise64", "flock", "fstatfs", "getitimer", "setitimer", "alarm", "umask", "mbind", "pidfd_open",
    NULL
};
// prctl, for these options only (compared on the full 64-bit argument, as
// ioctl's are): a thread's name, the signal at its parent's death, reading
// whether it is dumpable, whether no_new_privs is set, its bounding set and
// its securebits, and naming an anonymous mapping. Every other option (the
// seccomp, dumpable, ptracer, capability and memory-map setters among them)
// stays refused. PR_CAP_AMBIENT is admitted for PR_CAP_AMBIENT_IS_SET only.
static const unsigned long kPrctlAdmit[] = {
    PR_SET_NAME, PR_GET_NAME, PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_GET_DUMPABLE,
    PR_GET_NO_NEW_PRIVS, PR_CAPBSET_READ, PR_GET_SECUREBITS,
    0x53564d41UL,                 // PR_SET_VMA (Linux 5.17; anon_vma_name)
};

// HARD-DENY: never admissible (classes 3-6). KILL in strict mode, even in
// observe mode.
static const char *kHardDeny[] = {
    // v1.21: io_uring_setup answers ENOSYS (add_io_uring_setup) so libuv, and
    // with it Node.js, falls back to epoll; with no ring ever created, the
    // other two can only be reached by an agent probing for them.
    "io_uring_enter", "io_uring_register",
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

static bool in_list(const char **names, const char *n) {
    for (size_t i = 0; names[i]; ++i) if (!strcmp(names[i], n)) return true;
    return false;
}

static const char *kChange[];
static const char *kChangeAdmit[];
static const char *kMediate129[];
static const char *kAdmit129[];
static const char *kMediate[];
static const char *kHardDeny[];
static const char *kAdmit[];

// v1.29: a dry run sends every native system call the filter names nowhere
// to the supervisor (which records it and lets the kernel carry it out),
// instead of the default refusal. (The kernel takes no NOTIFY default.) A call
// with argument rules (ioctl's commands, kill of a group, clone's namespace
// bits, setsockopt's routing options, sendto, unshare, clone3,
// io_uring_setup) keeps them: what they refuse stays refused.
//
// v1.29 review: never the calls that reach a file by a name or a handle
// (the Warden's checks of the protected objects and kernel filesystems are
// made on opens and changes it mediates; openat2 or creat would read or
// write the verdict stream past them), other processes, or the system. Those
// stay refused (EPERM), as when enforcing, and are not recorded; so are the
// changes by name and stat/lstat under a policy before 1.29, which the
// Warden mediates only from 1.29.
static const char *const kDryNever[] = {
    "creat", "openat2", "open_by_handle_at", "name_to_handle_at", "uselib",
    "link", "linkat", "symlink", "symlinkat", "mknod", "mknodat",
    "chown", "fchown", "fchownat", "lchown", "utime", "utimes", "futimesat",
    "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
    "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
    "setxattrat", "getxattrat", "listxattrat", "removexattrat", "file_getattr", "file_setattr",
    "inotify_add_watch", "fanotify_init", "fanotify_mark", "statfs", "ustat", "sysfs",
    "statmount", "listmount", "mount_setattr", "fspick", "lookup_dcookie", "nfsservctl",
    "acct", "chroot", "pivot_root", "swapon", "swapoff", "quotactl", "quotactl_fd",
    "kcmp", "migrate_pages", "move_pages", "process_madvise", "process_mrelease",
    "pidfd_send_signal", "tkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo",
    "reboot", "sethostname", "setdomainname", "settimeofday", "clock_settime", "clock_adjtime",
    "adjtimex", "syslog", "iopl", "ioperm", "vhangup", "_sysctl",
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr",
    "msgget", "msgsnd", "msgrcv", "msgctl", "semget", "semop", "semtimedop", "semctl",
    "shmget", "shmat", "shmdt", "shmctl",
    NULL
};

static int add_dry_rest(scmp_filter_ctx ctx, int file_changes) {
    /* getpgid: admitted for 0 only (glibc's getpgrp() on arm64), refused
     * otherwise, in a dry run as when enforcing */
    static const char *const kConditional[] = { "clone", "clone3", "ioctl", "kill", "sendto", "setsockopt",
                                                "unshare", "io_uring_setup", "getpgid", NULL };
    for (int nr = 0; nr < 1024; nr++) {
        char *n = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
        if (!n) continue;
        bool named = in_list(kHardDeny, n) || in_list(kMediate, n) || in_list(kAdmit, n) ||
                     in_list((const char **)kConditional, n) || in_list((const char **)kDryNever, n) ||
                     in_list(kChange, n) || in_list(kMediate129, n) ||
                     (file_changes && (in_list(kChangeAdmit, n) || in_list(kAdmit129, n) ||
                                       !strcmp(n, "prctl")));
        free(n);
        if (named) continue;
        int rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, nr, 0);
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
#define __NR_clone3 435   // the same on x86_64 and aarch64
#endif
static int add_clone3(scmp_filter_ctx ctx) {
    int nr = seccomp_syscall_resolve_name("clone3");
    if (nr == __NR_SCMP_ERROR) nr = __NR_clone3;   // libseccomp older than clone3
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr, 0);
    return (rc < 0 && rc != -EEXIST) ? rc : 0;
}

// v1.21: sendto(fd, buf, len, flags, dest_addr, addrlen). With dest_addr NULL
// the kernel reads no address at all (dest_addr is a register, so no other
// thread can change it after this check), and the send goes to the socket's
// connected peer, exactly as write() would; write() is admitted. It is
// admitted here unless MSG_FASTOPEN is set, which on a TCP socket in the
// Warden's namespace could open a connection of its own. A sendto that names
// a destination, or sets MSG_FASTOPEN, goes to the Warden, which refuses it.
// Through v1.20.0 every sendto went to the Warden and was refused, so send()
// failed even where nothing could be reached.
static int add_sends(scmp_filter_ctx ctx) {
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 2,
                              SCMP_A4(SCMP_CMP_EQ, 0),
                              SCMP_A3(SCMP_CMP_MASKED_EQ, (scmp_datum_t)MSG_FASTOPEN, 0));
    if (rc < 0) return rc;
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(sendto), 1, SCMP_A4(SCMP_CMP_NE, 0));
    if (rc < 0) return rc;
    return seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(sendto), 1,
                            SCMP_A3(SCMP_CMP_MASKED_EQ, (scmp_datum_t)MSG_FASTOPEN,
                                    (scmp_datum_t)MSG_FASTOPEN));
}

// v1.21: socket options that would send the agent's packets somewhere the
// connect did not decide: IPv4 source routing (IP_OPTIONS with LSRR/SSRR) and
// IPv6 routing headers (IPV6_RTHDR, its RFC 2292 form IPV6_2292RTHDR, and
// IPV6_2292PKTOPTIONS, which installs sticky options in control-message form,
// a type 2 routing header among them; each can send a connected socket's
// packets to an address in the header instead of the peer decided on). A
// socket the Warden connected lives in the host's network namespace, so these
// are refused (EACCES) on every socket, in observe mode too. Every other
// setsockopt stays admitted.
//
// Two properties of libseccomp shape this. An unconditional rule on a call
// overrides conditional ones on the same call (an unconditional ALLOW would
// make the refusals dead), and a rule may compare an argument only once. So
// setsockopt is admitted by disjoint conditional rules that together cover
// every (level, optname) pair except the four refused ones. And the
// comparisons are 64-bit even through SCMP_A1_32 (which truncates only the
// constant), while the kernel reads level and optname as ints: an ordered
// comparison would let a register with junk in its upper half (level
// 41 | 1 << 40, which the kernel reads as 41) through. Every rule is
// therefore a masked equality whose mask lies within the low 32 bits: (arg &
// mask) == value tests exactly the int the kernel will read. A range of ints
// is covered by aligned power-of-two blocks, like a CIDR decomposition.
#define IP_OPTIONS_NR          4
#define IPV6_2292RTHDR_NR      5
#define IPV6_2292PKTOPTIONS_NR 6
#define IPV6_RTHDR_NR          57

// Rules admitting every int in [lo, hi] for argument `arg` (plus the extra
// comparison, if any), as aligned blocks.
static int allow_int_range(scmp_filter_ctx ctx, int nr, unsigned arg, uint64_t lo, uint64_t hi,
                           const struct scmp_arg_cmp *extra) {
    while (lo <= hi) {
        uint64_t size = 1;
        while (size < (1ull << 32) && (lo & (size * 2 - 1)) == 0 && lo + size * 2 - 1 <= hi)
            size *= 2;
        struct scmp_arg_cmp c = { arg, SCMP_CMP_MASKED_EQ,
                                  (scmp_datum_t)(0xffffffffull & ~(size - 1)), (scmp_datum_t)lo };
        int rc = extra ? seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 2, *extra, c)
                       : seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1, c);
        if (rc < 0) return rc;
        lo += size;
        if (lo == 0) break;               // wrapped past 2^64 (cannot happen below 2^32)
    }
    return 0;
}

// Admit every int of `arg` except the sorted values in ex[0..n).
static int allow_int_except(scmp_filter_ctx ctx, int nr, unsigned arg, const uint32_t *ex, size_t n,
                            const struct scmp_arg_cmp *extra) {
    uint64_t lo = 0;
    for (size_t i = 0; i <= n; i++) {
        uint64_t hi = i < n ? (uint64_t)ex[i] : 0x100000000ull;
        if (hi > lo) {
            int rc = allow_int_range(ctx, nr, arg, lo, hi - 1, extra);
            if (rc < 0) return rc;
        }
        if (i < n) lo = (uint64_t)ex[i] + 1;
    }
    return 0;
}

static int add_setsockopt(scmp_filter_ctx ctx) {
    const int nr = SCMP_SYS(setsockopt);
    int rc;
#define LOW32_EQ(arg, v) ((struct scmp_arg_cmp){ arg, SCMP_CMP_MASKED_EQ, 0xffffffffull, (scmp_datum_t)(v) })
    static const struct { uint32_t level, name; } ban[] = {
        { IPPROTO_IP, IP_OPTIONS_NR }, { IPPROTO_IPV6, IPV6_2292RTHDR_NR },
        { IPPROTO_IPV6, IPV6_2292PKTOPTIONS_NR }, { IPPROTO_IPV6, IPV6_RTHDR_NR },
    };
    for (size_t i = 0; i < sizeof ban / sizeof ban[0]; ++i)
        if ((rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), nr, 2, LOW32_EQ(1, ban[i].level),
                                   LOW32_EQ(2, ban[i].name))) < 0)
            return rc;
    // Every level but IPPROTO_IP (0) and IPPROTO_IPV6 (41): any optname.
    static const uint32_t levels_ex[] = { IPPROTO_IP, IPPROTO_IPV6 };
    if ((rc = allow_int_except(ctx, nr, 1, levels_ex, 2, NULL)) < 0) return rc;
    // IPPROTO_IP: every optname but IP_OPTIONS.
    static const uint32_t ip_ex[] = { IP_OPTIONS_NR };
    struct scmp_arg_cmp lv = LOW32_EQ(1, IPPROTO_IP);
    if ((rc = allow_int_except(ctx, nr, 2, ip_ex, 1, &lv)) < 0) return rc;
    // IPPROTO_IPV6: every optname but the routing-header options.
    static const uint32_t ip6_ex[] = { IPV6_2292RTHDR_NR, IPV6_2292PKTOPTIONS_NR, IPV6_RTHDR_NR };
    lv = LOW32_EQ(1, IPPROTO_IPV6);
    if ((rc = allow_int_except(ctx, nr, 2, ip6_ex, 3, &lv)) < 0) return rc;
#undef LOW32_EQ
    return 0;
}

// v1.21: io_uring_setup answers ENOSYS instead of killing the process.
//
// io_uring (bypass class 3) runs I/O the filter never sees, so no ring may
// exist. From v1.9.1 io_uring_setup killed the caller. But libuv (so Node.js
// 20 and later) calls io_uring_setup at startup to see whether the kernel has
// io_uring, so no Node program could run under the Warden. ENOSYS is the
// answer libuv (and liburing's users) take to mean "this kernel has none" and
// fall back to epoll and a thread pool, as they do on kernels before 5.1. No
// ring is ever created, so io_uring_enter and io_uring_register, which need
// one, stay on the kill list. The same reasoning as clone3 (add_clone3).
static int add_io_uring_setup(scmp_filter_ctx ctx) {
    int nr = seccomp_syscall_resolve_name("io_uring_setup");
    if (nr == __NR_SCMP_ERROR) nr = 425;           // x86_64
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr, 0);
    return (rc < 0 && rc != -EEXIST) ? rc : 0;
}

// Build the filter. default_action is EPERM (enforce) or LOG (observe).
static int build(scmp_filter_ctx *out_ctx, int observe, int flags) {
    int file_changes = flags & WD_FILTER_CHANGES;
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
    if ((rc = add_io_uring_setup(ctx)) < 0) goto fail;       // v1.21
    for (size_t i = 0; i < sizeof kIoctlAdmit / sizeof kIoctlAdmit[0]; ++i) {
        rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                              SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)kIoctlAdmit[i]));
        if (rc < 0) goto fail;
    }
    if ((rc = add_list(ctx, kMediate, SCMP_ACT_NOTIFY)) < 0) goto fail;
    if ((flags & WD_FILTER_DRY) && (rc = add_dry_rest(ctx, file_changes)) < 0) goto fail;   // v1.29
    if (file_changes) {                                       // v1.29
        if ((rc = add_list(ctx, kChange, SCMP_ACT_NOTIFY)) < 0) goto fail;
        if ((rc = add_list(ctx, kChangeAdmit, SCMP_ACT_ALLOW)) < 0) goto fail;
        if ((rc = add_list(ctx, kMediate129, SCMP_ACT_NOTIFY)) < 0) goto fail;   // step 6
        if ((rc = add_list(ctx, kAdmit129, SCMP_ACT_ALLOW)) < 0) goto fail;
        for (size_t i = 0; i < sizeof kPrctlAdmit / sizeof kPrctlAdmit[0]; ++i) {
            rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
                                  SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)kPrctlAdmit[i]));
            if (rc < 0) goto fail;
        }
        rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 2,
                              SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)PR_CAP_AMBIENT),
                              SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)PR_CAP_AMBIENT_IS_SET));
        if (rc < 0) goto fail;
    }
    if ((rc = add_sends(ctx)) < 0) goto fail;                 // v1.21
    if ((rc = add_setsockopt(ctx)) < 0) goto fail;            // v1.21
    // v1.27: kill, which subprocess uses to stop a child on a timeout, for a
    // pid of 1 to 2^31-1 only (the int the kernel reads). The agent runs as
    // init of its own PID namespace (v1.9.3) and in its own process group, so
    // any kill reaches only its own processes; kill(0), kill(-1) and
    // kill(-pgid) fall to the default refusal all the same, for a run with
    // VAREK_WARDEN_NO_PIDNS=1, where -1 would reach every process of its user.
    if ((rc = allow_int_range(ctx, SCMP_SYS(kill), 0, 1, 0x7fffffffull, NULL)) < 0) goto fail;
    // v1.33 (arm64's first CI run): getpgid(0), the caller's own process
    // group, under every policy, as getpgrp is from v1.31.1: arm64 has no
    // getpgrp, and glibc's getpgrp() calls getpgid(0) there, so bash could
    // not start under a policy before 1.29. From 1.29 getpgid is admitted for
    // any pid (kAdmit129).
    if (!file_changes &&
        (rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 1, SCMP_A0(SCMP_CMP_EQ, 0))) < 0) goto fail;
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
    return install_baseline_user_notif_filter_ex(observe, 0);
}

int install_baseline_user_notif_filter_ex(int observe, int flags) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;

    scmp_filter_ctx ctx;
    if (build(&ctx, observe, flags) < 0) return -1;

    if (seccomp_load(ctx) < 0) { seccomp_release(ctx); return -1; }

    // libseccomp installs with SECCOMP_FILTER_FLAG_NEW_LISTENER because the
    // filter contains NOTIFY rules; retrieve the listener fd to hand to the
    // supervisor. The fd outlives ctx.
    int notify_fd = seccomp_notify_fd(ctx);
    seccomp_release(ctx);
    return notify_fd;   // >=0 on success, -1 if no listener was created
}
