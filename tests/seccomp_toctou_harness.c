// SPDX-License-Identifier: MIT
/*
 * seccomp_toctou_harness.c
 *
 * Reproducer harness for the canonical TOCTOU race on pointer-argument
 * syscalls under seccomp-unotify. Compares two supervisor implementations:
 *
 *   --naive       Reads the userspace path string, validates it, and
 *                 returns SECCOMP_USER_NOTIF_FLAG_CONTINUE so the kernel
 *                 re-executes the syscall. Vulnerable to a CLONE_VM
 *                 sibling that overwrites the path bytes after the read
 *                 but before the kernel's re-execution.
 *
 *   --mitigated   Resolves the path itself with openat2() under
 *                 RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS and
 *                 returns the resolved fd to the caller via
 *                 SECCOMP_IOCTL_NOTIF_ADDFD with SECCOMP_ADDFD_FLAG_SEND.
 *                 Race is moot because the kernel never re-reads the
 *                 userspace pathname pointer.
 *
 * Threat model
 *   Supervised process is fully adversarial. It is allowed to spawn
 *   threads (CLONE_VM siblings) that share its address space and race
 *   to mutate the path buffer between supervisor read and kernel
 *   re-execution.
 *
 *   Supervisor is privileged, isolated, NOT co-resident in the
 *   supervised process's mm. Kernel is trusted.
 *
 * Files (auto-created in /tmp, removed on exit):
 *   /tmp/varek_allowed_0..3        innocent allowlisted files
 *   /tmp/varek_secret              non-allowlisted file containing the
 *                                  sentinel string VAREK_TOCTOU_LEAK
 *
 * A "leak" is counted when the target process opens a file under an
 * allowlisted path string but reads back the sentinel — proof that the
 * kernel actually opened /tmp/varek_secret because the path bytes were
 * mutated after supervisor inspection.
 *
 * Build:    make
 * Run:      sudo ./seccomp_toctou_harness --naive       [iterations]
 *           sudo ./seccomp_toctou_harness --mitigated   [iterations]
 *
 * Requires: Linux >= 5.14   (SECCOMP_ADDFD_FLAG_SEND)
 *           x86_64           (BPF arch check; trivially portable)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* openat2 / open_how — defined here for portability across libc versions
 * that don't yet expose <linux/openat2.h>. */
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS    0x04
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS  0x02
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH        0x08
#endif
struct open_how_local {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

#define ARCH_NR        AUDIT_ARCH_X86_64
#define PATH_LIMIT     4096
#define DEFAULT_ITER   20000

static const char *ALLOWED_PREFIX = "/tmp/varek_allowed_";
static const char *ATTACK_TARGET  = "/tmp/varek_secret";
static const char  SENTINEL[]     = "VAREK_TOCTOU_LEAK";

/* ------------------------------------------------------------------ */
/* fd passing over UNIX socket                                         */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* seccomp filter: trap openat with USER_NOTIF                         */
/* ------------------------------------------------------------------ */

static int install_user_notif_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
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

/* ------------------------------------------------------------------ */
/* supervisor helpers                                                  */
/* ------------------------------------------------------------------ */

static int read_remote_str(pid_t pid, uint64_t addr, char *buf, size_t len) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    /* Truncate at first NUL — userspace string semantics. */
    for (ssize_t i = 0; i < n; i++) if (buf[i] == '\0') return 0;
    buf[len - 1] = '\0';
    return 0;
}

static bool notif_id_valid(int notify_fd, uint64_t id) {
    return ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

static bool path_allowed(const char *path) {
    return strncmp(path, ALLOWED_PREFIX, strlen(ALLOWED_PREFIX)) == 0;
}

static void send_deny(int notify_fd, uint64_t id, int err) {
    struct seccomp_notif_resp resp = {
        .id = id, .val = 0, .error = -err, .flags = 0,
    };
    ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

/* ------------------------------------------------------------------ */
/* NAIVE supervisor — read string, allowlist, CONTINUE                 */
/* ------------------------------------------------------------------ */

static void supervise_naive(int notify_fd) {
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            return;  /* target dead, listener closed, etc. */
        }

        char path[PATH_LIMIT] = {0};
        if (read_remote_str(req.pid, req.data.args[1], path, sizeof(path)) < 0
            || !notif_id_valid(notify_fd, req.id)) {
            send_deny(notify_fd, req.id, EACCES);
            continue;
        }

        if (!path_allowed(path)) {
            send_deny(notify_fd, req.id, EACCES);
            continue;
        }

        /* Vulnerable path: kernel re-executes the syscall, re-reading
         * the (potentially-mutated) userspace pathname pointer. */
        struct seccomp_notif_resp resp = {
            .id    = req.id,
            .val   = 0,
            .error = 0,
            .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
}

/* ------------------------------------------------------------------ */
/* MITIGATED supervisor — resolve via openat2, return fd via ADDFD     */
/* ------------------------------------------------------------------ */

static void supervise_mitigated(int notify_fd) {
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            return;
        }

        /* Acquire stable resolution base from the supervised process's
         * cwd via /proc/<pid>/cwd. This is a snapshot — if the target
         * later changes cwd, our resolution remains anchored. */
        char proc_cwd[64];
        snprintf(proc_cwd, sizeof(proc_cwd), "/proc/%d/cwd", req.pid);
        int cwd_fd = open(proc_cwd, O_PATH | O_DIRECTORY);

        char path[PATH_LIMIT] = {0};
        if (cwd_fd < 0
            || read_remote_str(req.pid, req.data.args[1], path, sizeof(path)) < 0
            || !notif_id_valid(notify_fd, req.id)) {
            send_deny(notify_fd, req.id, EACCES);
            if (cwd_fd >= 0) close(cwd_fd);
            continue;
        }

        if (!path_allowed(path)) {
            send_deny(notify_fd, req.id, EACCES);
            close(cwd_fd);
            continue;
        }

        /* Supervisor-side resolution. Kernel will not re-read the
         * userspace path — we hand it the already-resolved fd. */
        struct open_how_local how = {
            .flags   = (uint64_t)(req.data.args[2]) & ~(uint64_t)O_PATH,
            .mode    = (uint64_t)(req.data.args[3]) & 0777,
            .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        int resolved = (int)syscall(__NR_openat2,
                                    cwd_fd, path, &how, sizeof(how));
        close(cwd_fd);

        if (resolved < 0) {
            send_deny(notify_fd, req.id, errno ? errno : EACCES);
            continue;
        }

        struct seccomp_notif_addfd addfd = {
            .id          = req.id,
            .flags       = SECCOMP_ADDFD_FLAG_SEND,
            .srcfd       = (uint32_t)resolved,
            .newfd       = 0,
            .newfd_flags = O_CLOEXEC,
        };
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0) {
            send_deny(notify_fd, req.id, errno ? errno : EACCES);
        }
        close(resolved);
    }
}

/* ------------------------------------------------------------------ */
/* TARGET (supervised) workload                                        */
/* ------------------------------------------------------------------ */

struct attacker_args {
    char           *path_buf;       /* shared buffer mutated each iter */
    atomic_int      stop;
};

static void *attacker_thread(void *p) {
    struct attacker_args *a = p;
    /* Tight loop: alternate between the allowlisted prefix and the
     * attack target. The race window opens during the supervisor's
     * read_remote_str() call — we spin to maximize the chance that
     * the kernel's re-read after CONTINUE picks up the attack bytes. */
    while (!atomic_load_explicit(&a->stop, memory_order_relaxed)) {
        memcpy(a->path_buf, ATTACK_TARGET, strlen(ATTACK_TARGET) + 1);
        for (volatile int i = 0; i < 30; i++) { /* tiny gap */ }
        snprintf(a->path_buf, PATH_LIMIT, "%s0", ALLOWED_PREFIX);
    }
    return NULL;
}

static int run_target(int iterations, int *leaks_out, int *opens_out) {
    char *path_buf = mmap(NULL, PATH_LIMIT, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (path_buf == MAP_FAILED) return -1;
    snprintf(path_buf, PATH_LIMIT, "%s0", ALLOWED_PREFIX);

    struct attacker_args args = { .path_buf = path_buf };
    atomic_init(&args.stop, 0);

    pthread_t tid;
    if (pthread_create(&tid, NULL, attacker_thread, &args) != 0) {
        munmap(path_buf, PATH_LIMIT);
        return -1;
    }

    int leaks = 0, opens = 0;
    for (int i = 0; i < iterations; i++) {
        /* Reset to allowed value just before the syscall. The attacker
         * thread is racing this assignment. */
        snprintf(path_buf, PATH_LIMIT, "%s%d", ALLOWED_PREFIX, i % 4);

        int fd = openat(AT_FDCWD, path_buf, O_RDONLY);
        if (fd < 0) continue;
        opens++;

        char sniff[128] = {0};
        ssize_t n = read(fd, sniff, sizeof(sniff) - 1);
        close(fd);
        if (n > 0 && memmem(sniff, (size_t)n, SENTINEL, sizeof(SENTINEL) - 1)) {
            leaks++;
        }
    }

    atomic_store(&args.stop, 1);
    pthread_join(tid, NULL);
    munmap(path_buf, PATH_LIMIT);

    *leaks_out = leaks;
    *opens_out = opens;
    return 0;
}

/* ------------------------------------------------------------------ */
/* fixture setup                                                       */
/* ------------------------------------------------------------------ */

static void setup_fixtures(void) {
    for (int i = 0; i < 4; i++) {
        char p[64];
        snprintf(p, sizeof(p), "%s%d", ALLOWED_PREFIX, i);
        int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) { (void)!write(fd, "innocent\n", 9); close(fd); }
    }
    int fd = open(ATTACK_TARGET, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        dprintf(fd, "%s\n", SENTINEL);
        close(fd);
    }
}

static void teardown_fixtures(void) {
    for (int i = 0; i < 4; i++) {
        char p[64];
        snprintf(p, sizeof(p), "%s%d", ALLOWED_PREFIX, i);
        unlink(p);
    }
    unlink(ATTACK_TARGET);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

enum mode { MODE_NAIVE, MODE_MITIGATED };

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s --naive | --mitigated [iterations]\n"
        "       (default iterations: %d)\n",
        argv0, DEFAULT_ITER);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    enum mode m;
    if      (!strcmp(argv[1], "--naive"))     m = MODE_NAIVE;
    else if (!strcmp(argv[1], "--mitigated")) m = MODE_MITIGATED;
    else                                       { usage(argv[0]); return 2; }

    int iterations = (argc >= 3) ? atoi(argv[2]) : DEFAULT_ITER;
    if (iterations <= 0) iterations = DEFAULT_ITER;

    setup_fixtures();

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); teardown_fixtures(); return 1;
    }

    pid_t target = fork();
    if (target < 0) {
        perror("fork"); teardown_fixtures(); return 1;
    }

    if (target == 0) {
        /* Target / supervised */
        close(sv[0]);
        int notify_fd = install_user_notif_filter();
        if (notify_fd < 0) { perror("seccomp"); _exit(1); }
        if (send_fd(sv[1], notify_fd) < 0) { perror("send_fd"); _exit(1); }
        close(notify_fd);
        close(sv[1]);

        /* Brief synchronization delay so the supervisor's RECV loop is
         * armed before we issue the first openat. */
        usleep(100 * 1000);

        int leaks = 0, opens = 0;
        run_target(iterations, &leaks, &opens);

        printf("[target ] iterations=%d  opens_succeeded=%d  sentinel_leaks=%d\n",
               iterations, opens, leaks);
        _exit(leaks > 0 ? 10 : 0);
    }

    /* Supervisor / privileged */
    close(sv[1]);
    int notify_fd = recv_fd(sv[0]);
    close(sv[0]);
    if (notify_fd < 0) {
        fprintf(stderr, "supervisor: failed to receive notify fd\n");
        kill(target, SIGKILL);
        waitpid(target, NULL, 0);
        teardown_fixtures();
        return 1;
    }

    printf("[super  ] mode=%s  notify_fd=%d  pid=%d\n",
           m == MODE_NAIVE ? "naive" : "mitigated",
           notify_fd, target);

    if (m == MODE_NAIVE) supervise_naive(notify_fd);
    else                  supervise_mitigated(notify_fd);

    int status = 0;
    waitpid(target, &status, 0);
    close(notify_fd);
    teardown_fixtures();

    int exitcode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    printf("[result ] %s\n",
        exitcode == 10
          ? "RACE WON  — sentinel observed; supervisor was bypassed."
          : exitcode == 0
              ? "RACE LOST — no sentinel observed."
              : "ERROR     — see above.");
    return exitcode;
}
