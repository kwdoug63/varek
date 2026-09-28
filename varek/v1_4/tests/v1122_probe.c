// SPDX-License-Identifier: MIT
// v1122_probe.c — target for the v1.12.2 regression test.
//
// Run UNDER the Warden with tests/v1122_policy.txt. Through v1.12.1 the
// baseline filter put clone3 on the kill list and left wait4/waitid out of the
// admit list, so:
//
//   - any agent that started a thread with a current C library (glibc >= 2.34
//     creates threads with clone3) was killed with SIGSYS on the spot, and
//   - an agent could start a child process but never collect its exit status.
//
// v1.12.2 answers clone3 with ENOSYS, so the C library falls back to clone(),
// whose flags the filter can inspect, and admits wait4/waitid. This probe
// checks the legitimate behaviour now works and that none of the namespace
// denials got weaker on the way:
//
//   threads     pthread_create/join; threads' own opens are mediated like the
//               main thread's (ALLOW delivered, DENY refused); 8 threads x 50
//               opens concurrently.
//   clone3      raw clone3, plain and with each namespace bit, returns ENOSYS
//               and creates nothing.
//   clone       raw clone() with CLONE_NEWUSER is still killed (SIGSYS), seen
//               from the parent through waitpid.
//   wait        fork + waitpid / wait4 (with rusage) / waitid report the child's
//               real exit status.
//   ioctl       the six admitted requests behave as on a normal system
//               (isatty() on a pipe says ENOTTY, FIOCLEX sets FD_CLOEXEC);
//               TIOCSTI, TCSETS and an admitted request with junk in the upper
//               32 bits are refused with EPERM before reaching any driver.
//   reexec      a thread, and a forked child, that execve the agent's own binary
//               are refused. The bootstrap exec is answered with CONTINUE, which
//               is only sound for the one launch the Warden made; through
//               v1.12.1 every new thread or child got its own bootstrap allow.
//   spawn       posix_spawn of a binary the policy does not allow fails with an
//               error instead of killing the agent.
//
// Output: one "PROBE <tag> <verdict>" line per check, then "PROBE done".
// test_v1122.sh asserts on these lines and on the Warden's verdict stream.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

#define ALLOW  "/tmp/varek_allowed_v1122"
#define DENIED "/tmp/varek_denied_v1122"

extern char **environ;

static pthread_mutex_t out_mu = PTHREAD_MUTEX_INITIALIZER;

static void line(const char *tag, const char *verdict, int err) {
    pthread_mutex_lock(&out_mu);
    if (err) printf("PROBE %-22s %s (%s)\n", tag, verdict, strerror(err));
    else     printf("PROBE %-22s %s\n", tag, verdict);
    fflush(stdout);
    pthread_mutex_unlock(&out_mu);
}

/* ---- threads ------------------------------------------------------------ */

struct tres { int allow_ok, allow_err, deny_refused, deny_err; pid_t tid; };

static void *thread_open(void *arg) {
    struct tres *r = arg;
    r->tid = (pid_t)syscall(SYS_gettid);
    int fd = open(ALLOW "/ok.txt", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char b[32] = {0};
        ssize_t n = read(fd, b, sizeof b - 1);
        r->allow_ok = (n > 0 && strncmp(b, "legitimate", 10) == 0);
        close(fd);
    } else r->allow_err = errno;
    fd = open(DENIED "/secret.txt", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { r->deny_refused = 0; close(fd); }
    else { r->deny_refused = 1; r->deny_err = errno; }
    return NULL;
}

enum { N_THREADS = 8, N_OPENS = 50 };
static void *thread_stress(void *arg) {
    long *ok = arg;
    for (int i = 0; i < N_OPENS; i++) {
        int fd = open(ALLOW "/ok.txt", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { (*ok)++; close(fd); }
    }
    return NULL;
}

static void check_threads(void) {
    pthread_t t;
    struct tres r = {0};
    int e = pthread_create(&t, NULL, thread_open, &r);
    if (e) { line("pthread_create", "FAILED", e); return; }
    pthread_join(t, NULL);
    line("pthread_create", "OK", 0);
    pid_t me = (pid_t)syscall(SYS_gettid);
    line("thread_is_separate_task", r.tid && r.tid != me ? "OK" : "FAILED", 0);
    line("thread_allowed_open", r.allow_ok ? "OK" : "DENIED", r.allow_ok ? 0 : r.allow_err);
    line("thread_denied_open", r.deny_refused ? "REFUSED" : "BYPASSED", r.deny_refused ? r.deny_err : 0);

    pthread_t ts[N_THREADS];
    long oks[N_THREADS] = {0};
    int started = 0;
    for (int i = 0; i < N_THREADS; i++)
        if (pthread_create(&ts[i], NULL, thread_stress, &oks[i]) == 0) started++;
    long total = 0;
    for (int i = 0; i < started; i++) { pthread_join(ts[i], NULL); total += oks[i]; }
    char tag[64];
    snprintf(tag, sizeof tag, "%ld/%d", total, N_THREADS * N_OPENS);
    line("thread_concurrent_opens", total == N_THREADS * N_OPENS ? "OK" : "SHORT", 0);
    printf("PROBE thread_concurrent_count  %s\n", tag);
    fflush(stdout);
}

/* ---- clone3 ------------------------------------------------------------- */

static void check_clone3(const char *tag, uint64_t flags) {
    struct clone_args ca;
    memset(&ca, 0, sizeof ca);
    ca.flags = flags;
    ca.exit_signal = SIGCHLD;
    long r = syscall(SYS_clone3, &ca, sizeof ca);
    if (r == 0) _exit(0);                 /* a child was created: must not happen */
    if (r > 0) {
        waitpid((pid_t)r, NULL, 0);
        line(tag, "CREATED", 0);
    } else if (errno == ENOSYS) {
        line(tag, "ENOSYS", 0);
    } else {
        line(tag, "OTHER", errno);
    }
}

/* ---- legacy clone with a namespace bit: must still be killed -------------- */

static void check_clone_newuser_killed(void) {
    pid_t c = fork();
    if (c < 0) { line("clone_newuser_killed", "FORK_FAILED", errno); return; }
    if (c == 0) {
        long r = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
        if (r == 0) _exit(0);
        _exit(r > 0 ? 60 : 61);           /* survived: the deny got weaker */
    }
    int st = 0;
    if (waitpid(c, &st, 0) != c) { line("clone_newuser_killed", "WAIT_FAILED", errno); return; }
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) line("clone_newuser_killed", "KILLED", 0);
    else if (WIFSIGNALED(st)) { char b[40]; snprintf(b, sizeof b, "SIGNAL_%d", WTERMSIG(st)); line("clone_newuser_killed", b, 0); }
    else if (WIFEXITED(st) && WEXITSTATUS(st) == 60) line("clone_newuser_killed", "CREATED", 0);
    else line("clone_newuser_killed", "SURVIVED", 0);
}

/* ---- wait family -------------------------------------------------------- */

static void check_wait(void) {
    pid_t c = fork();
    if (c < 0) { line("fork", "FAILED", errno); return; }
    if (c == 0) _exit(7);
    line("fork", "OK", 0);
    int st = 0;
    pid_t w = waitpid(c, &st, 0);
    if (w == c && WIFEXITED(st) && WEXITSTATUS(st) == 7) line("waitpid_status", "OK", 0);
    else line("waitpid_status", "FAILED", w < 0 ? errno : 0);

    c = fork();
    if (c == 0) _exit(9);
    struct rusage ru;
    w = wait4(c, &st, 0, &ru);
    if (w == c && WIFEXITED(st) && WEXITSTATUS(st) == 9) line("wait4_rusage", "OK", 0);
    else line("wait4_rusage", "FAILED", w < 0 ? errno : 0);

    c = fork();
    if (c == 0) _exit(11);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    int wr = waitid(P_PID, (id_t)c, &si, WEXITED);
    if (wr == 0 && si.si_pid == c && si.si_status == 11) line("waitid_status", "OK", 0);
    else line("waitid_status", "FAILED", wr < 0 ? errno : 0);

    /* WNOHANG on a running child returns 0 rather than blocking or failing. */
    int p[2];
    if (pipe2(p, O_CLOEXEC) == 0) {
        c = fork();
        if (c == 0) { char b; close(p[1]); if (read(p[0], &b, 1) < 0) _exit(1); _exit(0); }
        close(p[0]);
        w = waitpid(c, &st, WNOHANG);
        line("waitpid_wnohang", w == 0 ? "OK" : "FAILED", w < 0 ? errno : 0);
        close(p[1]);
        waitpid(c, &st, 0);
    }
}

/* ---- ioctl -------------------------------------------------------------- */

static void check_ioctl(void) {
    int p[2];
    if (pipe2(p, 0) != 0) { line("ioctl_setup", "FAILED", errno); return; }
    /* Admitted: on a pipe TCGETS must fail ENOTTY (kernel's answer), not EPERM. */
    errno = 0;
    int t = isatty(p[0]);
    if (!t && errno == ENOTTY) line("ioctl_isatty_enotty", "OK", 0);
    else line("ioctl_isatty_enotty", "FAILED", errno);
    /* Admitted: FIOCLEX sets FD_CLOEXEC, FIONCLEX clears it. */
    int ok = ioctl(p[0], FIOCLEX) == 0 && (fcntl(p[0], F_GETFD) & FD_CLOEXEC)
          && ioctl(p[0], FIONCLEX) == 0 && !(fcntl(p[0], F_GETFD) & FD_CLOEXEC);
    line("ioctl_fioclex", ok ? "OK" : "FAILED", ok ? 0 : errno);
    int n = -1;
    if (write(p[1], "abc", 3) == 3 && ioctl(p[0], FIONREAD, &n) == 0 && n == 3)
        line("ioctl_fionread", "OK", 0);
    else line("ioctl_fionread", "FAILED", errno);
    /* Refused: EPERM comes from the filter; a pipe would otherwise say ENOTTY. */
    char c = 'x';
    errno = 0;
    int r = ioctl(0, TIOCSTI, &c);
    line("ioctl_tiocsti", r < 0 && errno == EPERM ? "REFUSED" : "ADMITTED", r < 0 ? errno : 0);
    struct termios_stub { char b[64]; } tio = {0};
    errno = 0;
    r = ioctl(p[0], TCSETS, &tio);
    line("ioctl_tcsets", r < 0 && errno == EPERM ? "REFUSED" : "ADMITTED", r < 0 ? errno : 0);
    errno = 0;
    r = (int)syscall(SYS_ioctl, p[0], (unsigned long)TCGETS | (1UL << 32), &tio);
    line("ioctl_upper_bits", r < 0 && errno == EPERM ? "REFUSED" : "ADMITTED", r < 0 ? errno : 0);
    close(p[0]); close(p[1]);
}

/* ---- re-exec of the agent's own binary ----------------------------------- */

static const char *g_self;
static int g_reexec_err;

static void *thread_reexec(void *arg) {
    (void)arg;
    char *av[] = { (char *)g_self, "reexec-must-not-run", NULL };
    execve(g_self, av, environ);
    g_reexec_err = errno;
    return NULL;
}

static void check_reexec(void) {
    pthread_t t;
    g_reexec_err = 0;
    if (pthread_create(&t, NULL, thread_reexec, NULL) == 0) {
        pthread_join(t, NULL);
        line("thread_reexec_self", g_reexec_err ? "REFUSED" : "BYPASSED", g_reexec_err);
    }
    pid_t c = fork();
    if (c == 0) {
        char *av[] = { (char *)g_self, "reexec-must-not-run", NULL };
        execve(g_self, av, environ);
        _exit(errno == EACCES ? 0 : 2);
    }
    int st = 0;
    waitpid(c, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) line("child_reexec_self", "REFUSED", 0);
    else if (WIFEXITED(st) && WEXITSTATUS(st) == 42) line("child_reexec_self", "BYPASSED", 0);
    else line("child_reexec_self", "OTHER", 0);
}

/* ---- posix_spawn of a binary the policy does not name --------------------- */

static void check_spawn(void) {
    pid_t c;
    char *argv[] = { "true", NULL };
    int e = posix_spawn(&c, "/bin/true", NULL, NULL, argv, environ);
    if (e != 0) { line("spawn_unlisted", "REFUSED", e); return; }
    int st = 0;
    if (waitpid(c, &st, 0) != c) { line("spawn_unlisted", "WAIT_FAILED", errno); return; }
    /* glibc reports an exec failure in the vfork child through posix_spawn's
     * return value; reaching here with exit 0 means /bin/true really ran. */
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) line("spawn_unlisted", "BYPASSED", 0);
    else line("spawn_unlisted", "REFUSED", 0);
}

int main(int argc, char **argv) {
    /* A re-exec that got through lands here: say so and stop. */
    if (argc > 1 && strcmp(argv[1], "reexec-must-not-run") == 0) {
        printf("PROBE %-22s %s\n", "reexec_ran", "BYPASSED");
        fflush(stdout);
        _exit(42);
    }
    g_self = argv[0];
    setvbuf(stdout, NULL, _IOLBF, 0);
    check_threads();
    check_clone3("clone3_plain",    0);
    check_clone3("clone3_newuser",  CLONE_NEWUSER);
    check_clone3("clone3_newns",    CLONE_NEWNS);
    check_clone3("clone3_newnet",   CLONE_NEWNET);
    check_clone3("clone3_newpid",   CLONE_NEWPID);
    check_clone3("clone3_into_cgroup", CLONE_INTO_CGROUP);
    check_clone_newuser_killed();
    check_wait();
    check_ioctl();
    check_reexec();
    check_spawn();
    line("done", "", 0);
    return 0;
}
