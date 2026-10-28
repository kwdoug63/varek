// SPDX-License-Identifier: MIT
//
// varek_init.c — v1.34 step 3 (docs/security/v1.34-kubernetes.md, D3): the
// launcher, varek-init, built static. The NRI plugin (k8s/cmd/varek-nri) binds it
// read-only at /varek/init in each container of a pod VAREK supervises and
// puts it first in the container's command:
//
//   /varek/init -- COMMAND [ARG...]
//
// It runs under the Warden's filter, which the runtime has loaded already,
// and before any of the container's own code:
//   1. it reads the launch set from /etc/varek/launch-set, a view the node
//      agent's supervisor serves (built in the container's view with the
//      Warden's own expansion: each program the policy allows to launch, its
//      loader, a script's interpreter, and the container's command), one
//      path a line;
//   2. it applies Landlock to exactly those paths (each path, never another
//      name of its file: on the overlay file system a container's root is,
//      a rule on one name of a file does not cover its hardlinks); v1.36
//      step 7: a directory in the set (a dry run's, which is / alone) gives
//      execution beneath it, and moving a file between directories beneath
//      it (LANDLOCK_ACCESS_FS_REFER, from Landlock's ABI 2: a domain refuses
//      every such move otherwise, which a host's dry run, with no Landlock,
//      lets through);
//   3. it adds a filter of its own whose only effect is that a call from
//      another architecture (i386, x32 on x86_64; 32-bit ARM on aarch64)
//      kills the whole process, as the Warden's own filter does on a host
//      (OCI's profile has no field for it, so the runtime's filter kills only
//      the calling thread; the kernel takes the stricter of two filters);
//   4. it launches the container's command, which the node agent decides as
//      the run's first launch.
// Without Landlock, without the view (no node agent serving it), or if any
// step fails, it refuses to run the command (exit 126). The runtime has set
// no_new_privs (the node agent refuses a container without it), which
// Landlock and the filter need.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SET_VIEW "/etc/varek/launch-set"
#define SET_MAX  (1 << 20)

static int refuse(const char *what, const char *detail) {
    fprintf(stderr, "varek-init: %s%s%s: refusing to run the container's command\n", what, detail ? ": " : "",
            detail ? detail : "");
    return 126;
}

/* 3: another architecture's call kills the process */
static int arch_filter(void) {
#if defined(__x86_64__)
#define NATIVE AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE AUDIT_ARCH_AARCH64
#else
#error "varek-init is built for x86_64 and aarch64"
#endif
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#if defined(__x86_64__)
        /* x32's calls carry the native architecture and this bit */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = (unsigned short)(sizeof f / sizeof f[0]), .filter = f };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "--")) {
        fprintf(stderr, "usage: varek-init -- COMMAND [ARG...]\n");
        return 2;
    }
    const char *cmd = argv[2];
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return refuse("no Landlock", strerror(errno));

    /* 1: the launch set, from the node agent's view */
    int vf = open(SET_VIEW, O_RDONLY | O_CLOEXEC);
    if (vf < 0) return refuse("cannot read the launch set (" SET_VIEW ", served by the node agent)", strerror(errno));
    char *set = malloc(SET_MAX + 1);
    size_t n = 0;
    if (!set) return refuse("out of memory", NULL);
    for (;;) {
        ssize_t r = read(vf, set + n, SET_MAX - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return refuse("cannot read the launch set", strerror(errno));
        if (r == 0) break;
        n += (size_t)r;
        if (n == SET_MAX) return refuse("the launch set is too large", NULL);
    }
    close(vf);
    set[n] = '\0';
    if (n == 0 || set[n - 1] != '\n') return refuse("the launch set is not whole", NULL);

    /* 2: Landlock on exactly those paths */
    __u64 refer = abi >= 2 ? LANDLOCK_ACCESS_FS_REFER : 0;
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | refer };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) return refuse("landlock_create_ruleset", strerror(errno));
    int count = 0;
    for (char *line = set, *nl; *line; line = nl + 1) {
        nl = strchr(line, '\n');
        *nl = '\0';
        if (line[0] != '/') return refuse("the launch set holds a path that is not absolute", line);
        int fd = open(line, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return refuse(line, strerror(errno));
        struct stat st;
        if (fstat(fd, &st) < 0) return refuse(line, strerror(errno));
        struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
                                                 (S_ISDIR(st.st_mode) ? refer : 0), .parent_fd = fd };
        if (syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
            return refuse(line, strerror(errno));
        close(fd);
        count++;
    }
    free(set);

    /* 3, then the domain entered */
    if (arch_filter() < 0) return refuse("cannot add the filter for other architectures' calls", strerror(errno));
    if (syscall(SYS_landlock_restrict_self, rs, 0) < 0) return refuse("landlock_restrict_self", strerror(errno));
    close(rs);
    fprintf(stderr, "varek-init: Landlock ABI %ld, a launch set of %d file(s) applied; running %s\n", abi, count, cmd);

    /* 4 */
    execv(cmd, argv + 2);
    fprintf(stderr, "varek-init: %s: %s\n", cmd, strerror(errno));
    return 127;
}
