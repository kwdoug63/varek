/* SPDX-License-Identifier: MIT
 * warden_subagent.inc.c — v1.28.1 step 3: sub-agents (included by warden.c,
 * before warden_exec.inc.c, which calls it). docs/security/v1.28.1-delegation-chain.md,
 * section 3.
 *
 * With a policy that names a sub-agent (`allow exec PATH subagent=NAME`) the
 * Warden makes a control group (cgroup v2) for the run, varek-<run>, under
 * its own, and the agent enters it before its own launch. A launch the
 * policy allows by a rule with subagent=NAME is decided as any launch; before
 * the Warden answers it, it makes NAME-<n> under the launching process's
 * group and moves the process there (n counts that name's launches in the
 * run). The process and everything it starts stay there: the agent runs
 * unprivileged, and the Warden opens nothing on a control group's filesystem
 * for writing on its behalf.
 *
 * Every notification is attributed by the calling thread's group
 * (/proc/<tid>/cgroup, read before the call is decided; the notification's
 * id is checked valid after, so the thread read is the caller): the run's
 * group, the agent; a sub-agent's, that sub-agent. Nothing the process says
 * is believed.
 *
 * A launch is not known to have happened until its process shows it. clone
 * is not notified, so a process may start others unseen; to keep every
 * process's attribution right whatever the launch's outcome:
 *   - only a single-threaded process may launch a sub-agent (the one thread
 *     is in the launch, so nothing else of the process can run, or start a
 *     process, while it is moved): a threaded one is refused
 *     (subagent_threaded);
 *   - until it is known, a sub-agent is pending. The first call from any
 *     process in its group settles it (v1.28.1 review): the kernel's
 *     process events (the proc connector, NETLINK_CONNECTOR) report each
 *     launch that succeeded, before the process runs again; a sub-agent
 *     whose launcher launched is launched, else its launch failed (the
 *     launching process is back from it, running what it ran). Where the
 *     connector cannot be used (checked at the start with a launch of its
 *     own: in a container, whose network namespace the kernel sends none),
 *     the image a process runs is compared with the one the launch was
 *     decided for. A launch of the image the launcher already runs is told
 *     from a failed one by the process's memory layout (v1.32): where its
 *     code, stack, heap, arguments and environment begin and end
 *     (/proc/<pid>/stat), which every new program gets anew, randomized,
 *     and which the process cannot change but by a launch (PR_SET_MM needs
 *     CAP_SYS_RESOURCE, which the agent never holds); the same layout is a
 *     failed launch. Where the layout cannot be read, or is not
 *     randomized, such a launch is refused (subagent_same_image). Each
 *     sub-agent's settling is recorded (subagent_settled, "how": the
 *     process events, the image, or the layout);
 *   - a failed sub-agent's group is frozen (cgroup.freeze), every process in
 *     it moved back to the launcher's group, and the group removed; a
 *     process that cannot be moved is still attributed to the launcher.
 * A process in no group of the run is refused every call
 * (subagent_unattributed): it can only be there if something moved it.
 */

#include <sys/vfs.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
static void noexec_unescape(char *s);        /* warden_noexec.inc.c */
static unsigned long noexec_keep_flags(const char *mp);
static bool g_own_mntns;                     /* v1.32: the Warden has a mount namespace of its own */
static bool sub_aslr(void);                  /* v1.32, below */

/* Linux 6.13: a pidfd tells its process's cgroup id (the group directory's
 * inode number), without /proc's text */
#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif
struct sub_pidfd_info {
    uint64_t mask, cgroupid;
    uint32_t pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
    int32_t  exit_code;
    uint32_t coredump_mask, pad;
};
#define SUB_PIDFD_GET_INFO _IOWR(0xFF, 11, struct sub_pidfd_info)
#define SUB_PIDFD_INFO_CGROUPID (1UL << 2)

#define SUB_MAX       1024           /* sub-agent launches a run may make */
#define SUB_MAX_DEPTH 8              /* sub-agents nested in sub-agents */
#define SUB_REL_MAX   512            /* a group's path under the run's: 8 x "/NAME-n" */

enum { SUB_AGENT = 0, SUB_PENDING, SUB_LAUNCHED, SUB_FAILED };
#define SUB_LAYOUT_N 10              /* /proc/<pid>/stat's layout fields, below */

struct subject {
    char     name[33];               /* "" : the agent */
    uint32_t n;                      /* which launch of name */
    int      parent;                 /* the launcher's subject (-1: the agent) */
    int      depth;
    int      state;
    char     rel[SUB_REL_MAX];       /* under the run's group: "" or "/a-1/b-2" */
    uint64_t seq;                    /* its launch record */
    dev_t    edev;                   /* the image the launch was decided for */
    ino_t    eino;
    char     obo[SUB_MAX_DEPTH * 48 + 16];   /* its chain after "agent": ,"subagent:a#1",... */
    uint64_t cgid;                   /* its group's id (the directory's inode number); 0 once removed */
    pid_t    tgid;                   /* the launching process */
    bool     exec_seen;              /* the kernel reported its launch (proc connector) */
    /* v1.32: a launch of the image its launcher runs, without the connector:
     * the launcher's memory layout when it launched */
    bool     by_layout;
    unsigned long long layout[SUB_LAYOUT_N];
    /* v1.31: the policy subject its calls are decided as (smt_decide.h): the
     * confined subject its launch rule declares, else its launcher's (0: the
     * agent's rules); and whether an `mcp server` line launched it */
    int      psubj;
    bool     mcp;
    bool     confined;               /* v1.31: its launch rule declares it a confined subject */
};

static struct subject *g_sub;
static size_t g_nsub;
static char g_cg_dir[PATH_MAX];      /* the run's group, on the filesystem */
static struct { char name[33]; uint32_t n; } g_sub_count[VDP_MAX_RULES];
static bool g_sub_froze;             /* a group was frozen while attributing this call */
static bool g_sub_pidfd;             /* the kernel tells a thread's cgroup id through a pidfd */
static long long mono_ms_sub(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int  g_cn = -1;               /* v1.28.1 review: the proc connector, for launches that succeed */
static bool g_cn_lost;               /* it overflowed: an event may be missing */

/* Read every queued process event; mark the pending sub-agents whose
 * launcher launched. */
static void sub_cn_drain(void) {
    if (g_cn < 0) return;
    char buf[16384] __attribute__((aligned(NLMSG_ALIGNTO)));
    for (;;) {
        ssize_t n = recv(g_cn, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ENOBUFS) { g_cn_lost = true; continue; }
        if (n <= 0) return;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event))) continue;
            struct cn_msg *cm = NLMSG_DATA(h);
            struct proc_event *ev = (struct proc_event *)cm->data;
            if (cm->id.idx != CN_IDX_PROC || ev->what != PROC_EVENT_EXEC) continue;
            pid_t tg = ev->event_data.exec.process_tgid;
            for (size_t i = 1; i < g_nsub; i++)
                if (g_sub[i].state == SUB_PENDING && g_sub[i].tgid == tg) g_sub[i].exec_seen = true;
        }
    }
}

/* Open the connector and check it reports a launch of our own: 0, or -1 */
static int sub_cn_open(void) {
    if (getenv("VAREK_WARDEN_TEST_NO_PROC_CONNECTOR")) return -1;
    int s = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (s < 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = CN_IDX_PROC };
    int big = 8 << 20;
    (void)setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big);
    char m[NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op))] __attribute__((aligned(NLMSG_ALIGNTO)));
    memset(m, 0, sizeof m);
    struct nlmsghdr *h = (struct nlmsghdr *)m;
    struct cn_msg *cm = NLMSG_DATA(h);
    enum proc_cn_mcast_op op = PROC_CN_MCAST_LISTEN;
    h->nlmsg_len = sizeof m;
    h->nlmsg_type = NLMSG_DONE;
    cm->id.idx = CN_IDX_PROC;
    cm->id.val = CN_VAL_PROC;
    cm->len = sizeof op;
    memcpy(cm->data, &op, sizeof op);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0 || send(s, m, sizeof m, 0) != (ssize_t)sizeof m) {
        close(s);
        return -1;
    }
    /* a launch of our own, reported with its pid as this process sees it */
    const char *t = access("/usr/bin/true", X_OK) == 0 ? "/usr/bin/true" : "/bin/true";
    pid_t c = fork();
    if (c == 0) { execl(t, "true", (char *)NULL); _exit(127); }
    if (c < 0) { close(s); return -1; }
    int st = 0;
    while (waitpid(c, &st, 0) < 0 && errno == EINTR) { }
    bool seen = false;
    long long end = mono_ms_sub() + 2000;
    while (!seen && mono_ms_sub() < end) {
        struct pollfd pf = { .fd = s, .events = POLLIN };
        if (poll(&pf, 1, 100) != 1) continue;
        char buf[8192] __attribute__((aligned(NLMSG_ALIGNTO)));
        ssize_t n = recv(s, buf, sizeof buf, MSG_DONTWAIT);
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; n > 0 && NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event))) continue;
            struct proc_event *ev = (struct proc_event *)((struct cn_msg *)NLMSG_DATA(h))->data;
            if (ev->what == PROC_EVENT_EXEC && ev->event_data.exec.process_tgid == c) seen = true;
        }
    }
    if (!seen || !WIFEXITED(st) || WEXITSTATUS(st) != 0) { close(s); return -1; }
    g_cn = s;
    return 0;
}

/* tid's cgroup id through a pidfd, or 0 */
static uint64_t sub_cgid_of(pid_t tid) {
    int fd = (int)syscall(__NR_pidfd_open, tid, PIDFD_THREAD);
    if (fd < 0) return 0;
    struct sub_pidfd_info in;
    memset(&in, 0, sizeof in);
    in.mask = SUB_PIDFD_INFO_CGROUPID;
    int r = ioctl(fd, SUB_PIDFD_GET_INFO, &in);
    close(fd);
    return r == 0 && (in.mask & SUB_PIDFD_INFO_CGROUPID) ? in.cgroupid : 0;
}

static uint64_t sub_dir_id(const char *dir) {
    struct stat st;
    return stat(dir, &st) == 0 ? (uint64_t)st.st_ino : 0;
}
static size_t g_nsub_count;

/* The cgroup2 mount (its mount point and root), and this process's group in
 * it. 0, or -1 with why. */
static int sub_find_cgroup2(char *mnt, size_t mn, char *root, size_t rn, char *self, size_t sn,
                            char *why, size_t wn) {
    /* make test-v1281: act as if there were none */
    if (getenv("VAREK_WARDEN_TEST_NO_CGROUP2")) { snprintf(why, wn, "VAREK_WARDEN_TEST_NO_CGROUP2 is set"); return -1; }
    FILE *mi = fopen("/proc/self/mountinfo", "re");
    if (!mi) { snprintf(why, wn, "cannot read the mounts (%s)", strerror(errno)); return -1; }
    char *line = NULL;
    size_t lc = 0;
    bool found = false;
    while (!found && getline(&line, &lc, mi) > 0) {
        char *dash = strstr(line, " - ");
        if (!dash || strncmp(dash + 3, "cgroup2 ", 8)) continue;
        char *save = NULL, *f[5];
        int k = 0;
        for (char *t = strtok_r(line, " ", &save); t && k < 5; t = strtok_r(NULL, " ", &save)) f[k++] = t;
        if (k < 5) continue;
        noexec_unescape(f[3]);
        noexec_unescape(f[4]);
        snprintf(root, rn, "%s", f[3]);
        snprintf(mnt, mn, "%s", f[4]);
        found = true;
    }
    free(line);
    fclose(mi);
    if (!found) { snprintf(why, wn, "no cgroup2 filesystem is mounted"); return -1; }
    FILE *cg = fopen("/proc/self/cgroup", "re");
    if (!cg) { snprintf(why, wn, "cannot read /proc/self/cgroup (%s)", strerror(errno)); return -1; }
    char buf[PATH_MAX + 8];
    found = false;
    while (!found && fgets(buf, sizeof buf, cg))
        if (!strncmp(buf, "0::", 3)) {
            buf[strcspn(buf, "\n")] = '\0';
            if (strlen(buf + 3) >= sn) { fclose(cg); snprintf(why, wn, "this process's group's path is too long"); return -1; }
            memcpy(self, buf + 3, strlen(buf + 3) + 1);
            found = true;
        }
    fclose(cg);
    if (!found) { snprintf(why, wn, "this process is in no cgroup v2 group"); return -1; }
    return 0;
}

/* Is the policy's writing reach into the control groups? The paths a write
 * would move a process with, for the run's group and each sub-agent's first. */
static int sub_refuse_writable(const struct policy *p, const char *mnt) {
    static const char *const kFiles[] = { "cgroup.procs", "cgroup.threads", "cgroup.freeze", "cgroup.kill",
                                          "cgroup.subtree_control" };
    char path[PATH_MAX + 128];
    for (size_t f = 0; f < sizeof kFiles / sizeof kFiles[0]; f++) {
        const char *bases[3] = { mnt, g_cg_dir, NULL };
        for (int b = 0; bases[b]; b++) {
            snprintf(path, sizeof path, "%s/%s", bases[b], kFiles[f]);
            if (vdpc_path_writable(&p->c, path, strlen(path))) goto refuse;
        }
        for (size_t i = 0; i < p->v.n; i++) {
            if (!p->v.rules[i].subagent[0]) continue;
            snprintf(path, sizeof path, "%s/%s-1/%s", g_cg_dir, p->v.rules[i].subagent, kFiles[f]);
            if (vdpc_path_writable(&p->c, path, strlen(path))) goto refuse;
        }
    }
    return 0;
refuse:
    fprintf(stderr, "[warden] the policy lets the agent write %s: with sub-agents named, the control groups "
            "must be out of the agent's reach (deny the cgroup filesystem, %s); refusing to start\n", path, mnt);
    return -1;
}

/* v1.32: in a container. Docker and Podman mount the cgroup filesystem
 * read-only; with a cgroup namespace of the container's own
 * (--cgroupns=private) this process is at its root ("/"), and what the
 * filesystem shows is the container's own groups only. Then the Warden
 * remounts it read-write in a mount namespace of its own (made here unless
 * the noexec mounts made it), as a host's is: the container's mount stays
 * read-only, and the agent, which runs as its own user with no
 * capabilities, cannot write the groups, which root owns, any more than on
 * a host. Anywhere else nothing is done. 0; 1 in a check, where the run
 * would remount it; or -1 printed. */
/* v1.32 (D10): in a user namespace (rootless Podman)? The initial user
 * namespace's inode is fixed (PROC_USER_INIT_INO); a child namespace with an
 * identity map is still a child (v1.32 review). Unreadable: taken as one. */
static bool sub_in_userns(void) {
    struct stat st;
    if (stat("/proc/self/ns/user", &st) < 0) return true;
    return st.st_ino != 0xEFFFFFFDU;
}

/* The container's cgroup filesystem remounted read-write in this mount
 * namespace: a bind remount, which changes this mount's flags only, never
 * the filesystem's, which every cgroup2 mount on the machine shares (v1.32
 * review); noexec and the mount's other flags kept. 0, or -1 with errno. */
static int sub_cg_remount(const char *mnt) {
    unsigned long f = (noexec_keep_flags(mnt) & ~(unsigned long)MS_RDONLY) | MS_NOEXEC;
    if (mount(NULL, mnt, NULL, MS_BIND | MS_REMOUNT | f, NULL) < 0) return -1;
    struct statvfs sv;
    if (statvfs(mnt, &sv) < 0) return -1;
    if (sv.f_flag & ST_RDONLY) { errno = EROFS; return -1; }
    return 0;
}

static int sub_container_cgroup(const char *mnt, const char *self, bool check_only) {
    struct statvfs sv;
    if (statvfs(mnt, &sv) < 0 || !(sv.f_flag & ST_RDONLY)) return 0;
    /* D10, measured: in a user namespace the kernel refuses the remount;
     * rootless Podman's systemd mode mounts the container's own groups
     * read-write instead */
    if (sub_in_userns()) {
        fprintf(stderr, "[warden] the policy names a sub-agent: the cgroup filesystem at %s is read-only and this "
                "is a user namespace (rootless), where it cannot be remounted; run the container with "
                "--systemd=always (packaging/container/README.md); refusing to start\n", mnt);
        return -1;
    }
    if (strcmp(self, "/")) {
        fprintf(stderr, "[warden] the policy names a sub-agent: the cgroup filesystem at %s is read-only and "
                "this process's group (%s) is not its root; in a container, run it with --cgroupns=private "
                "(packaging/container/README.md); refusing to start\n", mnt, self);
        return -1;
    }
    const char *refused = "[warden] the policy names a sub-agent: cannot remount the container's cgroup "
                          "filesystem %s read-write (%s); under AppArmor or SELinux, run with VAREK's profile "
                          "(packaging/container/README.md); refusing to start\n";
    if (check_only) {
        /* tried, in a child's mount namespace, so the check says what a run
         * would find (v1.32 review) */
        pid_t c = fork();
        if (c < 0) { fprintf(stderr, refused, mnt, strerror(errno)); return -1; }
        if (c == 0) {
            if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0 ||
                sub_cg_remount(mnt) < 0) _exit(errno > 0 && errno < 126 ? errno : 1);
            _exit(0);
        }
        int st = 0;
        while (waitpid(c, &st, 0) < 0 && errno == EINTR) ;
        if (!WIFEXITED(st) || WEXITSTATUS(st)) {
            fprintf(stderr, refused, mnt, WIFEXITED(st) ? strerror(WEXITSTATUS(st)) : "the test was killed");
            return -1;
        }
        fprintf(stderr, "[warden] sub-agents: the cgroup filesystem at %s is read-only (a container's, its own "
                "groups only): a run remounts it read-write in the Warden's own mount namespace (tried)\n", mnt);
        return 1;
    }
    if (!g_own_mntns) {
        if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
            fprintf(stderr, "[warden] the policy names a sub-agent: cannot make a mount namespace for the cgroup "
                    "filesystem (%s); refusing to start\n", strerror(errno));
            return -1;
        }
        g_own_mntns = true;
    }
    if (sub_cg_remount(mnt) < 0) {
        fprintf(stderr, refused, mnt, strerror(errno));
        return -1;
    }
    fprintf(stderr, "[warden] sub-agents: the container's cgroup filesystem %s remounted read-write in the "
            "Warden's own mount namespace\n", mnt);
    return 0;
}

/* Startup: the run's group, made (not in a check). 0, or -1 printed. */
static int sub_setup(const struct policy *p, bool check_only, bool agent_root) {
    for (size_t i = 0; i < p->v.n; i++) if (p->v.rules[i].subagent[0]) g_sub_on = true;
    if (!g_sub_on) return 0;
    char mnt[PATH_MAX], root[PATH_MAX], self[PATH_MAX], why[PATH_MAX + 64];
    if (agent_root) {
        fprintf(stderr, "[warden] the policy names a sub-agent, and the agent runs as root (--run-as root): it "
                "could move itself between control groups; refusing to start\n");
        return -1;
    }
    if (sub_find_cgroup2(mnt, sizeof mnt, root, sizeof root, self, sizeof self, why, sizeof why) < 0) {
        fprintf(stderr, "[warden] the policy names a sub-agent, which needs cgroup v2: %s; refusing to start\n", why);
        return -1;
    }
    size_t rl = strcmp(root, "/") ? strlen(root) : 0;
    if (rl && (strncmp(self, root, rl) || (self[rl] && self[rl] != '/'))) {
        fprintf(stderr, "[warden] the policy names a sub-agent: this process's group (%s) is outside the cgroup2 "
                "mount at %s; refusing to start\n", self, mnt);
        return -1;
    }
    const char *under = self + rl;
    if (!strcmp(under, "/")) under = "";
    int a = snprintf(g_cg_dir, sizeof g_cg_dir, "%s%s/varek-%s", mnt, under, g_run_id);
    int b = snprintf(g_cg_self, sizeof g_cg_self, "%s/varek-%s", strcmp(self, "/") ? self : "", g_run_id);
    if (a < 0 || (size_t)a >= sizeof g_cg_dir - 64 || b < 0 || (size_t)b >= sizeof g_cg_self - SUB_REL_MAX) {
        fprintf(stderr, "[warden] the policy names a sub-agent: the control group's path is too long; refusing to start\n");
        return -1;
    }
    if (sub_refuse_writable(p, mnt) < 0) return -1;
    int ro = sub_container_cgroup(mnt, self, check_only);
    if (ro < 0) return -1;
    g_sub = calloc(SUB_MAX + 1, sizeof *g_sub);
    if (!g_sub) { fprintf(stderr, "[warden] out of memory\n"); return -1; }
    g_sub[0] = (struct subject){ .parent = -1, .state = SUB_AGENT };
    g_nsub = 1;
    if (check_only) {
        char parent[PATH_MAX];
        snprintf(parent, sizeof parent, "%s%s", mnt, under);
        if (!ro && access(parent, W_OK) < 0) {
            fprintf(stderr, "[warden] the policy names a sub-agent: cannot make groups in %s (%s); refusing to "
                    "start\n", parent, strerror(errno));
            return -1;
        }
        fprintf(stderr, "[warden] sub-agents: a run's control groups go under %s\n", parent);
        return 0;
    }
    if (mkdir(g_cg_dir, 0755) < 0) {
        fprintf(stderr, "[warden] the policy names a sub-agent: cannot make the run's control group %s (%s); "
                "refusing to start\n", g_cg_dir, strerror(errno));
        return -1;
    }
    char fz[PATH_MAX + 32];
    snprintf(fz, sizeof fz, "%s/cgroup.freeze", g_cg_dir);
    if (access(fz, W_OK) < 0) {
        fprintf(stderr, "[warden] the policy names a sub-agent: the kernel's cgroup v2 has no cgroup.freeze (5.2 "
                "or later is needed); refusing to start\n");
        rmdir(g_cg_dir);
        return -1;
    }
    g_sub[0].cgid = sub_dir_id(g_cg_dir);
    bool cn = sub_cn_open() == 0;
    /* the cheaper way to read a caller's group, when this kernel has it */
    g_sub_pidfd = g_sub[0].cgid != 0 && sub_cgid_of((pid_t)syscall(SYS_gettid)) != 0 &&
                  !getenv("VAREK_WARDEN_TEST_NO_PIDFD_INFO");
    fprintf(stderr, "[warden] sub-agents: the run's control group %s (each call's group read %s; launches "
            "known %s)\n", g_cg_dir, g_sub_pidfd ? "through a pidfd" : "from /proc",
            cn ? "from the kernel's process events" : sub_aslr() ? "by the image a process runs and, for a "
            "sub-agent of the image its launcher runs, its memory layout (no process events here)" :
            "by the image a process runs (no process events here, and layouts are not randomized: a sub-agent "
            "of the image its launcher runs is refused)");
    return 0;
}

/* The agent, in its child before its launch (still root): into the run's group */
static int sub_enter_run(void) {
    if (!g_sub_on) return 0;
    char procs[PATH_MAX + 32];
    snprintf(procs, sizeof procs, "%s/cgroup.procs", g_cg_dir);
    int fd = open(procs, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return w == 1 ? 0 : -1;
}

/* Move a thread group into the group at dir (by pid, checked against its
 * pidfd, so the pid is still the process meant). 0, or -1. */
static int sub_move(pid_t tgid, int pidfd, const char *dir) {
    char procs[PATH_MAX + SUB_REL_MAX + 32], num[16];
    snprintf(procs, sizeof procs, "%s/cgroup.procs", dir);
    int fd = open(procs, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int nl = snprintf(num, sizeof num, "%d", (int)tgid);
    ssize_t w = write(fd, num, (size_t)nl);
    close(fd);
    if (w != nl) return -1;
    if (pidfd >= 0 && syscall(__NR_pidfd_send_signal, pidfd, 0, NULL, 0) < 0) return -1;   /* not it: gone */
    return 0;
}

static void sub_dir(int s, char *out, size_t n) { snprintf(out, n, "%s%s", g_cg_dir, g_sub[s].rel); }

/* A subject's attribution: a failed sub-agent's processes are its launcher's */
static int sub_effective(int s) {
    while (s > 0 && g_sub[s].state == SUB_FAILED) s = g_sub[s].parent;
    return s;
}

/* v1.32: a process's memory layout, from /proc/<pid>/stat: startcode,
 * endcode, startstack (fields 26-28), start_data, end_data, start_brk,
 * arg_start, arg_end, env_start, env_end (45-51). Each is set by a launch
 * (randomized, with ASLR) and changed otherwise only by prctl(PR_SET_MM),
 * which needs CAP_SYS_RESOURCE. 0, or -1 (unreadable, or shown as zeros:
 * the reader may not trace it). */
static int sub_layout(pid_t pid, unsigned long long out[SUB_LAYOUT_N]) {
    static const int field[SUB_LAYOUT_N] = { 26, 27, 28, 45, 46, 47, 48, 49, 50, 51 };
    char p[64], buf[2048];
    snprintf(p, sizeof p, "/proc/%d/stat", (int)pid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *c = strrchr(buf, ')');                 /* the name may hold spaces and parentheses */
    if (!c) return -1;
    int f = 2, k = 0;                            /* field 2 is the name; c is its end */
    unsigned long long any = 0;
    for (char *t = c + 1; *t && k < SUB_LAYOUT_N; ) {
        while (*t == ' ') t++;
        if (!*t) break;
        f++;
        char *e;
        unsigned long long v = strtoull(t, &e, 10);
        if (f == field[k]) { out[k++] = v; any |= v; }
        t = e;
        while (*t && *t != ' ') t++;
    }
    return k == SUB_LAYOUT_N && any ? 0 : -1;
}

/* subagent_settled: how a sub-agent's launch came out (once) */
static void sub_settled_record(int s, const char *result) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    FILE *f = rec_begin();
    fprintf(f, "{\"event\":\"subagent_settled\",\"run\":\"%s\",\"subagent\":\"%s#%u\",\"result\":\"%s\","
            "\"how\":\"%s\",\"timestamp_ns\":%lld}\n", g_run_id, g_sub[s].name, g_sub[s].n, result,
            g_cn >= 0 && !g_cn_lost ? "process_events" : g_sub[s].by_layout ? "layout" : "image",
            (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    rec_end(NULL);
}

/* A failed sub-agent: freeze its group, move each process to the launcher's,
 * remove the group */
static void sub_fail(int s) {
    if (s <= 0 || g_sub[s].state == SUB_FAILED) return;
    g_sub[s].state = SUB_FAILED;
    g_sub_froze = true;
    sub_settled_record(s, "failed");
    int to = sub_effective(s);
    char dir[PATH_MAX + SUB_REL_MAX], dst[PATH_MAX + SUB_REL_MAX], f[PATH_MAX + SUB_REL_MAX + 32];
    sub_dir(s, dir, sizeof dir);
    sub_dir(to, dst, sizeof dst);
    snprintf(f, sizeof f, "%s/cgroup.freeze", dir);
    int fz = open(f, O_WRONLY | O_CLOEXEC);
    if (fz >= 0) { (void)!write(fz, "1", 1); close(fz); }
    /* wait (briefly) until frozen: then nothing in it can start another */
    snprintf(f, sizeof f, "%s/cgroup.events", dir);
    for (int i = 0; i < 200; i++) {
        char ev[256] = "";
        int e = open(f, O_RDONLY | O_CLOEXEC);
        ssize_t r = e >= 0 ? read(e, ev, sizeof ev - 1) : -1;
        if (e >= 0) close(e);
        if (r > 0) { ev[r] = '\0'; if (strstr(ev, "frozen 1")) break; }
        struct timespec ts = { 0, 5000000 };
        nanosleep(&ts, NULL);
    }
    for (int round = 0; round < 8; round++) {
        snprintf(f, sizeof f, "%s/cgroup.procs", dir);
        FILE *pf = fopen(f, "re");
        if (!pf) break;
        int moved = 0, left = 0;
        long pid;
        while (fscanf(pf, "%ld", &pid) == 1) {
            left++;
            if (sub_move((pid_t)pid, -1, dst) == 0) moved++;
        }
        fclose(pf);
        if (!left || !moved) break;
    }
    snprintf(f, sizeof f, "%s/cgroup.freeze", dir);
    fz = open(f, O_WRONLY | O_CLOEXEC);
    if (fz >= 0) { (void)!write(fz, "0", 1); close(fz); }
    if (rmdir(dir) == 0) g_sub[s].cgid = 0;          /* review: a removed group's id never matches */
}

/* Settle a pending sub-agent. With the connector: launched if its launcher
 * launched (the event is queued before the process runs again), else failed.
 * Without: by the image tid runs (the launch's, or not); tid 0 (the
 * launcher gone unseen) leaves it pending. Returns its state. */
static int sub_settle(int s, pid_t tid) {
    if (g_sub[s].state != SUB_PENDING) return g_sub[s].state;
    sub_cn_drain();
    if (g_cn >= 0 && !g_cn_lost) {
        if (g_sub[s].exec_seen) { g_sub[s].state = SUB_LAUNCHED; sub_settled_record(s, "launched"); }
        else sub_fail(s);
        return g_sub[s].state;
    }
    if (!tid) return SUB_PENDING;
    char p[64];
    struct stat st;
    snprintf(p, sizeof p, "/proc/%d/exe", (int)tid);
    bool launched = stat(p, &st) == 0 && st.st_dev == g_sub[s].edev && st.st_ino == g_sub[s].eino;
    if (launched && g_sub[s].by_layout) {
        /* v1.32: the launcher's own image: launched only if its layout is
         * new (a process it forked after has the same layout as it) */
        unsigned long long now[SUB_LAYOUT_N];
        launched = sub_layout(tid, now) == 0 && memcmp(now, g_sub[s].layout, sizeof now) != 0;
    }
    if (launched) {
        g_sub[s].state = SUB_LAUNCHED;
        sub_settled_record(s, "launched");
    } else sub_fail(s);
    return g_sub[s].state;
}

/* The launch's outcome, from exec_pend_drop (warden_exec.inc.c): what the
 * launch's exec_result says, which for a sub-agent is how it settled (the
 * image comparison there cannot tell a failed launch of the image the
 * launcher runs from one that happened) */
static const char *sub_pend_end(int s, pid_t tid, const char *result) {
    if (s <= 0 || (size_t)s >= g_nsub) return result;
    if (!strcmp(result, "killed")) { if (g_sub[s].state == SUB_PENDING) sub_fail(s); return result; }
    int st = sub_settle(s, strcmp(result, "gone") ? tid : 0);
    return st == SUB_LAUNCHED ? "launched" : st == SUB_FAILED ? "failed" : result;
}

/* The calling thread's subject, -1 (in no group of the run) or -2 (its
 * group could not be read: the thread has gone) */
static int sub_attribute(pid_t tid) {
    if (!g_sub_on) return 0;
    char p[64], buf[PATH_MAX + 64];
    int s = -1;
    if (g_sub_pidfd) {
        uint64_t id = sub_cgid_of(tid);
        if (!id) return -2;                                  /* the thread has gone: unreadable */
        for (size_t i = 0; i < g_nsub; i++)
            if (g_sub[i].cgid == id) { s = (int)i; break; }     /* a failed one's: its launcher's, below */
        if (s < 0) return -1;
        goto found;
    }
    snprintf(p, sizeof p, "/proc/%d/cgroup", (int)tid);
    /* review: line by line (a hybrid host's v1 lines come first, and may be long) */
    FILE *cf = fopen(p, "re");
    if (!cf) return -2;
    char *l = NULL;
    bool got = false;
    while (fgets(buf, sizeof buf, cf))
        if (!strncmp(buf, "0::", 3)) { l = buf + 3; got = true; break; }
    fclose(cf);
    if (!got) return -2;
    l[strcspn(l, "\n")] = '\0';
    size_t bl = strlen(g_cg_self);
    if (strncmp(l, g_cg_self, bl) || (l[bl] && l[bl] != '/')) return -1;
    const char *rel = l + bl;
    for (size_t i = 0; i < g_nsub; i++) if (!strcmp(g_sub[i].rel, rel)) { s = (int)i; break; }
    if (s < 0) return -1;
found:
    sub_settle(s, tid);                  /* the first call from its group settles the launch */
    return sub_effective(s);
}

/* v1.32: the kernel randomizes a new program's layout (kernel.randomize_va_space
 * 2: the stack, the program, the heap). Without it a new program of the same
 * image could keep the launcher's layout. */
static bool sub_aslr(void) {
    if (getenv("VAREK_WARDEN_TEST_NO_ASLR")) return false;    /* make test-v1281 */
    int fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY | O_CLOEXEC);
    char c = 0;
    if (fd >= 0) { if (read(fd, &c, 1) != 1) c = 0; close(fd); }
    return c == '2';
}

/* A launch the policy allows by a rule with subagent=name, from a process of
 * subject from: the sub-agent made, its group made and the process moved.
 * The subject, or -1 with the rule that refuses it. */
static int sub_launch(pid_t tid, int from, const char *name, int csubj, bool mcp, dev_t edev, ino_t eino,
                      uint64_t seq, const char **rule) {
    *rule = "subagent_failed";
    if (from < 0 || (size_t)from >= g_nsub) return -1;
    if (g_nsub > SUB_MAX) { *rule = "subagent_limit"; return -1; }
    if (g_sub[from].depth >= SUB_MAX_DEPTH) { *rule = "subagent_depth"; return -1; }
    pid_t tgid = task_tgid(tid);
    if (tgid <= 0) return -1;
    /* single-threaded only (see above) */
    char sp[64], line[128];
    snprintf(sp, sizeof sp, "/proc/%d/status", (int)tgid);
    FILE *sf = fopen(sp, "re");
    int threads = -1;
    while (sf && fgets(line, sizeof line, sf)) if (sscanf(line, "Threads: %d", &threads) == 1) break;
    if (sf) fclose(sf);
    if (threads != 1) { *rule = "subagent_threaded"; return -1; }
    /* without process events a launch of the image the launcher runs is told
     * from a failed one by the layout (v1.32); if it cannot be, refused
     * (v1.28.1 review) */
    bool by_layout = false;
    unsigned long long layout[SUB_LAYOUT_N] = { 0 };
    if (g_cn < 0) {
        struct stat xs;
        snprintf(sp, sizeof sp, "/proc/%d/exe", (int)tgid);
        if (stat(sp, &xs) < 0) { *rule = "subagent_same_image"; return -1; }
        if (xs.st_dev == edev && xs.st_ino == eino) {
            if (!sub_aslr() || sub_layout(tgid, layout) < 0) { *rule = "subagent_same_image"; return -1; }
            by_layout = true;
        }
    }
    sub_cn_drain();                      /* events from before this launch are not its */
    size_t c = 0;
    while (c < g_nsub_count && strcmp(g_sub_count[c].name, name)) c++;
    if (c == g_nsub_count) {
        if (c == sizeof g_sub_count / sizeof g_sub_count[0]) return -1;
        snprintf(g_sub_count[c].name, sizeof g_sub_count[c].name, "%s", name);
        g_nsub_count++;
    }
    struct subject *s = &g_sub[g_nsub];
    memset(s, 0, sizeof *s);
    snprintf(s->name, sizeof s->name, "%s", name);
    s->n = g_sub_count[c].n + 1;
    s->parent = from;
    s->depth = g_sub[from].depth + 1;
    s->state = SUB_PENDING;
    s->seq = seq;
    s->edev = edev;
    s->eino = eino;
    s->tgid = tgid;
    s->by_layout = by_layout;
    memcpy(s->layout, layout, sizeof s->layout);
    s->psubj = csubj > 0 ? csubj : g_sub[from].psubj;      /* v1.31 */
    s->mcp = mcp;
    s->confined = csubj > 0;
    char rel[SUB_REL_MAX + 48], obo[sizeof s->obo + 64];
    int rl = snprintf(rel, sizeof rel, "%s/%s-%u", g_sub[from].rel, name, s->n);
    int ol = snprintf(obo, sizeof obo, "%s,\"subagent:%s#%u\"", g_sub[from].obo, name, s->n);
    if (rl < 0 || (size_t)rl >= sizeof s->rel || ol < 0 || (size_t)ol >= sizeof s->obo) return -1;
    memcpy(s->rel, rel, (size_t)rl + 1);
    memcpy(s->obo, obo, (size_t)ol + 1);
    char dir[PATH_MAX + SUB_REL_MAX];
    sub_dir((int)g_nsub, dir, sizeof dir);
    if (mkdir(dir, 0755) < 0) return -1;
    s->cgid = sub_dir_id(dir);
    int pidfd = (int)syscall(__NR_pidfd_open, tgid, 0);
    int ok = pidfd >= 0 ? sub_move(tgid, pidfd, dir) : -1;
    if (pidfd >= 0) close(pidfd);
    if (ok < 0) { rmdir(dir); return -1; }
    g_sub_count[c].n++;
    return (int)g_nsub++;
}

/* v1.31: the policy subject the calls of runtime subject s are decided as
 * (0, the agent's rules, when no sub-agent is named or s is not one) */
static int sub_policy_subject(int s) {
    return g_sub_on && g_sub && s > 0 && (size_t)s < g_nsub ? g_sub[s].psubj : 0;
}

/* "obo":[...], for a record of subject s */
static void sub_obo(FILE *f, int s) {
    if (s < 0) { fputs("\"obo\":[],", f); return; }      /* refused: in no group of the run */
    fprintf(f, "\"obo\":[%s\"agent\"%s],", g_identity.has_user ? "\"user\"," : "", g_sub_on ? g_sub[s].obo : "");
}

/* A sub-agent's launch record: which one, and its group */
static void sub_launch_fields(struct action *a, int s) {
    size_t el = strlen(a->extra);
    int w = snprintf(a->extra + el, sizeof a->extra - el, "\"subagent\":\"%s#%u\",%s%s\"cgroup\":\"",
                     g_sub[s].name, g_sub[s].n, g_sub[s].mcp ? "\"mcp_server\":true," : "",
                     g_sub[s].confined ? "\"confined\":true," : "");
    if (w < 0 || (size_t)w >= sizeof a->extra - el) return;
    el += (size_t)w;
    /* review: the Warden's own group's path may hold any byte: escaped for JSON */
    char path[PATH_MAX + SUB_REL_MAX];
    snprintf(path, sizeof path, "%s%s", g_cg_self, g_sub[s].rel);
    for (const char *c = path; *c && el + 8 < sizeof a->extra; c++) {
        unsigned char u = (unsigned char)*c;
        if (u == '"' || u == '\\') { a->extra[el++] = '\\'; a->extra[el++] = (char)u; }
        else if (u < 0x20 || u >= 0x7f) el += (size_t)snprintf(a->extra + el, sizeof a->extra - el, "\\u%04x", u);
        else a->extra[el++] = (char)u;
    }
    snprintf(a->extra + el, sizeof a->extra - el, "\",");
}

/* The Warden opens nothing for writing on a control group's filesystem for
 * the agent while sub-agents are named: true when fd is such a file and the
 * open writes */
static bool sub_cgroup_write(int fd, int flags) {
    if (!g_sub_on || ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_TRUNC))) return false;
    struct statfs sf;
    return fstatfs(fd, &sf) == 0 && (sf.f_type == CGROUP2_SUPER_MAGIC || sf.f_type == CGROUP_SUPER_MAGIC);
}

/* The run's end: its groups removed, the deepest first (each process has
 * ended: the agent's PID namespace is gone) */
static void sub_finish(void) {
    if (!g_sub_on || !g_sub) return;
    for (int round = 0; round < 50; round++) {
        bool left = false;
        for (size_t i = g_nsub; i-- > 1; ) {
            if (g_sub[i].state == SUB_FAILED) continue;            /* removed when it failed */
            char dir[PATH_MAX + SUB_REL_MAX];
            sub_dir((int)i, dir, sizeof dir);
            if (rmdir(dir) < 0 && errno != ENOENT) left = true;
        }
        if (rmdir(g_cg_dir) < 0 && errno != ENOENT) left = true;
        if (!left) return;
        struct timespec ts = { 0, 20000000 };
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "[warden] sub-agents: could not remove the run's control groups under %s\n", g_cg_dir);
}
