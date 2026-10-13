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
 *     process in its group settles it: a process that runs the image the
 *     launch was decided for shows it happened (launched); one that runs
 *     anything else shows it failed (it is the launching process back from
 *     a failed launch, or one it started after);
 *   - a failed sub-agent's group is frozen (cgroup.freeze), every process in
 *     it moved back to the launcher's group, and the group removed; a
 *     process that cannot be moved is still attributed to the launcher.
 * A process in no group of the run is refused every call
 * (subagent_unattributed): it can only be there if something moved it.
 */

#include <sys/vfs.h>
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

#define SUB_MAX       1024           /* sub-agent launches a run may make */
#define SUB_MAX_DEPTH 8              /* sub-agents nested in sub-agents */
#define SUB_REL_MAX   512            /* a group's path under the run's: 8 x "/NAME-n" */

enum { SUB_AGENT = 0, SUB_PENDING, SUB_LAUNCHED, SUB_FAILED };

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
};

static struct subject *g_sub;
static size_t g_nsub;
static char g_cg_dir[PATH_MAX];      /* the run's group, on the filesystem */
static struct { char name[33]; uint32_t n; } g_sub_count[VDP_MAX_RULES];
static bool g_sub_froze;             /* a group was frozen while attributing this call */
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
    g_sub = calloc(SUB_MAX + 1, sizeof *g_sub);
    if (!g_sub) { fprintf(stderr, "[warden] out of memory\n"); return -1; }
    g_sub[0] = (struct subject){ .parent = -1, .state = SUB_AGENT };
    g_nsub = 1;
    if (check_only) {
        char parent[PATH_MAX];
        snprintf(parent, sizeof parent, "%s%s", mnt, under);
        if (access(parent, W_OK) < 0) {
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
    fprintf(stderr, "[warden] sub-agents: the run's control group %s\n", g_cg_dir);
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

/* A failed sub-agent: freeze its group, move each process to the launcher's,
 * remove the group */
static void sub_fail(int s) {
    if (s <= 0 || g_sub[s].state == SUB_FAILED) return;
    g_sub[s].state = SUB_FAILED;
    g_sub_froze = true;
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
    (void)rmdir(dir);
}

/* The launch's outcome, from exec_pend_drop (warden_exec.inc.c) */
static void sub_pend_end(int s, const char *result) {
    if (s <= 0 || (size_t)s >= g_nsub || g_sub[s].state != SUB_PENDING) return;
    if (!strcmp(result, "launched")) g_sub[s].state = SUB_LAUNCHED;
    else if (!strcmp(result, "failed") || !strcmp(result, "killed")) sub_fail(s);
    /* "gone": the launching process ended unseen; the first call from its
     * group settles it */
}

/* The calling thread's subject, or -1 (in no group of the run) */
static int sub_attribute(pid_t tid) {
    if (!g_sub_on) return 0;
    char p[64], buf[PATH_MAX + 64];
    snprintf(p, sizeof p, "/proc/%d/cgroup", (int)tid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *l = buf;
    while (l && strncmp(l, "0::", 3)) { l = strchr(l, '\n'); if (l) l++; }
    if (!l) return -1;
    l += 3;
    l[strcspn(l, "\n")] = '\0';
    size_t bl = strlen(g_cg_self);
    if (strncmp(l, g_cg_self, bl) || (l[bl] && l[bl] != '/')) return -1;
    const char *rel = l + bl;
    int s = -1;
    for (size_t i = 0; i < g_nsub; i++) if (!strcmp(g_sub[i].rel, rel)) { s = (int)i; break; }
    if (s < 0) return -1;
    if (g_sub[s].state == SUB_PENDING) {
        /* the first call from its group settles the launch (see above) */
        struct stat st;
        snprintf(p, sizeof p, "/proc/%d/exe", (int)tid);
        if (stat(p, &st) == 0 && st.st_dev == g_sub[s].edev && st.st_ino == g_sub[s].eino) g_sub[s].state = SUB_LAUNCHED;
        else sub_fail(s);
    }
    return sub_effective(s);
}

/* A launch the policy allows by a rule with subagent=name, from a process of
 * subject from: the sub-agent made, its group made and the process moved.
 * The subject, or -1 with the rule that refuses it. */
static int sub_launch(pid_t tid, int from, const char *name, dev_t edev, ino_t eino, uint64_t seq,
                      const char **rule) {
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
    char rel[SUB_REL_MAX + 48], obo[sizeof s->obo + 64];
    int rl = snprintf(rel, sizeof rel, "%s/%s-%u", g_sub[from].rel, name, s->n);
    int ol = snprintf(obo, sizeof obo, "%s,\"subagent:%s#%u\"", g_sub[from].obo, name, s->n);
    if (rl < 0 || (size_t)rl >= sizeof s->rel || ol < 0 || (size_t)ol >= sizeof s->obo) return -1;
    memcpy(s->rel, rel, (size_t)rl + 1);
    memcpy(s->obo, obo, (size_t)ol + 1);
    char dir[PATH_MAX + SUB_REL_MAX];
    sub_dir((int)g_nsub, dir, sizeof dir);
    if (mkdir(dir, 0755) < 0) return -1;
    int pidfd = (int)syscall(__NR_pidfd_open, tgid, 0);
    int ok = pidfd >= 0 ? sub_move(tgid, pidfd, dir) : -1;
    if (pidfd >= 0) close(pidfd);
    if (ok < 0) { rmdir(dir); return -1; }
    g_sub_count[c].n++;
    return (int)g_nsub++;
}

/* "obo":[...], for a record of subject s */
static void sub_obo(FILE *f, int s) {
    if (s < 0) { fputs("\"obo\":[],", f); return; }      /* refused: in no group of the run */
    fprintf(f, "\"obo\":[%s\"agent\"%s],", g_identity.has_user ? "\"user\"," : "", g_sub_on ? g_sub[s].obo : "");
}

/* A sub-agent's launch record: which one, and its group */
static void sub_launch_fields(struct action *a, int s) {
    size_t el = strlen(a->extra);
    snprintf(a->extra + el, sizeof a->extra - el, "\"subagent\":\"%s#%u\",\"cgroup\":\"%s%s\",",
             g_sub[s].name, g_sub[s].n, g_cg_self, g_sub[s].rel);
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
