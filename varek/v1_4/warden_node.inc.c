// SPDX-License-Identifier: MIT
/* warden_node.inc.c — v1.34 step 2 (docs/security/v1.34-kubernetes.md): the
 * node agent.
 *
 *   warden POLICY --node-agent SOCKET --node-streams DIR
 *
 * listens on SOCKET, the listener the cluster's seccomp profiles name
 * (OCI's linux.seccomp.listenerPath). For each container a runtime starts
 * under the Warden's filter, the runtime connects there and sends the
 * container's state (OCI's container process state, JSON) with the filter's
 * descriptor. The node agent forks one supervisor for that container: the
 * Warden keeps one run's state in globals and is single-threaded, so a
 * process per container keeps each run its own. The supervisor writes its
 * stream to DIR/<container>.<run>.jsonl, enters the container's network
 * namespace at once (everything it dials is the pod's, D5) and, once the
 * node's files are open, its mount namespace (names are resolved as the
 * agent resolves them, as on a host where the agent shares the Warden's),
 * not its PID namespace (it would end with the container's init, before the
 * run's end is written). It then supervises the descriptor as a run's, the
 * container's command its first launch.
 *
 * Step 2 carries what needs nothing of the Warden's own start of the agent:
 * files, opened as the agent's user (read from its process), the container's
 * command, connects to addresses. Refused at the start, until the steps that
 * bring them: host-name rules and the proxy (step 4, the pod's network),
 * decided launches and noexec mounts (step 3, the launcher), credentials,
 * the on-behalf-of chain and sub-agents (step 5), plans and the dry run. */
#include "node_json.h"

static void node_fail(const char *why) __attribute__((noreturn));

/* struct node_run and g_nr are in warden.c, before the supervision loop */

static int node_read_file(int dirfd, const char *name, char **out, size_t *on, size_t max) {
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap);
    for (;;) {
        if (!b) { close(fd); return -1; }
        if (n == cap) {
            if (cap >= max) { free(b); close(fd); errno = EFBIG; return -1; }
            cap *= 2;
            char *nb = realloc(b, cap);
            if (!nb) { free(b); close(fd); return -1; }
            b = nb;
        }
        ssize_t r = read(fd, b + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; free(b); close(fd); return -1; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    *out = b;
    *on = n;
    return 0;
}

static void node_str(const char *doc, size_t n, const char *const *path, size_t depth, char *out, size_t on) {
    const char *v;
    size_t vn;
    if (nj_find(doc, n, path, depth, &v, &vn) < 0 || nj_string(v, vn, out, on) < 0) out[0] = '\0';
}

/* The pod's namespace, name and uid and the container's name: containerd's
 * annotations or CRI-O's. A pod's own annotations can be passed through to
 * the container's, so each family can be claimed: one present but unusable
 * (not a string, too long), or both present and different, is refused. 0, or
 * -1. */
static int node_annotation(const char *doc, size_t n, const char *cd, const char *co, char *out, size_t on) {
    const char *p1[] = { "state", "annotations", cd }, *p2[] = { "state", "annotations", co }, *v;
    size_t vn;
    char other[256];
    bool h1 = nj_find(doc, n, p1, 3, &v, &vn) == 0, h2;
    if (h1 && nj_string(v, vn, out, on) < 0) return -1;
    if (!h1) out[0] = '\0';
    if (!(h2 = nj_find(doc, n, p2, 3, &v, &vn) == 0)) return 0;
    if (nj_string(v, vn, other, sizeof other) < 0 || strlen(other) >= on) return -1;
    if (h1 && strcmp(out, other)) return -1;
    if (!h1) snprintf(out, on, "%s", other);
    return 0;
}

/* The container's init named by its state, checked well formed: 0 and its
 * pid, or -1 with why */
static int node_state_pid(const char *doc, size_t n, pid_t *out, char *why, size_t wn) {
    char w[160];
    if (nj_check(doc, n, w, sizeof w) < 0) { snprintf(why, wn, "the container's state is not well formed (%s)", w); return -1; }
    const char *pp[] = { "pid" }, *sp[] = { "state", "pid" }, *v;
    size_t vn;
    long long pid = 0, spid = 0;
    if (nj_find(doc, n, pp, 1, &v, &vn) < 0 || nj_int(v, vn, &pid) < 0 || pid <= 0 || pid > INT_MAX) {
        snprintf(why, wn, "the container's state names no pid");
        return -1;
    }
    if (nj_find(doc, n, sp, 2, &v, &vn) == 0 && (nj_int(v, vn, &spid) < 0 || spid != pid)) {
        snprintf(why, wn, "the container's state names two pids");
        return -1;
    }
    *out = (pid_t)pid;
    return 0;
}

/* The rest of the container's state (its pid and pidfd are the listener's,
 * node_admit). 0, or -1 with why. */
static int node_state(const char *doc, size_t n, char *why, size_t wn) {
    const char *ip[] = { "state", "id" }, *bp[] = { "state", "bundle" }, *mp[] = { "metadata" };
    node_str(doc, n, ip, 2, g_nr.id, sizeof g_nr.id);
    node_str(doc, n, bp, 2, g_nr.bundle, sizeof g_nr.bundle);
    node_str(doc, n, mp, 1, g_nr.meta, sizeof g_nr.meta);
    if (!g_nr.id[0] || strchr(g_nr.id, '/') || !strcmp(g_nr.id, ".") || !strcmp(g_nr.id, "..")) {
        snprintf(why, wn, "the container's state names no usable id");
        return -1;
    }
    if (g_nr.bundle[0] != '/') { snprintf(why, wn, "the container's state names no bundle"); return -1; }
    if (node_annotation(doc, n, "io.kubernetes.cri.sandbox-namespace", "io.kubernetes.pod.namespace", g_nr.pod_ns, sizeof g_nr.pod_ns) < 0 ||
        node_annotation(doc, n, "io.kubernetes.cri.sandbox-name", "io.kubernetes.pod.name", g_nr.pod_name, sizeof g_nr.pod_name) < 0 ||
        node_annotation(doc, n, "io.kubernetes.cri.sandbox-uid", "io.kubernetes.pod.uid", g_nr.pod_uid, sizeof g_nr.pod_uid) < 0 ||
        node_annotation(doc, n, "io.kubernetes.cri.container-name", "io.kubernetes.container.name", g_nr.ctr, sizeof g_nr.ctr) < 0) {
        snprintf(why, wn, "the container's state names its pod twice, differently, or unusably (containerd's and CRI-O's annotations)");
        return -1;
    }
    return 0;
}

/* A number from a process's status ("PPid:", "Seccomp:"), through the
 * node's /proc: the value, or -1 */
static long node_status_field(pid_t pid, const char *key) {
    FILE *f = proc_fopenf("%d/status", pid);
    if (!f) return -1;
    char line[256];
    long v = -1;
    size_t kl = strlen(key);
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, key, kl)) { char *e; v = strtol(line + kl, &e, 10); if (e == line + kl) v = -1; break; }
    fclose(f);
    return v;
}

/* The process is the one its pidfd holds, still: after a read of its
 * /proc/<pid> by number, which a reused number would answer for another */
static bool node_alive(int pidfd) {
    return syscall(__NR_pidfd_send_signal, pidfd, 0, NULL, 0) == 0;
}

/* Whether a process shares the node agent's namespace of that kind */
static bool node_same_ns(pid_t pid, const char *ns) {
    struct stat a, b;
    return proc_statf(&a, "%d/ns/%s", pid, ns) == 0 && proc_statf(&b, "self/ns/%s", ns) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

/* A connection the listener takes, checked before a supervisor is forked
 * for it (review: through step 2 any root peer could name any process, to
 * have it killed, or supervised in its place): the peer is root, in the
 * node agent's own user, PID and mount namespaces (the runtime, on the
 * node); the state is well formed and names a process whose parent is the
 * peer (runc's init is its runtime's child; crun's is not yet tested); the
 * descriptor is a seccomp listener, and that process is under a filter.
 * 0 with the process's pid and pidfd, or -1 with why. */
static int node_admit(int c, const char *doc, size_t n, int fd, pid_t *pid, int *pidfd, char *why, size_t wn) {
    struct ucred cr;
    socklen_t cl = sizeof cr;
    *pidfd = -1;
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0 || cr.pid <= 0) {
        snprintf(why, wn, "the peer's credentials cannot be read");
        return -1;
    }
    if (cr.uid != 0) { snprintf(why, wn, "the peer (pid %d) is not root (uid %u)", (int)cr.pid, (unsigned)cr.uid); return -1; }
    static const char *const kNs[] = { "user", "pid", "mnt" };
    for (size_t i = 0; i < sizeof kNs / sizeof kNs[0]; i++)
        if (!node_same_ns(cr.pid, kNs[i])) {
            snprintf(why, wn, "the peer (pid %d) is not in the node agent's %s namespace (not the node's runtime)",
                     (int)cr.pid, kNs[i]);
            return -1;
        }
    char ln[64];
    ssize_t k = proc_readlinkf(ln, sizeof ln - 1, "self/fd/%d", fd);
    if (k < 0 || (ln[k] = '\0', strcmp(ln, "anon_inode:seccomp notify"))) {
        snprintf(why, wn, "the descriptor sent is not a seccomp listener");
        return -1;
    }
    if (node_state_pid(doc, n, pid, why, wn) < 0) return -1;
    if ((*pidfd = (int)syscall(__NR_pidfd_open, *pid, 0)) < 0) {
        snprintf(why, wn, "the container's process %d is gone", (int)*pid);
        return -1;
    }
    long pp = node_status_field(*pid, "PPid:"), sc = node_status_field(*pid, "Seccomp:");
    if (!node_alive(*pidfd)) { snprintf(why, wn, "the container's process %d is gone", (int)*pid); goto fail; }
    if (pp != (long)cr.pid) {
        snprintf(why, wn, "the process the state names (%d) is not the peer's child (its parent is %ld, the peer %d)",
                 (int)*pid, pp, (int)cr.pid);
        goto fail;
    }
    if (sc != 2) { snprintf(why, wn, "the process the state names (%d) is not under a seccomp filter", (int)*pid); goto fail; }
    return 0;
fail:
    close(*pidfd);
    *pidfd = -1;
    return -1;
}

/* The container's command, from its bundle: its first launch. 0, or -1. */
static int node_config(char *why, size_t wn) {
    int bd = open(g_nr.bundle, O_PATH | O_DIRECTORY | O_CLOEXEC);
    char *doc = NULL;
    size_t n = 0;
    if (bd < 0 || node_read_file(bd, "config.json", &doc, &n, 16u << 20) < 0) {
        snprintf(why, wn, "cannot read the bundle's config.json (%s)", strerror(errno));
        if (bd >= 0) close(bd);
        return -1;
    }
    close(bd);
    char w[160];
    int rc = -1;
    if (nj_check(doc, n, w, sizeof w) < 0) snprintf(why, wn, "the bundle's config.json is not well formed (%s)", w);
    else {
        const char *ap[] = { "process", "args", "#0" };
        node_str(doc, n, ap, 3, g_nr.argv0, sizeof g_nr.argv0);
        if (g_nr.argv0[0] != '/')
            snprintf(why, wn, "the container's command must be named by an absolute path (it is \"%.200s\")", g_nr.argv0);
        else rc = 0;
    }
    free(doc);
    return rc;
}

/* The container's init as the descriptor arrives: no new privileges (the
 * runtime then loads the filter after it takes the container's user), and
 * that user, the agent's. 0, or -1. */
static int node_process(char *why, size_t wn) {
    FILE *f = proc_fopenf("%d/status", g_nr.pid);
    if (!f) { snprintf(why, wn, "the container's process %d is gone", g_nr.pid); return -1; }
    char line[256];
    int nnp = -1;
    long uid = -1, gid = -1;
    bool groups_ok = false;
    while (fgets(line, sizeof line, f)) {
        long r, e;
        if (sscanf(line, "Uid: %ld %ld", &r, &e) == 2) uid = e;
        else if (sscanf(line, "Gid: %ld %ld", &r, &e) == 2) gid = e;
        else if (!strncmp(line, "Groups:", 7)) {
            /* a line this long holds 256 groups only if they are short:
             * one cut off is refused, not read short */
            groups_ok = strchr(line, '\n') != NULL;
            g_nr.ngroups = 0;
            char *s = line + 7, *e2;
            for (long x; (x = strtol(s, &e2, 10)), e2 != s; s = e2) {
                if (g_nr.ngroups == (int)(sizeof g_nr.groups / sizeof g_nr.groups[0]) || x < 0) { groups_ok = false; break; }
                g_nr.groups[g_nr.ngroups++] = (gid_t)x;
            }
        } else (void)sscanf(line, "NoNewPrivs: %d", &nnp);
    }
    fclose(f);
    if (nnp != 1) {
        snprintf(why, wn, "the container runs without no_new_privs (allowPrivilegeEscalation: false gives it)");
        return -1;
    }
    if (uid < 0 || gid < 0 || !groups_ok) { snprintf(why, wn, "cannot read the container's user and groups"); return -1; }
    if (!node_alive(g_nr.pidfd)) { snprintf(why, wn, "the container's process %d is gone", g_nr.pid); return -1; }
    /* review: files are opened as the container's user (node_as_agent), and
     * a root container would be opened for with every capability */
    if (uid == 0) {
        snprintf(why, wn, "the container runs as root (uid 0): a root container is not carried in this step "
                 "(runAsNonRoot, runAsUser)");
        return -1;
    }
    if (gid == 0) { snprintf(why, wn, "the container's user is in group 0 (root)"); return -1; }
    g_nr.uid = (uid_t)uid;
    g_nr.gid = (gid_t)gid;
    return 0;
}

/* Files are opened as the agent, whatever the policy's version (review:
 * through step 2 only a policy of 1.29 or later had them opened so, and the
 * node agent refuses the decided launches any `require` past 1.26 turns on:
 * every open was the node's root's), with its own user and groups: the
 * container process's (its pod's fsGroup and supplementalGroups among
 * them), not a name's on the node. Group 0 refused, as for --run-as. */
static void node_as_agent(void) {
    g_as.on = true;
    g_as.uid = g_nr.uid;
    g_as.gid = g_nr.gid;
    int r = getgroups(AS_AGENT_MAX_GROUPS, g_as.root_groups);
    if (r < 0) node_fail("cannot read the node agent's own groups");
    g_as.nroot = r;
    g_as.groups[0] = g_nr.gid;
    g_as.ngroups = 1;
    for (int i = 0; i < g_nr.ngroups && g_as.ngroups < AS_AGENT_MAX_GROUPS; i++)
        if (g_nr.groups[i] != g_nr.gid) g_as.groups[g_as.ngroups++] = g_nr.groups[i];
    for (int i = 0; i < g_as.ngroups; i++)
        if (g_as.groups[i] == 0) node_fail("the container's user is in group 0 (root): opening files as the agent with group root is refused");
}

/* Enter one of the container's namespaces, by its init's pidfd (review: not
 * by its number, which could be another's once it is gone) */
static int node_enter(int type) {
    return setns(g_nr.pidfd, type);
}

/* The policy's needs this step does not carry: why, or NULL */
static const char *node_unsupported(const struct policy *p, bool dry, const char *plan, const char *flow,
                                    const char *obo, const char *svid, const char *trust) {
    if (dry) return "a dry run";
    if (plan || flow) return "a plan";
    if (obo || svid) return "the on-behalf-of chain";
    if (trust) return "a trust bundle";
    if (p->v.proxy) return "the egress proxy (with step 4, the pod's network)";
    if (g_policy_any_name) return "host-name rules (with step 4, the pod's network)";
    if (p->v.ncreds) return "credentials";
    if (p->v.launches) return "decided launches (with step 3, the launcher)";
    for (size_t i = 0; i < p->v.n; i++)
        if (p->v.rules[i].subagent[0]) return "sub-agents";
    return NULL;
}

/* run_start's container fields */
static void node_run_start(FILE *f) {
    if (!g_nr.on) return;
    fprintf(f, "\"node\":{\"container\":\"");
    json_escape(f, g_nr.id);
    fprintf(f, "\",\"pid\":%d,\"metadata\":\"", (int)g_nr.pid);
    json_escape(f, g_nr.meta);
    fputs("\",\"pod\":{\"namespace\":\"", f);
    json_escape(f, g_nr.pod_ns);
    fputs("\",\"name\":\"", f);
    json_escape(f, g_nr.pod_name);
    fputs("\",\"uid\":\"", f);
    json_escape(f, g_nr.pod_uid);
    fputs("\",\"container\":\"", f);
    json_escape(f, g_nr.ctr);
    fprintf(f, "\"},\"command\":\"");
    json_escape(f, g_nr.argv0);
    fprintf(f, "\",\"uid\":%u,\"gid\":%u,\"opens_as_agent\":%s},", (unsigned)g_nr.uid, (unsigned)g_nr.gid,
            g_as.on ? "true" : "false");
}

/* A container the supervisor cannot carry: said in its stream, then the
 * container ended (its init killed: the pod's whole PID namespace), since
 * its calls under the filter could not be decided */
__attribute__((noreturn))
static void node_fail(const char *why) {
    fprintf(stderr, "[warden] node agent: container %s refused: %s\n", g_nr.id[0] ? g_nr.id : "?", why);
    if (g_nr.notify_fd >= 0) close(g_nr.notify_fd);
    if (g_nr.pidfd >= 0) (void)syscall(__NR_pidfd_send_signal, g_nr.pidfd, SIGKILL, NULL, 0);
    _exit(1);
}

/* Every way out of a supervisor (a failed start, a policy that does not
 * load, the end of the run) ends its container: its calls under the filter
 * would otherwise go unanswered, or, with the descriptor closed, fail */
static void node_atexit(void) {
    if (g_nr.pidfd >= 0) (void)syscall(__NR_pidfd_send_signal, g_nr.pidfd, SIGKILL, NULL, 0);
}

/* The listener's live supervisors, each with its container's init (review:
 * a supervisor that ends any way, killed or crashed too, ends its container,
 * which may not go on unsupervised) */
#define NODE_MAX_SUPERVISORS 256
static struct { pid_t sup; int pidfd; } g_node_live[NODE_MAX_SUPERVISORS];
static int g_node_nlive = 0;
static volatile sig_atomic_t g_node_chld = 0;
static void node_on_chld(int sig) { (void)sig; g_node_chld = 1; }

static void node_reap(void) {
    g_node_chld = 0;
    for (;;) {
        int st;
        pid_t k = waitpid(-1, &st, WNOHANG);
        if (k <= 0) return;
        for (int i = 0; i < g_node_nlive; i++)
            if (g_node_live[i].sup == k) {
                (void)syscall(__NR_pidfd_send_signal, g_node_live[i].pidfd, SIGKILL, NULL, 0);
                close(g_node_live[i].pidfd);
                g_node_live[i] = g_node_live[--g_node_nlive];
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
                    fprintf(stderr, "[warden] node agent: supervisor %d ended (%s %d): its container ended\n",
                            (int)k, WIFEXITED(st) ? "exit" : "signal", WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
                break;
            }
    }
}

/* The state and the descriptor a runtime sends: the descriptor with the
 * first part, then the rest until the runtime closes the connection (a
 * large state can come in parts), at most 1 MiB, within 5 s. The length,
 * or -1 (and *nfd the descriptors received, to close). */
#define NODE_STATE_MAX (1 << 20)
static ssize_t node_receive(int c, char *buf, size_t cap, int *fds, int *nfd) {
    struct timeval tv = { 5, 0 };
    (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    struct iovec iov = { buf, cap };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    ssize_t r;
    while ((r = recvmsg(c, &m, MSG_CMSG_CLOEXEC)) < 0 && errno == EINTR) {}
    *nfd = 0;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); r >= 0 && h; h = CMSG_NXTHDR(&m, h))
        if (h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS) {
            int k = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            for (int i = 0; i < k; i++) {
                int fd;
                memcpy(&fd, CMSG_DATA(h) + sizeof(int) * (size_t)i, sizeof fd);
                if (*nfd < 8) fds[(*nfd)++] = fd; else close(fd);
            }
        }
    if (r <= 0 || (m.msg_flags & MSG_CTRUNC)) return -1;
    size_t n = (size_t)r;
    while (n < cap) {
        ssize_t q = read(c, buf + n, cap - n);
        if (q < 0 && errno == EINTR) continue;
        if (q < 0) return -1;                 /* the timeout too */
        if (q == 0) return (ssize_t)n;
        n += (size_t)q;
    }
    return -1;                                /* past the cap */
}

/* Listen for the runtime. Returns 0 in each supervisor (one per container,
 * set up to continue the Warden's start as for a run) and -1 if the listener
 * cannot be made; the node agent itself never returns otherwise. */
static int node_listen(const char *sock_path, const char *streams) {
    int sd = open(streams, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (sd < 0) { fprintf(stderr, "[warden] --node-streams %s: %s\n", streams, strerror(errno)); return -1; }
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(sock_path) >= sizeof a.sun_path) { fprintf(stderr, "[warden] --node-agent: the path is too long\n"); return -1; }
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock_path);
    /* review: the socket's directory is root's alone, so no one else can
     * replace the socket or reach it (a pod with that directory mounted) */
    char dir[PATH_MAX];
    snprintf(dir, sizeof dir, "%s", sock_path);
    char *sl = strrchr(dir, '/');
    if (!sl) snprintf(dir, sizeof dir, ".");
    else if (sl == dir) dir[1] = '\0';
    else *sl = '\0';
    struct stat ds;
    if (lstat(dir, &ds) < 0 || !S_ISDIR(ds.st_mode) || ds.st_uid != 0 || (ds.st_mode & 077)) {
        fprintf(stderr, "[warden] --node-agent %s: its directory %s must be root's, with no access for others (chmod 700)\n",
                sock_path, dir);
        return -1;
    }
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    (void)unlink(sock_path);
    mode_t old = umask(077);                  /* only root may connect: the runtime */
    int b = ls < 0 ? -1 : bind(ls, (struct sockaddr *)&a, sizeof a);
    umask(old);
    if (b < 0 || listen(ls, 64) < 0) {
        fprintf(stderr, "[warden] --node-agent %s: %s\n", sock_path, strerror(errno));
        return -1;
    }
    struct sigaction sc = { .sa_handler = node_on_chld };   /* no SA_RESTART: accept returns to reap */
    sigemptyset(&sc.sa_mask);
    sigaction(SIGCHLD, &sc, NULL);
    fprintf(stderr, "[warden] node agent: listening on %s; streams in %s\n", sock_path, streams);
    static char buf[NODE_STATE_MAX + 1];
    for (;;) {
        if (g_node_chld) node_reap();
        int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR || errno == ECONNABORTED) continue; perror("[warden] accept"); continue; }
        int fds[8], nfd = 0;
        ssize_t r = node_receive(c, buf, NODE_STATE_MAX, fds, &nfd);
        if (r < 0 || nfd != 1) {
            fprintf(stderr, "[warden] node agent: a connection without one descriptor and a whole state; ignored\n");
            for (int i = 0; i < nfd; i++) close(fds[i]);
            close(c);
            continue;
        }
        char why[512];
        pid_t pid;
        int pidfd;
        int adm = node_admit(c, buf, (size_t)r, fds[0], &pid, &pidfd, why, sizeof why);
        close(c);
        if (adm < 0) {
            /* not the runtime's, or not a container's: nothing is killed (the
             * process it names may be anyone's), the descriptor closed */
            fprintf(stderr, "[warden] node agent: a connection refused: %s\n", why);
            close(fds[0]);
            continue;
        }
        if (g_node_chld) node_reap();
        if (g_node_nlive == NODE_MAX_SUPERVISORS) {
            fprintf(stderr, "[warden] node agent: %d containers supervised already: container %d refused, and ended\n",
                    NODE_MAX_SUPERVISORS, (int)pid);
            (void)syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
            close(pidfd);
            close(fds[0]);
            continue;
        }
        pid_t k = fork();
        if (k < 0) {
            perror("[warden] fork");
            (void)syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
            close(pidfd);
            close(fds[0]);
            continue;
        }
        if (k > 0) {
            g_node_live[g_node_nlive].sup = k;
            g_node_live[g_node_nlive++].pidfd = pidfd;
            close(fds[0]);
            continue;
        }
        /* the container's supervisor */
        close(ls);
        for (int i = 0; i < g_node_nlive; i++) close(g_node_live[i].pidfd);
        g_node_nlive = 0;
        sigaction(SIGCHLD, &(struct sigaction){ .sa_handler = SIG_DFL }, NULL);
        g_nr.on = true;
        g_nr.notify_fd = fds[0];
        g_nr.pid = pid;
        g_nr.pidfd = pidfd;
        /* not the first the kernel ends when the node is short of memory */
        int oom = proc_openf(O_WRONLY, 0, "self/oom_score_adj");
        if (oom >= 0) { (void)!write(oom, "-1000", 5); close(oom); }
        int ok = node_state(buf, (size_t)r, why, sizeof why);
        char sname[256];
        snprintf(sname, sizeof sname, "%s.%d.jsonl", ok == 0 ? g_nr.id : "unknown", (int)getpid());
        int so = openat(sd, sname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (so < 0 || dup2(so, STDERR_FILENO) < 0) node_fail("cannot open its stream");
        close(so);
        close(sd);
        if (ok == 0) ok = node_config(why, sizeof why);
        if (ok == 0) ok = node_process(why, sizeof why);
        if (ok == 0 && node_enter(CLONE_NEWNET) < 0) {
            snprintf(why, sizeof why, "cannot enter the container's network namespace (%s)", strerror(errno));
            ok = -1;
        }
        if (ok < 0) node_fail(why);
        atexit(node_atexit);
        return 0;
    }
}

/* The container's supervision, where a run forks its agent (main): into the
 * container's mount namespace, now that the node's files are open, then the
 * descriptor supervised as a run's. Returns the Warden's exit status. */
static int node_supervise(const struct policy *p, const char *boot_path) {
    if (node_enter(CLONE_NEWNS) < 0) {
        char why[160];
        snprintf(why, sizeof why, "cannot enter the container's mount namespace (%s)", strerror(errno));
        node_fail(why);
    }
    /* the container's /proc is its PID namespace's: its init's */
    if ((g_view_depth = pidns_depth(g_nr.pid)) < 0 || !node_alive(g_nr.pidfd))
        node_fail("cannot read the container's PID namespace (NSpid)");
    g_view_container = true;
    /* the pod's network namespace is the Warden's own now: both held, the
     * same, so a socket made "in the agent's" and the stub resolver's are the
     * pod's (warden_net.inc.c, warden_stub.inc.c) */
    g_host_netns = proc_openf(O_RDONLY, 0, "self/ns/net");
    g_agent_netns = proc_openf(O_RDONLY, 0, "self/ns/net");
    if (g_host_netns < 0 || g_agent_netns < 0) node_fail("cannot hold the pod's network namespace");
    g_netns_separate = true;
    sockref_warm();
    stub_setup();
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max < 65536 ? rl.rlim_max : 65536;
        (void)setrlimit(RLIMIT_NOFILE, &rl);
    }
    /* the container's init watched by the pidfd held since its state arrived
     * (review: not one opened again by its number) */
    int target_pidfd = fcntl(g_nr.pidfd, F_DUPFD_CLOEXEC, 0);
    if (target_pidfd < 0) node_fail("cannot watch the container's process");
    fprintf(stderr, "[warden] supervising container %s (pod %s/%s) pid=%d policy=%s (%zu rules) uid=%u\n",
            g_nr.id, g_nr.pod_ns, g_nr.pod_name, (int)g_nr.pid, p->name, p->v.n, (unsigned)g_nr.uid);
    bool ended = supervise(g_nr.notify_fd, target_pidfd, -1, p, boot_path, g_nr.pid);
    if (!ended || g_revoked)
        /* the Warden stopped supervising, or the run was revoked: the
         * container may not go on unsupervised */
        (void)syscall(__NR_pidfd_send_signal, target_pidfd, SIGKILL, NULL, 0);
    /* the container's exit status is the runtime's to report: -1 here */
    emit_run_end(-1);
    anchor_drain();
    if (g_sk) sodium_free(g_sk);
    close(target_pidfd);
    close(g_nr.notify_fd);
    return ended ? 0 : 1;
}
