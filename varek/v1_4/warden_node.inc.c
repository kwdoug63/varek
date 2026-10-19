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
 * annotations, else CRI-O's */
static void node_annotation(const char *doc, size_t n, const char *cd, const char *co, char *out, size_t on) {
    const char *p1[] = { "state", "annotations", cd }, *p2[] = { "state", "annotations", co };
    node_str(doc, n, p1, 3, out, on);
    if (!out[0]) node_str(doc, n, p2, 3, out, on);
}

/* The container's state, as the runtime sent it. 0, or -1 with why. */
static int node_state(const char *doc, size_t n, char *why, size_t wn) {
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
    g_nr.pid = (pid_t)pid;
    /* the process, not its number, from here: a pid can be reused once the
     * container's init is gone, and the Warden ends the container by it */
    g_nr.pidfd = (int)syscall(__NR_pidfd_open, g_nr.pid, 0);
    if (g_nr.pidfd < 0) { snprintf(why, wn, "the container's process %d is gone", (int)g_nr.pid); return -1; }
    const char *ip[] = { "state", "id" }, *bp[] = { "state", "bundle" }, *mp[] = { "metadata" };
    node_str(doc, n, ip, 2, g_nr.id, sizeof g_nr.id);
    node_str(doc, n, bp, 2, g_nr.bundle, sizeof g_nr.bundle);
    node_str(doc, n, mp, 1, g_nr.meta, sizeof g_nr.meta);
    if (!g_nr.id[0] || strchr(g_nr.id, '/') || !strcmp(g_nr.id, ".") || !strcmp(g_nr.id, "..")) {
        snprintf(why, wn, "the container's state names no usable id");
        return -1;
    }
    if (g_nr.bundle[0] != '/') { snprintf(why, wn, "the container's state names no bundle"); return -1; }
    node_annotation(doc, n, "io.kubernetes.cri.sandbox-namespace", "io.kubernetes.pod.namespace", g_nr.pod_ns, sizeof g_nr.pod_ns);
    node_annotation(doc, n, "io.kubernetes.cri.sandbox-name", "io.kubernetes.pod.name", g_nr.pod_name, sizeof g_nr.pod_name);
    node_annotation(doc, n, "io.kubernetes.cri.sandbox-uid", "io.kubernetes.pod.uid", g_nr.pod_uid, sizeof g_nr.pod_uid);
    node_annotation(doc, n, "io.kubernetes.cri.container-name", "io.kubernetes.container.name", g_nr.ctr, sizeof g_nr.ctr);
    return 0;
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
    g_nr.uid = (uid_t)uid;
    g_nr.gid = (gid_t)gid;
    return 0;
}

/* Files opened as the agent are opened with its own groups: the container
 * process's (its pod's fsGroup and supplementalGroups among them), not a
 * name's on the node. Group 0 refused, as for --run-as. */
static void node_as_agent_groups(void) {
    if (!g_as.on) return;
    g_as.groups[0] = g_nr.gid;
    g_as.ngroups = 1;
    for (int i = 0; i < g_nr.ngroups && g_as.ngroups < AS_AGENT_MAX_GROUPS; i++)
        if (g_nr.groups[i] != g_nr.gid) g_as.groups[g_as.ngroups++] = g_nr.groups[i];
    for (int i = 0; i < g_as.ngroups; i++)
        if (g_as.groups[i] == 0) node_fail("the container's user is in group 0 (root): opening files as the agent with group root is refused");
}

/* Enter one of the container's namespaces, through the node's /proc */
static int node_enter(const char *ns, int type) {
    int fd = proc_openf(O_RDONLY, 0, "%d/ns/%s", g_nr.pid, ns);
    if (fd < 0) return -1;
    int r = setns(fd, type);
    int e = errno;
    close(fd);
    errno = e;
    return r;
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
    fprintf(f, "\",\"uid\":%u,\"gid\":%u},", (unsigned)g_nr.uid, (unsigned)g_nr.gid);
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

/* Listen for the runtime. Returns 0 in each supervisor (one per container,
 * set up to continue the Warden's start as for a run) and -1 if the listener
 * cannot be made; the node agent itself never returns otherwise. */
static int node_listen(const char *sock_path, const char *streams) {
    int sd = open(streams, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (sd < 0) { fprintf(stderr, "[warden] --node-streams %s: %s\n", streams, strerror(errno)); return -1; }
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(sock_path) >= sizeof a.sun_path) { fprintf(stderr, "[warden] --node-agent: the path is too long\n"); return -1; }
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock_path);
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    (void)unlink(sock_path);
    mode_t old = umask(077);                  /* only root may connect: the runtime */
    int b = ls < 0 ? -1 : bind(ls, (struct sockaddr *)&a, sizeof a);
    umask(old);
    if (b < 0 || listen(ls, 64) < 0) {
        fprintf(stderr, "[warden] --node-agent %s: %s\n", sock_path, strerror(errno));
        return -1;
    }
    struct sigaction sc = { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDWAIT };   /* supervisors reap themselves */
    sigemptyset(&sc.sa_mask);
    sigaction(SIGCHLD, &sc, NULL);
    fprintf(stderr, "[warden] node agent: listening on %s; streams in %s\n", sock_path, streams);
    for (;;) {
        int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR || errno == ECONNABORTED) continue; perror("[warden] accept"); continue; }
        static char buf[1 << 16];
        char cbuf[CMSG_SPACE(sizeof(int) * 8)];
        struct iovec iov = { buf, sizeof buf - 1 };
        struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
        ssize_t r = recvmsg(c, &m, MSG_CMSG_CLOEXEC);
        close(c);
        int fds[8], nfd = 0;
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h))
            if (h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS) {
                nfd = (int)((h->cmsg_len - CMSG_LEN(0)) / sizeof(int));
                if (nfd > 8) nfd = 8;
                memcpy(fds, CMSG_DATA(h), sizeof(int) * (size_t)nfd);
            }
        if (r <= 0 || nfd != 1 || (m.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
            fprintf(stderr, "[warden] node agent: a connection without one descriptor and a state; ignored\n");
            for (int i = 0; i < nfd; i++) close(fds[i]);
            continue;
        }
        pid_t k = fork();
        if (k < 0) { perror("[warden] fork"); close(fds[0]); continue; }
        if (k > 0) { close(fds[0]); continue; }
        /* the container's supervisor */
        close(ls);
        sigaction(SIGCHLD, &(struct sigaction){ .sa_handler = SIG_DFL }, NULL);
        g_nr.on = true;
        g_nr.notify_fd = fds[0];
        char why[512];
        int ok = node_state(buf, (size_t)r, why, sizeof why);
        char sname[256];
        snprintf(sname, sizeof sname, "%s.%d.jsonl", ok == 0 ? g_nr.id : "unknown", (int)getpid());
        int so = openat(sd, sname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (so < 0 || dup2(so, STDERR_FILENO) < 0) _exit(1);
        close(so);
        close(sd);
        if (ok == 0) ok = node_config(why, sizeof why);
        if (ok == 0) ok = node_process(why, sizeof why);
        if (ok == 0 && node_enter("net", CLONE_NEWNET) < 0) {
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
    if (node_enter("mnt", CLONE_NEWNS) < 0) {
        char why[160];
        snprintf(why, sizeof why, "cannot enter the container's mount namespace (%s)", strerror(errno));
        node_fail(why);
    }
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
    int target_pidfd = wd_supervisor_watch_target(g_nr.pid);
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
