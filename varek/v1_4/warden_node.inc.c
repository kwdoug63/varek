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
 * command, connects to addresses. Refused at the start (step 5 names them,
 * and the webhook refuses them at deploy), not carried in v1.34.0:
 * credentials, the on-behalf-of chain and sub-agents, plans and the dry run.
 * v1.35 step 4c (D11) carries plans: a pod's plan by the name it gives
 * (varek.dev/plan), as POLICY_DIR/<namespace>/<name>.plan, held to the
 * plugin's SHA-256 of it and copied beside the stream as the policy is; it
 * is decided in the container's view once run_start is written (a step of a
 * kind the node agent does not carry, mcp_call, subagent or credential, is
 * UNKNOWN, so its plan is refused), and the run is held to it (D2). A
 * policy that says `require plan` runs no container whose pod names none.
 *
 * Step 4 (D5): the pod's network. Host-name rules and the egress proxy are
 * carried: the names are resolved from the pod's network namespace through
 * the pod's DNS server (node_dns), the views are served in the container's
 * view, the stub resolver binds the first address free from 127.53.53.53 in
 * the namespace the pod's containers share, and the proxy runs there, taking
 * only the connections the Warden announces.
 *
 * Step 3 (the NRI plugin, k8s/cmd/varek-nri, and the launcher, varek_init.c):
 *
 *   warden POLICY_DIR --node-agent SOCKET --node-streams DIR --node-launcher FILE
 *
 * takes each container's policy by the name its pod gives
 * (varek.dev/policy, which the plugin copies to the container's own
 * annotations: the state carries the container's, not the pod's), as
 * POLICY_DIR/<namespace>/<name>.policy (step 5), held to the SHA-256 the
 * plugin wrote the filter for; a single policy file stays one policy for
 * every container. The plugin puts the launcher first in the command
 * (/varek/init -- COMMAND ...), bound read-only from FILE on the node. The
 * supervisor checks /varek/init is that file, builds the launch set in the
 * container's view, and serves it to the launcher (NODE_SET_VIEW), which
 * applies it with Landlock and launches the command: the runtime's launch
 * of /varek/init is let through, then the launcher's calls, and the
 * command's launch is the bootstrap. With the launcher, a policy that
 * decides launches (require warden 1.27) is carried, under D4: the
 * container's root read-only, every writable mount noexec, and no mount
 * that allows execution showing what a writable one can change (checked
 * from the container's mounts as the descriptor arrives, before any of its
 * code runs).
 *
 * v1.36 step 4 (docs/security/v1.36-kubernetes-parity.md, D1 and D2):
 * credentials. warden-secrets is started in the node agent's own network
 * namespace, before the supervisor enters the pod's, so each store is
 * reached from the node under the DaemonSet's identity; a file: store must
 * be under --node-credentials DIR (the chart's Secrets, in VAREK's own
 * namespace). Each credential the policy names must be given to the pod's
 * namespace, from that source, by a VarekCredential resource (the NRI
 * plugin's sync writes the cluster's as POLICY_DIR/.credentials). The value
 * goes to the proxy in the pod's network namespace, as on a host; the agent
 * has the placeholder the NRI plugin put in its environment
 * (VAREK_CRED_<NAME>). */
/* v1.36 step 7 (D6, D7, D7b): the dry run, flow policies and trust bundles,
 * each said by the pod's VarekPolicy beside its policy, which the plugin
 * puts in the container's annotations (varek.dev/dry-run, trust-bundle,
 * flow-sha256, and service-account from the API server), never the pod's
 * own (node_inputs). A dry run is a host's, but a connect the policy
 * refuses is refused all the same (dry_net_let: the pod's network is the
 * cluster's), and no launch is held (the launcher's set is /). A flow
 * policy is copied beside the stream as the policy is, and gates the pod's
 * plan with its breaker, whose table is the node's (--node-flow-state) and
 * whose session is the pod's namespace and service account. A trust bundle
 * is a key of the ConfigMap at --node-trust-bundles, read in the node's
 * view. node_unsupported now refuses nothing a host runs. */
#include "node_json.h"

#define NODE_LAUNCHER "/varek/init"              /* where the plugin binds the launcher */
#define NODE_SET_VIEW "/etc/varek/launch-set"    /* the view the launcher reads */

static const char *g_node_policies;               /* the policies' directory, or NULL: one policy */
static const char *g_node_creds_dir;              /* v1.36 step 4: --node-credentials, the file: stores' */
#define NODE_CRED_LIST ".credentials"             /* POLICY_DIR/.credentials: the cluster's VarekCredential list */
static const char *const kNodeStore[] = { "", "file", "vault", "aws-sm" };
/* v1.36 step 6 (D5): the on-behalf-of chain. The user's token is in a
 * Secret volume of the pod (varek-obo, key token) that only an init
 * container mounts (VAREK's admission webhook adds both); the kubelet keeps
 * it on the node while the pod runs (M2b), and the node agent reads it there
 * by the pod's uid. The agent's SVID comes from the node's SPIRE agent,
 * asked by the container's process id through its Delegated Identity API
 * (M3), by varek-svid. Each is handed to warden-secrets as a root-only copy
 * in the socket's directory, as --on-behalf-of and --agent-svid are on a
 * host. */
static const char *g_node_kubelet = "/var/lib/kubelet";   /* --node-kubelet */
static const char *g_node_spire;                           /* --node-spire-socket: the SPIRE agent's admin socket */
static const char *g_node_spire_self;                      /* --node-spire-self: the node agent's own SPIFFE ID */
static const char *g_node_svid_bin;                        /* --node-svid-helper, else varek-svid beside the Warden */
static char g_node_sock_dir[PATH_MAX];                     /* the socket's directory, root's alone */
static char g_node_obo_file[PATH_MAX], g_node_svid_file[PATH_MAX];
#define NODE_OBO_VOLUME "varek-obo"
#define NODE_OBO_KEY    "token"
#define NODE_OBO_MAX    65536
static bool  g_node_have_launcher;
static dev_t g_node_launcher_dev;                 /* --node-launcher, on the node */
static ino_t g_node_launcher_ino;

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

/* The pod's namespace, name and uid and the container's name: the NRI
 * plugin's annotations (v1.34 step 3: CRI-O puts the kubelet's in one JSON
 * string, and crictl none), containerd's, or CRI-O's. A pod's own
 * annotations can be passed through to the container's, so each family can
 * be claimed: one present but unusable (not a string, too long), or two
 * present and different, is refused. 0, or -1. */
static int node_annotation(const char *doc, size_t n, const char *const keys[3], char *out, size_t on) {
    bool have = false;
    out[0] = '\0';
    for (int k = 0; k < 3; k++) {
        const char *pk[] = { "state", "annotations", keys[k] }, *v;
        size_t vn;
        char val[256];
        if (nj_find(doc, n, pk, 3, &v, &vn) < 0) continue;
        if (nj_string(v, vn, val, sizeof val) < 0 || strlen(val) >= on) return -1;
        if (have && strcmp(out, val)) return -1;
        if (!have) snprintf(out, on, "%s", val);
        have = true;
    }
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

/* One of the plugin's own annotations (it sets or removes each, so the
 * pod's author cannot give one): 1 and its value, 0 when absent, -1 when not
 * a string of fewer than ON bytes */
static int node_own(const char *doc, size_t n, const char *key, char *out, size_t on) {
    const char *pk[] = { "state", "annotations", key }, *v;
    size_t vn;
    out[0] = '\0';
    if (nj_find(doc, n, pk, 3, &v, &vn) < 0) return 0;
    if (nj_string(v, vn, out, on) < 0) { out[0] = '\0'; return -1; }
    return 1;
}

/* a DNS subdomain of Kubernetes' (a Secret's, a service account's name): 1 to
 * 253 of a-z, 0-9, - and ., beginning and ending with a letter or digit */
static bool node_dns_name(const char *s) {
    size_t k = 0;
    for (; s[k]; k++)
        if (!((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= '0' && s[k] <= '9') || s[k] == '-' || s[k] == '.'))
            return false;
    return k > 0 && k <= 253 && s[0] != '-' && s[0] != '.' && s[k - 1] != '-' && s[k - 1] != '.';
}

/* a key of a ConfigMap's: 1 to 253 of a-z, A-Z, 0-9, -, _ and ., not . or .. */
static bool node_cm_key(const char *s) {
    size_t k = 0;
    for (; s[k]; k++)
        if (!((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= 'A' && s[k] <= 'Z') || (s[k] >= '0' && s[k] <= '9') ||
              s[k] == '-' || s[k] == '_' || s[k] == '.'))
            return false;
    return k > 0 && k <= 253 && strcmp(s, ".") && strcmp(s, "..");
}

static bool node_hex64(const char *s) {
    size_t k = 0;
    for (; s[k]; k++) if (!strchr("0123456789abcdef", s[k])) return false;
    return k == 64;
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
    static const char *const kNs[3] = { "varek.dev/pod-namespace", "io.kubernetes.cri.sandbox-namespace",
                                        "io.kubernetes.pod.namespace" };
    static const char *const kName[3] = { "varek.dev/pod-name", "io.kubernetes.cri.sandbox-name", "io.kubernetes.pod.name" };
    static const char *const kUid[3] = { "varek.dev/pod-uid", "io.kubernetes.cri.sandbox-uid", "io.kubernetes.pod.uid" };
    static const char *const kCtr[3] = { "varek.dev/container", "io.kubernetes.cri.container-name",
                                         "io.kubernetes.container.name" };
    if (node_annotation(doc, n, kNs, g_nr.pod_ns, sizeof g_nr.pod_ns) < 0 ||
        node_annotation(doc, n, kName, g_nr.pod_name, sizeof g_nr.pod_name) < 0 ||
        node_annotation(doc, n, kUid, g_nr.pod_uid, sizeof g_nr.pod_uid) < 0 ||
        node_annotation(doc, n, kCtr, g_nr.ctr, sizeof g_nr.ctr) < 0) {
        snprintf(why, wn, "the container's state names its pod twice, differently, or unusably (the NRI plugin's, "
                 "containerd's and CRI-O's annotations)");
        return -1;
    }
    /* v1.36 step 6 (D5): the Secret its user's token is in, a DNS name */
    const char *op[] = { "state", "annotations", "varek.dev/on-behalf-of" }, *v;
    size_t vn;
    g_nr.obo[0] = '\0';
    if (nj_find(doc, n, op, 3, &v, &vn) == 0) {
        bool ok = nj_string(v, vn, g_nr.obo, sizeof g_nr.obo) == 0 && g_nr.obo[0] && g_nr.obo[0] != '.' &&
                  g_nr.obo[0] != '-';
        for (size_t k = 0; ok && g_nr.obo[k]; k++)
            ok = (g_nr.obo[k] >= 'a' && g_nr.obo[k] <= 'z') || (g_nr.obo[k] >= '0' && g_nr.obo[k] <= '9') ||
                 g_nr.obo[k] == '-' || g_nr.obo[k] == '.';
        if (!ok) {
            g_nr.obo[0] = '\0';
            snprintf(why, wn, "the container's varek.dev/on-behalf-of is not a Secret's name");
            return -1;
        }
    }
    /* v1.36 step 7: the dry run, the trust bundle, the flow policy's hash and
     * the service account, each the plugin's */
    char dv[8];
    int r = node_own(doc, n, "varek.dev/dry-run", dv, sizeof dv);
    if (r < 0 || (r == 1 && strcmp(dv, "true"))) {
        snprintf(why, wn, "the container's varek.dev/dry-run is not \"true\"");
        return -1;
    }
    g_nr.dry = r == 1;
    if ((r = node_own(doc, n, "varek.dev/trust-bundle", g_nr.trust, sizeof g_nr.trust)) < 0 ||
        (r == 1 && !node_cm_key(g_nr.trust))) {
        g_nr.trust[0] = '\0';
        snprintf(why, wn, "the container's varek.dev/trust-bundle is not a ConfigMap's key");
        return -1;
    }
    if ((r = node_own(doc, n, "varek.dev/flow-sha256", g_nr.flow_sha, sizeof g_nr.flow_sha)) < 0 ||
        (r == 1 && !node_hex64(g_nr.flow_sha))) {
        g_nr.flow_sha[0] = '\0';
        snprintf(why, wn, "the container's varek.dev/flow-sha256 is not a SHA-256 (64 hex digits)");
        return -1;
    }
    if ((r = node_own(doc, n, "varek.dev/service-account", g_nr.sa, sizeof g_nr.sa)) < 0 ||
        (r == 1 && !node_dns_name(g_nr.sa))) {
        g_nr.sa[0] = '\0';
        snprintf(why, wn, "the container's varek.dev/service-account is not a service account's name");
        return -1;
    }
    return 0;
}

/* a name of 1 to 63 of a-z, 0-9 and - (a policy's, a namespace's) */
static bool node_label(const char *s) {
    size_t k = 0;
    for (; s[k]; k++)
        if (!((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= '0' && s[k] <= '9') || s[k] == '-')) return false;
    return k > 0 && k <= 63;
}

/* v1.34 step 3: the container's policy, by the name its pod gives
 * (varek.dev/policy, copied by the NRI plugin to the container's annotations);
 * step 5: as POLICY_DIR/<pod's namespace>/<name>.policy, where the plugin
 * writes each namespace's VarekPolicy resources (D7). With a single policy
 * file, every container's (the name, if any, recorded). Also the plugin's
 * SHA-256 of the policy it wrote the filter for (varek.dev/policy-sha256),
 * required with a directory. 0, or -1 with why. */
static int node_policy(const char *doc, size_t n, const char **policy_path, char *why, size_t wn) {
    const char *pp[] = { "state", "annotations", "varek.dev/policy" }, *v;
    const char *ph[] = { "state", "annotations", "varek.dev/policy-sha256" };
    size_t vn;
    bool has = nj_find(doc, n, pp, 3, &v, &vn) == 0;
    if (has && nj_string(v, vn, g_nr.policy, sizeof g_nr.policy) < 0) g_nr.policy[0] = '\0';
    bool named = has && node_label(g_nr.policy);
    g_nr.policy_sha[0] = '\0';
    if (nj_find(doc, n, ph, 3, &v, &vn) == 0) {
        bool hex = nj_string(v, vn, g_nr.policy_sha, sizeof g_nr.policy_sha) == 0 && strlen(g_nr.policy_sha) == 64;
        for (size_t k = 0; hex && k < 64; k++) hex = strchr("0123456789abcdef", g_nr.policy_sha[k]) != NULL;
        if (!hex) { snprintf(why, wn, "the container's varek.dev/policy-sha256 is not a SHA-256 (64 hex digits)"); return -1; }
    }
    if (!g_node_policies) {
        if (!named) g_nr.policy[0] = '\0';
        return 0;
    }
    if (!has) {
        snprintf(why, wn, "the container names no policy (its pod's varek.dev/policy annotation, which the NRI "
                 "plugin copies to the container's)");
        return -1;
    }
    if (!named) {
        snprintf(why, wn, "the container's policy name (varek.dev/policy) is not 1 to 63 of a-z, 0-9 and -");
        return -1;
    }
    if (!node_label(g_nr.pod_ns)) {
        snprintf(why, wn, "the container's pod names no namespace its policy could be in");
        return -1;
    }
    if (!g_nr.policy_sha[0]) {
        snprintf(why, wn, "the container was not given its filter by VAREK's NRI plugin (no varek.dev/policy-sha256)");
        return -1;
    }
    static char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s/%s.policy", g_node_policies, g_nr.pod_ns, g_nr.policy);
    int e = lstat(path, &st) < 0 ? errno : 0;
    if (e || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "no policy named %s (%.300s: %s)", g_nr.policy, path, e ? strerror(e) : "not a file");
        return -1;
    }
    *policy_path = path;
    return 0;
}

/* v1.35 step 4c (D11): the pod's plan, by the name its pod gives
 * (varek.dev/plan, copied by the NRI plugin to the container's annotations),
 * as POLICY_DIR/<pod's namespace>/<name>.plan, where the plugin writes each
 * namespace's VarekPlan resources; held to the SHA-256 of the plan the
 * plugin checked the policy with (varek.dev/plan-sha256). A pod naming no
 * plan: *plan_path stays NULL. 0, or -1 with why. */
static int node_plan(const char *doc, size_t n, const char **plan_path, char *why, size_t wn) {
    const char *pp[] = { "state", "annotations", "varek.dev/plan" }, *v;
    const char *ph[] = { "state", "annotations", "varek.dev/plan-sha256" };
    size_t vn;
    g_nr.plan[0] = g_nr.plan_sha[0] = '\0';
    if (nj_find(doc, n, pp, 3, &v, &vn) < 0) return 0;
    if (nj_string(v, vn, g_nr.plan, sizeof g_nr.plan) < 0 || !node_label(g_nr.plan)) {
        g_nr.plan[0] = '\0';
        snprintf(why, wn, "the container's plan name (varek.dev/plan) is not 1 to 63 of a-z, 0-9 and -");
        return -1;
    }
    if (!g_node_policies) {
        snprintf(why, wn, "the container names a plan, and this node agent has one policy, not a directory of "
                 "policies and plans");
        return -1;
    }
    bool hex = nj_find(doc, n, ph, 3, &v, &vn) == 0 && nj_string(v, vn, g_nr.plan_sha, sizeof g_nr.plan_sha) == 0 &&
               strlen(g_nr.plan_sha) == 64;
    for (size_t k = 0; hex && k < 64; k++) hex = strchr("0123456789abcdef", g_nr.plan_sha[k]) != NULL;
    if (!hex) {
        g_nr.plan_sha[0] = '\0';
        snprintf(why, wn, "the container names a plan, and was not given its filter by VAREK's NRI plugin with it "
                 "(no varek.dev/plan-sha256 of 64 hex digits)");
        return -1;
    }
    static char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s/%s.plan", g_node_policies, g_nr.pod_ns, g_nr.plan);
    int e = lstat(path, &st) < 0 ? errno : 0;
    if (e || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "no plan named %s (%.300s: %s)", g_nr.plan, path, e ? strerror(e) : "not a file");
        return -1;
    }
    *plan_path = path;
    return 0;
}

/* v1.36 step 7 (D7b): the flow policy of the pod's VarekPolicy, which the
 * plugin's sync writes as POLICY_DIR/<pod's namespace>/<policy>.flow, held
 * to the SHA-256 of the one the plugin checked (varek.dev/flow-sha256). None:
 * *flow_path stays NULL. 0, or -1 with why. */
static int node_flow(const char **flow_path, char *why, size_t wn) {
    if (!g_nr.flow_sha[0]) return 0;
    if (!g_node_policies || !g_nr.policy[0]) {
        snprintf(why, wn, "the container names a flow policy, and this node agent has one policy, not a directory of "
                 "policies");
        return -1;
    }
    static char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s/%s.flow", g_node_policies, g_nr.pod_ns, g_nr.policy);
    int e = lstat(path, &st) < 0 ? errno : 0;
    if (e || !S_ISREG(st.st_mode)) {
        snprintf(why, wn, "no flow policy for policy %s (%.300s: %s)", g_nr.policy, path, e ? strerror(e) : "not a file");
        return -1;
    }
    *flow_path = path;
    return 0;
}

/* v1.34 step 5 (D8): the policy the container runs under, copied beside its
 * stream (DIR/<container>.<supervisor>.policy, root's, read-only) and loaded
 * from there, so the run's evidence holds the policy as it was, whatever the
 * cluster's resource becomes; its SHA-256 must be the one the plugin wrote
 * the filter for. *policy_path becomes the copy. 0, or -1 with why.
 * v1.35 step 4c (D11): the pod's plan the same (what "plan", ext ".plan",
 * want the plugin's SHA-256 of the plan). */
static int node_copy(int sd, const char *streams, const char *base, const char *what, const char *ext,
                     const char *want, const char **policy_path, char *why, size_t wn) {
    int src = open(*policy_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    struct stat st;
    if (src < 0 || fstat(src, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size > (8 << 20)) {
        snprintf(why, wn, "cannot read the %s %.300s (%s)", what, *policy_path,
                 src < 0 ? strerror(errno) : "not a file of at most 8 MiB");
        if (src >= 0) close(src);
        return -1;
    }
    char *b = malloc((size_t)st.st_size + 1);
    size_t n = 0;
    ssize_t r = 0;
    while (b && n < (size_t)st.st_size + 1 && (r = read(src, b + n, (size_t)st.st_size + 1 - n)) > 0) n += (size_t)r;
    close(src);
    if (!b || r < 0 || n > (size_t)st.st_size) {
        free(b);
        snprintf(why, wn, "cannot read the %s %.300s whole", what, *policy_path);
        return -1;
    }
    unsigned char h[crypto_hash_sha256_BYTES];
    char hex[65];
    crypto_hash_sha256(h, (const unsigned char *)b, n);
    sodium_bin2hex(hex, sizeof hex, h, sizeof h);
    if (want[0] && strcmp(hex, want)) {
        free(b);
        snprintf(why, wn, "the %s %.300s is not the one the NRI plugin wrote the container's filter for "
                 "(SHA-256 %.16s..., the plugin's %.16s...): it changed between them; the container is to be "
                 "created again", what, *policy_path, hex, want);
        return -1;
    }
    char cname[300];
    snprintf(cname, sizeof cname, "%s%s", base, ext);
    int dst = openat(sd, cname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    bool ok = dst >= 0 && write_all(dst, b, n) == 0 && fsync(dst) == 0;
    if (dst >= 0) close(dst);
    free(b);
    if (!ok) { snprintf(why, wn, "cannot copy the %s beside the stream (%s)", what, strerror(errno)); return -1; }
    static char copies[3][PATH_MAX];                  /* the policy's, the plan's, the flow policy's */
    char *copy = copies[!strcmp(what, "plan") ? 1 : !strcmp(what, "flow policy") ? 2 : 0];
    snprintf(copy, PATH_MAX, "%s/%s", streams, cname);
    *policy_path = copy;
    return 0;
}

/* v1.34 step 4: the pod's DNS server, the first IPv4 nameserver of the
 * container's /etc/resolv.conf (the kubelet's: the cluster's DNS), read
 * within the container's root (RESOLVE_IN_ROOT: a link in the image leads
 * nowhere outside it) before any of its code runs. None found: "". */
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif
static void node_dns(void) {
    g_nr.dns[0] = '\0';
    int root = proc_openf(O_PATH | O_DIRECTORY, 0, "%d/root", g_nr.pid);
    if (root < 0) return;
    struct open_how_local how = { .flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK,
                                  .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS };
    int fd = (int)syscall(__NR_openat2, root, "etc/resolv.conf", &how, sizeof how);
    close(root);
    struct stat st;
    if (fd < 0) return;
    FILE *f = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) ? fdopen(fd, "r") : NULL;
    if (!f) { close(fd); return; }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char ns[64];
        struct in_addr a;
        if (sscanf(line, " nameserver %63s", ns) == 1 && inet_pton(AF_INET, ns, &a) == 1) {
            snprintf(g_nr.dns, sizeof g_nr.dns, "%s:53", ns);
            break;
        }
    }
    fclose(f);
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

/* Whether a process is in the namespace of that kind of `of` ("self", or
 * "1": the node's init) */
static bool node_same_ns(pid_t pid, const char *ns, const char *of) {
    struct stat a, b;
    return proc_statf(&a, "%d/ns/%s", pid, ns) == 0 && proc_statf(&b, "%s/ns/%s", of, ns) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

/* a namespace's inode, for a refusal's wording (0: not read) */
static unsigned long long node_ns_ino(const char *of, const char *ns) {
    struct stat st;
    return proc_statf(&st, "%s/ns/%s", of, ns) == 0 ? (unsigned long long)st.st_ino : 0;
}

/* Whether a process runs where the node's runtime does: in the node agent's
 * own user and PID namespaces, and in its mount namespace or the node's (its
 * init's). v1.34 step 6: in the chart's DaemonSet the node agent runs in a
 * pod's mount namespace (with the node's PID and user namespaces), the
 * runtime in the node's; on a host the two are one (and where the node's
 * init cannot be read, as in some sandboxes, the node agent's own is the
 * node's). In the pod no other process shares the node agent's own: each
 * container has one. 0, or -1 with why (WHO names the process). */
static int node_runtime_ns(pid_t pid, const char *who, char *why, size_t wn) {
    static const char *const kNs[] = { "user", "pid" };
    for (size_t i = 0; i < sizeof kNs / sizeof kNs[0]; i++)
        if (!node_same_ns(pid, kNs[i], "self")) {
            snprintf(why, wn, "%s (pid %d) is not in the node agent's %s namespace (not the node's runtime)",
                     who, (int)pid, kNs[i]);
            return -1;
        }
    if (!node_same_ns(pid, "mnt", "self") && !node_same_ns(pid, "mnt", "1")) {
        char pn[16], comm[32] = "?";
        snprintf(pn, sizeof pn, "%d", (int)pid);
        FILE *f = proc_fopenf("%d/comm", (int)pid);
        if (f) {
            if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = '\0';
            fclose(f);
        }
        snprintf(why, wn, "%s (pid %d, %s) is not in the node's mount namespace nor the node agent's (not the node's "
                 "runtime; its mnt:[%llu], the node's mnt:[%llu], the node agent's mnt:[%llu])", who, (int)pid, comm,
                 node_ns_ino(pn, "mnt"), node_ns_ino("1", "mnt"), node_ns_ino("self", "mnt"));
        return -1;
    }
    return 0;
}

/* The peer, as the node agent finds it when it takes the connection, before
 * it reads the state. The runtime need not wait for the node agent: under
 * containerd, runc create sends the state and ends, its shim (a subreaper)
 * reaps it, and the container's process becomes the shim's child (kind, in
 * CI: refused, the peer then a zombie, whose mount namespace is gone, or
 * reaped, or its child the shim's). */
struct node_peer {
    pid_t pid;          /* SO_PEERCRED's, as the kernel took it at connect */
    uid_t uid;
    int state;          /* 1: read, where the runtime runs; 0: read, not (why); -1: ended before it could be read */
    long ppid;          /* its parent, where read (a zombie's too), or -1 */
    char why[400];
};

static void node_peer_read(int c, struct node_peer *p) {
    struct ucred cr;
    socklen_t cl = sizeof cr;
    memset(p, 0, sizeof *p);
    p->ppid = -1;
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0 || cr.pid <= 0) {
        snprintf(p->why, sizeof p->why, "the peer's credentials cannot be read");
        return;
    }
    p->pid = cr.pid;
    p->uid = cr.uid;
    p->ppid = node_status_field(cr.pid, "PPid:");
    struct stat st;
    if (proc_statf(&st, "%d/ns/mnt", (int)cr.pid) < 0) { p->state = -1; return; }   /* ended: a zombie has none */
    if (node_runtime_ns(cr.pid, "the peer", p->why, sizeof p->why) == 0) { p->state = 1; return; }
    /* not where the runtime runs, or ended while it was read (kind, in CI:
     * its mount namespace read, then gone when compared) */
    p->state = proc_statf(&st, "%d/ns/mnt", (int)cr.pid) < 0 ? -1 : 0;
}

/* A connection the listener takes, checked before a supervisor is forked
 * for it (review: through step 2 any root peer could name any process, to
 * have it killed, or supervised in its place): the peer is root and runs
 * where the runtime does (node_runtime_ns, read as the connection is taken,
 * node_peer_read); the state is well formed and names a process whose
 * parent is the peer (runc's init is its runtime's child; crun's is not yet
 * tested) or the peer's parent (the runtime ended, its child reparented to
 * the shim); the descriptor is a seccomp listener, and that process is under
 * a filter. A peer that ended before it could be read, or while it was: its
 * parent must have been read (a zombie's is; a reaped peer is refused), the
 * process's parent is the peer (still ending) or the peer's parent, and the
 * peer's parent, the shim, is root and runs where the runtime does. 0 with
 * the process's pid and pidfd, or -1 with why. */
static int node_admit(const struct node_peer *peer, const char *doc, size_t n, int fd, pid_t *pid, int *pidfd,
                      char *why, size_t wn) {
    *pidfd = -1;
    if (peer->pid <= 0 || peer->state == 0) { snprintf(why, wn, "%s", peer->why); return -1; }
    if (peer->uid != 0) {
        snprintf(why, wn, "the peer (pid %d) is not root (uid %u)", (int)peer->pid, (unsigned)peer->uid);
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
        snprintf(why, wn, "the container's process %d is gone (%s)", (int)*pid, strerror(errno));
        return -1;
    }
    long pp = node_status_field(*pid, "PPid:"), sc = node_status_field(*pid, "Seccomp:");
    if (!node_alive(*pidfd)) {
        snprintf(why, wn, "the container's process %d is gone (%s)", (int)*pid, strerror(errno));
        goto fail;
    }
    if (peer->state == 1) {
        if (pp != (long)peer->pid && !(peer->ppid > 0 && pp == peer->ppid)) {
            snprintf(why, wn, "the process the state names (%d) is not the peer's child nor its parent's (its parent "
                     "is %ld, the peer %d, the peer's parent %ld)", (int)*pid, pp, (int)peer->pid, peer->ppid);
            goto fail;
        }
    } else {
        /* the peer ended before it could be read, or while it was: the
         * process's parent is the peer, still ending (its children not yet
         * reparented), or the peer's parent (the shim, the process now its),
         * which is checked as the runtime. A peer already reaped, its parent
         * not read, is refused: nothing then ties it to the process it names
         * (review: a root peer anywhere could name another pod's process,
         * end at once, and have it supervised or killed) */
        long rt = peer->ppid;
        if (rt <= 0) {
            snprintf(why, wn, "the peer (pid %d) ended and was reaped before it could be read: nothing ties it to "
                     "the process the state names (%d), refused", (int)peer->pid, (int)*pid);
            goto fail;
        }
        if (pp != (long)peer->pid && pp != rt) {
            snprintf(why, wn, "the peer (pid %d) ended before it could be read, and the process the state names (%d) "
                     "is not its child nor its parent's (its parent is %ld, the peer's %ld)", (int)peer->pid, (int)*pid,
                     pp, peer->ppid);
            goto fail;
        }
        long ru = rt > 0 ? node_status_field((pid_t)rt, "Uid:") : -1;
        if (rt <= 0 || ru != 0) {
            snprintf(why, wn, "the peer (pid %d) ended before it could be read, and the runtime's process it leaves "
                     "(%ld) is not root (uid %ld)", (int)peer->pid, rt, ru);
            goto fail;
        }
        if (node_runtime_ns((pid_t)rt, "the runtime's process the peer leaves (it ended before it could be read)",
                            why, wn) < 0)
            goto fail;
    }
    if (sc != 2) { snprintf(why, wn, "the process the state names (%d) is not under a seccomp filter", (int)*pid); goto fail; }
    /* taken by the runtime's parent alone: said, so the node's log shows each
     * container taken so (decided October 21, 2026: kept, design note step 7) */
    if (peer->state != 1)
        fprintf(stderr, "[warden] node agent: the runtime (pid %d) ended before it could be read; its container's "
                "process %d taken by the runtime's parent (%ld: root, where the runtime runs)\n",
                (int)peer->pid, (int)*pid, peer->ppid);
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
        /* v1.34 step 3: the launcher first (the NRI plugin's), then "--" and
         * the container's own command, its first launch */
        if (!strcmp(g_nr.argv0, NODE_LAUNCHER)) {
            const char *p1[] = { "process", "args", "#1" }, *p2[] = { "process", "args", "#2" };
            char dd[4];
            node_str(doc, n, p1, 3, dd, sizeof dd);
            node_str(doc, n, p2, 3, g_nr.argv0, sizeof g_nr.argv0);
            g_nr.launcher = true;
            if (strcmp(dd, "--")) {
                snprintf(why, wn, "the container's command is the launcher (" NODE_LAUNCHER "), not followed by "
                         "\"-- COMMAND\"");
                goto out;
            }
            if (!g_node_have_launcher) {
                snprintf(why, wn, "the container's command is the launcher (" NODE_LAUNCHER "), and this node agent "
                         "has none (--node-launcher)");
                goto out;
            }
        }
        /* v1.36 step 4 (D1): the placeholders in its environment */
        g_nr.ncred_env = 0;
        g_nr.cred_env_over = false;
        for (int k = 0; k < 4096; k++) {
            char idx[16], ent[sizeof g_nr.cred_env[0] + 1];
            snprintf(idx, sizeof idx, "#%d", k);
            const char *ep[] = { "process", "env", idx }, *v;
            size_t vn;
            if (nj_find(doc, n, ep, 3, &v, &vn) < 0) break;
            if (vn < 13 || memcmp(v, "\"VAREK_CRED_", 12)) continue;
            if (nj_string(v, vn, ent, sizeof ent) < 0 || strlen(ent) >= sizeof g_nr.cred_env[0] ||
                g_nr.ncred_env == (int)(sizeof g_nr.cred_env / sizeof g_nr.cred_env[0])) {
                g_nr.cred_env_over = true;
                continue;
            }
            snprintf(g_nr.cred_env[g_nr.ncred_env++], sizeof g_nr.cred_env[0], "%s", ent);
        }
        if (g_nr.argv0[0] != '/')
            snprintf(why, wn, "the container's command must be named by an absolute path (it is \"%.200s\")", g_nr.argv0);
        else rc = 0;
    }
out:
    free(doc);
    return rc;
}

/* The container's init as the descriptor arrives: no new privileges (the
 * runtime then loads the filter after it takes the container's user and
 * capabilities), that user, the agent's, and no capability; PID 1 of a PID
 * namespace of its own (step 8 review: in a namespace the pod's containers
 * share, shareProcessNamespace, the agent's kill reaches its siblings, and its
 * descendants outlive the run, reparented to the pod's first process). 0, or
 * -1. */
static int node_process(char *why, size_t wn) {
    FILE *f = proc_fopenf("%d/status", g_nr.pid);
    if (!f) { snprintf(why, wn, "the container's process %d is gone", g_nr.pid); return -1; }
    char line[256];
    int nnp = -1;
    long uid = -1, gid = -1, nspid = -1;
    bool groups_ok = false;
    /* v1.34 step 7 (found by the sweep): the capabilities it holds; the
     * Warden's agent holds none (caps=none), and a pod's is to hold none
     * either (capabilities: drop: [ALL]) */
    unsigned long long cap_eff = ~0ULL, cap_prm = ~0ULL, cap_amb = ~0ULL;
    while (fgets(line, sizeof line, f)) {
        long r, e;
        if (sscanf(line, "CapEff: %llx", &cap_eff) == 1 || sscanf(line, "CapPrm: %llx", &cap_prm) == 1 ||
            sscanf(line, "CapAmb: %llx", &cap_amb) == 1) continue;
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
        } else if (!strncmp(line, "NSpid:", 6)) {
            char *s = line + 6, *e2;            /* its last: its own namespace's */
            for (long x; (x = strtol(s, &e2, 10)), e2 != s; s = e2) nspid = x;
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
    /* review (G-7): files are opened as the agent with its groups too */
    for (int i = 0; i < g_nr.ngroups; i++)
        if (g_nr.groups[i] == 0) {
            snprintf(why, wn, "the container's user is in group 0 (root) as a supplementary group "
                     "(supplementalGroups, fsGroup)");
            return -1;
        }
    if (nspid != 1) {
        snprintf(why, wn, "the container's process is %ld of its PID namespace, not 1: a PID namespace the pod's "
                 "containers share (shareProcessNamespace) is not carried", nspid);
        return -1;
    }
    if (cap_eff || cap_prm || cap_amb) {
        snprintf(why, wn, "the container holds capabilities (effective %llx, permitted %llx, ambient %llx): the "
                 "agent holds none (securityContext.capabilities: drop: [ALL], and none added)", cap_eff, cap_prm, cap_amb);
        return -1;
    }
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
/* v1.34 step 5: what of the policy itself the node agent does not carry
 * yet: why, or NULL (warden POLICY --oci-filter refuses it, so the plugin
 * and the admission check refuse it before the container starts) */
static const char *node_policy_why(const struct policy *p) {
    /* v1.36 step 4 (D1, D2): credentials are carried (node_creds_check);
     * step 5 (D3, D4): sub-agents and confined MCP servers (sub_setup_node);
     * step 6 (D5): the on-behalf-of chain (node_obo) */
    (void)p;
    return NULL;
}

static const char *node_unsupported(const struct policy *p, const char *obo, const char *svid) {
    /* v1.35 step 4c (D11): the pod's plan is carried; v1.36 step 7 (D6, D7,
     * D7b): the dry run, the flow policy and the trust bundle, each the pod's
     * VarekPolicy's (node_inputs) */
    /* v1.36 step 6 (D5): each pod names its own user's token, and the SVID is
     * its pod's, from SPIRE (node_obo); not one for every container */
    if (obo || svid) return "--on-behalf-of or --agent-svid given to the node agent itself";
    if (p->v.launches && !g_nr.launcher)
        return "decided launches without the launcher (" NODE_LAUNCHER " first in the command: the NRI plugin)";
    return node_policy_why(p);
}

/* v1.35 step 4c (D11): a pod's plan, as the plugin and the admission check
 * take it (warden POLICY --oci-filter --plan PLAN): it reads. v1.36 step 4:
 * credential steps are carried; step 5 (D4 (b)): mcp_call and subagent
 * steps too, decided as on a host (an mcp_call to a stdio server stays
 * UNKNOWN, and the plan is refused, as there). Its steps are decided by the
 * node agent, in the container's view. 0, or -1 with why. */
static int node_plan_carried(const char *plan_path, char *why, size_t wn) {
    char err[256] = {0};
    plan_parsed_t *parsed = plan_parser_load(plan_path, err, sizeof err);
    if (!parsed) { snprintf(why, wn, "the plan does not read: %s", err); return -1; }
    plan_parser_free(parsed);
    return 0;
}

/* v1.36 step 4 (D2): each credential the policy names given to namespace
 * NS, from the source the policy names, by one of the cluster's
 * VarekCredential resources, as the NRI plugin's sync lists them (the
 * supervisor's POLICY_DIR/.credentials; --oci-filter --credential-list FILE),
 * one a line:
 *   CREDENTIAL <tab> NAMESPACE[,NAMESPACE...] <tab> STORE:REFERENCE <tab> RESOURCE
 * (# begins a comment line). A list root's, written by no one else, when
 * strict (the node's). 0, or -1 with why. */
static int node_creds_given(const struct policy *p, const char *list, const char *ns, bool strict, char *why,
                            size_t wn) {
    int fd = open(list, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size > (4 << 20)) {
        snprintf(why, wn, "the policy names credentials, and the cluster's list of VarekCredential resources (%.300s) "
                 "cannot be read (%s)", list, fd < 0 ? strerror(errno) : "not a file of at most 4 MiB");
        if (fd >= 0) close(fd);
        return -1;
    }
    if (strict && (st.st_uid != 0 || (st.st_mode & 022))) {
        close(fd);
        snprintf(why, wn, "the list of VarekCredential resources %.300s must be root's, written by no one else", list);
        return -1;
    }
    char *b = malloc((size_t)st.st_size + 1);
    size_t n = 0;
    ssize_t r = 0;
    while (b && n < (size_t)st.st_size && (r = read(fd, b + n, (size_t)st.st_size - n)) > 0) n += (size_t)r;
    close(fd);
    if (!b || r < 0) { free(b); snprintf(why, wn, "cannot read %.300s", list); return -1; }
    b[n] = '\0';
    int rc = 0;
    for (size_t k = 0; k < p->v.ncreds && rc == 0; k++) {
        const char *name = p->v.creds[k].name;
        char src[1100];
        snprintf(src, sizeof src, "%s:%s", kNodeStore[p->v.creds[k].store], p->v.creds[k].ref);
        bool named = false, sourced = false, given = false;
        char other[160] = "", to[300] = "";
        int ln = 0;
        char *text = strdup(b);
        if (!text) { snprintf(why, wn, "out of memory"); rc = -1; break; }
        for (char *save = NULL, *line = strtok_r(text, "\n", &save); line && !given; line = strtok_r(NULL, "\n", &save)) {
            ln++;
            if (!line[0] || line[0] == '#') continue;
            char *f[4], *fs = NULL;
            int nf = 0;
            for (char *t = strtok_r(line, "\t", &fs); t && nf < 4; t = strtok_r(NULL, "\t", &fs)) f[nf++] = t;
            if (nf != 4 || strtok_r(NULL, "\t", &fs)) {
                snprintf(why, wn, "the list of VarekCredential resources %.300s: line %d is not four fields", list, ln);
                rc = -1;
                break;
            }
            if (strcmp(f[0], name)) continue;
            named = true;
            if (strcmp(f[2], src)) { snprintf(other, sizeof other, "%.150s", f[3]); continue; }
            sourced = true;
            snprintf(to, sizeof to, "%.120s (to %.160s)", f[3], f[1]);
            for (char *ns_save = NULL, *x = strtok_r(f[1], ",", &ns_save); x && !given; x = strtok_r(NULL, ",", &ns_save))
                given = !strcmp(x, ns);
        }
        free(text);
        if (rc < 0 || given) continue;
        rc = -1;
        if (!named)
            snprintf(why, wn, "credential %s (line %d) is given by no VarekCredential (a cluster administrator gives "
                     "a credential to namespaces; D2)", name, p->v.creds[k].line);
        else if (!sourced)
            snprintf(why, wn, "credential %s (line %d): its VarekCredential (%s) names another source than the "
                     "policy's %.300s", name, p->v.creds[k].line, other, src);
        else
            snprintf(why, wn, "credential %s (line %d) is not given to namespace %s (VarekCredential %s; D2)", name,
                     p->v.creds[k].line, ns, to);
    }
    free(b);
    return rc;
}

/* v1.36 step 4 (D1, D2): what the supervisor checks of a policy that names
 * credentials, before warden-secrets starts: each given to the pod's
 * namespace (node_creds_given, from POLICY_DIR/.credentials); each file:
 * store under --node-credentials DIR; and each one's placeholder, as the NRI
 * plugin put it in the container's environment (VAREK_CRED_<NAME> =
 * varek_ph_<name>_ and 43 of base64url), into ph. 0, or -1 with why. */
static int node_creds_check(const struct policy *p, char (*ph)[WP_PH_MAX], char *why, size_t wn) {
    if (!g_node_policies) {
        snprintf(why, wn, "the policy names credentials, and this node agent has one policy, not a directory of "
                 "policies with the cluster's VarekCredential list beside them");
        return -1;
    }
    if (!node_label(g_nr.pod_ns)) { snprintf(why, wn, "the container's pod names no namespace"); return -1; }
    char list[PATH_MAX];
    snprintf(list, sizeof list, "%s/%s", g_node_policies, NODE_CRED_LIST);
    if (node_creds_given(p, list, g_nr.pod_ns, true, why, wn) < 0) return -1;
    char dir[PATH_MAX] = "";
    if (g_node_creds_dir && !realpath(g_node_creds_dir, dir)) {
        snprintf(why, wn, "--node-credentials %.300s: %s", g_node_creds_dir, strerror(errno));
        return -1;
    }
    if (g_nr.cred_env_over) {
        snprintf(why, wn, "the container's environment has more VAREK_CRED_ entries than the node agent reads, or one "
                 "too long to be a placeholder");
        return -1;
    }
    for (size_t k = 0; k < p->v.ncreds; k++) {
        const vdp_cred_t *c = &p->v.creds[k];
        if (c->store == 1) {                                   /* file: under the chart's directory */
            char real[PATH_MAX];
            size_t dl = strlen(dir);
            if (!dir[0]) {
                snprintf(why, wn, "credential %s from file: needs the node agent's --node-credentials DIR (the chart's "
                         "Secrets)", c->name);
                return -1;
            }
            /* the file resolved, or (not there) its directory: where neither
             * is, warden-secrets cannot read it and says so */
            bool found = realpath(c->ref, real) != NULL, unread = false;
            if (!found && errno == ENOENT) {
                char up[PATH_MAX], rup[PATH_MAX];
                snprintf(up, sizeof up, "%s", c->ref);
                char *sl = strrchr(up, '/');
                if (sl && sl != up) *sl = '\0';
                found = sl && sl != up && realpath(up, rup) && (size_t)snprintf(real, sizeof real, "%s/%s", rup, sl + 1) < sizeof real;
                unread = !found && errno == ENOENT;
            }
            if (!unread && (!found || strncmp(real, dir, dl) || (real[dl] != '/' && !(dl == 1 && dir[0] == '/')))) {
                snprintf(why, wn, "credential %s: its file %.300s is not under the node's credentials directory %.300s "
                         "(D1)", c->name, c->ref, dir);
                return -1;
            }
        }
        char key[64], want[48];
        int kl = snprintf(key, sizeof key, "VAREK_CRED_%s=", c->name);
        for (int q = 11; q < kl - 1; q++) key[q] = (char)toupper((unsigned char)key[q]);
        snprintf(want, sizeof want, "varek_ph_%s_", c->name);
        const char *found = NULL;
        int seen = 0;
        for (int e = 0; e < g_nr.ncred_env; e++)
            if (!strncmp(g_nr.cred_env[e], key, (size_t)kl)) { found = g_nr.cred_env[e] + kl; seen++; }
        size_t wl = strlen(want);
        if (seen != 1 || strncmp(found, want, wl) || strlen(found + wl) != 43 ||
            strspn(found + wl, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != 43) {
            snprintf(why, wn, "the container's environment has %s placeholder for credential %s (%.*s, which VAREK's "
                     "NRI plugin sets)", seen > 1 ? "more than one" : "no", c->name, kl - 1, key);
            return -1;
        }
        snprintf(ph[k], WP_PH_MAX, "%s", found);
    }
    return 0;
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
    fprintf(f, "\",\"uid\":%u,\"gid\":%u,\"opens_as_agent\":%s,\"policy\":\"", (unsigned)g_nr.uid, (unsigned)g_nr.gid,
            g_as.on ? "true" : "false");
    json_escape(f, g_nr.policy);
    fputs("\",\"plan\":\"", f);                     /* v1.35 step 4c: the pod's plan by name, or "" */
    json_escape(f, g_nr.plan);
    fprintf(f, "\",\"launcher\":%s,\"pod_dns\":\"%s\"", g_nr.launcher ? "true" : "false", g_nr.dns);
    if (g_nr.set_text) {                         /* the paths Landlock is given, each name */
        fputs(",\"launch_paths\":[", f);
        const char *s = g_nr.set_text;
        for (bool first = true; *s; first = false) {
            const char *e = strchr(s, '\n');
            char one[PATH_MAX];
            snprintf(one, sizeof one, "%.*s", (int)(e - s), s);
            fputs(first ? "\"" : ",\"", f);
            json_escape(f, one);
            fputc('"', f);
            s = e + 1;
        }
        fputc(']', f);
    }
    fputs("},", f);
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
/* v1.36 step 6: the copies of the user's token and the agent's SVID, once
 * warden-secrets has read them (and at the supervisor's end) */
static void node_obo_forget(void) {
    if (g_node_obo_file[0]) { (void)unlink(g_node_obo_file); g_node_obo_file[0] = '\0'; }
    if (g_node_svid_file[0]) { (void)unlink(g_node_svid_file); g_node_svid_file[0] = '\0'; }
}

static void node_atexit(void) {
    if (g_nr.pidfd >= 0) (void)syscall(__NR_pidfd_send_signal, g_nr.pidfd, SIGKILL, NULL, 0);
    node_obo_forget();
}

/* The pod's uid, as a path component: hex digits and '-' */
static bool node_uid_ok(const char *u) {
    size_t k = 0;
    for (; u[k]; k++)
        if (!((u[k] >= '0' && u[k] <= '9') || (u[k] >= 'a' && u[k] <= 'f') || u[k] == '-')) return false;
    return k >= 8 && k <= 64;
}

/* The user's token, from the pod's varek-obo volume on the node, copied to
 * a file of root's alone. 0, or -1 with why. */
static int node_obo_token(char *why, size_t wn) {
    if (!node_uid_ok(g_nr.pod_uid)) {
        snprintf(why, wn, "the container's pod names no uid its token could be found by");
        return -1;
    }
    char vol[PATH_MAX], want[PATH_MAX], path[PATH_MAX + 16], real[PATH_MAX];
    int vl = snprintf(vol, sizeof vol, "%s/pods/%s/volumes/kubernetes.io~secret/" NODE_OBO_VOLUME, g_node_kubelet,
                      g_nr.pod_uid);
    if (vl < 0 || (size_t)vl >= sizeof vol) { snprintf(why, wn, "the kubelet's directory's path is too long"); return -1; }
    if (!realpath(vol, want)) {
        snprintf(why, wn, "its pod's token (Secret %.200s) is not on the node (%.300s: %s): the pod's init container "
                 NODE_OBO_VOLUME " mounts it, which VAREK's admission webhook adds (--node-kubelet names the kubelet's "
                 "directory)", g_nr.obo, vol, strerror(errno));
        return -1;
    }
    /* the key is a link into the kubelet's ..data, inside the volume */
    snprintf(path, sizeof path, "%s/" NODE_OBO_KEY, vol);
    size_t wl = strlen(want);
    if (!realpath(path, real) || strncmp(real, want, wl) || real[wl] != '/') {
        snprintf(why, wn, "its pod's token volume holds no key " NODE_OBO_KEY " inside it (%.300s)", path);
        return -1;
    }
    int fd = open(real, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_size <= 0 ||
        st.st_size > NODE_OBO_MAX) {
        snprintf(why, wn, "its pod's token (%.300s) is not a file of root's of 1 to %d bytes", path, NODE_OBO_MAX);
        if (fd >= 0) close(fd);
        return -1;
    }
    static char tok[NODE_OBO_MAX];
    size_t n = 0;
    while (n < (size_t)st.st_size) {
        ssize_t r = read(fd, tok + n, (size_t)st.st_size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (n != (size_t)st.st_size) {
        explicit_bzero(tok, sizeof tok);
        snprintf(why, wn, "its pod's token (%.300s) could not be read whole", path);
        return -1;
    }
    if ((size_t)snprintf(g_node_obo_file, sizeof g_node_obo_file, "%s/%.128s.obo", g_node_sock_dir, g_nr.id) >=
        sizeof g_node_obo_file) {
        explicit_bzero(tok, sizeof tok);
        g_node_obo_file[0] = '\0';
        snprintf(why, wn, "the node agent's socket directory's path is too long");
        return -1;
    }
    (void)unlink(g_node_obo_file);
    int out = open(g_node_obo_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok = out >= 0 && write(out, tok, n) == (ssize_t)n && fsync(out) == 0;
    explicit_bzero(tok, sizeof tok);
    if (out >= 0) close(out);
    if (!ok) {
        snprintf(why, wn, "cannot keep its pod's token for warden-secrets (%.300s: %s)", g_node_obo_file, strerror(errno));
        node_obo_forget();
        return -1;
    }
    return 0;
}

/* The agent's SVID, from the node's SPIRE agent by the container's process
 * id (varek-svid, its lines in the stream). 0, or -1 with why. */
static int node_obo_svid(char *why, size_t wn) {
    char bin[PATH_MAX];
    if (g_node_svid_bin) snprintf(bin, sizeof bin, "%s", g_node_svid_bin);
    else {
        ssize_t k = proc_readlinkf(bin, sizeof bin - 16, "self/exe");
        if (k <= 0) { snprintf(why, wn, "cannot find this binary's directory"); return -1; }
        bin[k] = '\0';
        char *sl = strrchr(bin, '/');
        snprintf(sl ? sl + 1 : bin, sizeof bin - (size_t)(sl ? sl + 1 - bin : 0), "varek-svid");
    }
    if ((size_t)snprintf(g_node_svid_file, sizeof g_node_svid_file, "%s/%.128s.svid", g_node_sock_dir, g_nr.id) >=
        sizeof g_node_svid_file) {
        g_node_svid_file[0] = '\0';
        snprintf(why, wn, "the node agent's socket directory's path is too long");
        return -1;
    }
    (void)unlink(g_node_svid_file);
    char pid[16];
    snprintf(pid, sizeof pid, "%d", (int)g_nr.pid);
    pid_t c = fork();
    if (c < 0) { snprintf(why, wn, "cannot start varek-svid (%s)", strerror(errno)); return -1; }
    if (c == 0) {
        dup2(STDERR_FILENO, STDOUT_FILENO);
        if (g_node_spire_self)
            execl(bin, "varek-svid", "-socket", g_node_spire, "-pid", pid, "-out", g_node_svid_file,
                  "-not", g_node_spire_self, (char *)NULL);
        else
            execl(bin, "varek-svid", "-socket", g_node_spire, "-pid", pid, "-out", g_node_svid_file, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    while (waitpid(c, &st, 0) < 0 && errno == EINTR) ;
    struct stat fs;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || lstat(g_node_svid_file, &fs) < 0 || !S_ISREG(fs.st_mode) ||
        fs.st_uid != 0 || (fs.st_mode & 077)) {
        snprintf(why, wn, "cannot get the pod's SVID from the node's SPIRE agent (%.200s %s, above)", bin,
                 WIFEXITED(st) ? (WEXITSTATUS(st) == 127 ? "did not start" : "refused") : "was killed");
        node_obo_forget();
        return -1;
    }
    return 0;
}

/* The pod's chain, as the Warden's --on-behalf-of and --agent-svid on a
 * host: the user's token when its pod names one (varek.dev/on-behalf-of,
 * required by `require on-behalf-of`), the agent's SVID when the policy
 * trusts a SPIFFE trust domain and the node agent has SPIRE's socket. The
 * paths are the copies', or NULL. node_fail on what refuses the start. */
static void node_obo(const struct policy *p, const char **obo, const char **svid) {
    char why[700];
    *obo = *svid = NULL;
    if (p->v.require_obo && !g_nr.obo[0])
        node_fail("its policy says `require on-behalf-of`, and its pod names no user's token (varek.dev/on-behalf-of: "
                  "the Secret it is in)");
    if (g_nr.obo[0]) {
        if (node_obo_token(why, sizeof why) < 0) node_fail(why);
        *obo = g_node_obo_file;
    }
    if (p->v.nspiffe && g_node_spire) {
        if (node_obo_svid(why, sizeof why) < 0) node_fail(why);
        *svid = g_node_svid_file;
    }
}

/* v1.36 step 7 (D6, D7, D7b): what the pod's VarekPolicy says beyond its
 * policy, from the plugin's annotations, as the Warden takes it on a host:
 * the dry run (--dry-run); the trust bundle, the key of that name in the
 * ConfigMap mounted at --node-trust-bundles DIR (--trust-bundle DIR/KEY,
 * read by trust_setup in the node's view, before the container's is
 * entered); and for a flow policy the breaker's table under
 * --node-flow-state DIR (the node's, a host path, as the streams are: the
 * budget bounds each node) and its session, the pod's namespace and service
 * account (namespace/name), which the plugin takes from the API server and
 * the pod's author does not choose. node_fail on what refuses the start. */
static const char *g_node_trust_dir;               /* --node-trust-bundles */
static const char *g_node_flow_state;              /* --node-flow-state */
static void node_inputs(const char *flow_path, const char **session, const char **state) {
    static char tb[PATH_MAX], sess[160], st[PATH_MAX];
    if (g_nr.dry) g_dry = true;
    if (g_nr.trust[0]) {
        if (!g_node_trust_dir)
            node_fail("its policy names a trust bundle (varek.dev/trust-bundle), and the node agent was given no "
                      "directory of them (--node-trust-bundles: the chart's trustBundles.configMap)");
        if ((size_t)snprintf(tb, sizeof tb, "%s/%s", g_node_trust_dir, g_nr.trust) >= sizeof tb)
            node_fail("the trust bundle's path is too long");
        struct stat ts;
        int e = stat(tb, &ts) < 0 ? errno : 0;
        if (e || !S_ISREG(ts.st_mode)) {
            char why[PATH_MAX + 160];
            snprintf(why, sizeof why, "its trust bundle %.253s is not in the node's ConfigMap (%.300s: %s)", g_nr.trust,
                     tb, e ? strerror(e) : "not a file");
            node_fail(why);
        }
        g_trust_bundle_arg = tb;
    }
    if (!flow_path) return;
    if (!g_nr.sa[0] || !node_label(g_nr.pod_ns))
        node_fail("its policy has a flow policy, and the container names no service account (varek.dev/service-account, "
                  "the NRI plugin's from the API server): the breaker's session");
    if ((size_t)snprintf(sess, sizeof sess, "%s/%s", g_nr.pod_ns, g_nr.sa) > 128)
        node_fail("the breaker's session (the pod's namespace/service account) is longer than 128 characters");
    *session = sess;
    if (!g_node_flow_state)
        node_fail("its policy has a flow policy, and the node agent was given no directory for the breaker's table "
                  "(--node-flow-state: the chart's flowPolicy.stateDir)");
    if ((size_t)snprintf(st, sizeof st, "%s/breaker.state", g_node_flow_state) >= sizeof st)
        node_fail("--node-flow-state: the path is too long");
    *state = st;
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
 * large state can come in parts), at most 1 MiB, all within 5 s. The length,
 * or -1 (and *nfd the descriptors received, to close). */
#define NODE_STATE_MAX (1 << 20)
/* the time left of a connection's 5 s, for poll(2): 0 when it is spent */
static int node_left_ms(const struct timespec *end) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long ms = (long long)(end->tv_sec - now.tv_sec) * 1000 + (end->tv_nsec - now.tv_nsec) / 1000000;
    return ms <= 0 ? 0 : (int)ms;
}

/* readable within the connection's time left (review: a per-read timeout let
 * a peer sending a byte at a time hold the listener, and so every container
 * after it, for as long as it liked) */
static bool node_wait(int c, const struct timespec *end) {
    for (;;) {
        int ms = node_left_ms(end);
        if (ms == 0) return false;
        struct pollfd p = { .fd = c, .events = POLLIN };
        int r = poll(&p, 1, ms);
        if (r < 0 && errno == EINTR) continue;
        return r > 0;
    }
}

static ssize_t node_receive(int c, char *buf, size_t cap, int *fds, int *nfd) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += 5;
    *nfd = 0;
    if (!node_wait(c, &end)) return -1;
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    struct iovec iov = { buf, cap };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    ssize_t r;
    for (;;) {
        r = recvmsg(c, &m, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && errno == EAGAIN && node_wait(c, &end)) continue;
        break;
    }
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
        if (!node_wait(c, &end)) return -1;   /* the 5 s spent */
        ssize_t q = recv(c, buf + n, cap - n, MSG_DONTWAIT);
        if (q < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (q < 0) return -1;
        if (q == 0) return (ssize_t)n;
        n += (size_t)q;
    }
    return -1;                                /* past the cap */
}

/* Listen for the runtime. Returns 0 in each supervisor (one per container,
 * set up to continue the Warden's start as for a run) and -1 if the listener
 * cannot be made; the node agent itself never returns otherwise. */
static int node_listen(const char *sock_path, const char *streams, const char *launcher, const char **policy_path,
                       const char **plan_path, const char **flow_path) {
    int sd = open(streams, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (sd < 0) { fprintf(stderr, "[warden] --node-streams %s: %s\n", streams, strerror(errno)); return -1; }
    /* v1.34 step 3: a directory of policies, chosen by name per container,
     * or one policy file for every container; root's, written by no one else */
    struct stat ps;
    if (stat(*policy_path, &ps) < 0) { fprintf(stderr, "[warden] %s: %s\n", *policy_path, strerror(errno)); return -1; }
    if (S_ISDIR(ps.st_mode)) {
        if (ps.st_uid != 0 || (ps.st_mode & 022)) {
            fprintf(stderr, "[warden] the policies' directory %s must be root's, written by no one else\n", *policy_path);
            return -1;
        }
        g_node_policies = *policy_path;
    }
    /* the launcher the plugin binds at /varek/init: root's, written by no
     * one else, known by its device and inode */
    if (launcher) {
        int lf = open(launcher, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        struct stat ls;
        if (lf < 0 || fstat(lf, &ls) < 0 || !S_ISREG(ls.st_mode) || ls.st_uid != 0 || (ls.st_mode & 022) ||
            !(ls.st_mode & 0111)) {
            fprintf(stderr, "[warden] --node-launcher %s: must be an executable file, root's, written by no one else%s%s\n",
                    launcher, lf < 0 ? ": " : "", lf < 0 ? strerror(errno) : "");
            if (lf >= 0) close(lf);
            return -1;
        }
        close(lf);
        g_node_have_launcher = true;
        g_node_launcher_dev = ls.st_dev;
        g_node_launcher_ino = ls.st_ino;
    }
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
    /* v1.36 step 6: where the copies of a pod's token and SVID are kept */
    if (!realpath(dir, g_node_sock_dir)) {
        fprintf(stderr, "[warden] --node-agent %s: %s\n", dir, strerror(errno));
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
    fprintf(stderr, "[warden] node agent: listening on %s; streams in %s; %s %s; launcher %s\n", sock_path, streams,
            g_node_policies ? "policies by name from" : "one policy,", *policy_path, launcher ? launcher : "none");
    static char buf[NODE_STATE_MAX + 1];
    for (;;) {
        if (g_node_chld) node_reap();
        int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR || errno == ECONNABORTED) continue; perror("[warden] accept"); continue; }
        struct node_peer peer;
        node_peer_read(c, &peer);   /* first: the runtime may end once it has sent the state */
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
        int adm = node_admit(&peer, buf, (size_t)r, fds[0], &pid, &pidfd, why, sizeof why);
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
        char sbase[200], sname[256];
        snprintf(sbase, sizeof sbase, "%s.%d", ok == 0 ? g_nr.id : "unknown", (int)getpid());
        snprintf(sname, sizeof sname, "%s.jsonl", sbase);
        int so = openat(sd, sname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (so < 0 || dup2(so, STDERR_FILENO) < 0) node_fail("cannot open its stream");
        close(so);
        if (ok == 0) ok = node_policy(buf, (size_t)r, policy_path, why, sizeof why);
        if (ok == 0) ok = node_copy(sd, streams, sbase, "policy", ".policy", g_nr.policy_sha, policy_path,
                                    why, sizeof why);                                        /* step 5 */
        if (ok == 0) ok = node_plan(buf, (size_t)r, plan_path, why, sizeof why);            /* v1.35 step 4c */
        if (ok == 0 && *plan_path) {
            ok = node_copy(sd, streams, sbase, "plan", ".plan", g_nr.plan_sha, plan_path, why, sizeof why);
            g_hold_req = true;                  /* D11: a pod's plan holds its run (D2) */
        }
        if (ok == 0) ok = node_flow(flow_path, why, sizeof why);                          /* v1.36 step 7 */
        if (ok == 0 && *flow_path)
            ok = node_copy(sd, streams, sbase, "flow policy", ".flow", g_nr.flow_sha, flow_path, why, sizeof why);
        close(sd);
        if (ok == 0) ok = node_config(why, sizeof why);
        if (ok == 0) ok = node_process(why, sizeof why);
        if (ok == 0 && node_alive(g_nr.pidfd)) node_dns();
        /* v1.36 step 4 (D1): the node agent's own network namespace, held for
         * warden-secrets, before the supervisor enters the pod's */
        if (ok == 0 && (g_nr.node_netns = proc_openf(O_RDONLY | O_CLOEXEC, 0, "self/ns/net")) < 0) {
            snprintf(why, sizeof why, "cannot hold the node's network namespace (%s)", strerror(errno));
            ok = -1;
        }
        if (ok == 0 && node_enter(CLONE_NEWNET) < 0) {
            snprintf(why, sizeof why, "cannot enter the container's network namespace (%s)", strerror(errno));
            ok = -1;
        }
        if (ok < 0) node_fail(why);
        atexit(node_atexit);
        return 0;
    }
}


/* ---- v1.34 step 3: the launcher and D4 ---- */

/* /varek/init in the container's view is the node's launcher, mounted
 * read-only (the plugin's bind of --node-launcher). 0, or -1 with why. */
static int node_launcher_check(char *why, size_t wn) {
    struct stat st;
    struct statvfs sv;
    if (lstat(NODE_LAUNCHER, &st) < 0 || !S_ISREG(st.st_mode) || st.st_dev != g_node_launcher_dev ||
        st.st_ino != g_node_launcher_ino) {
        snprintf(why, wn, NODE_LAUNCHER " in the container is not the node's launcher (--node-launcher)");
        return -1;
    }
    if (statvfs(NODE_LAUNCHER, &sv) < 0 || !(sv.f_flag & ST_RDONLY)) {
        snprintf(why, wn, NODE_LAUNCHER " is not mounted read-only in the container");
        return -1;
    }
    return 0;
}

/* Whether the process runs the node's launcher (its executable, through the
 * node's /proc) */
static bool node_runs_launcher(pid_t pid) {
    struct stat st;
    return proc_statf(&st, "%d/exe", pid) == 0 && st.st_dev == g_node_launcher_dev && st.st_ino == g_node_launcher_ino;
}

/* One of the container's mounts, from its mountinfo */
struct node_mnt {
    unsigned maj, min;
    char    *root, *mp;
    bool     ro, noexec, kernel, mask;
};

static bool node_opt(const char *opts, const char *o) {
    size_t ol = strlen(o);
    for (const char *s = opts; s && *s; ) {
        const char *c = strchr(s, ',');
        size_t l = c ? (size_t)(c - s) : strlen(s);
        if (l == ol && !strncmp(s, o, ol)) return true;
        s = c ? c + 1 : NULL;
    }
    return false;
}

/* a and b name one directory, or one is beneath the other */
static bool node_overlap(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b), l = al < bl ? al : bl;
    if (strncmp(a, b, l)) return false;
    if (al == bl) return true;
    const char *lg = al > bl ? a : b;
    return l == 1 || lg[l] == '/';               /* "/" holds everything */
}

/* D4, as the descriptor arrives (in the container's mount namespace, before
 * any of its code runs): the root read-only; every writable mount noexec,
 * except a kernel file system nothing can be written to as a program (proc,
 * sysfs, cgroup, mqueue, devpts) and a runtime's mask (a character device
 * bound over a /proc or /sys entry); and no mount that allows execution
 * showing files a writable mount can change (the same file system, one root
 * at or beneath the other: a volume mounted twice). 0, or -1 with why. */
#define NODE_MOUNTS_MAX 1024
static int node_d4(char *why, size_t wn) {
    FILE *mi = proc_fopenf("%d/mountinfo", g_nr.pid);
    if (!mi) { snprintf(why, wn, "cannot read the container's mounts"); return -1; }
    static struct node_mnt m[NODE_MOUNTS_MAX];
    size_t nm = 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    static const char *const kKernel[] = { "proc", "sysfs", "cgroup", "cgroup2", "mqueue", "devpts", NULL };
    while (rc == 0 && getline(&line, &cap, mi) > 0) {
        /* id parent maj:min root mountpoint opts [optional...] - fstype source superopts */
        char *f[64];
        int nf = 0;
        char *save = NULL;
        for (char *t = strtok_r(line, " \n", &save); t && nf < 64; t = strtok_r(NULL, " \n", &save)) f[nf++] = t;
        int dash = -1;
        for (int k = 6; k < nf; k++) if (!strcmp(f[k], "-")) { dash = k; break; }
        if (nm == NODE_MOUNTS_MAX) { snprintf(why, wn, "the container has more than %d mounts", NODE_MOUNTS_MAX); rc = -1; break; }
        struct node_mnt *x = &m[nm];
        if (dash < 0 || dash + 3 >= nf || sscanf(f[2], "%u:%u", &x->maj, &x->min) != 2) {
            snprintf(why, wn, "the container's mounts cannot be read (a line of its mountinfo)");
            rc = -1;
            break;
        }
        noexec_unescape(f[3]);
        noexec_unescape(f[4]);
        x->root = strdup(f[3]);
        x->mp = strdup(f[4]);
        if (!x->root || !x->mp) { snprintf(why, wn, "out of memory"); rc = -1; break; }
        nm++;
        x->ro = node_opt(f[5], "ro") || node_opt(f[dash + 3], "ro");
        x->noexec = node_opt(f[5], "noexec");
        x->kernel = false;
        for (int k = 0; kKernel[k]; k++) if (!strcmp(f[dash + 1], kKernel[k])) x->kernel = true;
        struct stat st;
        x->mask = (!strncmp(x->mp, "/proc/", 6) || !strncmp(x->mp, "/sys/", 5)) &&
                  lstat(x->mp, &st) == 0 && S_ISCHR(st.st_mode);
    }
    free(line);
    fclose(mi);
    bool root_seen = false;
    for (size_t i = 0; rc == 0 && i < nm; i++) {
        const struct node_mnt *x = &m[i];
        if (!strcmp(x->mp, "/")) {
            root_seen = true;
            if (!x->ro) {
                snprintf(why, wn, "the container's root file system is writable (D4: readOnlyRootFilesystem: true)");
                rc = -1;
            }
            continue;
        }
        if (x->kernel || x->mask || x->ro || x->noexec) continue;
        snprintf(why, wn, "the container's writable mount %.300s is not noexec (D4; the NRI plugin makes it so)", x->mp);
        rc = -1;
    }
    if (rc == 0 && !root_seen) { snprintf(why, wn, "the container's mounts show no root"); rc = -1; }
    for (size_t i = 0; rc == 0 && i < nm; i++) {
        const struct node_mnt *x = &m[i];
        if (x->kernel || x->mask || x->noexec) continue;               /* nothing written there runs */
        for (size_t j = 0; rc == 0 && j < nm; j++) {
            const struct node_mnt *w = &m[j];
            if (w->ro || w->kernel || w->mask || w->maj != x->maj || w->min != x->min ||
                !node_overlap(w->root, x->root)) continue;
            snprintf(why, wn, "the container's mount %.200s allows execution and shows files its writable mount "
                     "%.200s can change (one volume mounted twice; D4)", x->mp, w->mp);
            rc = -1;
        }
    }
    for (size_t i = 0; i < nm; i++) { free(m[i].root); free(m[i].mp); }
    return rc;
}

/* The launch set the launcher reads: each file's path in the container's
 * view, one a line, in a sealed memfd. Landlock is applied to each path, so
 * a file's other names (hardlinks: on the overlay file system a container's
 * root is, a rule on one name of a file does not cover another) are not in
 * it. 0, or -1 with why. */
static int node_set_view(char *why, size_t wn) {
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) { snprintf(why, wn, "out of memory"); return -1; }
    /* v1.36 step 7 (D6): a dry run's set is / alone (Landlock's rule is
     * beneath a directory: every file), as a host's dry run applies none */
    if (g_dry) fputs("/\n", f);
    for (size_t k = 0; !g_dry && k < g_exec_n + g_exec_nalias; k++) {
        const char *pk = k < g_exec_n ? g_exec_rs[k].path : g_exec_alias[k - g_exec_n];
        bool dup = false;
        for (size_t j = 0; j < k && !dup; j++) dup = !strcmp(j < g_exec_n ? g_exec_rs[j].path : g_exec_alias[j - g_exec_n], pk);
        if (dup) continue;
        if (pk[0] != '/' || strchr(pk, '\n')) {
            fclose(f);
            free(buf);
            snprintf(why, wn, "the launch set holds a path the launcher cannot read (a newline in it)");
            return -1;
        }
        fprintf(f, "%s\n", pk);
    }
    if (fclose(f) != 0) { free(buf); snprintf(why, wn, "out of memory"); return -1; }
    int fd = memfd_create("launch_set_view", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    bool ok = fd >= 0 && fchmod(fd, 0444) == 0 && write_all(fd, buf, len) == 0 &&
              fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0;
    g_nr.set_text = buf;                         /* run_start's "launch_paths" */
    if (!ok) {
        if (fd >= 0) close(fd);
        snprintf(why, wn, "cannot make the launch set's view (%s)", strerror(errno));
        return -1;
    }
    g_nr.set_view = fd;
    return 0;
}

/* The launcher's open of its launch set, answered from the view: true when
 * the call was answered. Any other call of the launcher is let through. */
static bool node_launcher_open(int notify_fd, const struct seccomp_notif *req) {
    if (req->data.nr != __NR_openat && req->data.nr != __NR_openat2
#ifdef __NR_open
        && req->data.nr != __NR_open
#endif
        ) return false;
    static struct action a;
    if (derive_intent(req, &a) < 0 || a.kind != ACT_FILE_OPEN || strcmp(a.target, NODE_SET_VIEW) ||
        !node_runs_launcher((pid_t)req->pid)) return false;
    int fd = proc_openf(O_RDONLY, 0, "self/fd/%d", g_nr.set_view);         /* its own offset */
    if (fd < 0 || !notif_id_valid(notify_fd, req->id) || inject_fd(notify_fd, req->id, fd) != 0)
        send_errno(notify_fd, req->id, EACCES);
    if (fd >= 0) close(fd);
    g_nr.launcher_calls++;
    return true;
}

/* A launch before the container's command (the bootstrap): the runtime's of
 * /varek/init, let through; then the launcher's of the command, which is the
 * bootstrap (false: the caller goes on to it). Anything else ends the
 * container. true when the call was answered. */
static int node_launcher_exec(int notify_fd, const struct seccomp_notif *req, const struct action *a,
                              const char *bootstrap_path, bool by_fd) {
    char why[PATH_MAX + 160];
    if ((pid_t)req->pid != g_nr.pid) node_fail("a launch before the container's command, not by its init");
    /* v1.36 step 6 (found by the sweep, once in 97 runs): the runtime's launch
     * of /varek/init, let through, can be restarted by the kernel before it
     * takes (a signal at its credential lock gives -ERESTARTNOINTR, and the
     * runtime's init is Go, whose preemption signals it), and so is notified
     * again. The process then still runs the runtime's init, not the
     * launcher: no code of the container's, or of the launcher's, has run. It
     * is the runtime's launch again, checked as the first was. */
    if (g_nr.in_launcher && !node_runs_launcher((pid_t)req->pid)) g_nr.in_launcher = false;
    if (!g_nr.in_launcher) {
        if (by_fd || strcmp(a->target, NODE_LAUNCHER)) {
            snprintf(why, sizeof why, "before the launcher, the container's init launched \"%.*s\", not " NODE_LAUNCHER,
                     PATH_MAX, by_fd ? "(a descriptor)" : a->target);
            node_fail(why);
        }
        /* the runtime's own launch, of the file checked to be the node's
         * launcher (node_launcher_check), on a read-only mount */
        struct seccomp_notif_resp r = { .id = req->id, .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE };
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &r) == 0) g_nr.in_launcher = true;
        return 1;                       /* (not taken: interrupted, the kernel restarts it) */
    }
    if (by_fd || strcmp(a->target, bootstrap_path)) {
        snprintf(why, sizeof why, "the launcher launched \"%.*s\", not the container's command", PATH_MAX,
                 by_fd ? "(a descriptor)" : a->target);
        node_fail(why);
    }
    /* the launcher's launch is answered with CONTINUE, as the Warden's own
     * child's is on a host: sound while nothing else can change the path it
     * names, so the caller runs the launcher, single-threaded */
    if (!node_runs_launcher((pid_t)req->pid))
        node_fail("the container's command was launched by a process that does not run the launcher");
    if (node_status_field((pid_t)req->pid, "Threads:") != 1)
        node_fail("the launcher is not single-threaded at the container's command");
    return 0;
}

/* The container's supervision, where a run forks its agent (main): into the
 * container's mount namespace, now that the node's files are open, then the
 * descriptor supervised as a run's. Returns the Warden's exit status. */
static int node_supervise(const struct policy *p, const char *boot_path, const char *policy_path,
                          const char *plan_path, plan_parsed_t *plan, const char *plan_err) {
    if (node_enter(CLONE_NEWNS) < 0) {
        char why[160];
        snprintf(why, sizeof why, "cannot enter the container's mount namespace (%s)", strerror(errno));
        node_fail(why);
    }
    /* the container's /proc is its PID namespace's: its init's */
    if ((g_view_depth = pidns_depth(g_nr.pid)) < 0 || !node_alive(g_nr.pidfd))
        node_fail("cannot read the container's PID namespace (NSpid)");
    g_view_container = true;
    /* v1.34 step 4: the views are the container's names: what each resolves
     * to in its view (views_setup ran in the node's) */
    if (g_any_name || g_inspect_on) views_setup();
    /* v1.34 step 3: the launcher, D4 and the launch set, in the container's
     * view, before any of its code runs; the Warden's own filter for the
     * policy, by which the calls the pod's filter notifies for the runtime
     * are answered once the command runs */
    char why[600];
    /* v1.36 step 7 (D6): a dry run's, as the plugin's (--oci-filter --dry-run):
     * a call outside the allowlist is notified, and goes to the kernel */
    if (wd_filter_bpf((p->v.open_as_agent ? WD_FILTER_CHANGES : 0) | (g_dry ? WD_FILTER_DRY : 0), &g_nr.bpf,
                      &g_nr.nbpf) < 0)
        node_fail("cannot compile the Warden's filter for the policy");
    if (g_nr.launcher && node_launcher_check(why, sizeof why) < 0) node_fail(why);
    /* v1.36 step 7 (D6): a dry run holds no launch, as on a host (no
     * Landlock, no noexec mounts: the plugin adds none), so D4 is not held */
    if (p->v.launches && !g_dry && node_d4(why, sizeof why) < 0) node_fail(why);
    if (g_nr.launcher) {
        g_exec_rules_off = !p->v.launches;      /* the command alone, when the policy decides no launch */
        if (exec_ruleset_build(p, boot_path) < 0 || (p->v.launches && exec_confined_checks(p) < 0))
            node_fail("the launch set cannot be built (above)");
        if (g_ll_abi < 1)
            node_fail("the node has no Landlock: the launcher could not hold the container to its launch set");
        if (p->v.launches && !g_dry) {
            if (noexec_build(p, boot_path) < 0) node_fail("the directories the agent may write (above)");
            if (g_nxi_n)
                node_fail("a program the policy allows to launch is under a directory it may write: kept executable "
                          "on a host, it cannot be in a pod (D4: every writable mount noexec)");
        }
        if (node_set_view(why, sizeof why) < 0) node_fail(why);
        if (g_dry)
            fprintf(stderr, "[warden] launch set: %zu files, decided and recorded; not held (dry run: the launcher's "
                    "Landlock is given /, every file)\n", g_exec_n);
        else
            fprintf(stderr, "[warden] launch set: %zu files, held by the launcher's Landlock (ABI %d)\n", g_exec_n,
                    g_ll_abi);
    }
    /* the pod's network namespace is the Warden's own now: both held, the
     * same, so a socket made "in the agent's" and the stub resolver's are the
     * pod's (warden_net.inc.c, warden_stub.inc.c) */
    g_host_netns = proc_openf(O_RDONLY, 0, "self/ns/net");
    g_agent_netns = proc_openf(O_RDONLY, 0, "self/ns/net");
    if (g_host_netns < 0 || g_agent_netns < 0) node_fail("cannot hold the pod's network namespace");
    g_netns_separate = true;
    sockref_warm();
    stub_setup();                     /* v1.34 step 4: before run_start, which names its address */
    emit_run_start(policy_path, p);
    /* v1.34 step 4: the names resolved, from the pod's network, the first
     * records after run_start as on a host (the helper started in main) */
    if (g_names_on) names_resolve_all(true);
    /* v1.35 step 4c (D11): the pod's plan, decided as on a host (its
     * records after run_start), in the container's view and with its launch
     * set; refused, the container ends; passed, the run is held to it (D2) */
    if (plan_path) {
        g_hold_collect = true;
        /* v1.36 step 7 (D7b): with a flow policy, its gate and breaker, the
         * node's table (node_inputs), as on a host */
        int gate = g_flow_cfg ? warden_gate_plan_flow_parsed(plan, plan_err, plan_path, p)
                              : warden_verify_plan_parsed(plan, plan_err, plan_path, p, true);
        if (gate != 0) {
            emit_run_end(g_flow_cfg ? gate : 1);
            node_fail(g_flow_cfg ? "its plan is refused by its flow policy's gate (the plan_gate record above; the "
                                   "breaker counts the refusal)"
                                 : "its plan is refused (the plan_step and plan_gate records above)");
        }
        g_hold_collect = false;
        g_hold_on = true;
        fprintf(stderr, "[warden] the run is held to its plan %s: %zu entries; a call the policy allows outside "
                "them is refused (outside_plan)\n", g_nr.plan, g_nhold);
    }
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max < 65536 ? rl.rlim_max : 65536;
        (void)setrlimit(RLIMIT_NOFILE, &rl);
    }
    /* the container's init watched by the pidfd held since its state arrived
     * (review: not one opened again by its number) */
    int target_pidfd = fcntl(g_nr.pidfd, F_DUPFD_CLOEXEC, 0);
    if (target_pidfd < 0) node_fail("cannot watch the container's process");
    fprintf(stderr, "[warden] supervising container %s (pod %s/%s) pid=%d policy=%s (%zu rules)%s%s uid=%u\n",
            g_nr.id, g_nr.pod_ns, g_nr.pod_name, (int)g_nr.pid, p->name, p->v.n, g_nr.plan[0] ? " plan=" : "",
            g_nr.plan, (unsigned)g_nr.uid);
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
