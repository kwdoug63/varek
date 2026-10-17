/*
 * warden_asagent.inc.c — v1.29 step 1: opening files as the agent (included
 * by warden.c, before resolve_target, which calls it).
 * docs/security/v1.29-varek-run.md, section 1, D4.
 *
 * Through v1.28 the Warden resolved and opened every file it handed the agent
 * as root: a file the agent created was root's, and a root-owned file under a
 * tree the policy lets the agent write was writable whatever its mode. Under
 * `require warden 1.29` (vdp_policy_t.open_as_agent) the resolution's walk and
 * the open run with the agent's filesystem user and group and its user's
 * supplementary groups, so the kernel's own checks (search permission on each
 * directory walked, the file's mode) apply on top of the decision, and a file
 * the agent creates is its own.
 *
 * Only the thread that resolves and opens changes, and only for those calls:
 * setfsuid, setfsgid and setgroups are made as raw system calls, which change
 * the calling thread's credentials alone (glibc's wrappers would change every
 * thread's). Moving the filesystem user off 0 drops the filesystem
 * capabilities (CAP_DAC_OVERRIDE, CAP_FOWNER, ...) from the effective set;
 * moving it back restores them. Every switch back is verified, and a Warden
 * that cannot verify it stops: it never goes on writing its stream or reading
 * its key with the agent's credentials.
 *
 * The agent itself keeps no supplementary groups (v1.17's drop): its own
 * calls the kernel carries out (lookups, launches) are made without them. The
 * groups are used for the opens the Warden makes for it, which the policy must
 * allow as well, so they never widen what the agent reaches beyond v1.28.
 *
 * With --run-as root the agent is root, and files are opened as root, as
 * before; run_start says so.
 */

#define AS_AGENT_MAX_GROUPS 256

static struct {
    bool  on;                          /* opens and their walk run as the agent */
    bool  policy;                      /* the policy asked for it (require warden 1.29) */
    uid_t uid;
    gid_t gid;
    int   ngroups;
    gid_t groups[AS_AGENT_MAX_GROUPS];
    int   nroot;                       /* the Warden's own supplementary groups, restored */
    gid_t root_groups[AS_AGENT_MAX_GROUPS];
    bool  inside;                      /* between as_agent_enter and as_agent_leave */
} g_as;

/* At startup, once the policy and --run-as are read: 0, or -1 (the reason
 * printed). name is --run-as as given (NULL: nobody); a name gets that user's
 * supplementary groups, a number (uid or uid:gid) none beyond its group. */
static int as_agent_setup(bool policy_on, bool drop, uid_t uid, gid_t gid, const char *name) {
    g_as.policy = policy_on;
    g_as.on = policy_on && drop;
    if (!g_as.on) return 0;
    g_as.uid = uid;
    g_as.gid = gid;
    g_as.ngroups = 0;
    struct passwd *pw = name && !(name[0] >= '0' && name[0] <= '9') ? getpwnam(name) : NULL;
    if (pw) {
        int n = AS_AGENT_MAX_GROUPS;
        if (getgrouplist(pw->pw_name, gid, g_as.groups, &n) < 0) {
            fprintf(stderr, "[warden] --run-as %s: the user is in more than %d groups; opening files as "
                    "the agent (require warden 1.29) is refused\n", name, AS_AGENT_MAX_GROUPS);
            return -1;
        }
        g_as.ngroups = n;
    } else {
        g_as.groups[0] = gid;
        g_as.ngroups = 1;
    }
    for (int i = 0; i < g_as.ngroups; i++)
        if (g_as.groups[i] == 0) {
            fprintf(stderr, "[warden] --run-as %s: the user is in group 0 (root); opening files as the "
                    "agent (require warden 1.29) with group root is refused\n", name ? name : "nobody");
            return -1;
        }
    int r = getgroups(AS_AGENT_MAX_GROUPS, g_as.root_groups);
    if (r < 0) {
        fprintf(stderr, "[warden] cannot read the Warden's own groups (%s)\n", strerror(errno));
        return -1;
    }
    g_as.nroot = r;
    return 0;
}

/* Stop: the thread's credentials could not be put back. */
static void as_agent_fatal(const char *what) {
    fprintf(stderr, "[warden] internal error: %s; stopping rather than go on with the agent's "
            "credentials\n", what);
    abort();
}

/* The thread takes the agent's filesystem credentials: 0, or -1 (errno set;
 * the thread's credentials are as they were). */
static int as_agent_enter(void) {
    if (!g_as.on) return 0;
    if (g_as.inside) as_agent_fatal("opening as the agent entered twice");
    if (syscall(SYS_setgroups, (size_t)g_as.ngroups, g_as.groups) != 0) return -1;
    (void)syscall(SYS_setfsgid, g_as.gid);
    (void)syscall(SYS_setfsuid, g_as.uid);
    /* setfsuid and setfsgid return the previous value, never an error: read
     * the values back to see that both took */
    if ((uid_t)syscall(SYS_setfsuid, (uid_t)-1) != g_as.uid ||
        (gid_t)syscall(SYS_setfsgid, (gid_t)-1) != g_as.gid) {
        (void)syscall(SYS_setfsuid, 0);
        (void)syscall(SYS_setfsgid, 0);
        if ((uid_t)syscall(SYS_setfsuid, (uid_t)-1) != 0 || (gid_t)syscall(SYS_setfsgid, (gid_t)-1) != 0 ||
            syscall(SYS_setgroups, (size_t)g_as.nroot, g_as.root_groups) != 0)
            as_agent_fatal("cannot restore the Warden's filesystem credentials");
        errno = EPERM;
        return -1;
    }
    g_as.inside = true;
    return 0;
}

/* Back to root's; verified, else the Warden stops. errno is kept. */
static void as_agent_leave(void) {
    if (!g_as.on) return;
    int saved = errno;
    (void)syscall(SYS_setfsuid, 0);
    (void)syscall(SYS_setfsgid, 0);
    if ((uid_t)syscall(SYS_setfsuid, (uid_t)-1) != 0 || (gid_t)syscall(SYS_setfsgid, (gid_t)-1) != 0 ||
        syscall(SYS_setgroups, (size_t)g_as.nroot, g_as.root_groups) != 0)
        as_agent_fatal("cannot restore the Warden's filesystem credentials");
    g_as.inside = false;
    errno = saved;
}

/* openat2_path as the agent (as root when opening as the agent is off) */
static int openat2_path_agent(int dirfd, const char *path, uint64_t extra_flags) {
    if (as_agent_enter() < 0) return -1;
    int fd = openat2_path(dirfd, path, extra_flags);
    as_agent_leave();
    return fd;
}

/* run_start: "open_as":{"agent":true,"uid":U,"gid":G,"groups":[...]} when
 * files are opened as the agent; {"agent":false,"why":"run_as_root"} when the
 * policy asked for it and the agent is root; nothing otherwise. */
static void as_agent_record(FILE *f) {
    if (!g_as.policy) return;
    if (!g_as.on) { fputs("\"open_as\":{\"agent\":false,\"why\":\"run_as_root\"},", f); return; }
    fprintf(f, "\"open_as\":{\"agent\":true,\"uid\":%u,\"gid\":%u,\"groups\":[", (unsigned)g_as.uid,
            (unsigned)g_as.gid);
    for (int i = 0; i < g_as.ngroups; i++) fprintf(f, "%s%u", i ? "," : "", (unsigned)g_as.groups[i]);
    fputs("]},", f);
}
