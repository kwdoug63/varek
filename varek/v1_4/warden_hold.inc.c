/* SPDX-License-Identifier: MIT */
/*
 * warden_hold.inc.c — v1.35 step 4 (D2, docs/security/v1.35-frameworks.md):
 * a run held to its plan (`--hold-to-plan`).
 *
 * The plan narrows the policy for this run: a call the policy allows (and
 * the checker certifies) is refused if no step of the plan covers it, with
 * the rule `outside_plan`; its record keeps the policy's verdict
 * (decision_raw) and names the plan. The decision procedure is unchanged:
 * the hold is applied after it, where each kind of call is finally
 * allowed, never instead of it, so it can only refuse.
 *
 * What is held, and what covers it (each step only for its own subject:
 * as=NAME, else the agent's, as its calls are decided, D6):
 *   - a file open, stat, access, readlink or change by name: a file_open
 *     step for the path, or for a directory above it (a target ending in
 *     '/'); a step with `open=read` covers reads only (no write access, no
 *     O_CREAT, O_TRUNC or O_APPEND, and no change by name). A stat, access
 *     or readlink of a directory above a covered path is covered too (a
 *     program checks the directories on its way), never its listing;
 *   - a connection (connect or sendto to an address, or a name:port the
 *     egress proxy reads): a net_connect step for that destination, or an
 *     mcp_call step for a server there;
 *   - a launch after the agent's own: a process_exec or subagent step for
 *     the program (its canonical name, as the launch and the step are each
 *     decided: a link followed, a hardlink by its own name);
 *   - an MCP call over HTTP: an mcp_call step for its object, or for its
 *     server and method when the step names no tool;
 *   - a request carrying a credential (credential=): a credential step for
 *     it. A request otherwise is held by its connection.
 * Not held: the agent's own launch, the Warden's synthetic views, name
 * lookups the stub resolver answers (for names the policy allows), binds.
 */

enum { HOLD_FILE = 1, HOLD_CONN, HOLD_EXEC, HOLD_MCP, HOLD_CRED };

struct hold_entry {
    int   kind;
    int   subj;                 /* the policy subject whose calls it covers */
    bool  dir;                  /* file: a directory, obj without its final '/' */
    bool  read_only;            /* file: open=read */
    bool  prefix;               /* mcp: the server and method, any tool */
    char *obj;
};

#define HOLD_MAX 1024           /* a plan has at most 256 steps, each at most two entries */
static struct hold_entry g_hold[HOLD_MAX];
static size_t g_nhold;
static bool   g_hold_req;       /* --hold-to-plan */
static bool   g_hold_collect;   /* the plan gate collects entries (--hold-to-plan) */
static char   g_hold_plan_sha[65];                 /* the plan file's SHA-256, for run_start */
static bool   g_hold_on;        /* the run is held (after the plan gate passed) */
static char   g_hold_plan_json[PATH_MAX * 2];   /* the plan's path, JSON-escaped, for records */

static void hold_add(int kind, int subj, const char *obj, bool dir, bool ro, bool prefix) {
    if (g_nhold >= HOLD_MAX || !obj) return;
    char *o = strdup(obj);
    if (!o) return;
    size_t n = strlen(o);
    if (dir && n > 1 && o[n - 1] == '/') o[n - 1] = '\0';
    g_hold[g_nhold++] = (struct hold_entry){ .kind = kind, .subj = subj, .dir = dir, .read_only = ro,
                                             .prefix = prefix, .obj = o };
}

/* A SATISFIED step's entries (warden_plan_decider): from what the step was
 * decided on, so a held call is matched as the step was decided */
static void hold_from_step(const plan_spec_action_t *a, const struct action *act, const struct plan_step_note *nt) {
    int subj = act->plan_psubj > 0 ? act->plan_psubj - 1 : 0;
    const char *k = a->kind ? a->kind : "";
    if (!strcmp(k, "credential")) { hold_add(HOLD_CRED, subj, a->target, false, false, false); return; }
    switch (act->kind) {
    case ACT_FILE_OPEN: {
        size_t tl = a->target ? strlen(a->target) : 0;
        bool dir = tl >= 1 && a->target[tl - 1] == '/';      /* step 9 (review): `file_open /` too */
        int acc = act->open_flags & O_ACCMODE;
        bool ro = act->flags_known && acc == O_RDONLY && !(act->open_flags & (O_CREAT | O_TRUNC | O_APPEND));
        hold_add(HOLD_FILE, subj, act->resolved, dir, ro, false);
        break;
    }
    case ACT_NET_CONNECT: hold_add(HOLD_CONN, subj, act->resolved, false, false, false); break;
    case ACT_PROCESS_EXEC: hold_add(HOLD_EXEC, subj, act->resolved, false, false, false); break;
    case ACT_NET_MCP: {
        size_t ol = strlen(act->resolved);
        hold_add(HOLD_MCP, subj, act->resolved, false, false, ol && act->resolved[ol - 1] == '#');
        if (nt->mcp_host[0]) hold_add(HOLD_CONN, subj, nt->mcp_host, false, false, false);
        break;
    }
    default: break;
    }
}

static bool hold_path_in(const char *path, const struct hold_entry *e) {
    size_t n = strlen(e->obj);
    if (!strcmp(path, e->obj)) return true;
    return e->dir && !strncmp(path, e->obj, n) && (n == 1 || path[n] == '/');
}

/* is the call covered by a step of the plan? */
static bool hold_covers(const struct action *a) {
    switch (a->kind) {                      /* step 9 (review): the kinds the hold narrows; any other is */
    case ACT_FILE_OPEN: case ACT_FILE_STAT: case ACT_FILE_ACCESS: case ACT_FILE_READLINK:
    case ACT_FILE_CHANGE: case ACT_NET_CONNECT: case ACT_NET_SEND: case ACT_NET_PROXY:
    case ACT_PROCESS_EXEC: case ACT_NET_MCP:
        break;
    default:
        return true;                        /* covered, whatever entries the subject has (none too) */
    }
    int subj = act_policy_subject(a);
    /* step 9 (review): a chdir is a lookup too (a directory above a step's path) */
    bool meta = a->kind == ACT_FILE_STAT || a->kind == ACT_FILE_ACCESS || a->kind == ACT_FILE_READLINK ||
                (a->kind == ACT_FILE_CHANGE && a->chg_op == CHG_CHDIR);
    bool write = a->kind == ACT_FILE_CHANGE && a->chg_op != CHG_CHDIR;
    if (a->kind == ACT_FILE_OPEN)
        write = (a->open_flags & O_ACCMODE) != O_RDONLY || (a->open_flags & (O_CREAT | O_TRUNC | O_APPEND));
    const char *s = a->resolved;
    for (size_t i = 0; i < g_nhold; i++) {
        const struct hold_entry *e = &g_hold[i];
        if (e->subj != subj) continue;
        switch (a->kind) {
        case ACT_FILE_OPEN: case ACT_FILE_STAT: case ACT_FILE_ACCESS: case ACT_FILE_READLINK:
        case ACT_FILE_CHANGE:
            if (e->kind != HOLD_FILE) break;
            if (hold_path_in(s, e) && !(write && e->read_only)) return true;
            /* a directory above a covered path: its metadata only */
            if (meta && s[0] == '/') {
                size_t n = strlen(s);
                if (!strncmp(e->obj, s, n) && (n == 1 || e->obj[n] == '/')) return true;
            }
            break;
        case ACT_NET_CONNECT: case ACT_NET_SEND: case ACT_NET_PROXY:
            if (e->kind == HOLD_CONN && !strcmp(s, e->obj)) return true;
            break;
        case ACT_PROCESS_EXEC:
            if (e->kind == HOLD_EXEC && !strcmp(s, e->obj)) return true;
            break;
        case ACT_NET_MCP:
            if (e->kind == HOLD_MCP &&
                (e->prefix ? !strncmp(s, e->obj, strlen(e->obj)) : !strcmp(s, e->obj))) return true;
            break;
        default:
            break;
        }
    }
    return false;
}

/* a request carrying credential c (1 + its index): is it a step of the plan? */
static bool hold_covers_cred(const struct policy *p, const struct action *a, int c) {
    if (c <= 0 || (size_t)c > p->v.ncreds) return true;
    int subj = act_policy_subject(a);
    for (size_t i = 0; i < g_nhold; i++)
        if (g_hold[i].kind == HOLD_CRED && g_hold[i].subj == subj && !strcmp(g_hold[i].obj, p->v.creds[c - 1].name))
            return true;
    return false;
}

/* After the policy's ALLOW (and the certificate): the hold. True when the
 * call is to be refused as outside the plan (the rule outside_plan; its
 * record names the plan, emit_pathology). */
static bool hold_refuses(struct action *a) {
    return g_hold_on && !hold_covers(a);
}

static bool hold_refuses_cred(const struct policy *p, struct action *a, int c) {
    return g_hold_on && !hold_covers_cred(p, a, c);
}

/* a launch: matched on the name it is decided on (exec_name: the name the
 * agent gave, made absolute, a final symlink's own), as the step was (step 9);
 * not on the launch set's entry, whose one name stands for every hardlink of
 * its file (v1.35 step 4c: busybox's /bin/cat was refused as /bin/sh's).
 * What is held is the file launched by that name, not what it does: a
 * multi-call binary (busybox) picks its applet from argv[0], which the agent
 * chooses, so a step naming /bin/cat on a busybox image launches a shell as
 * readily (step 9, review). A plan for such an image names the programs as
 * the policy does, for the file each is. */
static bool hold_refuses_exec(struct action *a, const char *canon) {
    if (!g_hold_on) return false;
    int subj = act_policy_subject(a);
    for (size_t i = 0; i < g_nhold; i++)
        if (g_hold[i].kind == HOLD_EXEC && g_hold[i].subj == subj && canon && !strcmp(g_hold[i].obj, canon))
            return false;
    return true;
}
