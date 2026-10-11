/* SPDX-License-Identifier: MIT
 * warden_noexec.inc.c — v1.27.1: the directories the policy lets the agent
 * write, to be mounted noexec where the Warden opens files
 * (docs/security/v1.27.1-writable-noexec.md). Included by warden.c.
 *
 * Step 1: the list, its refusals and its report. The two parsers agree on it
 * by construction: it is computed from each rule's verb, kind, matcher,
 * constant and flag clause, which policy_load has already required the
 * decision procedure and the certificate checker to read the same way. */

#define NOEXEC_MAX 256

struct noexec_dir {
    char *path;            /* canonical, absolute; a directory, or a file (an exact rule's) */
    int   line;            /* the policy line that makes it writable */
    bool  file;            /* a file, bind-mounted on itself */
};
static struct noexec_dir g_nx[NOEXEC_MAX];
static size_t g_nx_n;
static bool   g_writable_exec;      /* --writable-exec: the operator turned the mounts off (D2) */

/* Does path rule r allow some open that writes (an access mode of write or
 * read-write, O_TRUNC, or O_CREAT)? The flags a rule requires are its value;
 * the rest are free. Over-approximating is the safe direction: one more
 * directory not mapped executable. */
static bool noexec_rule_writable(const vdp_rule_t *r) {
    if (r->kind != VDP_KIND_PATH || r->verb != VDP_ALLOW) return false;
    static const uint32_t cand[] = {
        1u, 2u, (uint32_t)O_TRUNC, (uint32_t)O_CREAT, 1u | (uint32_t)O_TRUNC, 2u | (uint32_t)O_TRUNC, 1u | (uint32_t)O_CREAT, 2u | (uint32_t)O_CREAT,
        (uint32_t)O_CREAT | (uint32_t)O_TRUNC, 1u | (uint32_t)O_CREAT | (uint32_t)O_TRUNC, 2u | (uint32_t)O_CREAT | (uint32_t)O_TRUNC,
    };
    for (size_t k = 0; k < sizeof cand / sizeof cand[0]; k++) {
        uint32_t f = (cand[k] & ~r->b.mask) | r->b.value;
        if ((f & (uint32_t)O_ACCMODE) == 1u || (f & (uint32_t)O_ACCMODE) == 2u || (f & ((uint32_t)O_TRUNC | (uint32_t)O_CREAT)))
            return true;
    }
    return false;
}

/* Is p inside d (or d itself)? Both canonical. */
static bool noexec_under(const char *p, const char *d) {
    size_t n = strlen(d);
    if (n == 1 && d[0] == '/') return true;
    return !strncmp(p, d, n) && (p[n] == '\0' || p[n] == '/');
}

static void noexec_parent(char *s) {
    char *sl = strrchr(s, '/');
    if (sl == s) s[1] = '\0';
    else if (sl) *sl = '\0';
}

/* The directory (or file) one writable rule asks to mount, into out, or
 * an empty string to skip the rule (a constant that matches no absolute
 * path). -1: a rule that cannot be bounded (suffix, contains). */
static int noexec_target(const vdp_rule_t *r, char *out, size_t on) {
    const char *c = r->s.c;
    out[0] = '\0';
    switch (r->s.op) {
    case VDP_STR_SUFFIX:
    case VDP_STR_CONTAINS:
        return -1;
    case VDP_STR_EQ:
        if (c[0] != '/') return 0;
        snprintf(out, on, "%s", c);
        return 0;
    case VDP_STR_PREFIX: {
        if (c[0] != '/') return 0;
        snprintf(out, on, "%s", c);
        size_t n = strlen(out);
        if (n > 1 && out[n - 1] == '/') out[n - 1] = '\0';   /* a directory: itself */
        else noexec_parent(out);                             /* /work/out admits /work/out2 */
        return 0;
    }
    case VDP_STR_GLOB: {
        size_t k = 0;
        for (; c[k] && c[k] != '*' && c[k] != '?' && c[k] != '[' && c[k] != '\\' && k < on - 1; k++)
            out[k] = c[k];
        out[k] = '\0';
        if (out[0] != '/') { out[0] = '\0'; return -1; }     /* a glob from a wildcard: anywhere */
        if (c[k]) {                                          /* to the directory before the wildcard */
            char *sl = strrchr(out, '/');
            if (sl == out) out[1] = '\0'; else *sl = '\0';
        } else {
            size_t n = strlen(out);                          /* a glob with no wildcard: an exact path */
            if (n > 1 && out[n - 1] == '/') out[n - 1] = '\0';
        }
        return 0;
    }
    default:
        return 0;
    }
}

/* Build the list (launches on, the mounts not turned off). 0, or -1 with
 * the reason printed (the Warden does not start). */
static int noexec_build(const struct policy *p, const char *boot_path) {
    g_nx_n = 0;
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (!noexec_rule_writable(r)) continue;
        char t[PATH_MAX];
        if (noexec_target(r, t, sizeof t) < 0) {
            fprintf(stderr, "[warden] noexec: policy line %d lets the agent write paths no directory "
                    "bounds (a suffix, contains, or a glob that starts with a wildcard); name a "
                    "directory, or run with --writable-exec; refusing to start\n", r->line);
            return -1;
        }
        if (!t[0]) continue;
        char real[PATH_MAX];
        struct stat st;
        bool file = false;
        if (r->s.op == VDP_STR_EQ && realpath(t, real) && stat(real, &st) == 0 && !S_ISDIR(st.st_mode)) {
            file = true;                                     /* an existing file: itself (D3) */
        } else if (!realpath(t, real)) {
            if (r->s.op == VDP_STR_EQ) noexec_parent(t);     /* not there yet: its directory (D3) */
            if (r->s.op != VDP_STR_EQ || !realpath(t, real)) {
                fprintf(stderr, "[warden] note: noexec: policy line %d: %s does not exist; nothing "
                        "is mounted for it\n", r->line, t);
                continue;
            }
        }
        if (!strcmp(real, "/")) {
            fprintf(stderr, "[warden] noexec: policy line %d lets the agent write under /, which "
                    "cannot be mounted noexec; narrow the rule, or run with --writable-exec; "
                    "refusing to start\n", r->line);
            return -1;
        }
        if (g_nx_n == NOEXEC_MAX) {
            fprintf(stderr, "[warden] noexec: more than %d writable directories; refusing to start\n",
                    NOEXEC_MAX);
            return -1;
        }
        g_nx[g_nx_n].path = strdup(real);
        g_nx[g_nx_n].line = r->line;
        g_nx[g_nx_n].file = file;
        if (!g_nx[g_nx_n].path) { fprintf(stderr, "[warden] out of memory\n"); return -1; }
        g_nx_n++;
    }
    /* drop one inside another (keep the outer, the first line naming it) */
    for (size_t a = 0; a < g_nx_n; a++)
        for (size_t b = 0; b < g_nx_n; b++) {
            if (a == b || !g_nx[a].path || !g_nx[b].path) continue;
            if (noexec_under(g_nx[b].path, g_nx[a].path) &&
                (strcmp(g_nx[a].path, g_nx[b].path) || a < b)) {
                free(g_nx[b].path);
                g_nx[b].path = NULL;
            }
        }
    size_t w = 0;
    for (size_t k = 0; k < g_nx_n; k++) if (g_nx[k].path) g_nx[w++] = g_nx[k];
    g_nx_n = w;
    /* the operator's own program must be launchable */
    char breal[PATH_MAX];
    if (boot_path && realpath(boot_path, breal))
        for (size_t k = 0; k < g_nx_n; k++)
            if (noexec_under(breal, g_nx[k].path)) {
                fprintf(stderr, "[warden] noexec: the agent's own program %s is under %s, which policy "
                        "line %d lets the agent write; it could not be launched; move it, or run with "
                        "--writable-exec; refusing to start\n", breal, g_nx[k].path, g_nx[k].line);
                return -1;
            }
    /* a file of the launch set under one stays in the set but cannot launch (D4) */
    for (size_t e = 0; e < g_exec_n; e++)
        for (size_t k = 0; k < g_nx_n; k++)
            if (noexec_under(g_exec_rs[e].path, g_nx[k].path) && strcmp(g_exec_rs[e].why, "bootstrap")) {
                fprintf(stderr, "[warden] note: noexec: %s (in the launch set) is under %s, which policy "
                        "line %d lets the agent write; it will not launch\n", g_exec_rs[e].path,
                        g_nx[k].path, g_nx[k].line);
                break;
            }
    return 0;
}

/* ---- step 2: the mounts ---- */

/* The flags a mount already has, to keep on a remount (a remount may not drop
 * a locked flag such as nosuid or nodev). */
static unsigned long noexec_keep_flags(const char *mp) {
    struct statvfs sv;
    if (statvfs(mp, &sv) < 0) return 0;
    unsigned long f = 0;
    if (sv.f_flag & ST_RDONLY)      f |= MS_RDONLY;
    if (sv.f_flag & ST_NOSUID)      f |= MS_NOSUID;
    if (sv.f_flag & ST_NODEV)       f |= MS_NODEV;
    if (sv.f_flag & ST_NOATIME)     f |= MS_NOATIME;
    if (sv.f_flag & ST_NODIRATIME)  f |= MS_NODIRATIME;
    if (sv.f_flag & ST_RELATIME)    f |= MS_RELATIME;
    return f;
}

/* A mount point as /proc/self/mountinfo writes it (\040 for a space ...). */
static void noexec_unescape(char *s) {
    char *w = s;
    for (char *r = s; *r; ) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' && r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char)((r[1] - '0') * 64 + (r[2] - '0') * 8 + (r[3] - '0'));
            r += 4;
        } else *w++ = *r++;
    }
    *w = '\0';
}

/* Remount noexec every mount at or under root (the bind just made, and the
 * mounts beneath it). 0, or -1 with errno. */
static int noexec_remount_tree(const char *root) {
    FILE *mi = fopen("/proc/self/mountinfo", "re");
    if (!mi) return -1;
    char line[8192];
    int rc = 0, done = 0;
    while (rc == 0 && fgets(line, sizeof line, mi)) {
        /* id parent major:minor root mountpoint ... */
        char *save = NULL, *tok = strtok_r(line, " ", &save);
        for (int k = 0; tok && k < 4; k++) tok = strtok_r(NULL, " ", &save);
        if (!tok) continue;
        noexec_unescape(tok);
        if (!noexec_under(tok, root)) continue;
        if (mount(NULL, tok, NULL, MS_BIND | MS_REMOUNT | MS_NOEXEC | noexec_keep_flags(tok), NULL) < 0)
            rc = -1;
        else done++;
    }
    int e = errno;
    fclose(mi);
    errno = e;
    if (rc == 0 && done == 0) { errno = ENOENT; return -1; }
    return rc;
}

/* The Warden's own mount namespace, private, with each listed directory
 * re-mounted noexec. Done before the agent is forked (it inherits the view)
 * and while the Warden is single-threaded. The host's namespace is not
 * touched. 0, or -1 with the reason printed (the Warden does not start). */
static int noexec_mount(void) {
    if (!g_nx_n) return 0;
    if (unshare(CLONE_NEWNS) < 0) {
        fprintf(stderr, "[warden] noexec: cannot make a mount namespace (%s); run as root, or with "
                "--writable-exec; refusing to start\n", strerror(errno));
        return -1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        fprintf(stderr, "[warden] noexec: cannot make the mount namespace private (%s); refusing to "
                "start\n", strerror(errno));
        return -1;
    }
    for (size_t k = 0; k < g_nx_n; k++) {
        const char *d = g_nx[k].path;
        if (mount(d, d, NULL, MS_BIND | MS_REC, NULL) < 0 || noexec_remount_tree(d) < 0) {
            fprintf(stderr, "[warden] noexec: cannot mount %s noexec (%s); refusing to start\n", d,
                    strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* ---- step 4: the record ---- */

/* run_start's "noexec": each directory (or file) mounted noexec, with the
 * policy line that makes it writable; null when --writable-exec turned the
 * mounts off. Written with launches on only. */
static void noexec_record(FILE *f) {
    if (g_writable_exec) { fputs("\"noexec\":null,", f); return; }
    fputs("\"noexec\":[", f);
    for (size_t k = 0; k < g_nx_n; k++) {
        fprintf(f, "%s{\"path\":\"", k ? "," : "");
        json_escape(f, g_nx[k].path);
        fprintf(f, "\",\"policy_line\":%d%s}", g_nx[k].line, g_nx[k].file ? ",\"file\":true" : "");
    }
    fputs("],", f);
}
