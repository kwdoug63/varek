/*
 * warden_change.inc.c — v1.29 step 2b: changing files by name (included by
 * warden.c after warden_noexec.inc.c). docs/security/v1.29-varek-run.md, D12.
 *
 * Through v1.28 the agent could not remove, rename or make a file or a
 * directory, change its own directory, or change a file's mode, times or
 * length by name: unlink, rename, mkdir, rmdir, chdir, chmod, utimensat and
 * truncate were not in the system-call allowlist and failed with EPERM under
 * every policy. Under `require warden 1.29` the filter sends them here, and
 * each is decided like an open that writes, on every path it names:
 *
 *   file.unlink, file.rmdir   the name, as O_WRONLY|O_TRUNC (a rule that
 *                             refuses truncation refuses removal)
 *   file.mkdir                the new name, as O_WRONLY|O_CREAT|O_EXCL
 *   file.rename_from          the old name, as O_RDWR|O_TRUNC: its contents
 *                             are read under the new name (v1.29 review), so
 *                             a rule that lets the agent write it but not
 *                             read it refuses moving it (with
 *                             RENAME_EXCHANGE, O_RDWR|O_CREAT|O_TRUNC)
 *   file.rename_to            the new name, as O_WRONLY|O_CREAT|O_TRUNC
 *                             (with RENAME_EXCHANGE, O_RDWR|O_CREAT|O_TRUNC:
 *                             its contents move to the old name)
 *   file.chmod, file.utime    the object, as O_WRONLY
 *   file.truncate             the object, as O_WRONLY|O_TRUNC
 *   file.chdir                the directory, as a read (O_RDONLY|O_DIRECTORY)
 *
 * each certified by the checker and recorded with the flags it was decided
 * as. The Warden resolves the names itself (from /proc/<pid>/cwd, or the
 * directory descriptor the agent gave, through /proc/<pid>/fd), pinning the
 * parent directory of a name and the object of the rest, and carries out the
 * call as the agent (warden_asagent.inc.c) on the pinned descriptors: the
 * object changed is the object decided, and the kernel's own checks apply.
 * A change of directory is let through to the kernel (it can only change
 * where the agent's later relative names start, each of which is decided).
 *
 * Refused whatever the policy says: the protected objects (by identity, as
 * for opens), anything on procfs, sysfs or a control-group filesystem, and
 * the Warden's views. A directory is never renamed: its new name would carry
 * every file under it past the rules that name them, so the call is answered
 * EXDEV, and `mv` and the like fall back to copying, each file decided. Hard
 * and symbolic links stay refused by the filter: a second name for a file is
 * how a deny rule would be escaped.
 *
 * The calls on a descriptor (ftruncate, fchmod, utimensat on a descriptor)
 * are decided on the descriptor's object, reached through /proc/<pid>/fd.
 *
 * A name that is not there (v1.29 review) is decided on where it would be,
 * as a lookup's is: ENOENT only where the policy allows the change there,
 * EACCES elsewhere. Any other failed walk (a file where a directory is
 * named, a loop) is answered EACCES. The walk's own error is never passed
 * on: it is made as root where the agent's user may not search, and would
 * tell the agent what exists where neither the policy nor the kernel lets it
 * look.
 */

#ifndef SYSFS_MAGIC
#define SYSFS_MAGIC 0x62656572
#endif
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#define CHG_W_TRUNC   (O_WRONLY | O_TRUNC)
#define CHG_RW_TRUNC  (O_RDWR | O_TRUNC)
#define CHG_RW_SWAP   (O_RDWR | O_CREAT | O_TRUNC)
#define CHG_W_CREATE  (O_WRONLY | O_CREAT | O_EXCL)
#define CHG_W_REPLACE (O_WRONLY | O_CREAT | O_TRUNC)

static const char *change_op_name(int op) {
    switch (op) {
        case CHG_UNLINK:      return "file.unlink";
        case CHG_RMDIR:       return "file.rmdir";
        case CHG_MKDIR:       return "file.mkdir";
        case CHG_RENAME_FROM: return "file.rename_from";
        case CHG_RENAME_TO:   return "file.rename_to";
        case CHG_CHMOD:       return "file.chmod";
        case CHG_UTIME:       return "file.utime";
        case CHG_TRUNCATE:    return "file.truncate";
        case CHG_CHDIR:       return "file.chdir";
    }
    return "file.change";
}

/* the flags each kind of change is decided as */
static int change_flags(int op) {
    switch (op) {
        case CHG_UNLINK: case CHG_RMDIR: case CHG_TRUNCATE: return CHG_W_TRUNC;
        case CHG_RENAME_FROM: return CHG_RW_TRUNC;
        case CHG_MKDIR:     return CHG_W_CREATE;
        case CHG_RENAME_TO: return CHG_W_REPLACE;
        case CHG_CHMOD: case CHG_UTIME: return O_WRONLY;
        case CHG_CHDIR: return O_RDONLY | O_DIRECTORY;
    }
    return O_WRONLY | O_TRUNC;
}

/* derive_intent's part: 1 if the call is one of these (out filled; -1 if its
 * memory could not be read), 0 if not */
static int change_derive(const struct seccomp_notif *req, struct action *out) {
    int nr = (int)req->data.nr;
    const __u64 *g = req->data.args;
    int op = -1, pa = -1, pb = -1;            /* the path arguments' registers */
    out->chg_dirfd = out->chg_dirfd2 = VAREK_AT_FDCWD;
    out->chg_fd = -1;
    if (nr == __NR_unlink)      { op = CHG_UNLINK; pa = 0; }
    else if (nr == __NR_rmdir)  { op = CHG_RMDIR; pa = 0; }
    else if (nr == __NR_unlinkat) {
        out->chg_dirfd = (int)g[0]; pa = 1;
        unsigned fl = (unsigned)g[2];
        if (fl & ~(unsigned)AT_REMOVEDIR) out->bad_flags = true;
        op = fl & AT_REMOVEDIR ? CHG_RMDIR : CHG_UNLINK;
    }
    else if (nr == __NR_mkdir)  { op = CHG_MKDIR; pa = 0; out->chg_mode = (unsigned)g[1] & 07777; }
    else if (nr == __NR_mkdirat) { op = CHG_MKDIR; out->chg_dirfd = (int)g[0]; pa = 1; out->chg_mode = (unsigned)g[2] & 07777; }
    else if (nr == __NR_rename) { op = CHG_RENAME_FROM; pa = 0; pb = 1; }
    else if (nr == __NR_renameat || nr == __NR_renameat2) {
        op = CHG_RENAME_FROM; out->chg_dirfd = (int)g[0]; pa = 1; out->chg_dirfd2 = (int)g[2]; pb = 3;
        if (nr == __NR_renameat2) {
            out->chg_flags = (unsigned)g[4];
            if (out->chg_flags & ~(unsigned)(RENAME_NOREPLACE | RENAME_EXCHANGE) ||
                (out->chg_flags & RENAME_NOREPLACE && out->chg_flags & RENAME_EXCHANGE))
                out->bad_flags = true;
        }
    }
    else if (nr == __NR_chmod)  { op = CHG_CHMOD; pa = 0; out->chg_mode = (unsigned)g[1] & 07777; }
    else if (nr == __NR_fchmod) { op = CHG_CHMOD; out->chg_fd = (int)g[0]; out->chg_mode = (unsigned)g[1] & 07777; }
    else if (nr == __NR_fchmodat) { op = CHG_CHMOD; out->chg_dirfd = (int)g[0]; pa = 1; out->chg_mode = (unsigned)g[2] & 07777; }
#ifdef __NR_fchmodat2
    else if (nr == __NR_fchmodat2) {
        op = CHG_CHMOD; out->chg_dirfd = (int)g[0]; pa = 1; out->chg_mode = (unsigned)g[2] & 07777;
        out->chg_flags = (unsigned)g[3];
        if (out->chg_flags & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) out->bad_flags = true;
    }
#endif
    else if (nr == __NR_utimensat) {
        op = CHG_UTIME; out->chg_dirfd = (int)g[0];
        out->chg_flags = (unsigned)g[3];
        if (out->chg_flags & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) out->bad_flags = true;
        if (g[1]) pa = 1; else { out->chg_fd = (int)g[0]; out->path_null = true; }
        if (g[2]) {
            if (xproc_read_bytes(req->pid, g[2], out->chg_times, sizeof out->chg_times) < 0) return -1;
        } else out->chg_times_null = true;
    }
    else if (nr == __NR_truncate)  { op = CHG_TRUNCATE; pa = 0; out->chg_len = (int64_t)g[1]; }
    else if (nr == __NR_ftruncate) { op = CHG_TRUNCATE; out->chg_fd = (int)g[0]; out->chg_len = (int64_t)g[1]; }
    else if (nr == __NR_chdir)     { op = CHG_CHDIR; pa = 0; }
    else return 0;
    out->kind = ACT_FILE_CHANGE;
    out->chg_op = op;
    out->open_flags = change_flags(op);
    if (op == CHG_RENAME_FROM && out->chg_flags & RENAME_EXCHANGE) out->open_flags = CHG_RW_SWAP;
    out->flags_known = true;
    out->open_dirfd = out->chg_dirfd;
    if (pa >= 0 && xproc_read_str(req->pid, g[pa], out->target, sizeof out->target) < 0) return -1;
    if (pb >= 0 && xproc_read_str(req->pid, g[pb], out->target2, sizeof out->target2) < 0) return -1;
    if (out->chg_fd >= 0 && pa < 0) snprintf(out->target, sizeof out->target, "fd:%d", out->chg_fd);
    /* an empty path with AT_EMPTY_PATH: the descriptor itself */
    if (pa >= 0 && !out->target[0] && out->chg_flags & AT_EMPTY_PATH) {
        out->chg_fd = out->chg_dirfd;
        snprintf(out->target, sizeof out->target, "fd:%d", out->chg_fd);
    }
    return 1;
}

/* a descriptor on the base a relative name starts from: the agent's working
 * directory, or the directory descriptor it gave (fail: -1) */
static int change_base(pid_t pid, int dirfd, const char *path) {
    int fd = agent_fd(pid, path[0] == '/' ? VAREK_AT_FDCWD : dirfd);
    return fd < 0 ? -1 : fd;
}

/* the filesystem types no change reaches: 0 fine, -1 refused */
static int change_fs_ok(int fd) {
    struct statfs sf;
    if (fstatfs(fd, &sf) < 0) return -1;
    unsigned long t = (unsigned long)sf.f_type;
    if (t == (unsigned long)PROC_SUPER_MAGIC || t == (unsigned long)SYSFS_MAGIC ||
        t == (unsigned long)CGROUP_SUPER_MAGIC || t == (unsigned long)CGROUP2_SUPER_MAGIC) return -1;
    return 0;
}

/* is the object st one of the protected objects? */
static bool change_protected(const struct stat *st) {
    for (int i = 0; i < g_nprotected; i++)
        if (st->st_dev == g_protected[i].dev && st->st_ino == g_protected[i].ino) return true;
    return g_pdir_set && st->st_dev == g_pdir_dev && st->st_ino == g_pdir_ino;
}

/* One resolved name or object. */
struct chg_pin {
    int  fd;              /* O_PATH: the parent directory (named), or the object */
    bool named;           /* fd is the parent and name the last component */
    char name[256];
    bool trailing_slash;
    int  agent_err;       /* the walk as the agent failed with this */
};

/* change_resolve's answer for a name that is not there (the pin's fd -1, res
 * the name where it would be): decided by the policy, ENOENT where allowed */
static const char CHG_MISSING[] = "change_missing";

static bool path_has_dotdot(const char *p) {
    for (const char *c = p; (c = strstr(c, "..")); c += 2)
        if ((c == p || c[-1] == '/') && (c[2] == '\0' || c[2] == '/')) return true;
    return false;
}

/* The name where a missing one would be: under the directory q (pinned, the
 * deepest that is there), nm, then the rest of the walk and the last
 * component of a named change. NULL, or the rule refusing it. */
static const char *change_missing(pid_t pid, int q, const char *nm, const char *tail, const char *last,
                                  char *res, size_t resn) {
    pid_t tgid = -1;
    char parent[PATH_LIMIT];
    if (fd_canonical_path(q, parent, sizeof parent) < 0 ||
        check_proc_object(q, pid, &tgid, parent, sizeof parent) < 0) return "resolution_failed";
    if (change_fs_ok(q) < 0) return "change_on_kernel_fs";
    int pd = in_protected_dir(NULL, q);
    if (pd < 0) return "resolution_failed";
    if (pd > 0) return "protected_object";
    int n = snprintf(res, resn, "%s%s%s%s%s%s%s", parent, strcmp(parent, "/") ? "/" : "", nm,
                     tail[0] ? "/" : "", tail, last ? "/" : "", last ? last : "");
    if (n < 0 || (size_t)n >= resn) { res[0] = '\0'; return "resolution_failed"; }
    if ((g_any_name || g_inspect_on) && view_by_canonical(res) >= 0) return "view_write_refused";
    return CHG_MISSING;
}

/* Resolve one path of a change. named: pin the parent and keep the last
 * component (not followed). Sets a->resolved (or res) to the canonical name.
 * Returns NULL, CHG_MISSING (a name not there, res where it would be), or
 * the record's rule for refusing it (with *err its errno). */
static const char *change_resolve(pid_t pid, const struct action *a, int dirfd, const char *path, bool named,
                                  bool want_dir, struct chg_pin *pin, char *res, size_t resn, int *err) {
    memset(pin, 0, sizeof *pin);
    pin->fd = -1;
    res[0] = '\0';
    *err = EACCES;
    if (!path[0]) { *err = ENOENT; return "change_invalid"; }
    int base = change_base(pid, dirfd, path);
    if (base < 0) { *err = EBADF; return "resolution_failed"; }
    pid_t tgid = -1;
    char work[PATH_LIMIT];
    bool ts = false;
    if (path_is_proc_self(path, &ts)) { close(base); return "change_on_kernel_fs"; }
    snprintf(work, sizeof work, "%s", path);
    char dir[PATH_LIMIT];
    if (named) {
        size_t l = strlen(work);
        while (l > 1 && work[l - 1] == '/') { work[--l] = '\0'; pin->trailing_slash = true; }
        const char *sl = strrchr(work, '/');
        const char *nm = sl ? sl + 1 : work;
        if (!*nm || !strcmp(nm, ".") || !strcmp(nm, "..") || strlen(nm) >= sizeof pin->name) {
            close(base);
            *err = EINVAL;
            return "change_invalid";
        }
        snprintf(pin->name, sizeof pin->name, "%s", nm);
        if (!sl) snprintf(dir, sizeof dir, ".");
        else if (sl == work) snprintf(dir, sizeof dir, "/");
        else snprintf(dir, sizeof dir, "%.*s", (int)(sl - work), work);
        pin->fd = resolve_openat2(base, dir, (uint64_t)O_DIRECTORY, &pin->agent_err);
    } else {
        pin->fd = resolve_openat2(base, work, want_dir ? (uint64_t)O_DIRECTORY : 0, &pin->agent_err);
    }
    int e = errno;
    if (pin->fd < 0) {
        /* v1.29 review: never the walk's own errno (see the top of this file) */
        const char *walked = named ? dir : work;
        int q = -1;
        char mnm[256], tail[PATH_LIMIT];
        const char *w = "resolution_failed";
        if (e == ENOENT && !path_has_dotdot(walked) &&
            meta_first_missing(base, walked, &q, mnm, sizeof mnm, tail, sizeof tail) == 0) {
            w = change_missing(pid, q, mnm, tail, named ? pin->name : NULL, res, resn);
            close(q);
        }
        close(base);
        pin->fd = -1;
        *err = w == CHG_MISSING ? ENOENT : EACCES;
        return w;
    }
    close(base);
    char canon[PATH_LIMIT];
    if (fd_canonical_path(pin->fd, canon, sizeof canon) < 0 ||
        check_proc_object(pin->fd, pid, &tgid, canon, sizeof canon) < 0) return "resolution_failed";
    if (change_fs_ok(pin->fd) < 0) return "change_on_kernel_fs";
    struct stat st;
    if (named) {
        int n = snprintf(res, resn, "%s%s%s", canon, strcmp(canon, "/") ? "/" : "", pin->name);
        if (n < 0 || (size_t)n >= resn) { res[0] = '\0'; return "resolution_failed"; }
        if (fstat(pin->fd, &st) < 0) return "resolution_failed";
        if (change_protected(&st)) return "protected_object";      /* the state directory itself */
        int pd = in_protected_dir(NULL, pin->fd);
        if (pd < 0) return "resolution_failed";
        if (pd > 0) return "protected_object";
        if (fstatat(pin->fd, pin->name, &st, AT_SYMLINK_NOFOLLOW) == 0 && change_protected(&st))
            return "protected_object";
    } else {
        snprintf(res, resn, "%s", canon);
        const char *f = forbidden_object(pin->fd, canon);
        if (f) return f;
    }
    if ((g_any_name || g_inspect_on) && view_by_canonical(res) >= 0) return "view_write_refused";
    (void)a;
    return NULL;
}

/* The object a descriptor of the agent's names, pinned (O_PATH). */
static const char *change_resolve_fd(pid_t pid, int fd, struct chg_pin *pin, char *res, size_t resn, int *err) {
    memset(pin, 0, sizeof *pin);
    res[0] = '\0';
    *err = EBADF;
    pin->fd = agent_fd(pid, fd);        /* the caller's own descriptor */
    if (pin->fd < 0) { pin->fd = -1; return "resolution_failed"; }
    *err = EACCES;
    pid_t tgid = -1;
    if (fd_canonical_path(pin->fd, res, resn) < 0 ||
        check_proc_object(pin->fd, pid, &tgid, res, resn) < 0) { res[0] = '\0'; *err = EINVAL; return "resolution_failed"; }
    if (change_fs_ok(pin->fd) < 0) return "change_on_kernel_fs";
    const char *f = forbidden_object(pin->fd, res);
    if (f) return f;
    if ((g_any_name || g_inspect_on) && view_by_canonical(res) >= 0) return "view_write_refused";
    return NULL;
}

/* For ftruncate: is the agent's descriptor open for writing? */
static bool change_fd_writable(pid_t pid, int fd) {
    char line[128];
    FILE *f = proc_fopenf("%d/fdinfo/%d", pid, fd);
    if (!f) return false;
    unsigned flags = 0;
    bool got = false;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "flags: %o", &flags) == 1) { got = true; break; }
    fclose(f);
    return got && (flags & O_ACCMODE) != O_RDONLY;
}

static uint64_t change_lat(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0->tv_nsec);
}

/* Decide one path: 0 allowed and certified, else the rule refusing it. */
static const char *change_decide(const struct policy *p, struct action *a, decision_t *raw) {
    *raw = policy_decide(p, a);
    if (*raw != DEC_ALLOW) return decision_rule_id(a, *raw);
    if (!certify(p, a)) {
        log_line_start();
        fprintf(g_log, "[warden] certificate refused (record seq %" PRIu64 "): %s\n", g_records, a->check_why);
        return "certificate_refused";
    }
    if (hold_refuses(a)) return "outside_plan";          /* v1.35 step 4: outside the run's plan */
    return NULL;
}

/* Carry out an allowed change as the agent: 0 or -errno */
static int change_do(pid_t pid, const struct action *a, const struct chg_pin *x, const struct chg_pin *y) {
    if (y && y->fd < 0) y = NULL;
    char self[64];   /* below the node's /proc (v1.34) */
    if (!x->named) snprintf(self, sizeof self, "self/fd/%d", x->fd);
    /* a name written with a trailing '/' must be a directory, as the kernel
     * would have it (unlink("f/") of a file is ENOTDIR, not a removal) */
    const struct chg_pin *ts[2] = { x, y };
    for (int i = 0; i < 2; i++) {
        struct stat s;
        if (ts[i] && ts[i]->named && ts[i]->trailing_slash &&
            fstatat(ts[i]->fd, ts[i]->name, &s, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISDIR(s.st_mode))
            return -ENOTDIR;
    }
    int r = 0;
    if (as_agent_enter() < 0) return -EACCES;
    switch (a->chg_op) {
        case CHG_UNLINK:
            r = unlinkat(x->fd, x->name, 0);
            break;
        case CHG_RMDIR:
            r = unlinkat(x->fd, x->name, AT_REMOVEDIR);
            break;
        case CHG_MKDIR: {
            mode_t old = umask(target_umask(pid));
            r = mkdirat(x->fd, x->name, (mode_t)a->chg_mode);
            int e = errno;
            umask(old);
            errno = e;
            break;
        }
        case CHG_RENAME_FROM:
            r = (int)syscall(SYS_renameat2, x->fd, x->name, y->fd, y->name, a->chg_flags);
            break;
        case CHG_CHMOD:
            r = fchmodat(proc_dir(), self, (mode_t)a->chg_mode, 0);
            break;
        case CHG_UTIME:
            if (x->named)
                r = utimensat(x->fd, x->name, a->chg_times_null ? NULL : a->chg_times, AT_SYMLINK_NOFOLLOW);
            else
                r = utimensat(proc_dir(), self, a->chg_times_null ? NULL : a->chg_times, 0);
            break;
        case CHG_TRUNCATE: {
            int w = openat(proc_dir(), self, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
            if (w < 0) { r = -1; break; }
            r = ftruncate(w, (off_t)a->chg_len);
            int e = errno;
            close(w);
            errno = e;
            break;
        }
        default:
            errno = EINVAL;
            r = -1;
    }
    int e = errno;
    as_agent_leave();
    return r < 0 ? -e : 0;
}

static void change_close(struct chg_pin *x) {
    if (x->fd >= 0) close(x->fd);
    x->fd = -1;
}

/* The handler: decide, record, carry out, answer. */
static void change_handle(int notify_fd, const struct seccomp_notif *req, struct action *a,
                          const struct policy *p, const struct timespec *t0) {
    pid_t pid = (pid_t)req->pid;
    if (a->bad_flags || (a->chg_op == CHG_TRUNCATE && a->chg_len < 0)) {
        send_errno(notify_fd, req->id, EINVAL);
        return;
    }
    if (a->chg_op == CHG_CHMOD && a->chg_flags & AT_SYMLINK_NOFOLLOW) {   /* as the kernel: a link has no mode */
        send_errno(notify_fd, req->id, EOPNOTSUPP);
        return;
    }
    struct chg_pin x, y;
    memset(&y, 0, sizeof y);
    x.fd = y.fd = -1;
    int err = EACCES;
    const char *why;
    bool named = a->chg_op == CHG_UNLINK || a->chg_op == CHG_RMDIR || a->chg_op == CHG_MKDIR ||
                 a->chg_op == CHG_RENAME_FROM || (a->chg_op == CHG_UTIME && a->chg_flags & AT_SYMLINK_NOFOLLOW);
    if (a->chg_fd >= 0 && !named) {
        if (a->chg_op == CHG_TRUNCATE && !change_fd_writable(pid, a->chg_fd)) {
            send_errno(notify_fd, req->id, EINVAL);
            return;
        }
        why = change_resolve_fd(pid, a->chg_fd, &x, a->resolved, sizeof a->resolved, &err);
    } else {
        why = change_resolve(pid, a, a->chg_dirfd, a->target, named, a->chg_op == CHG_CHDIR, &x,
                             a->resolved, sizeof a->resolved, &err);
    }
    bool missing = why == CHG_MISSING, missing2 = false;
    if (missing) why = NULL;
    if (why) {
        emit_pathology(g_report_seq++, pid, a, strcmp(why, "resolution_failed") ? DEC_DENY : DEC_UNKNOWN,
                       DEC_DENY, why, change_lat(t0), err);
        send_errno(notify_fd, req->id, err);
        change_close(&x);
        return;
    }
    /* v1.29 (step 6): a mkdir of a name that is there is answered EEXIST, as
     * the kernel would, where the agent may look the name up: the policy
     * allows reading it, or it is a directory the policy leads to. A
     * recursive mkdir walks the names above what it makes (Bun's from the
     * home directory, Python's from the working directory), and refused
     * there with EACCES it stops. Nothing changes; the record says it was
     * decided as a lookup (flags 0x0). */
    if (a->chg_op == CHG_MKDIR && !x.agent_err && !missing) {
        struct stat es;
        if (fstatat(x.fd, x.name, &es, AT_SYMLINK_NOFOLLOW) == 0) {
            int saved = a->open_flags;
            const char *erule = NULL;
            decision_t eraw = DEC_UNKNOWN;
            a->open_flags = O_RDONLY;
            /* v1.35 step 9 (review): held, the answer is the hold's too: a lookup,
             * asked as a metadata call is (a directory above a step's path) */
            bool hold_ok = true;
            if (g_hold_on) {
                int k = a->kind;
                a->kind = ACT_FILE_STAT;
                hold_ok = hold_covers(a);
                a->kind = k;
            }
            if (S_ISDIR(es.st_mode) && is_ancestor(a->resolved, sub_policy_subject(a->subject)) &&
                !ancestor_denied(p, a->resolved, sub_policy_subject(a->subject)) && hold_ok) {
                erule = "mkdir_exists_ancestor";
                eraw = DEC_ALLOW;
            } else if (!change_decide(p, a, &eraw)) {
                erule = "mkdir_exists";
            }
            if (erule) {
                change_close(&x);
                emit_pathology(g_report_seq++, pid, a, eraw, DEC_ALLOW, erule, change_lat(t0), EEXIST);
                send_errno(notify_fd, req->id, EEXIST);
                return;
            }
            a->open_flags = saved;
        }
    }
    /* a rename: the new name, and never a directory */
    struct action b;
    if (a->chg_op == CHG_RENAME_FROM) {
        memcpy(&b, a, sizeof b);
        b.chg_op = CHG_RENAME_TO;
        b.open_flags = a->chg_flags & RENAME_EXCHANGE ? CHG_RW_SWAP : CHG_W_REPLACE;
        snprintf(b.target, sizeof b.target, "%s", a->target2);
        const char *why2 = change_resolve(pid, &b, a->chg_dirfd2, a->target2, true, false, &y,
                                          b.resolved, sizeof b.resolved, &err);
        missing2 = why2 == CHG_MISSING;
        if (missing2) why2 = NULL;
        struct stat ss, ds;
        bool src_dir = !missing && fstatat(x.fd, x.name, &ss, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(ss.st_mode);
        bool dst_dir = !why2 && !missing2 && a->chg_flags & RENAME_EXCHANGE &&
                       fstatat(y.fd, y.name, &ds, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(ds.st_mode);
        if (!why2 && (src_dir || dst_dir)) why2 = "rename_directory_refused", err = EXDEV;
        if (why2) {
            emit_pathology(g_report_seq++, pid, a, DEC_DENY, DEC_DENY, why2, change_lat(t0), err);
            send_errno(notify_fd, req->id, err);
            change_close(&x);
            change_close(&y);
            return;
        }
    }
    decision_t raw;
    why = change_decide(p, a, &raw);
    if (why && dry_let(a, why)) {             /* v1.29: a dry run: to the kernel, as the agent */
        change_close(&x);
        change_close(&y);
        emit_pathology(g_report_seq++, pid, a, raw, DEC_DENY, why, change_lat(t0), 0);
        /* a rename's new name is decided and recorded too (v1.29 review):
         * the call goes through, and the draft must see both names */
        if (a->chg_op == CHG_RENAME_FROM) {
            decision_t rb = DEC_ALLOW;
            const char *wb = change_decide(p, &b, &rb);
            if (!wb || !dry_let(&b, wb)) b.dry = true;
            emit_pathology(g_report_seq++, pid, &b, rb, DEC_DENY, wb ? wb : "rename_from_refused",
                           change_lat(t0), 0);
        }
        send_simple(notify_fd, req->id, DEC_ALLOW);
        return;
    }
    if (why) {
        emit_pathology(g_report_seq++, pid, a, raw, DEC_DENY, why, change_lat(t0), EACCES);
        send_errno(notify_fd, req->id, EACCES);
        change_close(&x);
        change_close(&y);
        return;
    }
    decision_t raw2 = DEC_ALLOW;
    if (a->chg_op == CHG_RENAME_FROM) {
        const char *w2 = change_decide(p, &b, &raw2);
        if (w2 && dry_let(&b, w2)) {          /* v1.29: a dry run */
            a->dry = true;
            change_close(&x);
            change_close(&y);
            emit_pathology(g_report_seq++, pid, a, raw, DEC_DENY, "rename_to_refused", change_lat(t0), 0);
            emit_pathology(g_report_seq++, pid, &b, raw2, DEC_DENY, w2, change_lat(t0), 0);
            send_simple(notify_fd, req->id, DEC_ALLOW);
            return;
        }
        if (w2) {
            emit_pathology(g_report_seq++, pid, a, raw, DEC_DENY, "rename_to_refused", change_lat(t0), EACCES);
            emit_pathology(g_report_seq++, pid, &b, raw2, DEC_DENY, w2, change_lat(t0), EACCES);
            send_errno(notify_fd, req->id, EACCES);
            change_close(&x);
            change_close(&y);
            return;
        }
    }
    /* a name that is not there, where the policy allows the change: the
     * kernel's ENOENT, recorded (a change of directory goes to the kernel
     * as any allowed one, below, which answers it) */
    if ((missing || missing2) && a->chg_op != CHG_CHDIR) {
        change_close(&x);
        change_close(&y);
        emit_pathology(g_report_seq++, pid, a, raw, DEC_ALLOW, "change_failed", change_lat(t0), ENOENT);
        if (a->chg_op == CHG_RENAME_FROM)
            emit_pathology(g_report_seq++, pid, &b, raw2, DEC_ALLOW, "change_failed", change_lat(t0), ENOENT);
        send_errno(notify_fd, req->id, ENOENT);
        return;
    }
    /* a change of directory: the kernel does it, as the agent */
    if (a->chg_op == CHG_CHDIR) {
        change_close(&x);
        emit_pathology(g_report_seq++, pid, a, raw, DEC_ALLOW, "chdir_continued", change_lat(t0), 0);
        send_simple(notify_fd, req->id, DEC_ALLOW);
        return;
    }
    int ae = x.agent_err ? x.agent_err : y.agent_err;
    int r = ae ? -ae : change_do(pid, a, &x, &y);
    change_close(&x);
    change_close(&y);
    const char *rule = r < 0 ? "change_failed" : "change_done";
    emit_pathology(g_report_seq++, pid, a, raw, DEC_ALLOW, rule, change_lat(t0), r < 0 ? -r : 0);
    if (a->chg_op == CHG_RENAME_FROM)
        emit_pathology(g_report_seq++, pid, &b, raw2, DEC_ALLOW, rule, change_lat(t0), r < 0 ? -r : 0);
    if (r < 0) send_errno(notify_fd, req->id, -r);
    else       send_value(notify_fd, req->id, 0);
}
