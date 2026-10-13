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
 *   file.rename_from          the old name, as O_WRONLY|O_TRUNC (with
 *                             RENAME_EXCHANGE, as the new name below)
 *   file.rename_to            the new name, as O_WRONLY|O_CREAT|O_TRUNC
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
        case CHG_UNLINK: case CHG_RMDIR: case CHG_RENAME_FROM: case CHG_TRUNCATE: return CHG_W_TRUNC;
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
    if (op == CHG_RENAME_FROM && out->chg_flags & RENAME_EXCHANGE) out->open_flags = CHG_W_REPLACE;
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

/* Resolve one path of a change. named: pin the parent and keep the last
 * component (not followed). Sets a->resolved (or res) to the canonical name.
 * Returns NULL, or the record's rule for refusing it (with *err its errno). */
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
        char dir[PATH_LIMIT];
        if (!sl) snprintf(dir, sizeof dir, ".");
        else if (sl == work) snprintf(dir, sizeof dir, "/");
        else snprintf(dir, sizeof dir, "%.*s", (int)(sl - work), work);
        pin->fd = resolve_openat2(base, dir, (uint64_t)O_DIRECTORY, &pin->agent_err);
    } else {
        pin->fd = resolve_openat2(base, work, want_dir ? (uint64_t)O_DIRECTORY : 0, &pin->agent_err);
    }
    int e = errno;
    close(base);
    if (pin->fd < 0) { *err = e == ENOENT || e == ENOTDIR || e == ELOOP ? e : EACCES; return "resolution_failed"; }
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
    char p[64], line[128];
    snprintf(p, sizeof p, "/proc/%d/fdinfo/%d", pid, fd);
    FILE *f = fopen(p, "re");
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
    return NULL;
}

/* Carry out an allowed change as the agent: 0 or -errno */
static int change_do(pid_t pid, const struct action *a, const struct chg_pin *x, const struct chg_pin *y) {
    if (y && y->fd < 0) y = NULL;
    char self[64];
    if (!x->named) snprintf(self, sizeof self, "/proc/self/fd/%d", x->fd);
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
            r = fchmodat(AT_FDCWD, self, (mode_t)a->chg_mode, 0);
            break;
        case CHG_UTIME:
            if (x->named)
                r = utimensat(x->fd, x->name, a->chg_times_null ? NULL : a->chg_times, AT_SYMLINK_NOFOLLOW);
            else
                r = utimensat(AT_FDCWD, self, a->chg_times_null ? NULL : a->chg_times, 0);
            break;
        case CHG_TRUNCATE: {
            int w = open(self, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
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
    if (why) {
        emit_pathology(g_report_seq++, pid, a, strcmp(why, "resolution_failed") ? DEC_DENY : DEC_UNKNOWN,
                       DEC_DENY, why, change_lat(t0), err);
        send_errno(notify_fd, req->id, err);
        change_close(&x);
        return;
    }
    /* a rename: the new name, and never a directory */
    struct action b;
    if (a->chg_op == CHG_RENAME_FROM) {
        memcpy(&b, a, sizeof b);
        b.chg_op = CHG_RENAME_TO;
        b.open_flags = CHG_W_REPLACE;
        snprintf(b.target, sizeof b.target, "%s", a->target2);
        const char *why2 = change_resolve(pid, &b, a->chg_dirfd2, a->target2, true, false, &y,
                                          b.resolved, sizeof b.resolved, &err);
        struct stat ss, ds;
        bool src_dir = fstatat(x.fd, x.name, &ss, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(ss.st_mode);
        bool dst_dir = !why2 && a->chg_flags & RENAME_EXCHANGE &&
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
        if (w2) {
            emit_pathology(g_report_seq++, pid, a, raw, DEC_DENY, "rename_to_refused", change_lat(t0), EACCES);
            emit_pathology(g_report_seq++, pid, &b, raw2, DEC_DENY, w2, change_lat(t0), EACCES);
            send_errno(notify_fd, req->id, EACCES);
            change_close(&x);
            change_close(&y);
            return;
        }
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
