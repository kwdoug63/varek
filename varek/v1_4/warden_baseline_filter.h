// SPDX-License-Identifier: MIT
// warden_baseline_filter.h — v1.9.2
#ifndef WARDEN_BASELINE_FILTER_H
#define WARDEN_BASELINE_FILTER_H

// Drop-in replacement for install_user_notif_filter() in warden.c.
// Sets PR_SET_NO_NEW_PRIVS, installs a DEFAULT-DENY libseccomp filter that
// mediates exactly openat/connect/execve/execveat to the supervisor, and
// returns the unotify listener fd (>=0) or -1.
//
// observe != 0: default action is allow-and-log instead of EPERM, for harvesting
// the target's required syscalls before enforcing. Hard-deny still kills.
int install_baseline_user_notif_filter(int observe);

// v1.29: flags. WD_FILTER_CHANGES (under `require warden 1.29`) also sends
// the changes by name (unlink, rename, mkdir, rmdir, chmod, utimensat,
// truncate, chdir and their *at and descriptor forms) to the supervisor, and
// admits fchdir; hard and symbolic links stay refused. WD_FILTER_DRY (a dry
// run) sends every call outside the allowlist to the supervisor instead of
// refusing it (EPERM); the hard-deny rules are unchanged.
#define WD_FILTER_CHANGES 1
#define WD_FILTER_DRY     2
// v1.42 step 3: the policy holds calls (mode=hold): on Linux 5.19 or later,
// a held call's wait is ended by a fatal signal only
// (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV); elsewhere a signal ends it and
// the kernel notifies the call again. v1.42 step 4: with libseccomp before
// 2.6 too (the program it builds, loaded with the flag).
#define WD_FILTER_WAITKILL 4
int wd_filter_waitkill_built(void);   // 1 if this build can ask for it
int wd_filter_waitkill_kernel(void);  // 1 if this kernel accepts it (a child tries it)
int install_baseline_user_notif_filter_ex(int observe, int flags);

#endif
