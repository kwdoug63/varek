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

#endif
