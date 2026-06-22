// SPDX-License-Identifier: MIT
// warden_seccomp_baseline.h — v1.9.2
#ifndef WARDEN_SECCOMP_BASELINE_H
#define WARDEN_SECCOMP_BASELINE_H

#include <seccomp.h>

#ifdef __cplusplus
extern "C" {
#endif

// Build the default-deny allowlist baseline filter. Does NOT load it; the caller
// loads after prctl(PR_SET_NO_NEW_PRIVS,1) and after attaching an unotify
// listener for the SCMP_ACT_NOTIFY (mediate) rules. Returns 0 on success, a
// negative errno on failure. On success *out_ctx owns a filter the caller must
// seccomp_load() then seccomp_release().
int wd_seccomp_build_baseline(scmp_filter_ctx *out_ctx);

// Build + load. If out_notify_fd is non-NULL, receives the notification fd
// (or -1 if no listener is available for the mediate rules). Returns 0 / -errno.
int wd_seccomp_install_baseline(int *out_notify_fd);

#ifdef __cplusplus
}
#endif
#endif // WARDEN_SECCOMP_BASELINE_H
