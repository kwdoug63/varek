// SPDX-License-Identifier: MIT
#ifndef WARDEN_OCI_H
#define WARDEN_OCI_H
#include <stdio.h>

/* v1.34 step 3: the Warden's filter in OCI's form, for a pod the node agent
 * supervises (warden_oci.c). flags as install_baseline_user_notif_filter_ex's.
 * 0, or -1 with why. */
int wd_oci_filter_write(FILE *f, int flags, char *why, size_t wn);

/* The Warden's own filter for those flags, compiled: *out (malloc'd), *n
 * instructions. 0, or -1. */
struct sock_filter;
struct seccomp_data;
int wd_filter_bpf(int flags, struct sock_filter **out, unsigned *n);
/* The action that filter takes on a call (a malformed program: kill) */
#include <stdint.h>
uint32_t wd_bpf_run(const struct sock_filter *f, unsigned n, const struct seccomp_data *d);

#endif
