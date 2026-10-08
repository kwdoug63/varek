// SPDX-License-Identifier: MIT
// shared_domains.h — v1.25: which wildcard host patterns are refused at load
// (docs/security/v1.25-wildcard-host-names.md, section 2).
//
// A wildcard `allow host *.<suffix>` allows every name under <suffix>. That is
// refused when anyone can create names there:
//
//   - <suffix> is a public suffix (the Public Suffix List's ICANN section,
//     with its * and ! rules): *.com, *.co.uk;
//   - <suffix> is, or is under, an entry of the list's private section:
//     *.s3.amazonaws.com, *.cloudfront.net, *.myorg.github.io;
//   - <suffix> is, or is under, an entry of the VAREK list
//     (data/varek_shared_domains.txt): *.my.salesforce.com.
//
// The lists are pinned files shipped with the release; the Warden records
// their SHA-256 in run_start. Entries in Unicode are compared in their A-label
// (xn--) form, as policy names are written.

#ifndef VAREK_SHARED_DOMAINS_H
#define VAREK_SHARED_DOMAINS_H

#include <stddef.h>

typedef struct sd_lists sd_lists_t;

/* v1.25 review: the SHA-256 of the lists this release ships (data/). The
 * Warden refuses a default-path list that differs (a partial or altered
 * install), and records whether the lists it used are these. make test-v1250
 * checks that these match the files, so a list change updates them. */
#define SD_PSL_SHA256   "102b252c18b5f87f4c81f017e75282a82c18e00cd0c2e601b5b02a0f7a601f2c"
#define SD_VAREK_SHA256 "f70f7da49db614da2ea20c101e741ba352d98df1afc0859ba709c1f144816244"

/* Load the two lists. Returns the lists, or NULL with the reason in why. */
sd_lists_t *sd_load(const char *psl_path, const char *varek_path, char *why, size_t wn);
void        sd_free(sd_lists_t *l);

/* Is a wildcard over suffix refused? suffix is a valid lowercase host name
 * without a port. Returns 1 and describes the matching entry in why ("s3.
 * amazonaws.com is a shared domain where anyone can register names (Public
 * Suffix List, private section)"), or 0. */
int sd_refuses(const sd_lists_t *l, const char *suffix, char *why, size_t wn);

/* The suffix of a wildcard rule as both parsers hold it (the glob
 * "?*.<suffix>:<port>" or "?*.<suffix>:*"): writes <suffix> to out. 0, or -1
 * if glob is not in that form. */
int sd_wildcard_suffix(const char *glob, char *out, size_t n);

/* The lists' default location: <dir>/data/<file>, where <dir> is the directory
 * of the running program or its parent (the Warden sits beside data/, the
 * tools one level down, in the source tree and in an installation). Writes
 * the first path that exists to out; 0, or -1. */
int sd_default_path(const char *file, char *out, size_t n);

/* Number of rules read from each list (for reports). */
size_t sd_count(const sd_lists_t *l, int which);   /* 0 ICANN, 1 private, 2 VAREK */

/* An IDNA label in UTF-8 to its A-label (xn--...), RFC 3492. ASCII labels are
 * lowercased and copied. 0, or -1 if the label cannot be encoded. */
int sd_to_alabel(const char *label, size_t n, char *out, size_t outn);

#endif /* VAREK_SHARED_DOMAINS_H */
