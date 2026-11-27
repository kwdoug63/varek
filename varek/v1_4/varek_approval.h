// SPDX-License-Identifier: MIT
// varek_approval.h — v1.42 step 6: signed approvals (docs/security/
// v1.42-step-up-defer.md, "Grants", Signing).
//
// One format for every signed approval (a standing grant, a plan approval, a
// runtime grant signed with `varek approve --sign-key`): a detached signature
// file X.sig holding exactly
//
//     varek-approval 1
//     kind KIND
//     key HEX
//     sig SIGHEX
//
// KIND is `grant` or `plan`; HEX the signer's public key as varek_keygen
// writes KEY.pub (the uncompressed P-384 point, 194 lowercase hex digits);
// SIGHEX the DER ECDSA-P384-SHA384 signature, as hex, over the
// domain-separated message
//
//     "varek-approval-v1" NUL KIND NUL <the exact bytes of X>
//
// Signed and verified only through varek_fips (the FIPS provider in the
// Defense build). Header-only: the Warden and varek_keygen both include it.
#ifndef VAREK_APPROVAL_H
#define VAREK_APPROVAL_H

#include "varek_fips.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VAPPR_DOMAIN   "varek-approval-v1"
#define VAPPR_KEY_HEX  194
#define VAPPR_SIG_MAX  4096          /* a .sig file's size, at most */

typedef struct {
    char kind[8];
    char key[VAPPR_KEY_HEX + 1];
    char sig[VFIPS_SIG_HEX_MAX + 1];
} vappr_sig_t;

static inline bool vappr_kind_ok(const char *k) { return !strcmp(k, "grant") || !strcmp(k, "plan"); }

static inline bool vappr_hex_ok(const char *h, size_t min, size_t max) {
    size_t l = strlen(h);
    if (l < min || l > max || (l & 1)) return false;
    for (size_t i = 0; i < l; i++)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return false;
    return true;
}

// The signed message for kind over body[0..n): malloc'd, *ml its length; NULL on failure.
static inline unsigned char *vappr_message(const char *kind, const void *body, size_t n, size_t *ml) {
    size_t dl = sizeof VAPPR_DOMAIN, kl = strlen(kind) + 1;          // each with its NUL
    unsigned char *m = malloc(dl + kl + n + 1);
    if (!m) return NULL;
    memcpy(m, VAPPR_DOMAIN, dl);
    memcpy(m + dl, kind, kl);
    if (n) memcpy(m + dl + kl, body, n);
    *ml = dl + kl + n;
    return m;
}

// Parse a .sig file's text, exactly the four lines above. 0, or -1 with why.
static inline int vappr_parse(const char *t, size_t n, vappr_sig_t *s, char *why, size_t wn) {
    memset(s, 0, sizeof *s);
    char buf[VAPPR_SIG_MAX + 1];
    if (n > VAPPR_SIG_MAX || memchr(t, '\0', n)) { snprintf(why, wn, "not a signature file"); return -1; }
    memcpy(buf, t, n);
    buf[n] = '\0';
    char *l[5] = { 0 };
    int nl = 0;
    char *p = buf;
    while (nl < 5 && *p) {
        char *e = strchr(p, '\n');
        if (!e) { snprintf(why, wn, "a signature file's lines each end in a newline"); return -1; }
        *e = '\0';
        l[nl++] = p;
        p = e + 1;
    }
    if (nl != 4 || *p || strcmp(l[0], "varek-approval 1") || strncmp(l[1], "kind ", 5) ||
        strncmp(l[2], "key ", 4) || strncmp(l[3], "sig ", 4)) {
        snprintf(why, wn, "not a varek-approval 1 signature (varek-approval 1, kind, key, sig: four lines)");
        return -1;
    }
    if (!vappr_kind_ok(l[1] + 5)) { snprintf(why, wn, "a signature's kind is grant or plan"); return -1; }
    if (!vappr_hex_ok(l[2] + 4, VAPPR_KEY_HEX, VAPPR_KEY_HEX) || strncmp(l[2] + 4, "04", 2)) {
        snprintf(why, wn, "a signature's key is the signer's KEY.pub (194 lowercase hex digits)");
        return -1;
    }
    if (!vappr_hex_ok(l[3] + 4, 16, VFIPS_SIG_HEX_MAX)) { snprintf(why, wn, "a signature's sig is lowercase hex"); return -1; }
    snprintf(s->kind, sizeof s->kind, "%s", l[1] + 5);
    snprintf(s->key, sizeof s->key, "%s", l[2] + 4);
    snprintf(s->sig, sizeof s->sig, "%s", l[3] + 4);
    return 0;
}

// Verify s over body as kind. 1 valid, 0 not (with why).
static inline int vappr_verify(const vappr_sig_t *s, const char *kind, const void *body, size_t n,
                               char *why, size_t wn) {
    if (strcmp(s->kind, kind)) { snprintf(why, wn, "the signature is for a %s, not a %s", s->kind, kind); return 0; }
    size_t ml = 0;
    unsigned char *m = vappr_message(kind, body, n, &ml);
    if (!m) { snprintf(why, wn, "out of memory"); return 0; }
    int v = vfips_verify(s->key, m, ml, s->sig);
    free(m);
    if (v != 1) { snprintf(why, wn, "the signature does not verify"); return 0; }
    return 1;
}

// Sign body as kind with k: the .sig file's text into out. 0, or -1.
static inline int vappr_sign(const vfips_key *k, const char *kind, const void *body, size_t n,
                             char *out, size_t on) {
    char pub[VFIPS_PUB_HEX_MAX + 1], sig[VFIPS_SIG_HEX_MAX + 1];
    size_t ml = 0;
    if (!vappr_kind_ok(kind) || vfips_pubkey_hex(k, pub, sizeof pub) != VAPPR_KEY_HEX) return -1;
    unsigned char *m = vappr_message(kind, body, n, &ml);
    if (!m) return -1;
    int sl = vfips_sign(k, m, ml, sig, sizeof sig);
    free(m);
    if (sl < 0) return -1;
    int w = snprintf(out, on, "varek-approval 1\nkind %s\nkey %s\nsig %s\n", kind, pub, sig);
    return w < 0 || (size_t)w >= on ? -1 : 0;
}

#endif
