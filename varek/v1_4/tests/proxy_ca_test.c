// SPDX-License-Identifier: MIT
// proxy_ca_test.c: the run CA's name constraints (proxy_ca.c, pca_make_ca),
// under AddressSanitizer and UBSan. Each CA made must carry, critical, every
// permitted name, every excluded name and the two excluded IP ranges, at
// every size up to PCA_MAX_NAMES names of 253 characters each way. The
// constraints are assembled in one buffer: a short buffer, or a write past
// its end, must fail the run, never drop a constraint.
#include "../proxy_ca.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0, checks = 0;

static void fail(const char *label, const char *what) {
    printf("  FAIL   %s: %s\n", label, what);
    fails++;
}

/* the dNSName of subtree i, or NULL */
static const char *dns_at(STACK_OF(GENERAL_SUBTREE) *sk, int i) {
    GENERAL_SUBTREE *t = sk_GENERAL_SUBTREE_value(sk, i);
    if (!t || t->base->type != GEN_DNS) return NULL;
    return (const char *)ASN1_STRING_get0_data(t->base->d.dNSName);
}

static void check(const char *label, char *const *names, size_t n, char *const *excl, size_t nx) {
    pca_t c;
    char why[256] = "";
    checks++;
    pca_init(&c);
    if (pca_make_ca(&c, "test-run", names, n, excl, nx, PCA_VALID_S, why, sizeof why) != 0) {
        fail(label, why);
        goto out;
    }
    int crit = -1;
    NAME_CONSTRAINTS *ncs = X509_get_ext_d2i(c.cert, NID_name_constraints, &crit, NULL);
    if (!ncs) { fail(label, "no name constraints"); goto out; }
    if (crit != 1) fail(label, "name constraints not critical");
    size_t want_p = n ? n : 1, want_x = nx + 2;
    int np = sk_GENERAL_SUBTREE_num(ncs->permittedSubtrees), nxs = sk_GENERAL_SUBTREE_num(ncs->excludedSubtrees);
    if (np < 0 || (size_t)np != want_p || nxs < 0 || (size_t)nxs != want_x) {
        char m[96];
        snprintf(m, sizeof m, "%d permitted, %d excluded (want %zu, %zu)", np, nxs, want_p, want_x);
        fail(label, m);
    } else {
        for (size_t i = 0; i < want_p; i++) {
            const char *d = dns_at(ncs->permittedSubtrees, (int)i), *w = n ? names[i] : "invalid";
            if (!d || strcmp(d, w)) { fail(label, "a permitted name differs"); break; }
        }
        for (size_t i = 0; i < nx; i++) {
            const char *d = dns_at(ncs->excludedSubtrees, (int)i);
            if (!d || strcmp(d, excl[i])) { fail(label, "an excluded name differs"); break; }
        }
        for (size_t i = nx; i < want_x; i++) {
            GENERAL_SUBTREE *t = sk_GENERAL_SUBTREE_value(ncs->excludedSubtrees, (int)i);
            if (!t || t->base->type != GEN_IPADD) { fail(label, "an IP range is not excluded"); break; }
        }
    }
    NAME_CONSTRAINTS_free(ncs);
out:
    X509_free(c.cert);
    EVP_PKEY_free(c.key);
}

/* a 253-character DNS name: four labels of 63, 63, 63 and 61, the first
 * carrying tag and index so each is different */
static char *long_name(char tag, size_t i) {
    char *s = malloc(254);
    memset(s, 'a', 253);
    s[253] = '\0';
    s[63] = s[127] = s[191] = '.';
    snprintf(s, 9, "%c%07zu", tag, i);
    s[8] = 'a';
    return s;
}

int main(void) {
    char *some[] = {"example.com", "api.test.org"}, *pass[] = {"pass.test.org"};
    check("two names, one passthrough", some, 2, pass, 1);
    check("no names (permits only \"invalid\")", NULL, 0, NULL, 0);
    check("names, no passthrough", some, 2, NULL, 0);

    char *many[PCA_MAX_NAMES], *mx[PCA_MAX_NAMES];
    for (size_t i = 0; i < PCA_MAX_NAMES; i++) {
        many[i] = long_name('p', i);
        mx[i] = long_name('x', i);
    }
    for (size_t k = 1; k <= PCA_MAX_NAMES; k *= 2) {
        char label[64];
        snprintf(label, sizeof label, "%zu names of 253 characters each way", k);
        check(label, many, k, mx, k);
    }
    for (size_t i = 0; i < PCA_MAX_NAMES; i++) {
        free(many[i]);
        free(mx[i]);
    }

    printf("proxy_ca_test: %d of %d CAs as wanted\n", checks - fails, checks);
    return fails ? 1 : 0;
}
