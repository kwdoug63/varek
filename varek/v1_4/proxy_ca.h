// SPDX-License-Identifier: MIT
// proxy_ca.h — v1.26.1: the run's CA, made and held by warden-proxy alone
// (docs/security/v1.26.1-inspecting-mode.md, section 3).
//
// In inspecting mode the proxy makes a CA when the run starts: an ECDSA
// P-256 key that never leaves the proxy's memory (OpenSSL's secure heap
// where it can be had), and a certificate with critical name constraints
// permitting only the names the policy lets the agent reach through the
// proxy. The Warden is sent only the certificate, and a PKCS#12 trust store
// (the host's roots and the CA) for Java. Nothing is written to disk.

#ifndef VAREK_PROXY_CA_H
#define VAREK_PROXY_CA_H

#include <stddef.h>

#define PCA_SECURE_HEAP  65536       /* bytes of locked memory for keys */
#define PCA_MAX_ROOTS    1024        /* certificates in the host's bundle */
#define PCA_BACKDATE_S   300         /* notBefore: this long before now (clock skew) */
#define PCA_VALID_S      (7L * 86400) /* notAfter: this long after now */
#define PCA_MAX_NAMES    256         /* name-constraint subtrees */

typedef struct {
    struct evp_pkey_st  *key;        /* the CA's key */
    struct x509_st      *cert;       /* its certificate */
    struct stack_st_X509 *roots;     /* the host's trust bundle */
    int                  secure_heap;/* the key is in locked memory */
} pca_t;

int pca_init(pca_t *c);
/* Read the host's trust bundle (PEM). 0, or -1 with why. */
int pca_load_roots(pca_t *c, const char *bundle, char *why, size_t wn);
/* Make the CA, valid from PCA_BACKDATE_S ago for valid_s, permitting the n
 * names (host names; a name covers the names under it). 0, or -1 with why. */
int pca_make_ca(pca_t *c, const char *run_id, char *const *names, size_t n, long valid_s,
                char *why, size_t wn);
/* The CA certificate in PEM, and the PKCS#12 trust store (malloc'd). 0 or -1. */
int pca_pem(const pca_t *c, unsigned char **out, size_t *len);
int pca_p12(const pca_t *c, unsigned char **out, size_t *len);
/* How many certificates were read from the host's bundle. */
int pca_nroots(const pca_t *c);

#endif /* VAREK_PROXY_CA_H */
