// SPDX-License-Identifier: MIT
// proxy_ca.c — v1.26.1: the run's CA, in warden-proxy only
// (docs/security/v1.26.1-inspecting-mode.md, section 3). See proxy_ca.h.

#include "proxy_ca.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ossl_why(char *why, size_t wn, const char *what) {
    unsigned long e = ERR_get_error();
    char b[200] = "";
    if (e) ERR_error_string_n(e, b, sizeof b);
    snprintf(why, wn, "%s%s%s", what, e ? ": " : "", b);
    ERR_clear_error();
}

int pca_init(pca_t *c) {
    memset(c, 0, sizeof *c);
    /* the CA's private key in OpenSSL's secure heap: locked memory, kept out
     * of swap and core dumps, wiped when freed. Where the memory-lock limit
     * is too low for it, the key is held in ordinary memory, which run_start
     * records. */
    c->secure_heap = CRYPTO_secure_malloc_init(PCA_SECURE_HEAP, 16) == 1;
    return 0;
}

int pca_load_roots(pca_t *c, const char *bundle, char *why, size_t wn) {
    BIO *b = BIO_new_file(bundle, "r");
    if (!b) { ossl_why(why, wn, "cannot read the host's trust bundle"); return -1; }
    c->roots = sk_X509_new_null();
    if (!c->roots) { BIO_free(b); snprintf(why, wn, "out of memory"); return -1; }
    X509 *x;
    while ((x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_num(c->roots) >= PCA_MAX_ROOTS || !sk_X509_push(c->roots, x)) {
            X509_free(x);
            BIO_free(b);
            snprintf(why, wn, "the host's trust bundle holds more than %d certificates", PCA_MAX_ROOTS);
            return -1;
        }
    }
    ERR_clear_error();                      /* the end of the file */
    BIO_free(b);
    if (sk_X509_num(c->roots) == 0) { snprintf(why, wn, "the host's trust bundle holds no certificate"); return -1; }
    return 0;
}

static int add_ext(X509 *cert, X509V3_CTX *ctx, int nid, const char *value) {
    X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
    if (!e) return -1;
    int ok = X509_add_ext(cert, e, -1);
    X509_EXTENSION_free(e);
    return ok ? 0 : -1;
}

int pca_make_ca(pca_t *c, const char *run_id, char *const *names, size_t n, long valid_s,
                char *why, size_t wn) {
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kc || EVP_PKEY_keygen_init(kc) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kc, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kc, &c->key) <= 0) {
        EVP_PKEY_CTX_free(kc);
        ossl_why(why, wn, "generating the CA key");
        return -1;
    }
    EVP_PKEY_CTX_free(kc);
    X509 *x = X509_new();
    if (!x) { ossl_why(why, wn, "out of memory"); return -1; }
    c->cert = x;
    /* a random 16-byte serial, positive */
    unsigned char sb[16];
    BIGNUM *bn = NULL;
    if (RAND_bytes(sb, sizeof sb) != 1) { ossl_why(why, wn, "random serial"); return -1; }
    sb[0] &= 0x7f;
    sb[0] |= 0x01;
    bn = BN_bin2bn(sb, sizeof sb, NULL);
    ASN1_INTEGER *serial = bn ? BN_to_ASN1_INTEGER(bn, NULL) : NULL;
    BN_free(bn);
    if (!serial || !X509_set_serialNumber(x, serial)) { ASN1_INTEGER_free(serial); ossl_why(why, wn, "serial"); return -1; }
    ASN1_INTEGER_free(serial);
    char cn[96];
    snprintf(cn, sizeof cn, "VAREK run CA %.40s", run_id);
    X509_NAME *nm = X509_get_subject_name(x);
    if (!X509_set_version(x, 2) ||
        !X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char *)"VAREK Warden (this run only)", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) ||
        !X509_set_issuer_name(x, nm) ||
        !X509_gmtime_adj(X509_getm_notBefore(x), -PCA_BACKDATE_S) ||
        !X509_gmtime_adj(X509_getm_notAfter(x), valid_s) ||
        !X509_set_pubkey(x, c->key)) {
        ossl_why(why, wn, "the CA certificate");
        return -1;
    }
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    /* the policy's names: a dNSName subtree covers the name and every name
     * under it (a wildcard's suffix covers its names); with none, only the
     * reserved name "invalid", so the CA can sign for nothing */
    size_t cap = 64;
    for (size_t i = 0; i < n; i++) cap += strlen(names[i]) + 16;
    char *nc = malloc(cap);
    if (!nc) { snprintf(why, wn, "out of memory"); return -1; }
    size_t off = (size_t)snprintf(nc, cap, "critical");
    for (size_t i = 0; i < n; i++) off += (size_t)snprintf(nc + off, cap - off, ",permitted;DNS:%s", names[i]);
    if (n == 0) snprintf(nc + off, cap - off, ",permitted;DNS:invalid");
    int bad = add_ext(x, &ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") ||
              add_ext(x, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign") ||
              add_ext(x, &ctx, NID_subject_key_identifier, "hash") ||
              add_ext(x, &ctx, NID_name_constraints, nc);
    free(nc);
    if (bad) { ossl_why(why, wn, "the CA certificate's extensions"); return -1; }
    if (X509_sign(x, c->key, EVP_sha256()) <= 0) { ossl_why(why, wn, "signing the CA certificate"); return -1; }
    return 0;
}

static int bio_take(BIO *b, unsigned char **out, size_t *len) {
    char *p;
    long l = BIO_get_mem_data(b, &p);
    if (l <= 0 || !(*out = malloc((size_t)l))) return -1;
    memcpy(*out, p, (size_t)l);
    *len = (size_t)l;
    return 0;
}

int pca_pem(const pca_t *c, unsigned char **out, size_t *len) {
    BIO *b = BIO_new(BIO_s_mem());
    int rc = b && PEM_write_bio_X509(b, c->cert) == 1 ? bio_take(b, out, len) : -1;
    BIO_free(b);
    return rc;
}

/* A PKCS#12 trust store: the host's roots and the run's CA, each a trusted
 * certificate entry as Java reads one (the attribute OpenSSL 3.2's
 * -jdktrust writes: Oracle's trusted key usage, anyExtendedKeyUsage), with
 * no encryption and no MAC, so it opens without a password. */
static int add_trusted(STACK_OF(PKCS12_SAFEBAG) **bags, X509 *x, const char *alias) {
    PKCS12_SAFEBAG *bag = PKCS12_add_cert(bags, x);
    if (!bag) return -1;
    ASN1_OBJECT *any = OBJ_txt2obj("2.5.29.37.0", 1);
    int ok = any && PKCS12_add1_attr_by_txt(bag, "2.16.840.1.113894.746875.1.1", V_ASN1_OBJECT,
                                            (const unsigned char *)any, -1) == 1 &&
             PKCS12_add_friendlyname(bag, alias, -1) == 1;
    ASN1_OBJECT_free(any);
    return ok ? 0 : -1;
}

int pca_p12(const pca_t *c, unsigned char **out, size_t *len) {
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    PKCS12 *p12 = NULL;
    int rc = -1;
    if (add_trusted(&bags, c->cert, "varek-run-ca") < 0) goto done;
    for (int i = 0; i < sk_X509_num(c->roots); i++) {
        char alias[32];
        snprintf(alias, sizeof alias, "host-root-%d", i);
        if (add_trusted(&bags, sk_X509_value(c->roots, i), alias) < 0) goto done;
    }
    if (!PKCS12_add_safe(&safes, bags, -1, 0, NULL)) goto done;      /* -1: not encrypted */
    if (!(p12 = PKCS12_add_safes(safes, 0))) goto done;              /* no MAC is set */
    BIO *b = BIO_new(BIO_s_mem());
    if (b && i2d_PKCS12_bio(b, p12) == 1) rc = bio_take(b, out, len);
    BIO_free(b);
done:
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    PKCS12_free(p12);
    ERR_clear_error();
    return rc;
}

int pca_nroots(const pca_t *c) { return c->roots ? sk_X509_num(c->roots) : 0; }
