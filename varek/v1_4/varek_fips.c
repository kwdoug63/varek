// SPDX-License-Identifier: MIT
// varek_fips.c — VAREK's single cryptographic backend (v1.41). See varek_fips.h.
//
// This file contains no cryptographic algorithm of its own. Every primitive is
// fetched from and executed by the host OpenSSL 3 provider. Algorithms are
// fetched with a NULL property query, so the library context's default
// properties decide the implementation: fips=yes once the FIPS provider is
// active, which makes the FIPS 140-3 validated module perform all of VAREK's
// hashing, signing and random generation.

#include "varek_fips.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

struct vfips_md  { EVP_MD_CTX *ctx; EVP_MD *md; };
struct vfips_key { EVP_PKEY *pkey; };

static void why_set(char *why, size_t wn, const char *msg) {
    if (why && wn) snprintf(why, wn, "%s", msg);
}

// ---- init / provider selection / FIPS gate ---------------------------------

static bool provider_is_fips(const OSSL_PROVIDER *p) {
    return p && strcmp(OSSL_PROVIDER_get0_name(p), "fips") == 0;
}

bool vfips_fips_active(void) {
    // The default fetch path is the one VAREK uses everywhere: check it for a
    // digest and for the signature algorithm.
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA-384", NULL);
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ECDSA", NULL);
    bool ok = md && sig && provider_is_fips(EVP_MD_get0_provider(md)) &&
              provider_is_fips(EVP_SIGNATURE_get0_provider(sig));
    EVP_SIGNATURE_free(sig);
    EVP_MD_free(md);
    return ok;
}

const char *vfips_provider_label(void) {
    return vfips_fips_active() ? "fips" : "default";
}

static bool kernel_fips_mode(void) {
    FILE *f = fopen("/proc/sys/crypto/fips_enabled", "re");
    if (!f) return false;
    int c = fgetc(f);
    fclose(f);
    return c == '1';
}

// Load the FIPS provider (and base, for encoders/decoders) and make fips=yes
// the default property. 0 if the FIPS provider then services VAREK's crypto.
static int activate_fips(void) {
    if (!OSSL_PROVIDER_available(NULL, "fips") && !OSSL_PROVIDER_load(NULL, "fips"))
        return -1;
    if (!OSSL_PROVIDER_available(NULL, "base")) (void)OSSL_PROVIDER_load(NULL, "base");
    if (EVP_default_properties_enable_fips(NULL, 1) != 1) return -1;
    return vfips_fips_active() ? 0 : -1;
}

static int  g_init_done;
static int  g_init_rc;
static char g_init_why[256];

int vfips_init(int flags, char *why, size_t wn) {
    if (g_init_done) {
        if (g_init_rc) why_set(why, wn, g_init_why);
        return g_init_rc;
    }
    g_init_done = 1;
    uint64_t opts = (flags & VFIPS_INIT_NO_CONFIG) ? OPENSSL_INIT_NO_LOAD_CONFIG
                                                   : OPENSSL_INIT_LOAD_CONFIG;
    if (OPENSSL_init_crypto(opts, NULL) != 1) {
        snprintf(g_init_why, sizeof g_init_why, "libcrypto failed to initialise");
        g_init_rc = -1;
        goto out;
    }
    // Best-effort secure heap for private-key material, for the callers that
    // hold a private key (VFIPS_INIT_SECURE_HEAP); unsupported is fine.
    if (flags & VFIPS_INIT_SECURE_HEAP)
        (void)CRYPTO_secure_malloc_init((size_t)1 << 17, (size_t)1 << 5);

    // Activate the FIPS provider before anything is fetched: an explicit load
    // turns off OpenSSL's fallback, so the default (non-validated) provider is
    // never loaded into a FIPS run. activate_fips() then checks that the
    // validated module is what VAREK's default fetches resolve to.
#ifdef VAREK_REQUIRE_FIPS
    // The host in FIPS mode first: RHEL's FIPS provider loads, and services
    // every fetch, whether or not the host is in FIPS mode, but it is the
    // validated module only on a host in FIPS mode (its security policy).
    // Off FIPS mode nothing is loaded and init refuses.
    if (!kernel_fips_mode() || activate_fips() != 0) {
        snprintf(g_init_why, sizeof g_init_why,
                 "the FIPS provider is not active%s; this Defense build runs only "
                 "with the host's FIPS 140-3 validated OpenSSL module",
                 kernel_fips_mode() ? "" : " (the host is not in FIPS mode)");
        g_init_rc = -1;
        goto out;
    }
#else
    if (kernel_fips_mode() && activate_fips() != 0)
        // The core build on a FIPS-mode host whose FIPS provider cannot be
        // activated: say so. (Refusing is the Defense build's behaviour.)
        fprintf(stderr, "varek: warning: the host is in FIPS mode but its FIPS provider "
                        "could not be activated; using the default provider\n");
#endif
    g_init_rc = 0;
out:
    if (g_init_rc) why_set(why, wn, g_init_why);
    return g_init_rc;
}

// ---- digests ---------------------------------------------------------------

vfips_md *vfips_md_new(int bits) {
    const char *name = bits == 384 ? "SHA-384" : bits == 256 ? "SHA-256" : NULL;
    if (!name) return NULL;
    vfips_md *m = OPENSSL_zalloc(sizeof *m);
    if (!m) return NULL;
    m->md = EVP_MD_fetch(NULL, name, NULL);
    m->ctx = EVP_MD_CTX_new();
    if (!m->md || !m->ctx || EVP_DigestInit_ex2(m->ctx, m->md, NULL) != 1) {
        vfips_md_free(m);
        return NULL;
    }
    return m;
}

int vfips_md_update(vfips_md *m, const void *d, size_t n) {
    return (m && EVP_DigestUpdate(m->ctx, d, n) == 1) ? 0 : -1;
}

int vfips_md_final(vfips_md *m, unsigned char *out) {
    unsigned int outl = 0;
    return (m && EVP_DigestFinal_ex(m->ctx, out, &outl) == 1) ? 0 : -1;
}

void vfips_md_free(vfips_md *m) {
    if (!m) return;
    EVP_MD_CTX_free(m->ctx);
    EVP_MD_free(m->md);
    OPENSSL_free(m);
}

static int one_shot(const char *name, const void *d, size_t n, unsigned char *out) {
    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int outl = 0;
    int ok = md && c && EVP_DigestInit_ex2(c, md, NULL) == 1 &&
             EVP_DigestUpdate(c, d, n) == 1 && EVP_DigestFinal_ex(c, out, &outl) == 1;
    EVP_MD_CTX_free(c);
    EVP_MD_free(md);
    return ok ? 0 : -1;
}

int vfips_sha256(const void *d, size_t n, unsigned char out[VFIPS_SHA256_LEN]) {
    return one_shot("SHA-256", d, n, out);
}
int vfips_sha384(const void *d, size_t n, unsigned char out[VFIPS_SHA384_LEN]) {
    return one_shot("SHA-384", d, n, out);
}

// ---- signing key -----------------------------------------------------------

static bool is_p384(EVP_PKEY *pkey) {
    char g[64] = {0};
    size_t gl = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       g, sizeof g, &gl) != 1)
        return false;
    return strcmp(g, "secp384r1") == 0 || strcmp(g, "P-384") == 0;
}

// The public key as the uncompressed point 0x04 || X || Y (97 bytes for
// P-384), built from the key's coordinates. OSSL_PKEY_PARAM_PUB_KEY gives the
// point in the key's conversion form, which is not fixed: RHEL 9.8's OpenSSL
// 3.5 with its FIPS provider gives the compressed form (49 bytes), so the
// encoding VAREK records is built here, whatever the library's default.
static int pub_octets(EVP_PKEY *pkey, unsigned char *buf, size_t cap, size_t *len) {
    BIGNUM *x = NULL, *y = NULL;
    int rc = -1;
    if (cap >= 97 &&
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1 &&
        BN_bn2binpad(x, buf + 1, 48) == 48 && BN_bn2binpad(y, buf + 49, 48) == 48) {
        buf[0] = 0x04;
        *len = 97;
        rc = 0;
    }
    BN_free(x);
    BN_free(y);
    return rc;
}

int vfips_keygen_pem(char *pem, size_t pemn, char *pub_hex, size_t pubn) {
    EVP_PKEY *pkey = EVP_EC_gen("P-384");
    if (!pkey) return -1;
    BIO *b = BIO_new(BIO_s_mem());
    unsigned char pub[160];
    size_t pl = 0;
    int rc = -1;
    if (b && PEM_write_bio_PrivateKey(b, pkey, NULL, NULL, 0, NULL, NULL) == 1) {
        BUF_MEM *bm = NULL;
        BIO_get_mem_ptr(b, &bm);
        if (bm && bm->length + 1 <= pemn &&
            pub_octets(pkey, pub, sizeof pub, &pl) == 0 && pubn >= 2 * pl + 1) {
            memcpy(pem, bm->data, bm->length);
            pem[bm->length] = '\0';
            vfips_bin2hex(pub_hex, pubn, pub, pl);
            rc = 0;
        }
        if (bm && bm->data) OPENSSL_cleanse(bm->data, bm->length);
    }
    BIO_free(b);
    EVP_PKEY_free(pkey);
    return rc;
}

vfips_key *vfips_key_load_pem(const char *pem, size_t pem_len, char *why, size_t wn) {
    BIO *b = BIO_new_mem_buf(pem, (int)pem_len);
    if (!b) { why_set(why, wn, "out of memory"); return NULL; }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    BIO_free(b);
    if (!pkey) {
        why_set(why, wn, "not a PEM private key (a PKCS#8 EC P-384 key is expected)");
        ERR_clear_error();
        return NULL;
    }
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC || !is_p384(pkey)) {
        why_set(why, wn, "the signing key is not on curve P-384");
        EVP_PKEY_free(pkey);
        return NULL;
    }
    vfips_key *k = OPENSSL_zalloc(sizeof *k);
    if (!k) { EVP_PKEY_free(pkey); why_set(why, wn, "out of memory"); return NULL; }
    k->pkey = pkey;
    return k;
}

void vfips_key_free(vfips_key *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    OPENSSL_free(k);
}

int vfips_pubkey_hex(const vfips_key *k, char *out, size_t outn) {
    unsigned char pub[160];
    size_t pl = 0;
    if (!k || pub_octets(k->pkey, pub, sizeof pub, &pl) != 0) return -1;
    if (outn < 2 * pl + 1) return -1;
    vfips_bin2hex(out, outn, pub, pl);
    return (int)(2 * pl);
}

int vfips_sign(const vfips_key *k, const void *msg, size_t n,
               char *sig_hex, size_t sn) {
    if (!k) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char der[160];
    size_t dl = sizeof der;
    int rc = -1;
    if (ctx &&
        EVP_DigestSignInit_ex(ctx, NULL, "SHA-384", NULL, NULL, k->pkey, NULL) == 1 &&
        EVP_DigestSign(ctx, der, &dl, msg, n) == 1 &&
        sn >= 2 * dl + 1) {
        vfips_bin2hex(sig_hex, sn, der, dl);
        rc = (int)(2 * dl);
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

int vfips_verify(const char *pub_hex, const void *msg, size_t n, const char *sig_hex) {
    size_t hl = strlen(pub_hex), sl = strlen(sig_hex);
    unsigned char pub[160], der[160];
    if (hl == 0 || sl == 0 || hl > 2 * sizeof pub || sl > 2 * sizeof der || (hl | sl) & 1)
        return -1;
    size_t pl = hl / 2, dl = sl / 2;
    if (vfips_hex2bin(pub, pl, pub_hex, hl) != 0 ||
        vfips_hex2bin(der, dl, sig_hex, sl) != 0) return -1;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_MD_CTX *mctx = NULL;
    int rc = -1;
    if (!pctx || !bld) goto done;
    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-384", 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, pl) != 1)
        goto done;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto done;
    if (EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
        goto done;
    mctx = EVP_MD_CTX_new();
    if (!mctx) goto done;
    if (EVP_DigestVerifyInit_ex(mctx, NULL, "SHA-384", NULL, NULL, pkey, NULL) != 1)
        goto done;
    rc = EVP_DigestVerify(mctx, der, dl, msg, n);    // 1 ok, 0 bad, <0 error
    if (rc < 0) rc = -1;
done:
    if (rc != 1) ERR_clear_error();
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

// ---- encoding and memory helpers (not cryptography) ------------------------

void vfips_bin2hex(char *hex, size_t hexn, const unsigned char *b, size_t bn) {
    static const char d[] = "0123456789abcdef";
    if (!hexn) return;
    size_t i = 0;
    for (; i < bn && 2 * i + 2 < hexn; i++) {
        hex[2 * i]     = d[b[i] >> 4];
        hex[2 * i + 1] = d[b[i] & 15];
    }
    hex[2 * i] = '\0';
}

static int nyb(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int vfips_hex2bin(unsigned char *b, size_t bn, const char *hex, size_t hexn) {
    if (hexn != 2 * bn) return -1;
    for (size_t i = 0; i < bn; i++) {
        int hi = nyb((unsigned char)hex[2 * i]), lo = nyb((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        b[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

void vfips_memzero(void *p, size_t n) { OPENSSL_cleanse(p, n); }

int vfips_rand(void *buf, size_t n) {
    return n <= INT32_MAX && RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

int vfips_b64url(char *out, size_t outn, const unsigned char *b, size_t bn) {
    size_t need = 4 * ((bn + 2) / 3) + 1;
    if (outn < need || bn > INT32_MAX / 2) return -1;
    int w = EVP_EncodeBlock((unsigned char *)out, b, (int)bn);
    if (w < 0) return -1;
    for (int i = 0; i < w; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    while (w > 0 && out[w - 1] == '=') w--;
    out[w] = '\0';
    return 0;
}

int vfips_b64decode(unsigned char *out, size_t cap, const char *in, size_t inlen,
                    size_t *outlen) {
    // OpenSSL's PEM base64 decoder: newlines are skipped, anything else that
    // is not base64 is an error. The output is at most 3/4 of the input.
    if (inlen > INT32_MAX || cap < (inlen / 4 + 1) * 3) return -1;
    EVP_ENCODE_CTX *c = EVP_ENCODE_CTX_new();
    if (!c) return -1;
    int a = 0, f = 0, rc = -1;
    EVP_DecodeInit(c);
    if (EVP_DecodeUpdate(c, out, &a, (const unsigned char *)in, (int)inlen) >= 0 &&
        EVP_DecodeFinal(c, out + a, &f) == 1) {
        *outlen = (size_t)a + (size_t)f;
        rc = 0;
    }
    EVP_ENCODE_CTX_free(c);
    return rc;
}
