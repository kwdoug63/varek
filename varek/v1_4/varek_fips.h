// SPDX-License-Identifier: MIT
// varek_fips.h — VAREK's single cryptographic backend (v1.41).
//
// Every hash and signature the Warden, the certificate checker and the tools
// perform goes through this interface, and the implementation does no
// cryptography of its own: it calls the host's OpenSSL 3 provider.
//
// Provider selection (vfips_init):
//   * On a host whose kernel is in FIPS mode (/proc/sys/crypto/fips_enabled
//     is 1), the FIPS provider is activated and made the default (fips=yes),
//     so VAREK's crypto runs in the FIPS 140-3 validated module.
//   * In a build defined with -DVAREK_REQUIRE_FIPS (the Defense build), the
//     FIPS provider is activated whatever the kernel says, and vfips_init()
//     fails unless it is the provider that services VAREK's hashing and
//     signing. The caller then refuses to start (fail closed).
//   * Otherwise (the open-source core on an ordinary host) the default
//     provider is used.
//
// Algorithms (CNSA-aligned): SHA-384 for the audit chain; SHA-256 for the
// policy digest and content hashes (these surface as sha256= and match
// operator-authored pins, so the algorithm is kept and only its
// implementation moves to the validated module); ECDSA P-384 with SHA-384 for
// the verdict-stream signatures.
//
// The legacy SHA-256 + Ed25519 audit format (streams written before v1.41)
// stays verifiable offline by tools/varek_audit.py; this file does not carry
// it. New streams set "log":"chain-2" and "sigalg":"ecdsa-p384-sha384" in
// run_start and sign with VFIPS_LOG_SIG_DOMAIN, so a verifier never confuses
// the two.

#ifndef VAREK_FIPS_H
#define VAREK_FIPS_H

#include <stddef.h>
#include <stdbool.h>

#define VFIPS_SHA256_LEN 32
#define VFIPS_SHA384_LEN 48
#define VFIPS_CHAIN_LEN  VFIPS_SHA384_LEN          // v1.41 audit-chain width

#define VFIPS_SIGALG_LEGACY_ED25519 "ed25519"
#define VFIPS_SIGALG_P384           "ecdsa-p384-sha384"
#define VFIPS_LOG_SIG_DOMAIN        "VAREK-LOG-SIG-2"   // legacy domain was ...-1

// DER ECDSA P-384 signatures are at most ~104 bytes; the hex form fits here.
#define VFIPS_SIG_HEX_MAX 232
// Uncompressed P-384 public point 0x04||X(48)||Y(48) = 97 bytes -> 194 hex + NUL.
#define VFIPS_PUB_HEX_MAX 196

// vfips_init flags.
// VFIPS_INIT_NO_CONFIG: initialise libcrypto without reading OpenSSL's
// configuration file (the Warden's hardening: no module or provider a config
// file names is loaded into it). The FIPS provider, when wanted, is loaded
// explicitly. Without this flag the host's configuration is read, so system
// crypto policy (TLS versions, groups, ciphers) applies — the helpers that
// speak TLS use that.
#define VFIPS_INIT_NO_CONFIG 0x1
// VFIPS_INIT_SECURE_HEAP: set up OpenSSL's secure heap (locked memory, best
// effort) for private-key material: the Warden (its signing key) and the
// keygen ask for it. The helpers do not: the proxy's run CA sets up its own
// (proxy_ca.c, which reports whether it is locked) and warden-secrets locks
// its own arena; a heap made here first would take their RLIMIT_MEMLOCK.
#define VFIPS_INIT_SECURE_HEAP 0x2

// One-time process init. Must be the process's first OpenSSL call (it makes
// the library-initialisation choice above); later calls return the first
// call's result. Returns 0, or -1 with a reason in why[] (the caller refuses
// to start).
int  vfips_init(int flags, char *why, size_t wn);

// True iff the provider that would service VAREK's default fetches — SHA-384
// and ECDSA — is the one named "fips".
bool vfips_fips_active(void);

// A short label for run_start and status lines: "fips" or "default".
const char *vfips_provider_label(void);

// Streaming digest. bits is 256 or 384. out must be bits/8 bytes.
typedef struct vfips_md vfips_md;
vfips_md *vfips_md_new(int bits);
int  vfips_md_update(vfips_md *m, const void *d, size_t n);
int  vfips_md_final(vfips_md *m, unsigned char *out);
void vfips_md_free(vfips_md *m);

// One-shot digests. 0 ok, -1 error.
int  vfips_sha256(const void *d, size_t n, unsigned char out[VFIPS_SHA256_LEN]);
int  vfips_sha384(const void *d, size_t n, unsigned char out[VFIPS_SHA384_LEN]);

// ECDSA P-384 signing key. The private key is held by OpenSSL (secure heap
// when available) and never leaves this module in the clear.
typedef struct vfips_key vfips_key;

// Generate a fresh P-384 signing key in the host provider. Writes a
// NUL-terminated PKCS#8 PEM private key into pem and the uncompressed public
// point as hex into pub_hex. 0 ok, -1 error.
int  vfips_keygen_pem(char *pem, size_t pemn, char *pub_hex, size_t pubn);

// Load a signing key from an in-memory PEM PKCS#8 EC private key on curve
// P-384. NULL with a reason in why[] on any mismatch.
vfips_key *vfips_key_load_pem(const char *pem, size_t pem_len, char *why, size_t wn);
void vfips_key_free(vfips_key *k);

// The uncompressed public point as hex (NUL-terminated). Hex length or -1.
int  vfips_pubkey_hex(const vfips_key *k, char *out, size_t outn);

// ECDSA-P384-SHA384 over msg, DER then hex (NUL-terminated). Hex length or -1.
int  vfips_sign(const vfips_key *k, const void *msg, size_t n,
                char *sig_hex, size_t sn);

// Verify sig_hex over msg under the uncompressed-point public key pub_hex.
// 1 valid, 0 invalid, -1 malformed key or signature. Never aborts.
int  vfips_verify(const char *pub_hex, const void *msg, size_t n,
                  const char *sig_hex);

// Encoding and memory helpers (these replace the libsodium utilities VAREK
// used; none of them is cryptography).
// vfips_bin2hex: lowercase, always NUL-terminated; hexn >= 2*bn+1 for all of it.
void vfips_bin2hex(char *hex, size_t hexn, const unsigned char *b, size_t bn);
// vfips_hex2bin: exactly 2*bn hex characters. 0 ok, -1 bad.
int  vfips_hex2bin(unsigned char *b, size_t bn, const char *hex, size_t hexn);
void vfips_memzero(void *p, size_t n);
int  vfips_rand(void *buf, size_t n);                        // 0 ok, -1 error (DRBG of the provider)
// URL-safe base64, no padding. 0 ok, -1 error.
int  vfips_b64url(char *out, size_t outn, const unsigned char *b, size_t bn);
// Standard base64 (PEM body; newlines ignored). 0 ok with *outlen set, -1 bad.
int  vfips_b64decode(unsigned char *out, size_t cap, const char *in, size_t inlen,
                     size_t *outlen);

#endif // VAREK_FIPS_H
