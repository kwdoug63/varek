// SPDX-License-Identifier: MIT
// vfips_selftest.c — v1.41: the crypto backend (varek_fips.c) checked alone.
//
//   vfips_selftest [P384-PEM-KEY]
//
// Known answers (SHA-256 and SHA-384 of "abc"; RFC 6979 A.2.6's ECDSA P-384
// SHA-384 signatures, verified through vfips_verify), streaming against
// one-shot hashing, hex and base64 helpers, and, with a key from
// tools/varek_keygen, a sign/verify round trip of the verdict stream's own
// message (DOMAIN || 48-byte chain) and its tampered forms.
//
// Built with -DVAREK_REQUIRE_FIPS (the Defense build's switch): on a host not
// in FIPS mode vfips_init must refuse (fail closed) and nothing else runs; on
// a host in FIPS mode it must succeed with the FIPS provider active, and the
// rest runs inside it. Exit 0 when every check holds.

#include "varek_fips.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("  FAIL   %s\n", msg); fails++; } \
                           else printf("  PASS   %s\n", msg); } while (0)

static int kernel_fips(void) {
    FILE *f = fopen("/proc/sys/crypto/fips_enabled", "re");
    int c = f ? fgetc(f) : EOF;
    if (f) fclose(f);
    return c == '1';
}

int main(int argc, char **argv) {
    char why[256] = {0};
    int rc = vfips_init(0, why, sizeof why);
#ifdef VAREK_REQUIRE_FIPS
    if (!kernel_fips()) {
        CHECK(rc == -1, "Defense switch, host not in FIPS mode: init refuses (fail closed)");
        CHECK(!vfips_fips_active(), "... and the FIPS provider is not the one in use");
        printf("  (reason given: %s)\n", why);
        return fails ? 1 : 0;
    }
    CHECK(rc == 0, "Defense switch, host in FIPS mode: init succeeds");
    CHECK(vfips_fips_active(), "... with the FIPS provider servicing SHA-384 and ECDSA");
    if (rc != 0) { printf("  (reason given: %s)\n", why); return 1; }
#else
    CHECK(rc == 0, "init");
    if (kernel_fips()) CHECK(vfips_fips_active(), "host in FIPS mode: the FIPS provider is the one in use");
#endif
    printf("  (provider: %s)\n", vfips_provider_label());

    unsigned char h[VFIPS_SHA384_LEN], h2[VFIPS_SHA384_LEN];
    char hx[2 * VFIPS_SHA384_LEN + 1];
    CHECK(vfips_sha256("abc", 3, h) == 0, "SHA-256 computed");
    vfips_bin2hex(hx, sizeof hx, h, 32);
    CHECK(!strcmp(hx, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "SHA-256(\"abc\") known answer");
    CHECK(vfips_sha384("abc", 3, h) == 0, "SHA-384 computed");
    vfips_bin2hex(hx, sizeof hx, h, 48);
    CHECK(!strcmp(hx, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                      "8086072ba1e7cc2358baeca134c825a7"), "SHA-384(\"abc\") known answer");
    vfips_md *m = vfips_md_new(384);
    CHECK(m && !vfips_md_update(m, "a", 1) && !vfips_md_update(m, "bc", 2) && !vfips_md_final(m, h2),
          "streaming SHA-384");
    vfips_md_free(m);
    CHECK(!memcmp(h, h2, 48), "streaming SHA-384 equals one-shot");

    // RFC 6979 A.2.6: the P-384 key; SHA-384 signatures, DER-encoded
    static const char *pub =
        "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13"
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
    static const char *sig_sample =      // r, s for "sample"
        "3066023100"
        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46"
        "023100"
        "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8";
    CHECK(vfips_verify(pub, "sample", 6, sig_sample) == 1, "ECDSA P-384 SHA-384: RFC 6979 A.2.6 \"sample\" verifies");
    CHECK(vfips_verify(pub, "sampl3", 6, sig_sample) == 0, "... and not over another message");
    CHECK(vfips_verify("04abcd", "sample", 6, sig_sample) == -1, "... a malformed key is an error, not a pass");

    unsigned char raw[7] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80}, back[7];
    char rx[15], b64[16];
    vfips_bin2hex(rx, sizeof rx, raw, 7);
    CHECK(!strcmp(rx, "deadbeef007f80") && !vfips_hex2bin(back, 7, rx, 14) && !memcmp(raw, back, 7), "hex both ways");
    size_t bl = 0;
    unsigned char dec[16];
    CHECK(!vfips_b64url(b64, sizeof b64, raw, 7) && !strcmp(b64, "3q2-7wB_gA"), "base64url, no padding");
    CHECK(!vfips_b64decode(dec, sizeof dec, "3q2+7wB/gA==", 12, &bl) && bl == 7 && !memcmp(dec, raw, 7),
          "base64 (PEM body) decoded");
    CHECK(vfips_b64decode(dec, sizeof dec, "3q2+7w*/gA==", 12, &bl) != 0, "... and a stray byte refused");

    if (argc < 2) { printf("  (no key given: the round trip is not run)\n"); return fails ? 1 : 0; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    char pem[4096];
    size_t pl = fread(pem, 1, sizeof pem - 1, f);
    fclose(f);
    pem[pl] = '\0';
    vfips_key *k = vfips_key_load_pem(pem, pl, why, sizeof why);
    vfips_memzero(pem, sizeof pem);
    CHECK(k != NULL, "a P-384 PEM key (tools/varek_keygen) loads");
    if (!k) { printf("  (%s)\n", why); return 1; }
    char kp[VFIPS_PUB_HEX_MAX];
    CHECK(vfips_pubkey_hex(k, kp, sizeof kp) == 194 && !strncmp(kp, "04", 2), "its public key: the 97-byte point");
    unsigned char chain[VFIPS_CHAIN_LEN];
    vfips_sha384("record-bytes", 12, chain);
    unsigned char msg[sizeof VFIPS_LOG_SIG_DOMAIN - 1 + VFIPS_CHAIN_LEN];
    memcpy(msg, VFIPS_LOG_SIG_DOMAIN, sizeof VFIPS_LOG_SIG_DOMAIN - 1);
    memcpy(msg + sizeof VFIPS_LOG_SIG_DOMAIN - 1, chain, VFIPS_CHAIN_LEN);
    char sig[VFIPS_SIG_HEX_MAX];
    CHECK(vfips_sign(k, msg, sizeof msg, sig, sizeof sig) > 0, "the verdict stream's message signed (ECDSA P-384)");
    CHECK(vfips_verify(kp, msg, sizeof msg, sig) == 1, "... the signature verifies");
    msg[sizeof msg - 1] ^= 1;
    CHECK(vfips_verify(kp, msg, sizeof msg, sig) == 0, "... not over a changed chain value");
    msg[sizeof msg - 1] ^= 1;
    sig[20] = sig[20] == 'a' ? 'b' : 'a';
    CHECK(vfips_verify(kp, msg, sizeof msg, sig) != 1, "... and a changed signature does not verify");
    vfips_key_free(k);
    const char *notp384 = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    CHECK(vfips_key_load_pem(notp384, strlen(notp384), why, sizeof why) == NULL, "a key that is not P-384 PEM is refused");
    return fails ? 1 : 0;
}
