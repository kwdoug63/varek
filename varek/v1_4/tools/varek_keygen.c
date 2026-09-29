// SPDX-License-Identifier: MIT
// varek_keygen.c — make an Ed25519 key pair for signing the Warden's verdict
// stream (v1.16).
//
//   varek_keygen <keyfile>
//
// Writes <keyfile>: the 32-byte seed as 64 hex characters, mode 0600, and
// <keyfile>.pub: the public key as 64 hex characters. Neither may exist
// already. Prints the public key. Run the Warden with --sign-key <keyfile>;
// give auditors <keyfile>.pub (tools/varek_audit.py --pubkey). Keep the key
// where the log's holder cannot read it, or the signatures prove nothing
// against that holder.

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_new(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) {
        fprintf(stderr, "varek_keygen: %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(text);
    ssize_t w = write(fd, text, len);
    if (w != (ssize_t)len || fsync(fd) != 0 || close(fd) != 0) {
        fprintf(stderr, "varek_keygen: %s: write failed\n", path);
        unlink(path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <keyfile>   (writes <keyfile> and <keyfile>.pub)\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0) { fprintf(stderr, "varek_keygen: libsodium failed\n"); return 1; }
    size_t kl = strlen(argv[1]);
    char *pub = malloc(kl + 5);
    if (!pub) return 1;
    memcpy(pub, argv[1], kl);
    memcpy(pub + kl, ".pub", 5);

    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES];
    randombytes_buf(seed, sizeof seed);
    crypto_sign_seed_keypair(pk, sk, seed);
    char seed_hex[2 * sizeof seed + 2], pk_hex[2 * sizeof pk + 2];
    sodium_bin2hex(seed_hex, sizeof seed_hex - 1, seed, sizeof seed);
    sodium_bin2hex(pk_hex, sizeof pk_hex - 1, pk, sizeof pk);
    strcat(seed_hex, "\n");
    strcat(pk_hex, "\n");
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(sk, sizeof sk);

    int rc = 0;
    if (write_new(argv[1], seed_hex, 0600) < 0) rc = 1;
    else if (write_new(pub, pk_hex, 0644) < 0) { unlink(argv[1]); rc = 1; }
    sodium_memzero(seed_hex, sizeof seed_hex);
    if (rc == 0) printf("%s", pk_hex);
    free(pub);
    return rc;
}
