// SPDX-License-Identifier: MIT
// v1300_oflags.c — v1.30: the open flags between this architecture's kernel
// encoding and VAREK's (x86_64's uapi values, which rules, certificates and
// records use on every architecture). Built and run on each architecture
// (make test-v1300-oflags): every flag the policy language names maps to its
// VAREK bit, each translation is the other's inverse over every bit, and on
// x86_64 both are the identity.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include "../smt_decide.h"

static int fails;
static void check(int ok, const char *what) {
    printf("  %s   %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) fails++;
}

int main(void) {
    /* VAREK's bits (smt_decide.c's K_ values): x86_64's uapi */
    static const struct { const char *name; uint32_t native, varek; } kFlags[] = {
        { "O_CREAT", O_CREAT, 0100 },           { "O_EXCL", O_EXCL, 0200 },
        { "O_NOCTTY", O_NOCTTY, 0400 },         { "O_TRUNC", O_TRUNC, 01000 },
        { "O_APPEND", O_APPEND, 02000 },        { "O_NONBLOCK", O_NONBLOCK, 04000 },
        { "O_DSYNC", O_DSYNC, 010000 },         { "O_ASYNC", O_ASYNC, 020000 },
        { "O_DIRECT", O_DIRECT, 040000 },       { "O_DIRECTORY", O_DIRECTORY, 0200000 },
        { "O_NOFOLLOW", O_NOFOLLOW, 0400000 },  { "O_NOATIME", O_NOATIME, 01000000 },
        { "O_CLOEXEC", O_CLOEXEC, 02000000 },   { "O_PATH", O_PATH, 010000000 },
        { "O_TMPFILE", O_TMPFILE, 020200000 },  { "O_SYNC", O_SYNC, 04010000 },
#if defined(__aarch64__)
        { "O_LARGEFILE (the kernel's bit)", 0400000, 0100000 },
#else
        { "O_LARGEFILE (the kernel's bit)", 0100000, 0100000 },
#endif
    };
    char what[160];
    for (size_t i = 0; i < sizeof kFlags / sizeof kFlags[0]; i++) {
        snprintf(what, sizeof what, "%s: the kernel's 0%o is VAREK's 0%o, and back", kFlags[i].name,
                 kFlags[i].native, kFlags[i].varek);
        check(vdp_oflags_from_native(kFlags[i].native) == kFlags[i].varek &&
              vdp_oflags_to_native(kFlags[i].varek) == kFlags[i].native, what);
    }
    /* each the other's inverse, bit by bit and over combinations */
    int inv = 1;
    for (int b = 0; b < 32; b++) {
        uint32_t f = 1u << b;
        inv &= vdp_oflags_to_native(vdp_oflags_from_native(f)) == f &&
               vdp_oflags_from_native(vdp_oflags_to_native(f)) == f;
        inv &= __builtin_popcount(vdp_oflags_from_native(f)) == 1;
    }
    uint32_t x = 0x2545f491u;
    for (int i = 0; i < 100000; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        inv &= vdp_oflags_to_native(vdp_oflags_from_native(x)) == x &&
               vdp_oflags_from_native(vdp_oflags_to_native(x)) == x;
    }
    check(inv, "each translation is the other's inverse (every bit, 100000 combinations); one bit maps to one bit");
    uint32_t ro = O_RDONLY, wt = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
    check(vdp_oflags_from_native(ro) == 0 && vdp_oflags_from_native(wt) == (01 | 0100 | 01000 | 02000000),
          "the access modes and the bits both encodings share are unchanged");
#if defined(__x86_64__)
    int id = 1;
    for (int b = 0; b < 32; b++) id &= vdp_oflags_from_native(1u << b) == (1u << b);
    check(id, "x86_64: the identity");
#elif defined(__aarch64__)
    check(vdp_oflags_from_native(O_DIRECTORY | O_NOFOLLOW) == (0200000 | 0400000),
          "arm64: O_DIRECTORY | O_NOFOLLOW is VAREK's 0200000 | 0400000");
#endif
    printf("v1300_oflags: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
