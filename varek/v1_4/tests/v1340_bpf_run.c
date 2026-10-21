// SPDX-License-Identifier: MIT
//
// v1340_bpf_run.c — v1.34 step 3 (tests/test_v1340.sh): the node agent's
// BPF interpreter (warden_oci.c, wd_bpf_run), which answers the calls the
// pod's filter notifies as the Warden's own filter would, run on that filter
// for each call read from standard input (struct seccomp_data, 64 bytes
// each); one action a line. The filter itself is written to OUT for
// tests/v1340_bpf_compare.py's interpreter to run on the same calls.
//
//   v1340_bpf_run FLAGS OUT < calls
#include <stdio.h>
#include <stdlib.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "../warden_oci.h"

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: v1340_bpf_run FLAGS OUT < calls\n"); return 2; }
    struct sock_filter *f;
    unsigned n;
    if (wd_filter_bpf(atoi(argv[1]), &f, &n) < 0) { fprintf(stderr, "wd_filter_bpf failed\n"); return 1; }
    FILE *o = fopen(argv[2], "wb");
    if (!o || fwrite(f, sizeof *f, n, o) != n || fclose(o)) { perror(argv[2]); return 1; }
    struct seccomp_data d;
    while (fread(&d, sizeof d, 1, stdin) == 1) printf("%u\n", wd_bpf_run(f, n, &d));
    return 0;
}
