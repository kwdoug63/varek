// SPDX-License-Identifier: MIT
// test_v1250_shared.c — shared_domains.c for test_v1250.sh.
//   test_v1250_shared <psl> <varek-list> refuses <suffix>...   one line each: REFUSED <why> | ok
//   test_v1250_shared <psl> <varek-list> alabel                 UTF-8 labels on stdin -> A-labels
//   test_v1250_shared <psl> <varek-list> counts                 rules read per list
//   test_v1250_shared <psl> <varek-list> cases                  suffixes on stdin -> refused | ok
#include "../shared_domains.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    char why[512];
    if (!strcmp(argv[3], "alabel")) {
        char line[512], out[512];
        while (fgets(line, sizeof line, stdin)) {
            line[strcspn(line, "\r\n")] = '\0';
            printf("%s\n", sd_to_alabel(line, strlen(line), out, sizeof out) == 0 ? out : "!");
        }
        return 0;
    }
    sd_lists_t *l = sd_load(argv[1], argv[2], why, sizeof why);
    if (!l) { fprintf(stderr, "%s\n", why); return 1; }
    if (!strcmp(argv[3], "cases")) {
        char line[1024];
        while (fgets(line, sizeof line, stdin)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0]) printf("%s\n", sd_refuses(l, line, why, sizeof why) ? "refused" : "ok");
        }
    } else if (!strcmp(argv[3], "counts")) {
        printf("icann %zu private %zu varek %zu\n", sd_count(l, 0), sd_count(l, 1), sd_count(l, 2));
    } else {
        for (int i = 4; i < argc; i++)
            printf("%s %s\n", argv[i], sd_refuses(l, argv[i], why, sizeof why) ? why : "ok");
    }
    sd_free(l);
    return 0;
}
