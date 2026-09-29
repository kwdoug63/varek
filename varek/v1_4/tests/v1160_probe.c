// SPDX-License-Identifier: MIT
// v1160_probe.c — target for the v1.16.0 regression test.
//
//   v1160_probe [-n N] [-s MS] FILE...
//
// Opens and reads each FILE in turn (N times each, default 1), sleeping MS
// milliseconds after the first open. Run under the Warden with
// tests/v1160_policy.txt: many opens exercise count-based checkpoints and fill
// an anchor FIFO; the sleep exercises the once-a-second checkpoint. Statically
// linked, so its own start-up makes no opens.

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    long n = 1, ms = 0;
    int i = 1;
    for (; i + 1 < argc && argv[i][0] == '-'; i += 2) {
        if (!strcmp(argv[i], "-n")) n = strtol(argv[i + 1], NULL, 10);
        else if (!strcmp(argv[i], "-s")) ms = strtol(argv[i + 1], NULL, 10);
        else break;
    }
    long opened = 0, refused = 0;
    bool slept = false;
    for (; i < argc; i++) {
        for (long k = 0; k < n; k++) {
            int fd = open(argv[i], O_RDONLY | O_CLOEXEC);
            if (fd < 0) { refused++; continue; }
            char buf[64];
            (void)!read(fd, buf, sizeof buf);
            close(fd);
            opened++;
            if (ms && !slept) {
                struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
                nanosleep(&ts, NULL);
                slept = true;
            }
        }
    }
    printf("PROBE opened=%ld refused=%ld\n", opened, refused);
    return 0;
}
