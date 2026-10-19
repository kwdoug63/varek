// SPDX-License-Identifier: MIT
//
// v1340_init.c — v1.34 step 1 (docs/security/v1.34-kubernetes.md, D3): a
// stand-in for varek-init, the launcher the NRI plugin (tests/v1340_nri) puts
// first in a pod's command. It runs under the Warden's filter, which the
// runtime has applied already; it limits what the container can execute to
// the launch set with Landlock, then executes the container's own command:
//
//   v1340_init PATH... -- COMMAND [ARG...]
//
// Each PATH (a file, or a directory for everything below it) may be
// executed; nothing else can be. Without Landlock it refuses to run the
// command (exit 126), as the Warden refuses a launch set it cannot apply.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int dd = 1;
    while (dd < argc && strcmp(argv[dd], "--")) dd++;
    if (dd >= argc - 1) { fprintf(stderr, "usage: %s PATH... -- COMMAND [ARG...]\n", argv[0]); return 2; }
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) { fprintf(stderr, "varek-init: no Landlock (%s): refusing to run %s\n", strerror(errno), argv[dd + 1]); return 126; }
    struct landlock_ruleset_attr ra = { .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE };
    int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) { fprintf(stderr, "varek-init: landlock_create_ruleset: %s\n", strerror(errno)); return 126; }
    for (int i = 1; i < dd; i++) {
        int fd = open(argv[i], O_PATH | O_CLOEXEC);
        if (fd < 0) { fprintf(stderr, "varek-init: launch set %s: %s\n", argv[i], strerror(errno)); return 126; }
        struct landlock_path_beneath_attr pb = { .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE, .parent_fd = fd };
        if (syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
            fprintf(stderr, "varek-init: landlock_add_rule %s: %s\n", argv[i], strerror(errno));
            return 126;
        }
        close(fd);
    }
    // the runtime sets no_new_privs for a pod without privilege escalation;
    // Landlock needs it, and the filter admits only the prctl calls it lists
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "varek-init: no_new_privs: %s\n", strerror(errno));
        return 126;
    }
    if (syscall(SYS_landlock_restrict_self, rs, 0) < 0) { fprintf(stderr, "varek-init: landlock_restrict_self: %s\n", strerror(errno)); return 126; }
    close(rs);
    fprintf(stderr, "varek-init: Landlock ABI %ld, launch set of %d path(s) applied; running %s\n", abi, dd - 1, argv[dd + 1]);
    execv(argv[dd + 1], argv + dd + 1);
    fprintf(stderr, "varek-init: %s: %s\n", argv[dd + 1], strerror(errno));
    return 127;
}
