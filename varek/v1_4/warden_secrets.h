// SPDX-License-Identifier: MIT
// warden_secrets.h — v1.28 (docs/security/v1.28-credential-release.md):
// warden-secrets, the helper that fetches the credentials a policy names,
// and the messages between it and the Warden.
//
// The Warden starts warden-secrets (as root, from a sealed copy it hashed,
// as it starts warden-proxy) with its control socket as descriptor 3:
//
//   Warden -> helper   WS_MSG_SETUP   the configuration file's path and the
//                                     number of credentials
//                      WS_MSG_CRED    one per credential: index, store, ref
//   helper             as root: reads the configuration (root-owned, not
//                      readable by its group or others) and each file store
//                      (the same), then drops to its own user (no groups,
//                      no capabilities, no-new-privileges, not dumpable) and
//                      fetches each network store over verified HTTPS
//   helper -> Warden   WS_MSG_FILE    each local file it read (the Warden
//                                     refuses to start if the policy lets
//                                     the agent open one)
//                      WS_MSG_RESULT  one per credential: ok, the store's
//                                     version, the value's length; or why not
//                      WS_MSG_READY   with SCM_CREDENTIALS (its user)
//
// No message carries a value. The helper keeps the values in locked
// memory; step 3 hands them to warden-proxy. When its control socket
// closes it clears them and exits.
#ifndef VAREK_WARDEN_SECRETS_H
#define VAREK_WARDEN_SECRETS_H

#include <stdint.h>
#include <sys/types.h>

enum {
    WS_MSG_SETUP = 1,
    WS_MSG_CRED,
    WS_MSG_FILE,
    WS_MSG_RESULT,
    WS_MSG_READY,
    WS_MSG_PROXY,                     /* v1.28 step 3: Warden -> helper, SCM_RIGHTS: the socket to warden-proxy */
    WS_MSG_VALUE,                     /* helper -> warden-proxy, on that socket: one value */
};

#define WS_MAX_CREDS   32
#define WS_MAX_VALUE   8192           /* a value goes in one header of a head of at most 8 KB */
#define WS_MAX_FILES   (WS_MAX_CREDS + 4)

struct ws_setup {
    uint32_t type;                    /* WS_MSG_SETUP */
    uint32_t ncreds;
    char     conf[4096];              /* the configuration file ("" : none) */
};

struct ws_cred {
    uint32_t type;                    /* WS_MSG_CRED */
    uint32_t index;
    uint32_t store;                   /* VDP_CRED_FILE, _VAULT, _AWSSM (smt_decide.h) */
    uint32_t pad;
    char     ref[1025];
};

struct ws_file {
    uint32_t type;                    /* WS_MSG_FILE */
    uint32_t pad;
    char     path[4096];
};

struct ws_result {
    uint32_t type;                    /* WS_MSG_RESULT */
    uint32_t index;
    uint32_t ok;
    uint32_t len;                     /* the value's length in bytes */
    char     version[160];            /* the store's version of it: "kv2:N", a lease id, an AWS
                                         version id, or a file's "inode:N mtime:S" */
    char     why[256];                /* not ok: why */
};

struct ws_ready {
    uint32_t type;                    /* WS_MSG_READY, WS_MSG_PROXY */
    uint32_t n;                       /* credentials fetched */
};

/* Step 3: one value, helper -> warden-proxy (never through the Warden) */
struct ws_value {
    uint32_t      type;               /* WS_MSG_VALUE */
    uint32_t      index;
    uint32_t      len;
    uint32_t      pad;
    unsigned char value[WS_MAX_VALUE];
};

/* The Warden's side (warden_secrets.c). */
typedef struct {
    int   ctl;                        /* the control socket, -1 when not started */
    pid_t pid;
    uid_t uid;
    gid_t gid;
} ws_t;

typedef struct {
    char     version[160];
    uint32_t len;
} ws_meta_t;

/* Start the helper from exe_fd (wp_load's sealed copy) as uid:gid. 0, or -1
 * with errno. */
int ws_start(ws_t *w, int exe_fd, uid_t uid, gid_t gid);

/* Send the configuration path and the credentials (names are not sent; the
 * helper knows them by index), and wait (up to timeout_ms) for the files it
 * read, a result per credential and its ready message. files[] gets the
 * paths (up to WS_MAX_FILES), meta[] the results. 0 when every credential
 * was fetched; -1 with the reason in why. */
int ws_fetch(ws_t *w, const char *conf, size_t n, const int *store, const char *const *ref,
             ws_meta_t *meta, char (*files)[4096], size_t *nfiles, int timeout_ms,
             char *why, size_t wn);

/* Step 3: give the helper one end of a socket to warden-proxy; it writes
 * each value there, then clears its own copies. 0, or -1. */
int ws_hand_to(ws_t *w, int fd);

/* Close the control socket: the helper clears its values and exits. */
void ws_stop(ws_t *w);

#endif
