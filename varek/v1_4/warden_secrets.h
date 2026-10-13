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
//
// v1.28.1 (docs/security/v1.28.1-delegation-chain.md, section 2): the same
// helper verifies the user's token (--on-behalf-of) and the agent's
// X.509-SVID (--agent-svid), when the Warden is given either:
//
//   Warden -> helper   WS_MSG_SETUP   also the token's and the SVID's paths
//                                     and how many issuers and trust domains
//                      WS_MSG_ISSUER  one per `trust issuer` line
//                      WS_MSG_SPIFFE  one per `trust spiffe` line
//   helper             as root: reads the token and the SVID (as a file
//                      store) and the SVID's trust bundle (root-owned,
//                      writable by no other user: WS_MSG_FILE, kind
//                      WS_FILE_TRUSTED), and checks the SVID; as its own
//                      user: fetches the issuer's keys and checks the token,
//                      before any network store is fetched
//   helper -> Warden   WS_MSG_IDENTITY the verified claims (never the token,
//                                     never the key), or why not
//
// v1.31 step 5 (docs/security/v1.31-standards.md, section 4): a credential
// may be an MCP access token (WS_MSG_CRED's audience, opaque): the helper
// checks it is a JWT whose aud names that URL and whose exp is at least
// 60 s away (an opaque one: neither), and reports the exp (WS_MSG_RESULT).
// The user's issuer may be found through an MCP server's metadata:
//
//   Warden -> helper   WS_MSG_MCPRES  one per `trust mcp-resource` line
//                                     (with the token, as the issuers)
//   helper             fetches the resource's metadata (RFC 9728), each of
//                      its authorization servers' (RFC 8414, or OpenID
//                      discovery; the issuer identical to the identifier),
//                      and their keys; a token from one of them is checked
//                      with the line's audience (or its URL as written)
#ifndef VAREK_WARDEN_SECRETS_H
#define VAREK_WARDEN_SECRETS_H

#include <stdbool.h>
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
    /* step 4 */
    WS_MSG_REVOKE,                    /* Warden -> helper (struct ws_ready): revoke the run's leases */
    WS_MSG_REVOKED,                   /* helper -> Warden (struct ws_revoked) */
    WS_MSG_RENEWED,                   /* helper -> Warden (struct ws_renewed): a lease renewed, or not */
    /* v1.28.1 */
    WS_MSG_ISSUER,                    /* Warden -> helper (struct ws_issuer) */
    WS_MSG_SPIFFE,                    /* Warden -> helper (struct ws_spiffe) */
    WS_MSG_IDENTITY,                  /* helper -> Warden (struct ws_identity) */
    WS_MSG_MCPRES,                    /* v1.31: Warden -> helper (struct ws_mcpres) */
};

/* struct ws_file's kind: a file whose contents are secret (the agent may not
 * open it), or one whose contents are trusted (the agent may not write it) */
enum { WS_FILE_SECRET = 0, WS_FILE_TRUSTED = 1 };

#define WS_MAX_ISSUERS 8              /* VDP_MAX_ISSUERS */
#define WS_MAX_SPIFFE  8              /* VDP_MAX_SPIFFE */
#define WS_MAX_MCPRES  8              /* VDP_MAX_MCPRES */
#define WS_MAX_ACTORS  8              /* an `act` chain nested at most 8 deep */
#define WS_MAX_TOKEN   16384          /* the user's token file, at most */

#define WS_MAX_CREDS   32
#define WS_MAX_VALUE   8192           /* a value goes in one header of a head of at most 8 KB */
#define WS_MAX_FILES   (WS_MAX_CREDS + 4)

struct ws_setup {
    uint32_t type;                    /* WS_MSG_SETUP */
    uint32_t ncreds;
    char     conf[4096];              /* the configuration file ("" : none) */
    /* v1.28.1 */
    uint32_t nissuers;
    uint32_t nspiffe;
    char     token[4096];             /* --on-behalf-of: the user's token ("" : none) */
    char     svid[4096];              /* --agent-svid: the agent's X.509-SVID and key ("" : none) */
    uint32_t nmcpres;                 /* v1.31 */
    uint32_t pad;
};

/* v1.31: an MCP server whose authorization servers the policy trusts as the
 * user's issuers */
struct ws_mcpres {
    uint32_t type;                    /* WS_MSG_MCPRES */
    uint32_t index;
    char     url[256];                /* as written */
    char     aud[256];                /* "" : the URL */
};

/* v1.28.1: an issuer the policy trusts */
struct ws_issuer {
    uint32_t type;                    /* WS_MSG_ISSUER */
    uint32_t index;
    char     iss[256];
    char     aud[256];
    char     jwks[1025];              /* "" : from the issuer's discovery document */
};

/* v1.28.1: a SPIFFE trust domain the policy trusts */
struct ws_spiffe {
    uint32_t type;                    /* WS_MSG_SPIFFE */
    uint32_t index;
    char     domain[256];
    char     bundle[1025];
};

/* v1.28.1: what the helper verified. Every string is printable ASCII. */
struct ws_actor {
    char sub[256];
    char iss[256];                    /* "" : not given */
};

struct ws_identity {
    uint32_t type;                    /* WS_MSG_IDENTITY */
    uint32_t ok;                      /* 0: why says which check failed */
    uint32_t has_user;                /* a token was verified */
    uint32_t issuer;                  /* its issuer: the policy's issuers[issuer] */
    int64_t  exp, iat, nbf;           /* iat, nbf: -1 when absent */
    char     sub[256];
    char     jti[256];                /* "" : absent */
    char     alg[16];
    char     kid[256];                /* "" : absent */
    char     token_sha256[65];
    char     pad1[7];
    uint32_t nact;                    /* the actors (RFC 8693 `act`), the current one first */
    uint32_t has_svid;
    struct ws_actor act[WS_MAX_ACTORS];
    uint32_t spiffe;                  /* the SVID's trust domain: the policy's spiffe[spiffe] */
    uint32_t pad2;
    int64_t  svid_not_after;
    char     spiffe_id[2049];
    char     svid_sha256[65];         /* of the leaf certificate (DER) */
    char     why[512];
    /* v1.31: 0, the token's issuer is the policy's issuers[issuer]; k > 0,
     * it was found through `trust mcp-resource` k - 1: its identifier and
     * the audience the token was checked against */
    uint32_t mcp_resource;
    uint32_t pad3;
    char     found_iss[256];
    char     found_aud[256];
};

struct ws_cred {
    uint32_t type;                    /* WS_MSG_CRED */
    uint32_t index;
    uint32_t store;                   /* VDP_CRED_FILE, _VAULT, _AWSSM (smt_decide.h) */
    uint32_t opaque;                  /* v1.31: an MCP token that is not a JWT */
    char     ref[1025];
    char     audience[1025];          /* v1.31: an MCP token for this server (canonical URL; "" : none) */
};

struct ws_file {
    uint32_t type;                    /* WS_MSG_FILE */
    uint32_t kind;                    /* v1.28.1: WS_FILE_SECRET or WS_FILE_TRUSTED */
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
    int64_t  exp;                     /* v1.31: an MCP token's expiry (a JWT's exp; -1: none, or opaque) */
};

struct ws_ready {
    uint32_t type;                    /* WS_MSG_READY, WS_MSG_PROXY */
    uint32_t n;                       /* credentials fetched */
};

/* Step 4: the run's Vault leases revoked (how many, how many could not be) */
struct ws_revoked {
    uint32_t type;                    /* WS_MSG_REVOKED */
    uint32_t revoked;
    uint32_t failed;
    uint32_t pad;
};

/* Step 4: a leased secret renewed before its lease ended (ok, its new
 * lease in seconds), or not (why) */
struct ws_renewed {
    uint32_t type;                    /* WS_MSG_RENEWED */
    uint32_t index;
    uint32_t ok;
    uint32_t ttl;
    char     why[160];
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
    int64_t  exp;                     /* v1.31: an MCP token's expiry (-1: none) */
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

/* v1.28.1: what ws_fetch_id adds: the identities to verify (token, svid:
 * paths, or NULL), the policy's issuers and trust domains; id gets what was
 * verified, and kinds[] each file's kind. */
typedef struct {
    const char *token, *svid;
    const struct ws_issuer *issuers;
    size_t nissuers;
    const struct ws_spiffe *spiffe;
    size_t nspiffe;
    struct ws_identity *id;
    uint32_t *kinds;
    /* v1.31: each credential's audience= ("" : none) and opaque, and the
     * MCP resources trusted for the user's token */
    const char *const *audience;
    const bool *opaque;
    const struct ws_mcpres *mcpres;
    size_t nmcpres;
} ws_idreq_t;

/* ws_fetch, and the identities: a token or an SVID that fails a check makes
 * it -1, with why saying which ("the user's token: ..." or "the agent's
 * SVID: ..."). The identity is checked before any network store is fetched. */
int ws_fetch_id(ws_t *w, const char *conf, size_t n, const int *store, const char *const *ref,
                ws_meta_t *meta, char (*files)[4096], size_t *nfiles, const ws_idreq_t *idr,
                int timeout_ms, char *why, size_t wn);

/* Step 3: give the helper one end of a socket to warden-proxy; it writes
 * each value there, then clears its own copies. 0, or -1. */
int ws_hand_to(ws_t *w, int fd);

/* Step 4: ask the helper to revoke the run's leases (its answer comes on
 * the control socket: WS_MSG_REVOKED). 0, or -1. */
int ws_revoke(ws_t *w);

/* Close the control socket: the helper clears its values and exits. */
void ws_stop(ws_t *w);

#endif
