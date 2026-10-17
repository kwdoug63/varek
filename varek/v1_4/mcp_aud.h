// SPDX-License-Identifier: MIT
// mcp_aud.h — v1.31 step 5 (docs/security/v1.31-standards.md, section 4):
// does a token's audience name an MCP server? Shared by the Warden (the
// agent's own tokens, warden_pxdecide.inc.c) and warden-secrets (a
// credential's `audience=`, and `trust mcp-resource`), so both compare the
// same way.
//
// The server's URL is held canonical (vdp_mcp_url): scheme://host:port/path,
// the port always written, the path "/" when none. The audience is compared
// without normalizing it, against the spellings of that URL a token may
// carry (RFC 8707's canonical URI omits a default port, and a path of "/"):
// the URL itself; without its scheme's default port; and, when its path is
// "/", each of those without the trailing '/'.
#ifndef VAREK_MCP_AUD_H
#define VAREK_MCP_AUD_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static inline bool mcp_aud_names(const char *url, const char *aud) {
    char a[4096], b[4096];
    if (!strcmp(aud, url)) return true;
    if (strlen(url) >= sizeof a) return false;
    memcpy(a, url, strlen(url) + 1);
    bool https = !strncmp(a, "https://", 8);
    if (!https && strncmp(a, "http://", 7)) return false;
    char *host = a + (https ? 8 : 7), *slash = strchr(host, '/');
    if (!slash) return false;
    char *colon = NULL;
    for (char *c = host; c < slash; c++) if (*c == ':') colon = c;
    bool root = !strcmp(slash, "/");
    if (root) {
        *slash = '\0';
        if (!strcmp(aud, a)) return true;
        *slash = '/';
    }
    const char *dp = https ? ":443" : ":80";
    if (colon && (size_t)(slash - colon) == strlen(dp) && !strncmp(colon, dp, strlen(dp))) {
        size_t hl = (size_t)(colon - a);
        memcpy(b, a, hl);
        snprintf(b + hl, sizeof b - hl, "%s", slash);
        if (!strcmp(aud, b)) return true;
        if (root) {
            b[hl] = '\0';
            if (!strcmp(aud, b)) return true;
        }
    }
    return false;
}

#endif
