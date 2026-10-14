/* SPDX-License-Identifier: MIT
 * warden_proxy_mcp.inc.c — v1.31 (docs/security/v1.31-standards.md,
 * section 3): an MCP call over HTTP, in warden-proxy (included by
 * warden_proxy_helper.c, after cred_swap).
 *
 * A POST to an MCP endpoint is answered by the Warden with "read its body"
 * (WP_MSG_REQVERDICT, mcp 1): nothing of the request has been sent. The
 * proxy takes every body byte out of buf as it arrives (into h->mbody, the
 * body as framed), up to the limit, then parses the body (a chunked one
 * without its framing) with mcp_json.c, checks the Mcp-Method and Mcp-Name
 * headers of the head against it, and reports the call (WP_MSG_MCPREQ).
 * On the Warden's verdict (WP_MSG_MCPVERDICT) the head (with its
 * credential, if the deciding rule names one) and the body are put back
 * into buf, in order, and let through; or the client gets a JSON-RPC error
 * in a 403 and the connection takes no more requests. A call the proxy
 * cannot read is reported as such (ok 0), and the Warden refuses it.
 */

#include "mcp_json.h"
#include <ctype.h>

static bool mcp_body_put(struct wp_held *h, const uint8_t *b, size_t n) {
    if (h->mlen + n > h->mlimit) return false;
    if (h->mlen + n > h->mcap) {
        size_t nc = h->mcap ? h->mcap : 16384;
        while (nc < h->mlen + n) nc *= 2;
        uint8_t *nb = realloc(h->mbody, nc);
        if (!nb) return false;
        h->mbody = nb;
        h->mcap = nc;
    }
    memcpy(h->mbody + h->mlen, b, n);
    h->mlen += n;
    return true;
}

/* A chunked body (already checked by pp_chunked_feed) without its framing,
 * into out (malloc'd). The length, -1 (malformed) or -2 (it has trailers). */
static long mcp_dechunk(const uint8_t *b, size_t n, uint8_t **out) {
    uint8_t *o = malloc(n ? n : 1);
    size_t i = 0, ol = 0;
    if (!o) return -1;
    for (;;) {
        size_t sz = 0;
        int digits = 0;
        while (i < n && isxdigit(b[i])) {
            if (++digits > 15) { free(o); return -1; }
            sz = sz * 16 + (size_t)(isdigit(b[i]) ? b[i] - '0' : (b[i] | 0x20) - 'a' + 10);
            i++;
        }
        if (!digits) { free(o); return -1; }
        while (i + 1 < n && !(b[i] == '\r' && b[i + 1] == '\n')) i++;     /* chunk extensions */
        if (i + 1 >= n) { free(o); return -1; }
        i += 2;
        if (sz == 0) {
            /* review: trailers are bytes the decision never read; refused */
            if (i + 1 >= n || b[i] != '\r' || b[i + 1] != '\n') { free(o); return -2; }
            break;
        }
        if (sz > n - i || n - i - sz < 2) { free(o); return -1; }
        memcpy(o + ol, b + i, sz);
        ol += sz;
        i += sz + 2;
    }
    *out = o;
    return (long)ol;
}

/* The value of header name in the waiting head (buf[fwd, fwd + pend_head)),
 * spaces and tabs around it trimmed. 1 found (once), 0 absent, -1 given more
 * than once. */
static int mcp_header(const struct wp_held *h, const char *name, const uint8_t **v, size_t *vn) {
    const uint8_t *hb = h->buf + h->fwd, *end = hb + h->pend_head;
    const uint8_t *line = memmem(hb, h->pend_head, "\r\n", 2);
    size_t nl = strlen(name);
    int found = 0;
    if (!line) return 0;
    line += 2;
    while (line < end) {
        const uint8_t *eol = memmem(line, (size_t)(end - line), "\r\n", 2);
        if (!eol || eol == line) break;
        const uint8_t *colon = memchr(line, ':', (size_t)(eol - line));
        if (colon && (size_t)(colon - line) == nl && !strncasecmp((const char *)line, name, nl)) {
            if (found++) return -1;
            const uint8_t *a = colon + 1, *b = eol;
            while (a < b && (*a == ' ' || *a == '\t')) a++;
            while (b > a && (b[-1] == ' ' || b[-1] == '\t')) b--;
            *v = a;
            *vn = (size_t)(b - a);
        }
        line = eol + 2;
    }
    return found;
}

/* review: a Content-Type that says application/json in UTF-8: the media
 * type (any case), then at most a charset parameter of utf-8 (quoted or not,
 * any case), spaces and tabs around ';' and '=' allowed */
static bool mcp_json_type(const uint8_t *v, size_t n) {
    static const char kType[] = "application/json";
    size_t tl = sizeof kType - 1, i = tl;
    if (n < tl || strncasecmp((const char *)v, kType, tl)) return false;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    if (i == n) return true;
    if (v[i++] != ';') return false;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    if (n - i < 7 || strncasecmp((const char *)v + i, "charset", 7)) return false;
    i += 7;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    if (i == n || v[i++] != '=') return false;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    bool q = i < n && v[i] == '"';
    if (q) i++;
    if (n - i < 5 || strncasecmp((const char *)v + i, "utf-8", 5)) return false;
    i += 5;
    if (q && (i == n || v[i++] != '"')) return false;
    while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
    return i == n;
}

/* Parse the body read, check the headers, and report the call (or why it
 * could not be read: fail, with ok code, WP_MCP_*). The gate then waits for
 * the verdict. */
static void mcp_report(struct wp_held *h, const char *fail, uint32_t code) {
    static struct wp_mcpreq m;
    memset(&m, 0, sizeof m);
    m.type = WP_MSG_MCPREQ;
    m.id = h->id;
    m.seq = h->seq;
    m.body_len = h->mlen;
    unsigned ml = 0;
    (void)EVP_Digest(h->mbody ? h->mbody : (const uint8_t *)"", h->mlen, m.sha256, &ml, EVP_sha256(), NULL);
    const uint8_t *pv;
    size_t pvn;
    if (mcp_header(h, "MCP-Protocol-Version", &pv, &pvn) == 1 && pvn < sizeof m.proto) {
        bool ok = true;
        for (size_t k = 0; k < pvn; k++) ok = ok && pv[k] >= 0x21 && pv[k] <= 0x7e;
        if (ok) memcpy(m.proto, pv, pvn);
    }
    char why[96] = "";
    uint32_t ok = WP_MCP_UNREADABLE;
    if (fail) { snprintf(why, sizeof why, "%s", fail); ok = code; }
    mj_call_t *c = calloc(1, sizeof *c);
    if (!why[0] && !c) snprintf(why, sizeof why, "the proxy is out of memory");
    if (!why[0]) {
        uint8_t *json = h->mbody;
        long jl = (long)h->mlen;
        if (h->pend_body == WP_BODY_CHUNKED && (jl = mcp_dechunk(h->mbody, h->mlen, &json)) < 0)
            snprintf(why, sizeof why, "%s", jl == -2 ? "a chunked body with trailers" : "a malformed chunked body");
        else {
            char jwhy[72];
            if (mj_call(json ? json : (const uint8_t *)"", (size_t)jl, c, jwhy, sizeof jwhy) < 0)
                snprintf(why, sizeof why, "not one JSON-RPC call: %s", jwhy);
            if (json != h->mbody) free(json);
        }
    }
    if (!why[0]) {
        /* review: the body is read as UTF-8 JSON, so it must be sent as that:
         * one Content-Type, application/json, no charset but UTF-8, and no
         * content coding (a server that decodes by the charset or the coding
         * would read other bytes than the ones decided) */
        int r = mcp_header(h, "Content-Type", &pv, &pvn);
        if (r != 1 || !mcp_json_type(pv, pvn)) {
            snprintf(why, sizeof why, "the Content-Type is not application/json in UTF-8");
            ok = WP_MCP_HEADERS;
        }
        r = why[0] ? 0 : mcp_header(h, "Content-Encoding", &pv, &pvn);
        if (r < 0 || (r == 1 && !(pvn == 8 && !strncasecmp((const char *)pv, "identity", 8)))) {
            snprintf(why, sizeof why, "the body has a Content-Encoding");
            ok = WP_MCP_HEADERS;
        }
    }
    if (!why[0]) {
        /* the transport's own headers, when present, are the body's values */
        char hv[MJ_NAME_MAX];
        int r = mcp_header(h, "Mcp-Method", &pv, &pvn);
        if (r < 0 || (r == 1 && (mj_header_value((const char *)pv, pvn, hv, sizeof hv) < 0 || strcmp(hv, c->method)))) {
            snprintf(why, sizeof why, "the Mcp-Method header does not match the body");
            ok = WP_MCP_HEADERS;
        }
        r = why[0] ? 0 : mcp_header(h, "Mcp-Name", &pv, &pvn);
        if (r < 0 || (r == 1 && (!c->has_name || mj_header_value((const char *)pv, pvn, hv, sizeof hv) < 0 ||
                                 strcmp(hv, c->name)))) {
            snprintf(why, sizeof why, "the Mcp-Name header does not match the body");
            ok = WP_MCP_HEADERS;
        }
    }
    /* v1.31 step 5: the bearer token, if any (read from the head as sent) */
    if (!why[0]) {
        int r = mcp_header(h, "Authorization", &pv, &pvn);
        if (r < 0) {
            snprintf(why, sizeof why, "the call has two Authorization headers");
            ok = WP_MCP_HEADERS;
        } else if (r == 1 && ((pvn >= 6 && !strncasecmp((const char *)pv, "Bearer", 6) && (pvn == 6 || pv[6] == ' ' || pv[6] == '\t')) ||
                              (pvn >= 4 && !strncasecmp((const char *)pv, "DPoP", 4) && (pvn == 4 || pv[4] == ' ' || pv[4] == '\t')))) {
            /* v1.31 review: the scheme (Bearer, or DPoP's), any case, then any
             * spaces and tabs (the header's own were trimmed) */
            size_t sl = (pv[0] | 0x20) == 'b' ? 6 : 4;
            const char *t = (const char *)pv + sl;
            size_t tn = pvn - sl;
            while (tn && (*t == ' ' || *t == '\t')) { t++; tn--; }
            for (unsigned k = 0; k < WS_MAX_CREDS && !m.token; k++)
                if (g_ph[k][0] && strlen(g_ph[k]) == tn && !memcmp(g_ph[k], t, tn)) m.token = WP_TOK_PLACEHOLDER;
            if (!m.token) {
                unsigned tl = 0;
                (void)EVP_Digest(t, tn, m.token_sha256, &tl, EVP_sha256(), NULL);
                mj_jwt_t *j = calloc(1, sizeof *j);
                char jw[72] = "";
                int jr = j ? mj_jwt(t, tn, j, jw, sizeof jw) : -1;
                if (!j) snprintf(jw, sizeof jw, "the proxy is out of memory");
                if (jr == 1) {
                    m.token = WP_TOK_JWT;
                    unsigned sl2 = 0;          /* review: the signing input, which re-signing does not change */
                    (void)EVP_Digest(t, j->signing_len, m.token_sin_sha256, &sl2, EVP_sha256(), NULL);
                    m.naud = j->naud;
                    m.aud_over = j->aud_over;
                    m.has_exp = j->has_exp;
                    m.exp = j->exp;
                    for (uint32_t k = 0; k < j->naud && k < WP_AUD_MAX; k++) snprintf(m.aud[k], sizeof m.aud[k], "%s", j->aud[k]);
                } else if (jr == 0) m.token = WP_TOK_OPAQUE;
                else {
                    m.token = WP_TOK_MALFORMED;
                    snprintf(m.token_why, sizeof m.token_why, "%s", jw);
                }
                free(j);
            }
        }
    }
    if (!why[0]) {
        m.ok = WP_MCP_OK;
        memcpy(m.method, c->method, sizeof m.method);
        memcpy(m.name, c->name, sizeof m.name);
        memcpy(m.rpc_id, c->id, sizeof m.rpc_id);
        memcpy(m.traceparent, c->traceparent, sizeof m.traceparent);
        m.has_name = c->has_name;
        m.notification = c->notification;
        snprintf(h->mcp_id, sizeof h->mcp_id, "%s", c->id[0] ? c->id : "null");
    } else {
        m.ok = ok;
        snprintf(m.why, sizeof m.why, "%s", why);
        snprintf(h->mcp_id, sizeof h->mcp_id, "null");
    }
    free(c);
    h->ig = IG_MCPWAIT;
    h->since = mono_ms();
    (void)send(g_ctl, &m, sizeof m, MSG_NOSIGNAL);
}

/* v1.31: the connection ends while the body is read: reported (refused) */
static void mcp_report_gone(struct wp_held *h) {
    mcp_report(h, "the connection ended before the body did", WP_MCP_UNREADABLE);
}

/* The Warden said: read this request's body (limit: its max_body) */
static void mcp_begin(struct wp_held *h, const struct wp_reqverdict *v) {
    h->ig = IG_MCPBODY;
    h->mlimit = v->max_body;
    h->mlen = 0;
    h->body_left = h->pend_blen;
    memset(&h->ck, 0, sizeof h->ck);
    if (h->pend_body == WP_BODY_NONE || (h->pend_body == WP_BODY_LENGTH && !h->pend_blen))
        mcp_report(h, NULL, 0);                                             /* an empty body: refused as such */
    else if (h->pend_body == WP_BODY_LENGTH && h->pend_blen > h->mlimit) {
        char w[96];
        snprintf(w, sizeof w, "a body of %llu bytes, over the limit of %llu", (unsigned long long)h->pend_blen,
                 (unsigned long long)h->mlimit);
        mcp_report(h, w, WP_MCP_OVER);
    }
}

/* Move the body bytes that have arrived out of buf (they follow the head) */
static void mcp_collect(struct wp_held *h) {
    size_t at = h->fwd + h->pend_head;
    if (h->len <= at) return;
    size_t avail = h->len - at, take;
    bool done = false;
    if (h->pend_body == WP_BODY_LENGTH) {
        take = avail < h->body_left ? avail : (size_t)h->body_left;
        h->body_left -= take;
        done = !h->body_left;
    } else {
        long c = pp_chunked_feed(&h->ck, h->buf + at, avail, &done);
        if (c < 0) { mcp_report(h, "a malformed chunked body", WP_MCP_UNREADABLE); return; }
        take = (size_t)c;
    }
    if (!mcp_body_put(h, h->buf + at, take)) {
        char w[96];
        snprintf(w, sizeof w, "a body over the limit of %llu bytes", (unsigned long long)h->mlimit);
        mcp_report(h, w, WP_MCP_OVER);
        return;
    }
    memmove(h->buf + at, h->buf + at + take, h->len - at - take);
    h->len -= take;
    if (done) mcp_report(h, NULL, 0);
}

/* The Warden's verdict on the call waiting */
static void mcp_verdict(struct wp_held *h, const struct wp_mcpverdict *v) {
    if (h->ig != IG_MCPWAIT || v->seq != h->seq) return;
    if (!v->allow) {
        h->mcp_refused = true;
        gate_stop(h, memchr(v->why, 0, sizeof v->why) && v->why[0] ? v->why : "refused by the policy");
        return;
    }
    if (v->cred) {
        struct wp_reqverdict rv;
        memset(&rv, 0, sizeof rv);
        rv.cred = v->cred;
        memcpy(rv.hdr, v->hdr, sizeof rv.hdr);
        memcpy(rv.scheme, v->scheme, sizeof rv.scheme);
        const char *why = cred_swap(h, &rv);
        if (why) {
            struct wp_credfail f;
            memset(&f, 0, sizeof f);
            f.type = WP_MSG_CREDFAIL;
            f.cred = v->cred;
            f.id = h->id;
            f.seq = h->seq;
            snprintf(f.why, sizeof f.why, "%s", why);
            (void)send(g_ctl, &f, sizeof f, MSG_NOSIGNAL);
            h->mcp_refused = true;
            gate_stop(h, why);
            return;
        }
    }
    /* the body back in after the head: buf = [.. fwd][head][body][the rest] */
    size_t at = h->fwd + h->pend_head, cap = h->bufcap ? h->bufcap : PP_IN_MAX;
    if (h->len + h->mlen > cap) {
        size_t ncap = h->len + h->mlen + PP_IN_MAX;
        uint8_t *nb = malloc(ncap);
        if (!nb) { h->mcp_refused = true; gate_stop(h, "the proxy is out of memory"); return; }
        memcpy(nb, h->buf, h->len);
        if (h->credbuf) OPENSSL_cleanse(h->buf, cap);
        free(h->buf);
        h->buf = nb;
        h->bufcap = ncap;
    }
    memmove(h->buf + at + h->mlen, h->buf + at, h->len - at);
    if (h->mlen) memcpy(h->buf + at, h->mbody, h->mlen);
    h->len += h->mlen;
    h->fwd = at + h->mlen;
    free(h->mbody);
    h->mbody = NULL;
    h->mlen = h->mcap = 0;
    h->ig = IG_HEAD;
}
