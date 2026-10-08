// SPDX-License-Identifier: MIT
// vdp_cert_check.c — command-line front end to the certificate checker
// (checker/vdp_checker.c), the same code the Warden runs before every ALLOW.
// It links the checker only, never the decision procedure.
//
//   vdp_cert_check <policy> digest
//       Print the policy's SHA-256 (the digest the Warden records in run_start).
//   vdp_cert_check <policy> batch
//       Read certificates from stdin, one per line:
//           <path|host|exec> <flags|-> <hex string> <rule> <witness>
//       flags is 0x-hex or decimal, '-' for a symbolic (any-flags) claim; the
//       hex string is '=' for the empty string;
//       witness is '-' (none), 'c:<offset>' (contains) or 'g:<a>-<b>,...'
//       (glob spans, possibly none: 'g:'). Writes one JSON line per
//       certificate: {"check":"ok"} or {"check":"reject","why":"..."}.
//   vdp_cert_check <policy> holds
//       Read hex strings ('=' for the empty string) from stdin, one per line;
//       write one line of '0'/'1' per string, one character per rule: does
//       that rule's constant match, by the checker's own matchers (testing).
//   vdp_cert_check <policy> kinds
//       v1.24: one line, one character per rule: p (path), h (host) or e
//       (exec), by the checker's own parse (varek_audit.py uses it with holds
//       to confirm that no earlier host rule holds on a connect's other
//       candidates).
//   vdp_cert_check <policy> openable
//       v1.16.1: read absolute paths from stdin, one per line. For each, print
//       "openable <path>" if some open(2) flags value of an open of that path
//       is decided by an allow rule (the agent could open it), else
//       "closed <path>", with <path> the canonical path an open would reach
//       (symlinks followed, a dangling one to its target; for a path that
//       does not exist, its deepest existing ancestor canonicalized), which
//       is what the Warden decides on. This is the check the Warden makes
//       at startup for its verdict stream, signing key and anchor
//       (tools/varek_preflight.sh uses it). Exit 1 if any path is openable.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../checker/vdp_checker.h"

#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* A decimal number of at most 10 digits (no sign, no space), <= 2^32 - 1. */
static int parse_u32(const char *s, const char **end, uint32_t *out) {
    uint64_t v = 0;
    int nd = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (uint64_t)(*s++ - '0');
        if (++nd > 10 || v > 0xffffffffULL) return -1;
    }
    if (!nd) return -1;
    *end = s;
    *out = (uint32_t)v;
    return 0;
}

/* Flags: 0x followed by 1-8 hex digits, or a decimal number. */
static int parse_flags(const char *s, uint32_t *out) {
    const char *end;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        uint32_t v = 0;
        int nd = 0;
        for (s += 2; *s; s++) {
            int h = hexval(*s);
            if (h < 0 || ++nd > 8) return -1;
            v = v * 16 + (uint32_t)h;
        }
        if (!nd) return -1;
        *out = v;
        return 0;
    }
    if (parse_u32(s, &end, out) < 0 || *end) return -1;
    return 0;
}

static int parse_witness(const char *w, vdpc_cert_t *c) {
    c->wkind = 0;
    c->nspan = 0;
    if (!strcmp(w, "-")) return 0;
    const char *end;
    if (!strncmp(w, "c:", 2)) {
        if (parse_u32(w + 2, &end, &c->off) < 0 || *end) return -1;
        c->wkind = 1;
        return 0;
    }
    if (!strncmp(w, "g:", 2)) {
        c->wkind = 2;
        const char *q = w + 2;
        while (*q) {
            if (c->nspan >= VDPC_MAX_STRETCH) return -1;
            uint32_t a, b;
            if (parse_u32(q, &end, &a) < 0 || *end != '-') return -1;
            if (parse_u32(end + 1, &end, &b) < 0 || (*end && *end != ',')) return -1;
            if (*end == ',' && !end[1]) return -1;
            c->span[c->nspan][0] = a;
            c->span[c->nspan][1] = b;
            c->nspan++;
            q = *end ? end + 1 : end;
        }
        return 0;
    }
    return -1;
}

static void json_str(const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') putchar('\\');
        putchar(*s);
    }
}

/* The canonical path an open of p would reach, following symlinks (as a
 * shell's `2> p` does) and creating the last component if it is missing: an
 * existing path is canonicalized; a dangling symlink is followed to its
 * target; otherwise the deepest existing ancestor is canonicalized and the
 * rest appended. 0, or -1 if it cannot be told. */
static int canon_for_open(const char *p, char out[PATH_MAX], int depth) {
    if (depth > 40 || p[0] != '/' || strlen(p) >= PATH_MAX) return -1;
    if (realpath(p, out)) return 0;
    struct stat st;
    if (lstat(p, &st) == 0 && S_ISLNK(st.st_mode)) {
        char tgt[PATH_MAX], next[PATH_MAX];
        ssize_t k = readlink(p, tgt, sizeof tgt - 1);
        if (k <= 0) return -1;
        tgt[k] = '\0';
        if (tgt[0] == '/') {
            memcpy(next, tgt, (size_t)k + 1);
        } else {
            const char *slash = strrchr(p, '/');
            size_t dl = (size_t)(slash - p) + 1;              /* keep the '/' */
            if (dl + (size_t)k >= sizeof next) return -1;
            memcpy(next, p, dl);
            memcpy(next + dl, tgt, (size_t)k + 1);
        }
        return canon_for_open(next, out, depth + 1);
    }
    char buf[PATH_MAX];
    size_t len = strlen(p);
    memcpy(buf, p, len + 1);
    for (size_t i = len; i > 0; i--) {
        if (buf[i - 1] != '/' || i - 1 == len - 1) continue;
        size_t cut = i - 1;                                    /* p[cut] == '/' */
        char save = buf[cut > 0 ? cut : 1];
        if (cut == 0) { buf[1] = '\0'; } else buf[cut] = '\0';
        char rd[PATH_MAX];
        int ok = realpath(buf, rd) != NULL;
        if (cut == 0) buf[1] = save; else buf[cut] = '/';
        if (!ok) continue;
        size_t a = strcmp(rd, "/") ? strlen(rd) : 0, b = len - cut;
        if (a + b >= PATH_MAX) return -1;
        memcpy(out, rd, a);
        memcpy(out + a, p + cut, b + 1);
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[2], "digest") && strcmp(argv[2], "batch") &&
                      strcmp(argv[2], "holds") && strcmp(argv[2], "openable") &&
                      strcmp(argv[2], "kinds") && strcmp(argv[2], "rules") && strcmp(argv[2], "proxy"))) {
        fprintf(stderr, "usage: %s <policy> digest|batch|holds|openable|kinds|rules|proxy\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "%s: %s\n", argv[1], strerror(errno)); return 2; }
    char *buf = NULL;
    size_t len = 0, cap = 0;
    for (;;) {
        if (len == cap) {
            cap = cap ? cap * 2 : 65536;
            char *nb = realloc(buf, cap);
            if (!nb) { fclose(f); return 2; }
            buf = nb;
        }
        size_t got = fread(buf + len, 1, cap - len, f);
        len += got;
        if (got == 0) break;
    }
    fclose(f);
    vdpc_policy_t pol;
    char err[512];
    if (vdpc_load(argv[1], buf, len, &pol, err, sizeof err) < 0) {
        fprintf(stderr, "policy error: %s\n", err);
        free(buf);
        return 2;
    }
    free(buf);
    if (!strcmp(argv[2], "digest")) {
        char hex[65];
        vdpc_digest_hex(&pol, hex);
        printf("%s\n", hex);
        vdpc_free(&pol);
        return 0;
    }

    if (!strcmp(argv[2], "kinds")) {
        for (size_t i = 0; i < pol.n; i++) {
            vdpc_rule_info_t ri;
            vdpc_rule_info(&pol, i, &ri);
            putchar(ri.kind == VDPC_PATH ? 'p' : ri.kind == VDPC_HOST ? 'h' : 'e');
        }
        putchar('\n');
        vdpc_free(&pol);
        return 0;
    }

    /* v1.24 review: each rule, one line: kind (p|h|e), verb (a|d), a host name
     * rule (n|-), the flag clause's mask and value (hex). v1.25 review: then a
     * wildcard (w|-), the policy line, the names= and rate= budgets as
     * written (0: the default), and the rule's constant in hex. varek_audit.py
     * reads the policy's rules from here, as this parser reads the file, not
     * from the stream or its own reading of the file. */
    if (!strcmp(argv[2], "rules")) {
        for (size_t i = 0; i < pol.n; i++) {
            vdpc_rule_info_t ri;
            vdpc_rule_info(&pol, i, &ri);
            printf("%c %c %c %x %x %c %d %u %u ", ri.kind == VDPC_PATH ? 'p' : ri.kind == VDPC_HOST ? 'h' : 'e',
                   ri.allow ? 'a' : 'd', ri.name ? 'n' : '-', (unsigned)ri.mask, (unsigned)ri.value,
                   ri.wild ? 'w' : '-', ri.line, (unsigned)ri.names, (unsigned)ri.rate);
            for (size_t k = 0; k < ri.clen; k++) printf("%02x", (unsigned char)ri.c[k]);
            printf("%s\n", ri.clen ? "" : "=");
        }
        vdpc_free(&pol);
        return 0;
    }

    /* v1.26: the egress proxy, one line: "off", or "on" and the proxied
     * ports in force (80 443 when the policy names none). */
    if (!strcmp(argv[2], "proxy")) {
        if (!pol.proxy) printf("off\n");
        else if (!pol.proxy_nports) printf("on 80 443\n");
        else {
            printf("on");
            for (size_t k = 0; k < pol.proxy_nports; k++) printf(" %u", pol.proxy_ports[k]);
            printf("\n");
        }
        vdpc_free(&pol);
        return 0;
    }

    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    static char s[VDPC_MAX_S + 64];
    if (!strcmp(argv[2], "openable")) {
        int any = 0;
        while ((n = getline(&line, &lcap, stdin)) >= 0) {
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
            if (n == 0) continue;
            if (line[0] != '/') { printf("error %s (not an absolute path)\n", line); any = 1; continue; }
            char rp[PATH_MAX];
            if (canon_for_open(line, rp, 0) < 0) {
                printf("error %s (cannot determine the path an open would reach)\n", line);
                any = 1;
                continue;
            }
            const char *path = rp;
            int o = vdpc_path_openable(&pol, path, strlen(path));
            printf("%s %s\n", o ? "openable" : "closed", path);
            any |= o;
        }
        free(line);
        vdpc_free(&pol);
        return any;
    }
    if (!strcmp(argv[2], "holds")) {
        while ((n = getline(&line, &lcap, stdin)) >= 0) {
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
            const char *hx = strcmp(line, "=") ? line : "";
            size_t hl = strlen(hx), sl = 0;
            int bad = (hl % 2) || hl / 2 > VDPC_MAX_S + 32;
            for (size_t i = 0; !bad && i < hl; i += 2) {
                int a = hexval(hx[i]), b = hexval(hx[i + 1]);
                if (a < 0 || b < 0) bad = 1;
                else s[sl++] = (char)(a * 16 + b);
            }
            if (bad) { printf("error\n"); continue; }
            for (size_t i = 0; i < pol.n; i++) putchar(vdpc_holds(&pol, i, s, sl) ? '1' : '0');
            putchar('\n');
        }
        free(line);
        vdpc_free(&pol);
        return 0;
    }
    while ((n = getline(&line, &lcap, stdin)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;
        char *save = NULL;
        char *k = strtok_r(line, " ", &save);
        char *fl = strtok_r(NULL, " ", &save);
        char *hx = strtok_r(NULL, " ", &save);
        char *rs = strtok_r(NULL, " ", &save);
        char *ws = strtok_r(NULL, " ", &save);
        if (hx && !strcmp(hx, "=")) hx = (char *)"";   /* empty string */
        int kind = !k ? -1 : !strcmp(k, "path") ? VDPC_PATH : !strcmp(k, "host") ? VDPC_HOST
                 : !strcmp(k, "exec") ? VDPC_EXEC : -1;
        vdpc_cert_t c;
        memset(&c, 0, sizeof c);
        if (kind < 0 || !fl || !hx || !rs || !ws || parse_witness(ws, &c) < 0) {
            printf("{\"check\":\"error\",\"why\":\"bad input line\"}\n");
            continue;
        }
        uint32_t ru;
        const char *rend;
        if (!strcmp(rs, "-1")) c.r = -1;
        else if (parse_u32(rs, &rend, &ru) == 0 && !*rend && ru < 100000) c.r = (int)ru;
        else { printf("{\"check\":\"error\",\"why\":\"bad rule\"}\n"); continue; }
        size_t hl = strlen(hx);
        if (hl % 2 || hl / 2 > sizeof s - 1) { printf("{\"check\":\"error\",\"why\":\"bad hex\"}\n"); continue; }
        size_t sl = 0;
        int bad = 0;
        for (size_t i = 0; i < hl; i += 2) {
            int a = hexval(hx[i]), b = hexval(hx[i + 1]);
            if (a < 0 || b < 0) { bad = 1; break; }
            s[sl++] = (char)(a * 16 + b);
        }
        if (bad) { printf("{\"check\":\"error\",\"why\":\"bad hex\"}\n"); continue; }
        s[sl] = '\0';
        bool has_flags = strcmp(fl, "-") != 0;
        uint32_t flags = 0;
        if (has_flags && parse_flags(fl, &flags) < 0) {
            printf("{\"check\":\"error\",\"why\":\"bad flags\"}\n");
            continue;
        }
        char why[160];
        if (vdpc_check(&pol, kind, s, sl, flags, has_flags, &c, why, sizeof why)) {
            printf("{\"check\":\"ok\"}\n");
        } else {
            printf("{\"check\":\"reject\",\"why\":\"");
            json_str(why);
            printf("\"}\n");
        }
    }
    free(line);
    vdpc_free(&pol);
    fflush(stdout);
    return 0;
}
