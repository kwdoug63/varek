// SPDX-License-Identifier: MIT
// shared_domains.c — v1.25: wildcard host patterns refused at load. See
// shared_domains.h.

#include "shared_domains.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    F_ICANN      = 1,      /* an ICANN rule "x": x is a public suffix */
    F_ICANN_WILD = 2,      /* an ICANN rule "*.x": every label.x is a public suffix */
    F_ICANN_EXC  = 4,      /* an ICANN rule "!x": x is not */
    F_PRIVATE    = 8,      /* a private rule "x" or "*.x": x and everything under it */
    F_VAREK      = 16,     /* the VAREK list: x and everything under it */
};

typedef struct {
    char    *key;
    unsigned flags;
} slot_t;

struct sd_lists {
    slot_t *slot;
    size_t  cap, used;
    size_t  count[3];
};

static uint64_t fnv(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}

static slot_t *find(const sd_lists_t *l, const char *k) {
    size_t i = (size_t)(fnv(k) & (l->cap - 1));
    while (l->slot[i].key) {
        if (!strcmp(l->slot[i].key, k)) return &l->slot[i];
        i = (i + 1) & (l->cap - 1);
    }
    return &l->slot[i];
}

static int grow(sd_lists_t *l) {
    size_t nc = l->cap ? l->cap * 2 : 1 << 15;
    slot_t *ns = calloc(nc, sizeof *ns);
    if (!ns) return -1;
    slot_t *old = l->slot;
    size_t oc = l->cap;
    l->slot = ns;
    l->cap = nc;
    for (size_t i = 0; i < oc; i++) {
        if (!old[i].key) continue;
        *find(l, old[i].key) = old[i];
    }
    free(old);
    return 0;
}

static int add(sd_lists_t *l, const char *k, unsigned flag) {
    if ((l->used + 1) * 2 > l->cap && grow(l) < 0) return -1;
    slot_t *s = find(l, k);
    if (!s->key) {
        s->key = strdup(k);
        if (!s->key) return -1;
        l->used++;
    }
    s->flags |= flag;
    return 0;
}

static unsigned flags_of(const sd_lists_t *l, const char *k) {
    if (!l->cap) return 0;
    slot_t *s = find(l, k);
    return s->key ? s->flags : 0;
}

/* ---- RFC 3492 punycode, encoding only ---- */

static int utf8_decode(const unsigned char *s, size_t n, uint32_t *cp, size_t *ncp, size_t max) {
    size_t i = 0, k = 0;
    while (i < n) {
        unsigned c = s[i];
        uint32_t v;
        int extra;
        if (c < 0x80) { v = c; extra = 0; }
        else if ((c & 0xe0) == 0xc0) { v = c & 0x1f; extra = 1; }
        else if ((c & 0xf0) == 0xe0) { v = c & 0x0f; extra = 2; }
        else if ((c & 0xf8) == 0xf0) { v = c & 0x07; extra = 3; }
        else return -1;
        for (int e = 1; e <= extra; e++) {
            if (i + (size_t)e >= n || (s[i + (size_t)e] & 0xc0) != 0x80) return -1;
            v = (v << 6) | (s[i + (size_t)e] & 0x3f);
        }
        if (k >= max) return -1;
        cp[k++] = v;
        i += (size_t)extra + 1;
    }
    *ncp = k;
    return 0;
}

static char digit(uint32_t d) { return (char)(d < 26 ? 'a' + d : '0' + (d - 26)); }

static uint32_t adapt(uint32_t delta, uint32_t numpoints, int first) {
    delta = first ? delta / 700 : delta / 2;
    delta += delta / numpoints;
    uint32_t k = 0;
    while (delta > ((36 - 1) * 26) / 2) { delta /= 36 - 1; k += 36; }
    return k + (36 * delta) / (delta + 38);
}

int sd_to_alabel(const char *label, size_t n, char *out, size_t outn) {
    uint32_t cp[256];
    size_t ncp;
    if (utf8_decode((const unsigned char *)label, n, cp, &ncp, 256) < 0) return -1;
    size_t basic = 0;
    for (size_t i = 0; i < ncp; i++) if (cp[i] < 0x80) basic++;
    size_t o = 0;
#define PUT(ch) do { if (o + 1 >= outn) return -1; out[o++] = (ch); } while (0)
    if (basic == ncp) {
        for (size_t i = 0; i < ncp; i++) PUT((char)(cp[i] >= 'A' && cp[i] <= 'Z' ? cp[i] + 32 : cp[i]));
        out[o] = '\0';
        return 0;
    }
    PUT('x'); PUT('n'); PUT('-'); PUT('-');
    for (size_t i = 0; i < ncp; i++)
        if (cp[i] < 0x80) PUT((char)(cp[i] >= 'A' && cp[i] <= 'Z' ? cp[i] + 32 : cp[i]));
    if (basic) PUT('-');
    uint32_t nn = 0x80, delta = 0, bias = 72, h = (uint32_t)basic;
    while (h < ncp) {
        uint32_t m = UINT32_MAX;
        for (size_t i = 0; i < ncp; i++) if (cp[i] >= nn && cp[i] < m) m = cp[i];
        if ((uint64_t)(m - nn) * (h + 1) + delta > UINT32_MAX) return -1;
        delta += (m - nn) * (h + 1);
        nn = m;
        for (size_t i = 0; i < ncp; i++) {
            if (cp[i] < nn) delta++;
            if (cp[i] == nn) {
                uint32_t q = delta;
                for (uint32_t k = 36;; k += 36) {
                    uint32_t t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
                    if (q < t) break;
                    PUT(digit(t + (q - t) % (36 - t)));
                    q = (q - t) / (36 - t);
                }
                PUT(digit(q));
                bias = adapt(delta, h + 1, h == basic);
                delta = 0;
                h++;
            }
        }
        delta++;
        nn++;
    }
#undef PUT
    out[o] = '\0';
    return 0;
}

/* A whole domain (labels separated by '.') to A-labels. */
static int to_ascii(const char *s, char *out, size_t outn) {
    size_t o = 0;
    const char *p = s;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ln = dot ? (size_t)(dot - p) : strlen(p);
        char lab[256];
        if (sd_to_alabel(p, ln, lab, sizeof lab) < 0) return -1;
        size_t ll = strlen(lab);
        if (o + ll + 2 > outn) return -1;
        if (o) out[o++] = '.';
        memcpy(out + o, lab, ll);
        o += ll;
        if (!dot) break;
        p = dot + 1;
    }
    out[o] = '\0';
    return 0;
}

static int read_lines(const char *path, int psl, sd_lists_t *l, char *why, size_t wn) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(why, wn, "cannot read %s", path); return -1; }
    char line[1024];
    int section = psl ? 0 : 2;          /* 0 ICANN, 1 private, 2 VAREK */
    int seen_icann = 0, seen_private = 0;
    while (fgets(line, sizeof line, f)) {
        if (psl && strstr(line, "===BEGIN ICANN DOMAINS===")) { section = 0; seen_icann = 1; continue; }
        if (psl && strstr(line, "===BEGIN PRIVATE DOMAINS===")) { section = 1; seen_private = 1; continue; }
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!psl) { char *h = strchr(p, '#'); if (h) *h = '\0'; }
        if (psl && p[0] == '/' && p[1] == '/') continue;
        size_t n = strcspn(p, " \t\r\n");
        p[n] = '\0';
        if (!n) continue;
        unsigned flag;
        const char *dom = p;
        if (section == 2) flag = F_VAREK;
        else if (p[0] == '!') { dom = p + 1; flag = section == 0 ? F_ICANN_EXC : 0; }
        else if (p[0] == '*' && p[1] == '.') { dom = p + 2; flag = section == 0 ? F_ICANN_WILD : F_PRIVATE; }
        else flag = section == 0 ? F_ICANN : F_PRIVATE;
        if (!flag) continue;            /* a private exception: the parent's rule still refuses */
        char a[600];
        if (to_ascii(dom, a, sizeof a) < 0) continue;
        if (add(l, a, flag) < 0) { fclose(f); snprintf(why, wn, "out of memory"); return -1; }
        l->count[section]++;
    }
    fclose(f);
    if (psl && (!seen_icann || !seen_private)) {
        snprintf(why, wn, "%s is not the Public Suffix List (no ICANN and private sections)", path);
        return -1;
    }
    return 0;
}

sd_lists_t *sd_load(const char *psl_path, const char *varek_path, char *why, size_t wn) {
    sd_lists_t *l = calloc(1, sizeof *l);
    if (!l || grow(l) < 0) { free(l); snprintf(why, wn, "out of memory"); return NULL; }
    if (read_lines(psl_path, 1, l, why, wn) < 0 || read_lines(varek_path, 0, l, why, wn) < 0) {
        sd_free(l);
        return NULL;
    }
    return l;
}

void sd_free(sd_lists_t *l) {
    if (!l) return;
    for (size_t i = 0; i < l->cap; i++) free(l->slot[i].key);
    free(l->slot);
    free(l);
}

size_t sd_count(const sd_lists_t *l, int which) { return which >= 0 && which < 3 ? l->count[which] : 0; }

int sd_refuses(const sd_lists_t *l, const char *suffix, char *why, size_t wn) {
    /* ICANN: is suffix itself a public suffix? */
    unsigned f = flags_of(l, suffix);
    const char *parent = strchr(suffix, '.');
    if (!(f & F_ICANN_EXC)) {
        if (f & F_ICANN) {
            snprintf(why, wn, "%s is a public suffix (Public Suffix List): anyone can register a "
                     "name under it", suffix);
            return 1;
        }
        if (parent && (flags_of(l, parent + 1) & F_ICANN_WILD)) {
            snprintf(why, wn, "%s is a public suffix (Public Suffix List rule *.%s): anyone can "
                     "register a name under it", suffix, parent + 1);
            return 1;
        }
    }
    /* Private section and the VAREK list: suffix or any domain it is under. */
    for (const char *s = suffix; s; s = strchr(s, '.') ? strchr(s, '.') + 1 : NULL) {
        unsigned g = flags_of(l, s);
        if (g & (F_PRIVATE | F_VAREK)) {
            if (s == suffix)
                snprintf(why, wn, "%s is a shared domain where anyone can register names (%s)", s,
                         g & F_VAREK ? "VAREK list" : "Public Suffix List, private section");
            else
                snprintf(why, wn, "%s is under %s, a shared domain where anyone can register names "
                         "(%s)", suffix, s,
                         g & F_VAREK ? "VAREK list" : "Public Suffix List, private section");
            return 1;
        }
    }
    return 0;
}

int sd_wildcard_suffix(const char *glob, char *out, size_t n) {
    if (strncmp(glob, "?*.", 3) != 0) return -1;
    const char *colon = strrchr(glob, ':');
    if (!colon || colon < glob + 4) return -1;
    size_t l = (size_t)(colon - glob - 3);
    if (l + 1 > n) return -1;
    memcpy(out, glob + 3, l);
    out[l] = '\0';
    return 0;
}

int sd_default_path(const char *file, char *out, size_t n) {
    char exe[4096];
    ssize_t k = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (k <= 0) return -1;
    exe[k] = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return -1;
    *slash = '\0';
    for (int up = 0; up < 2; up++) {
        if ((size_t)snprintf(out, n, "%s%s/data/%s", exe, up ? "/.." : "", file) >= n) return -1;
        if (access(out, R_OK) == 0) return 0;
    }
    return -1;
}
