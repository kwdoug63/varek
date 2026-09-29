// SPDX-License-Identifier: MIT
/*
 * tests/test_plan_fields.c — VAREK v1.20.0: fields on plan steps.
 *
 *   action <label> <kind> <target> [<key>=<value> ...]
 *
 * Checks that fields parse (bare and quoted, with escapes), that the
 * three-field form is unchanged, and that every malformed form is refused
 * with a message rather than read some other way.
 */

#define _POSIX_C_SOURCE 200809L

#include "../plan_parser.h"
#include "../plan_spec.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_pass, g_fail;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; printf("  ok:   %s\n", msg); }             \
    else      { g_fail++; printf("  FAIL: %s\n", msg); }             \
} while (0)

static char g_err[512];

/* Parse text as a plan file; NULL on a parse error (message in g_err). */
static plan_parsed_t *parse(const char *text)
{
    char path[64];
    snprintf(path, sizeof path, "/tmp/varek_plan_fields_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return NULL;
    size_t n = strlen(text);
    ssize_t w = write(fd, text, n);
    close(fd);
    g_err[0] = '\0';
    plan_parsed_t *p = (w == (ssize_t)n) ? plan_parser_load(path, g_err, sizeof g_err) : NULL;
    unlink(path);
    return p;
}

static const char *field(const plan_parsed_t *p, size_t idx, const char *key)
{
    size_t n = 0;
    const plan_spec_field_t *f = plan_parser_fields(p, idx, &n);
    for (size_t i = 0; i < n; i++)
        if (strcmp(f[i].key, key) == 0) return f[i].value;
    return NULL;
}

static void test_valid(void)
{
    printf("-- fields parse\n");
    plan_parsed_t *p = parse(
        "action a file_open /srv/in\n"
        "action post http_request https://api.example.com/v1 method=POST body=\"{\\\"q\\\": \\\"hi there\\\"}\" "
        "header_authorization=\"Bearer x\\ty\" note=a\\\\b\n"
        "action b file_open /srv/out\tmode=write\n"
        "edge a post\n");
    CHECK(p != NULL, "a plan with fields loads");
    if (!p) { printf("        %s\n", g_err); return; }
    const plan_spec_t *s = plan_parser_spec(p);
    size_t n = 99;
    CHECK(plan_parser_fields(p, 0, &n) == NULL && n == 0, "a step with no fields has none");
    CHECK(s->actions[1].target && strcmp(s->actions[1].target, "https://api.example.com/v1") == 0,
          "the target is still the third field");
    (void)plan_parser_fields(p, 1, &n);
    CHECK(n == 4, "the request step has 4 fields");
    const char *v = field(p, 1, "method");
    CHECK(v && strcmp(v, "POST") == 0, "a bare value");
    v = field(p, 1, "body");
    CHECK(v && strcmp(v, "{\"q\": \"hi there\"}") == 0, "a quoted value keeps its spaces and decodes \\\"");
    v = field(p, 1, "header_authorization");
    CHECK(v && strcmp(v, "Bearer x\ty") == 0, "\\t decodes to a tab");
    v = field(p, 1, "note");
    CHECK(v && strcmp(v, "a\\\\b") == 0, "a bare value is taken as written (no escapes)");
    const plan_spec_field_t *f = plan_parser_fields(p, 1, &n);
    CHECK(f && strcmp(f[0].key, "method") == 0 && strcmp(f[3].key, "note") == 0, "fields keep file order");
    v = field(p, 2, "mode");
    CHECK(v && strcmp(v, "write") == 0, "a tab separates the target from a field");
    CHECK(plan_parser_fields(p, 7, &n) == NULL && n == 0, "an out-of-range step has no fields");
    plan_parser_free(p);

    p = parse("action x http_request u body=\"\\x41\\x7e\\n\\r\\\\\" empty=\"\"\n");
    CHECK(p && field(p, 0, "body") && strcmp(field(p, 0, "body"), "A~\n\r\\") == 0,
          "\\xHH, \\n, \\r and \\\\ decode");
    CHECK(p && field(p, 0, "empty") && field(p, 0, "empty")[0] == '\0', "an empty quoted value is allowed");
    plan_parser_free(p);

    p = parse("action x http_request u body=\"caf\xc3\xa9 # not a comment\"\n");
    CHECK(p && strcmp(field(p, 0, "body"), "caf\xc3\xa9 # not a comment") == 0,
          "UTF-8 and '#' inside a value are kept");
    plan_parser_free(p);

    /* The longest value and the most fields. */
    char *line = malloc(20000);
    if (line) {
        int o = sprintf(line, "action x http_request u body=\"");
        memset(line + o, 'a', 4096);
        o += 4096;
        sprintf(line + o, "\"\n");
        p = parse(line);
        CHECK(p && strlen(field(p, 0, "body")) == 4096, "a 4096-byte value loads");
        plan_parser_free(p);
        line[o - 1] = 'a';                               /* 4097 bytes */
        sprintf(line + o, "a\"\n");
        p = parse(line);
        CHECK(!p && strstr(g_err, "too long"), "a 4097-byte value is refused");
        plan_parser_free(p);
        o = sprintf(line, "action x k t");
        for (int i = 0; i < 16; i++) o += sprintf(line + o, " f%d=%d", i, i);
        sprintf(line + o, "\n");
        p = parse(line);
        CHECK(p != NULL, "16 fields load");
        plan_parser_free(p);
        sprintf(line + o, " f16=16\n");
        p = parse(line);
        CHECK(!p && strstr(g_err, "too many fields"), "a 17th field is refused");
        plan_parser_free(p);
        free(line);
    }
}

static void test_invalid(void)
{
    printf("-- malformed fields are refused\n");
    struct { const char *text, *want, *why; } bad[] = {
        { "action a k t extra\n",                    "key=value",        "a fourth bare token is refused" },
        { "action a k t =v\n",                       "invalid field",    "an empty key is refused" },
        { "action a k t Body=x\n",                   "invalid field",    "an upper-case key is refused" },
        { "action a k t url.host=x\n",               "invalid field",    "a dotted key (a URL component name) is refused" },
        { "action a k t 9a=x\n",                     "invalid field",    "a key starting with a digit is refused" },
        { "action a k t aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=x\n", "invalid field", "a 33-character key is refused" },
        { "action a k t target=/etc/x\n",            "reserved",         "a field named target is refused" },
        { "action a k t m=1 m=2\n",                  "duplicate field",  "a repeated key is refused" },
        { "action a k t b=\"open\n",                 "unterminated",     "an unterminated quote is refused" },
        { "action a k t b=\"x\"y\n",                 "after a closing",  "text after the closing quote is refused" },
        { "action a k t b=\"\\q\"\n",                "bad escape",       "an unknown escape is refused" },
        { "action a k t b=\"\\x00\"\n",              "bad escape",       "\\x00 is refused" },
        { "action a k t b=\"\\x4\"\n",               "bad escape",       "a short \\x escape is refused" },
        { "action a k t b=\"a\x01\"\n",              "control",          "a raw control character in a quoted value is refused" },
        { "action a k t b=a\x7f\n",                  "control",          "DEL in a bare value is refused" },
        { "action a k t b=a\"b\n",                   "quote it",         "a quote inside a bare value is refused" },
        { "action a k t b\n",                        "key=value",        "a key with no '=' is refused" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        plan_parsed_t *p = parse(bad[i].text);
        bool ok = p == NULL && strstr(g_err, bad[i].want) != NULL;
        CHECK(ok, bad[i].why);
        if (!ok) printf("        got: %s\n", p ? "(loaded)" : g_err);
        plan_parser_free(p);
    }

    /* v1.20.0 review: a target longer than the Warden's path buffer, a NUL
     * byte, and the exact line limit. */
    char *t = malloc(20000);
    if (t) {
        int o = sprintf(t, "action x file_open /");
        memset(t + o, 'a', 4094);                          /* 4095-byte target */
        sprintf(t + o + 4094, "\n");
        plan_parsed_t *p = parse(t);
        CHECK(p != NULL, "a 4095-byte target loads");
        plan_parser_free(p);
        sprintf(t + o + 4094, "a\n");                     /* 4096 bytes */
        p = parse(t);
        CHECK(!p && strstr(g_err, "target too long"), "a 4096-byte target is refused");
        plan_parser_free(p);
        o = sprintf(t, "action x k t b=");
        memset(t + o, 'a', 16383 - o);                     /* 16383 bytes, then newline */
        sprintf(t + 16383, "\n");
        p = parse(t);
        CHECK(!p && strstr(g_err, "too long"), "a 16383-byte line fails only on its 4096-byte value cap");
        plan_parser_free(p);
        o = sprintf(t, "action x k t");
        for (int i = 0; i < 4; i++) {
            o += sprintf(t + o, " f%d=\"", i);
            memset(t + o, 'v', 4000);
            o += 4000;
            o += sprintf(t + o, "\"");
        }
        CHECK(o < 16383, "(setup: a line under the limit)");
        memset(t + o, ' ', 16383 - o);                     /* pad to exactly 16383 */
        sprintf(t + 16383, "\n");
        p = parse(t);
        CHECK(p != NULL, "a line of exactly 16383 bytes loads");
        plan_parser_free(p);
        memset(t + o, ' ', 16384 - o);                     /* 16384 */
        sprintf(t + 16384, "\n");
        p = parse(t);
        CHECK(!p && strstr(g_err, "line too long"), "a line of 16384 bytes is refused");
        plan_parser_free(p);
        free(t);
    }
    {
        char path[64];
        snprintf(path, sizeof path, "/tmp/varek_plan_fields_XXXXXX");
        int fd = mkstemp(path);
        static const char nul[] = "action a k /t k=v\0 j=evil";   /* no final newline */
        ssize_t w = fd >= 0 ? write(fd, nul, sizeof nul - 1) : -1;
        if (fd >= 0) close(fd);
        plan_parsed_t *p = (w == (ssize_t)(sizeof nul - 1)) ? plan_parser_load(path, g_err, sizeof g_err) : NULL;
        unlink(path);
        CHECK(!p && strstr(g_err, "NUL byte"), "a NUL byte in a line is refused, not a silent end of line");
        plan_parser_free(p);
    }

    /* A line longer than the limit is refused rather than split. */
    char *line = malloc(20000);
    if (line) {
        int o = sprintf(line, "action x k t b=");
        memset(line + o, 'a', 16500);
        sprintf(line + o + 16500, "\n");
        plan_parsed_t *p = parse(line);
        CHECK(!p && strstr(g_err, "too long"), "a line over 16384 bytes is refused");
        plan_parser_free(p);
        free(line);
    }
}

static void test_unchanged(void)
{
    printf("-- the three-field form is unchanged\n");
    plan_parsed_t *p = parse("# c\naction load file_open /tmp/in\naction out file_open /tmp/o=ut\nedge load out\n");
    CHECK(p != NULL, "a plan without fields loads as before");
    if (p) {
        const plan_spec_t *s = plan_parser_spec(p);
        CHECK(s->n_actions == 2 && s->n_edges == 1, "same actions and edges");
        CHECK(strcmp(s->actions[1].target, "/tmp/o=ut") == 0, "an '=' in the target is part of the target");
        size_t n = 1;
        CHECK(plan_parser_fields(p, 1, &n) == NULL && n == 0, "and is not a field");
        plan_parser_free(p);
    }
    p = parse("action load file_open\n");
    CHECK(!p && strstr(g_err, "action requires"), "an action with no target is still refused");
    plan_parser_free(p);
}

int main(void)
{
    test_valid();
    test_invalid();
    test_unchanged();
    printf("%d/%d checks passed\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
