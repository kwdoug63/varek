// SPDX-License-Identifier: MIT
/*
 * tests/test_plan_parser.c — exercises the plan_parser_load path
 * against in-memory plan files written to a temp file.
 */

#define _POSIX_C_SOURCE 200809L

#include "../plan_parser.h"
#include "../plan_spec.h"
#include "../warden_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXPECT_TRUE(cond) do {                                         \
    if (!(cond)) {                                                     \
        fprintf(stderr, "FAIL %s:%d: '%s' was false\n",                \
                __FILE__, __LINE__, #cond);                            \
        return 1;                                                      \
    }                                                                  \
} while (0)

#define EXPECT_STR_EQ(actual, expected) do {                           \
    const char *_a = (actual);                                         \
    const char *_e = (expected);                                       \
    if (!_a || strcmp(_a, _e) != 0) {                                  \
        fprintf(stderr, "FAIL %s:%d: expected '%s', got '%s'\n",       \
                __FILE__, __LINE__, _e, _a ? _a : "(null)");           \
        return 1;                                                      \
    }                                                                  \
} while (0)

/* Write text to a temp file and return its path. The caller is
 * responsible for unlink()'ing. */
static int write_temp(const char *content, char *out_path, size_t out_len)
{
    snprintf(out_path, out_len, "/tmp/varek_plan_test_XXXXXX");
    int fd = mkstemp(out_path);
    if (fd < 0) return -1;
    size_t n = strlen(content);
    if (write(fd, content, n) != (ssize_t)n) {
        close(fd);
        unlink(out_path);
        return -1;
    }
    close(fd);
    return 0;
}

static plan_decision_t allow_all(const plan_spec_action_t *a, void *ud)
{
    (void)a; (void)ud;
    return PLAN_DEC_SATISFIED;
}

static int test_minimal_valid(void)
{
    const char *plan =
        "# minimal plan\n"
        "action a file_open /etc/passwd\n";

    char path[64];
    if (write_temp(plan, path, sizeof(path)) != 0) {
        fprintf(stderr, "FAIL: write_temp\n");
        return 1;
    }

    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);
    EXPECT_TRUE(h != NULL);
    EXPECT_TRUE(plan_parser_action_count(h) == 1);
    EXPECT_TRUE(plan_parser_edge_count(h)   == 0);

    const plan_spec_t *s = plan_parser_spec(h);
    EXPECT_TRUE(s != NULL);
    EXPECT_STR_EQ(s->actions[0].label,  "a");
    EXPECT_STR_EQ(s->actions[0].kind,   "file_open");
    EXPECT_STR_EQ(s->actions[0].target, "/etc/passwd");

    plan_parser_free(h);
    return 0;
}

static int test_full_diamond(void)
{
    const char *plan =
        "action load  file_open    /var/data/input.json\n"
        "action exec  process_exec /usr/bin/python3\n"
        "action post  net_connect  api.example.com:443\n"
        "action audit file_open    /var/data/audit.log\n"
        "\n"
        "edge load exec\n"
        "edge exec post\n"
        "edge exec audit\n";

    char path[64];
    write_temp(plan, path, sizeof(path));

    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h != NULL);
    EXPECT_TRUE(plan_parser_action_count(h) == 4);
    EXPECT_TRUE(plan_parser_edge_count(h)   == 3);

    const plan_spec_t *s = plan_parser_spec(h);
    EXPECT_TRUE(s->edges[0].from_idx == 0 && s->edges[0].to_idx == 1);
    EXPECT_TRUE(s->edges[1].from_idx == 1 && s->edges[1].to_idx == 2);
    EXPECT_TRUE(s->edges[2].from_idx == 1 && s->edges[2].to_idx == 3);

    /* Sanity: a parsed plan flows through the adapter unchanged. */
    plan_decision_t d = warden_adapter_verify(s, allow_all, NULL, NULL);
    EXPECT_TRUE(d == PLAN_DEC_SATISFIED);

    plan_parser_free(h);
    return 0;
}

static int test_blank_lines_and_comments(void)
{
    const char *plan =
        "# comment line\n"
        "\n"
        "    # indented comment\n"
        "action a file_open /a\n"
        "\n"
        "# another comment\n"
        "action b file_open /b\n"
        "edge a b\n"
        "\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h != NULL);
    EXPECT_TRUE(plan_parser_action_count(h) == 2);
    EXPECT_TRUE(plan_parser_edge_count(h)   == 1);

    plan_parser_free(h);
    return 0;
}

static int test_duplicate_label_rejected(void)
{
    const char *plan =
        "action a file_open /a\n"
        "action a net_connect h:1\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "duplicate") != NULL);
    return 0;
}

static int test_unknown_label_in_edge(void)
{
    const char *plan =
        "action a file_open /a\n"
        "edge a zzz\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "undefined") != NULL);
    return 0;
}

static int test_self_edge_rejected(void)
{
    const char *plan =
        "action a file_open /a\n"
        "edge a a\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "self-edge") != NULL);
    return 0;
}

static int test_unknown_directive_rejected(void)
{
    const char *plan =
        "action a file_open /a\n"
        "garbage line here\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "unknown directive") != NULL);
    return 0;
}

static int test_invalid_label_chars(void)
{
    const char *plan =
        "action 1abc file_open /a\n";   /* leading digit invalid */

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "invalid label") != NULL);
    return 0;
}

static int test_missing_target(void)
{
    const char *plan =
        "action a file_open\n";   /* no target */

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "action requires") != NULL);
    return 0;
}

static int test_empty_plan_rejected(void)
{
    const char *plan = "# nothing but comments\n";

    char path[64];
    write_temp(plan, path, sizeof(path));
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load(path, err, sizeof(err));
    unlink(path);

    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "no actions") != NULL);
    return 0;
}

static int test_missing_file(void)
{
    char err[256] = {0};
    plan_parsed_t *h = plan_parser_load("/tmp/varek_definitely_not_present_999999",
                                        err, sizeof(err));
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "cannot open") != NULL);
    return 0;
}

static int test_null_safety(void)
{
    EXPECT_TRUE(plan_parser_spec(NULL) == NULL);
    EXPECT_TRUE(plan_parser_action_count(NULL) == 0);
    EXPECT_TRUE(plan_parser_edge_count(NULL) == 0);
    plan_parser_free(NULL);   /* must not crash */
    return 0;
}

/* v1.35 (D3): `plan 1.35`, first and once; a plan without it is version 0 */
static int load_str(const char *plan, char *err, size_t errn, plan_parsed_t **out)
{
    char path[64];
    write_temp(plan, path, sizeof(path));
    *out = plan_parser_load(path, err, errn);
    unlink(path);
    return 0;
}

static int test_plan_version(void)
{
    char err[256] = {0};
    plan_parsed_t *h = NULL;
    load_str("# a comment first is fine\nplan 1.35\naction a mcp_call https://m.example.com/mcp name=search\n",
             err, sizeof err, &h);
    EXPECT_TRUE(h != NULL);
    EXPECT_TRUE(plan_parser_version(h) == 135);
    EXPECT_TRUE(plan_parser_action_count(h) == 1);
    plan_parser_free(h);

    load_str("action a file_open /a\n", err, sizeof err, &h);
    EXPECT_TRUE(h != NULL);
    EXPECT_TRUE(plan_parser_version(h) == 0);
    plan_parser_free(h);
    EXPECT_TRUE(plan_parser_version(NULL) == 0);

    err[0] = '\0';
    load_str("action a file_open /a\nplan 1.35\n", err, sizeof err, &h);
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "must be the plan's first line") != NULL);

    err[0] = '\0';
    load_str("plan 1.35\nplan 1.35\naction a file_open /a\n", err, sizeof err, &h);
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "first line, once") != NULL);

    err[0] = '\0';
    load_str("plan 1.36\naction a file_open /a\n", err, sizeof err, &h);
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "unknown plan version") != NULL);

    err[0] = '\0';
    load_str("plan\naction a file_open /a\n", err, sizeof err, &h);
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "plan requires") != NULL);

    err[0] = '\0';
    load_str("plan 1.35 extra\naction a file_open /a\n", err, sizeof err, &h);
    EXPECT_TRUE(h == NULL);
    EXPECT_TRUE(strstr(err, "plan requires") != NULL);
    return 0;
}

int main(void)
{
    int fails = 0;
    fails += test_minimal_valid();
    fails += test_full_diamond();
    fails += test_blank_lines_and_comments();
    fails += test_duplicate_label_rejected();
    fails += test_unknown_label_in_edge();
    fails += test_self_edge_rejected();
    fails += test_unknown_directive_rejected();
    fails += test_invalid_label_chars();
    fails += test_missing_target();
    fails += test_empty_plan_rejected();
    fails += test_missing_file();
    fails += test_null_safety();
    fails += test_plan_version();
    printf("test_plan_parser: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
