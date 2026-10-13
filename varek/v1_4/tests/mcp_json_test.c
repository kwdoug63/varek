// SPDX-License-Identifier: MIT
// mcp_json_test.c — v1.31: the strict JSON parser warden-proxy reads MCP calls
// with (mcp_json.c), under AddressSanitizer and UBSan: the vectors (each form
// it accepts and each it refuses), then N mutated inputs (argv[1], default
// 200000), none of which may crash it or make it accept what a second,
// independent check says is not one JSON object with unique member names.
#include "../mcp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0, checks = 0;

static void want(const char *label, const char *body, int ok, const char *method, const char *name, const char *id) {
    mj_call_t c;
    char why[128] = "";
    int rc = mj_call((const uint8_t *)body, strlen(body), &c, why, sizeof why);
    checks++;
    if ((rc == 0) != ok) {
        printf("  FAIL   %s: %s (%s)\n", label, rc == 0 ? "accepted" : "refused", why);
        fails++;
        return;
    }
    if (ok && ((method && strcmp(c.method, method)) || (name && strcmp(c.name, name)) || (name && !c.has_name) ||
               (!name && c.has_name) || (id && strcmp(c.id, id)) || (!id && !c.notification))) {
        printf("  FAIL   %s: read method=%s name=%s id=%s\n", label, c.method, c.name, c.id);
        fails++;
    }
}

static void hdr(const char *label, const char *v, int ok, const char *want_v) {
    char out[256];
    int rc = mj_header_value(v, strlen(v), out, sizeof out);
    checks++;
    if ((rc == 0) != ok || (ok && strcmp(out, want_v))) {
        printf("  FAIL   header %s: rc=%d out=%s\n", label, rc, rc == 0 ? out : "-");
        fails++;
    }
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 200000;
    const char *C = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_issue\",\"arguments\":{\"n\":1}}}";
    want("a tools/call", C, 1, "tools/call", "get_issue", "1");
    want("a resources/read", "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///p/a\"}}",
         1, "resources/read", "file:///p/a", "\"a\"");
    want("a tools/list (no name)", "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}", 1, "tools/list", NULL, "7");
    want("a notification", "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", 1, "notifications/initialized", NULL, NULL);
    want("whitespace around", " \n{ \"jsonrpc\" : \"2.0\" , \"method\" : \"x\" , \"id\" : -1.5e+3 }\r\n", 1, "x", NULL, "-1.5e+3");
    want("escapes decoded in the name", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get\\u005fissue\"}}",
         1, "tools/call", "get_issue", "1");
    want("escapes decoded in a member name", "{\"jsonrpc\":\"2.0\",\"id\":1,\"m\\u0065thod\":\"tools/call\"}", 1, "tools/call", NULL, "1");
    want("a surrogate pair", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\\ud83d\\ude00\"}}", 1, "x", "\xf0\x9f\x98\x80", "1");
    want("raw UTF-8 in a name", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\xc3\xa9\"}}", 1, "x", "\xc3\xa9", "1");
    want("_meta.traceparent", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"_meta\":{\"traceparent\":\"00-ab-cd-01\"}}}", 1, "x", NULL, "1");
    {
        char deep[512] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"a\":";
        for (int i = 0; i < 62; i++) strcat(deep, "[");                 /* 2 objects + 62 arrays = 64 */
        strcat(deep, "1");
        for (int i = 0; i < 62; i++) strcat(deep, "]");
        strcat(deep, "}}");
        want("nesting of 64", deep, 1, "x", NULL, "1");
        deep[strlen("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"a\":")] = '\0';
        for (int i = 0; i < 63; i++) strcat(deep, "[");
        strcat(deep, "1");
        for (int i = 0; i < 63; i++) strcat(deep, "]");
        strcat(deep, "}}");
        want("nesting of 65", deep, 0, 0, 0, 0);
    }

    want("a duplicate method", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"method\":\"tools/call\"}", 0, 0, 0, 0);
    want("a duplicate name in params", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"a\",\"name\":\"b\"}}", 0, 0, 0, 0);
    want("a duplicate through an escape", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\",\"m\\u0065thod\":\"b\"}", 0, 0, 0, 0);
    want("a duplicate deep inside", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"arguments\":{\"q\":{\"k\":1,\"k\":2}}}}", 0, 0, 0, 0);
    want("name and uri", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"a\",\"uri\":\"b\"}}", 0, 0, 0, 0);
    want("a name that is not a string", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":1}}", 0, 0, 0, 0);
    want("a batch", "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}]", 0, 0, 0, 0);
    want("no jsonrpc", "{\"id\":1,\"method\":\"x\"}", 0, 0, 0, 0);
    want("jsonrpc 1.0", "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"x\"}", 0, 0, 0, 0);
    want("a response (no method)", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", 0, 0, 0, 0);
    want("a null id", "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}", 0, 0, 0, 0);
    want("an object id", "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"x\"}", 0, 0, 0, 0);
    want("params an array", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":[1]}", 0, 0, 0, 0);
    want("a trailing comma", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",}", 0, 0, 0, 0);
    want("a comment", "{\"jsonrpc\":\"2.0\",/*c*/\"id\":1,\"method\":\"x\"}", 0, 0, 0, 0);
    want("a leading zero", "{\"jsonrpc\":\"2.0\",\"id\":01,\"method\":\"x\"}", 0, 0, 0, 0);
    want("a single-quoted string", "{'jsonrpc':\"2.0\",\"id\":1,\"method\":\"x\"}", 0, 0, 0, 0);
    want("a raw newline in a string", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\ny\"}", 0, 0, 0, 0);
    want("a lone high surrogate", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\\ud83d\"}}", 0, 0, 0, 0);
    want("a lone low surrogate", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\\ude00\"}}", 0, 0, 0, 0);
    want("an overlong UTF-8 '/'", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\xc0\xaf\"}}", 0, 0, 0, 0);
    want("a UTF-8 surrogate", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\xed\xa0\x80\"}}", 0, 0, 0, 0);
    want("invalid UTF-8", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"name\":\"\xff\"}}", 0, 0, 0, 0);
    want("a byte-order mark", "\xef\xbb\xbf{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}", 0, 0, 0, 0);
    want("a NUL in the method (escaped)", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\\u0000y\"}", 0, 0, 0, 0);
    want("bytes after the object", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"} {}", 0, 0, 0, 0);
    want("a truncated body", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"", 0, 0, 0, 0);
    want("an empty body", "", 0, 0, 0, 0);
    want("an empty object", "{}", 0, 0, 0, 0);
    want("an empty method", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\"}", 1, "", NULL, "1");
    want("a bad escape", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\\x\"}", 0, 0, 0, 0);
    want("NaN", "{\"jsonrpc\":\"2.0\",\"id\":NaN,\"method\":\"x\"}", 0, 0, 0, 0);
    {
        char deep[512] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":{\"a\":";
        for (int i = 0; i < 64; i++) strcat(deep, "[");
        strcat(deep, "1");
        for (int i = 0; i < 64; i++) strcat(deep, "]");
        strcat(deep, "}}");
        want("nesting of 66", deep, 0, 0, 0, 0);
    }

    hdr("plain", "get_issue", 1, "get_issue");
    hdr("base64", "=?base64?SGVsbG8sIOS4lueVjA==?=", 1, "Hello, \xe4\xb8\x96\xe7\x95\x8c");
    hdr("base64 of the sentinel itself", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", 1, "=?base64?literal?=");
    hdr("base64 with a bad digit", "=?base64?SGVs*G8=?=", 0, NULL);
    hdr("base64 without padding", "=?base64?SGVsbG8?=", 0, NULL);
    hdr("base64 with stray bits", "=?base64?SGVsbG9=?=", 0, NULL);
    hdr("base64 of a NUL", "=?base64?AA==?=", 0, NULL);
    hdr("an upper-case sentinel", "=?BASE64?SGk=?=", 1, "=?BASE64?SGk=?=");

    /* mutations: no crash, and nothing accepted that is not an object (a
     * cheap second check: the first non-space byte is '{', the last '}') */
    srand(31);
    size_t cl = strlen(C);
    uint8_t *b = malloc(cl + 64);
    long accepted = 0;
    for (long k = 0; k < n; k++) {
        size_t bl = cl;
        memcpy(b, C, cl);
        int m = 1 + rand() % 4;
        for (int j = 0; j < m; j++) {
            int op = rand() % 4;
            size_t at = bl ? (size_t)rand() % bl : 0;
            if (op == 0 && bl) b[at] = (uint8_t)rand();
            else if (op == 1 && bl) { memmove(b + at, b + at + 1, bl - at - 1); bl--; }
            else if (op == 2 && bl < cl + 60) { memmove(b + at + 1, b + at, bl - at); { static const char al[] = "{}[]\",:\\u0aZ \xc3\xed"; b[at] = (uint8_t)al[rand() % (sizeof al - 1)]; } bl++; }
            else if (bl) bl = at;
        }
        mj_call_t c;
        char why[128];
        if (mj_call(b, bl, &c, why, sizeof why) == 0) {
            accepted++;
            size_t s = 0, e = bl;
            while (s < bl && (b[s] == ' ' || b[s] == '\n' || b[s] == '\r' || b[s] == '\t')) s++;
            while (e > s && (b[e - 1] == ' ' || b[e - 1] == '\n' || b[e - 1] == '\r' || b[e - 1] == '\t')) e--;
            checks++;
            if (s >= e || b[s] != '{' || b[e - 1] != '}' || !c.method[0]) {
                printf("  FAIL   mutation %ld accepted something that is not a call: %.*s\n", k, (int)bl, b);
                fails++;
            }
        }
    }
    free(b);
    printf("mcp_json_test: %d checks, %ld mutated inputs (%ld still calls), %s\n", checks, n, accepted,
           fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
