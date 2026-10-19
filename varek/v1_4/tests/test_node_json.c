// SPDX-License-Identifier: MIT
// test_node_json.c — v1.34 step 2: the node agent's JSON reader (node_json.c).
#include "../node_json.h"

#include <stdio.h>
#include <string.h>

static int fails = 0, checks = 0;
#define CHECK(d, e) do { checks++; if (e) printf("  PASS   %s\n", d); else { printf("  FAIL   %s\n", d); fails++; } } while (0)

static int ok(const char *doc) { char w[128]; return nj_check(doc, strlen(doc), w, sizeof w) == 0; }

static int str_at(const char *doc, const char *const *p, size_t d, char *out, size_t on) {
    const char *v; size_t vn;
    if (nj_find(doc, strlen(doc), p, d, &v, &vn) < 0) return -1;
    return nj_string(v, vn, out, on);
}

int main(void) {
    /* a container's state as runc sends it with the descriptor */
    const char *state =
        "{\"ociVersion\":\"1.2.1\",\"fds\":[\"seccompFd\"],\"pid\":4242,\"metadata\":\"ns/pod/agent\","
        "\"state\":{\"ociVersion\":\"1.2.1\",\"id\":\"abc123\",\"status\":\"creating\",\"pid\":4242,"
        "\"bundle\":\"/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc123\","
        "\"annotations\":{\"io.kubernetes.cri.sandbox-namespace\":\"varek\",\"io.kubernetes.cri.sandbox-name\":\"varek-a\"}}}";
    CHECK("a runtime's state is well formed", ok(state));
    {
        const char *p[] = { "pid" }, *v; size_t vn; long long pid = 0;
        CHECK("its pid", nj_find(state, strlen(state), p, 1, &v, &vn) == 0 && nj_int(v, vn, &pid) == 0 && pid == 4242);
        char b[256];
        const char *pb[] = { "state", "bundle" };
        CHECK("its bundle", str_at(state, pb, 2, b, sizeof b) == 0 && !strcmp(b, "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc123"));
        const char *pa[] = { "state", "annotations", "io.kubernetes.cri.sandbox-name" };
        CHECK("an annotation", str_at(state, pa, 3, b, sizeof b) == 0 && !strcmp(b, "varek-a"));
        const char *pf[] = { "fds", "#0" };
        CHECK("an array element", str_at(state, pf, 2, b, sizeof b) == 0 && !strcmp(b, "seccompFd"));
        const char *px[] = { "state", "nope" };
        CHECK("a missing member is not found", nj_find(state, strlen(state), px, 2, &v, &vn) < 0);
        const char *pi[] = { "fds", "#1" };
        CHECK("a missing element is not found", nj_find(state, strlen(state), pi, 2, &v, &vn) < 0);
        const char *pm[] = { "metadata" };
        CHECK("a string is not an integer", nj_find(state, strlen(state), pm, 1, &v, &vn) == 0 && nj_int(v, vn, &pid) < 0);
    }
    /* a member given twice is refused at any depth: the runtime's reader would take the last */
    CHECK("a name twice at the top is refused", !ok("{\"uid\":0,\"uid\":65534}"));
    CHECK("a name twice deep is refused", !ok("{\"process\":{\"user\":{\"uid\":0,\"gid\":1,\"uid\":65534}}}"));
    CHECK("a name twice through an escape is refused", !ok("{\"uid\":0,\"\\u0075id\":1}"));
    CHECK("the same name in two objects is fine", ok("{\"a\":{\"x\":1},\"b\":{\"x\":2}}"));
    /* strictness */
    CHECK("trailing data is refused", !ok("{} x"));
    CHECK("a byte-order mark is refused", !ok("\xEF\xBB\xBF{}"));
    CHECK("a trailing comma is refused", !ok("{\"a\":1,}"));
    CHECK("a leading zero is refused", !ok("{\"a\":01}"));
    CHECK("an overlong UTF-8 form is refused", !ok("\"\xC0\xAF\""));
    CHECK("an encoded surrogate is refused", !ok("\"\xED\xA0\x80\""));
    CHECK("a lone surrogate escape is refused", !ok("\"\\ud800\""));
    CHECK("a raw control character is refused", !ok("\"a\x01\""));
    CHECK("a surrogate pair is fine", ok("\"\\ud83d\\ude00\""));
    {
        char d[64]; char deep[200] = "";
        for (int k = 0; k < 40; k++) strcat(deep, "[");
        for (int k = 0; k < 40; k++) strcat(deep, "]");
        CHECK("nesting past the limit is refused", !ok(deep));
        const char *e = "{\"s\":\"a\\tb\\u00e9\\\"\"}";
        const char *p[] = { "s" };
        CHECK("escapes are decoded", ok(e) && str_at(e, p, 1, d, sizeof d) == 0 && !strcmp(d, "a\tb\xC3\xA9\""));
        const char *z = "{\"s\":\"a\\u0000b\"}";
        CHECK("a decoded NUL is refused as a string", ok(z) && str_at(z, p, 1, d, sizeof d) < 0);
        const char *l = "{\"s\":\"0123456789\"}";
        CHECK("a string longer than the buffer is refused", str_at(l, p, 1, d, 5) < 0);
    }
    printf("\ntest_node_json: %d of %d passed\n", checks - fails, checks);
    return fails ? 1 : 0;
}
