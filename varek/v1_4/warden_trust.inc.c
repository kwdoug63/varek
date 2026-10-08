/* warden_trust.inc.c — v1.26.1, inspecting mode: the run's CA and the trust
 * views (docs/security/v1.26.1-inspecting-mode.md, section 3). Included by
 * warden.c after warden_pxdecide.inc.c.
 *
 * Before the agent starts, the Warden picks the host's trust bundle, sends
 * the proxy the names the run's CA may sign for, and receives the CA
 * certificate and a PKCS#12 trust store; the CA's key stays in the proxy.
 * The agent is then served, read-only, the host's bundle with the CA after
 * it (at the usual bundle paths and /etc/varek/run-bundle.pem), the CA alone
 * (/etc/varek/run-ca.pem) and the trust store (/etc/varek/run-trust.p12),
 * and its environment names them, so common clients trust the CA with no
 * settings of their own. Every hash is in run_start. */

/* The host's bundle: the first of these that is a regular file. */
static const char *const kHostBundles[] = {
    "/etc/ssl/certs/ca-certificates.crt",                 /* Debian, Ubuntu, Alpine */
    "/etc/pki/tls/certs/ca-bundle.crt",                   /* Fedora, RHEL, Amazon Linux */
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
};
#define TRUST_BUNDLE_MAX (8u << 20)

static void trust_sha_hex(const unsigned char *d, size_t n, char out[65]) {
    unsigned char h[32];
    crypto_hash_sha256(h, d, n);
    sodium_bin2hex(out, 65, h, sizeof h);
}

/* The names the CA may sign for: each host name an allow rule lets the agent
 * reach on a proxied port, and each wildcard's suffix (a name covers the
 * names under it), without duplicates and without passthrough hosts, which
 * are never decrypted. */
static size_t trust_names(const struct policy *p, char ***out) {
    char **v = calloc(VDP_MAX_RULES, sizeof *v);
    size_t n = 0;
    if (!v) { *out = NULL; return 0; }
    for (size_t i = 0; i < p->v.n; i++) {
        const vdp_rule_t *r = &p->v.rules[i];
        if (r->kind != VDP_KIND_HOST || r->verb != VDP_ALLOW || !r->s.name) continue;
        char name[256];
        const char *c = r->s.c;
        unsigned port = 0;
        bool anyport;
        if (r->s.wild) {                                  /* ?*.<suffix>:<port or *> */
            const char *colon = strrchr(c, ':');
            if (!colon || colon < c + 3) continue;
            snprintf(name, sizeof name, "%.*s", (int)(colon - (c + 3)), c + 3);
            anyport = colon[1] == '*';
            if (!anyport) port = (unsigned)strtoul(colon + 1, NULL, 10);
        } else {
            const char *colon = strchr(c, ':');
            snprintf(name, sizeof name, "%.*s", (int)(colon ? (size_t)(colon - c) : strlen(c)), c);
            anyport = !colon;
            if (colon) port = (unsigned)strtoul(colon + 1, NULL, 10);
        }
        if (!anyport && !proxied_port(p, port)) continue;
        bool skip = false;
        for (size_t k = 0; !skip && k < p->v.proxy_npass; k++)
            if (!r->s.wild && !strcmp(p->v.proxy_pass[k], name)) skip = true;
        for (size_t k = 0; !skip && k < n; k++) if (!strcmp(v[k], name)) skip = true;
        if (skip) continue;
        if (!(v[n] = strdup(name))) break;
        n++;
    }
    *out = v;
    return n;
}

/* The DER of the one certificate in a PEM text, or -1. */
static int trust_pem_der(const unsigned char *pem, size_t n, unsigned char **der, size_t *dl) {
    static const char B[] = "-----BEGIN CERTIFICATE-----\n", E[] = "-----END CERTIFICATE-----\n";
    size_t bl = sizeof B - 1, el = sizeof E - 1;
    if (n < bl + el || memcmp(pem, B, bl) || memcmp(pem + n - el, E, el)) return -1;
    if (memmem(pem + bl, n - bl - el, "-----", 5)) return -1;   /* one certificate only */
    size_t cap = n;
    *der = malloc(cap);
    if (!*der) return -1;
    const char *end = NULL;
    if (sodium_base642bin(*der, cap, (const char *)pem + bl, n - bl - el, "\n", dl, &end,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || *dl == 0 || (*der)[0] != 0x30) {
        free(*der);
        *der = NULL;
        return -1;
    }
    return 0;
}

static int trust_setup(const struct policy *p) {
    char why[512];
    struct stat st;
    g_trust_host_bundle[0] = '\0';
    for (size_t i = 0; i < sizeof kHostBundles / sizeof kHostBundles[0]; i++)
        if (stat(kHostBundles[i], &st) == 0 && S_ISREG(st.st_mode)) {
            char *rp = realpath(kHostBundles[i], NULL);
            snprintf(g_trust_host_bundle, sizeof g_trust_host_bundle, "%s", rp ? rp : kHostBundles[i]);
            free(rp);
            break;
        }
    if (!g_trust_host_bundle[0]) {
        fprintf(stderr, "[warden] inspecting mode: no trust bundle found on the host (looked for %s and "
                "others); refusing to start\n", kHostBundles[0]);
        return -1;
    }
    /* the Warden reads the bundle for the views; the proxy reads it too, for
     * the trust store (and, from step 4, to verify servers) */
    FILE *bf = fopen(g_trust_host_bundle, "re");
    unsigned char *host = NULL;
    size_t hl = 0;
    if (bf) {
        host = malloc(TRUST_BUNDLE_MAX);
        if (host) hl = fread(host, 1, TRUST_BUNDLE_MAX, bf);
        bool over = host && hl == TRUST_BUNDLE_MAX && fgetc(bf) != EOF;
        if (ferror(bf) || over) { free(host); host = NULL; }
        fclose(bf);
    }
    if (!host || hl == 0) {
        fprintf(stderr, "[warden] inspecting mode: cannot read the trust bundle %s (or it is over 8 MB); "
                "refusing to start\n", g_trust_host_bundle);
        free(host);
        return -1;
    }
    trust_sha_hex(host, hl, g_trust_host_sha);
    char **names;
    g_trust_nnames = trust_names(p, &names);
    unsigned char *pem = NULL, *p12 = NULL;
    size_t pl = 0, ql = 0;
    int rc = wp_inspect_setup(&g_proxy, g_run_id, g_trust_host_bundle, names, g_trust_nnames, &pem, &pl,
                              &p12, &ql, &g_trust_secure_heap, &g_trust_nroots, why, sizeof why);
    for (size_t i = 0; names && i < g_trust_nnames; i++) free(names[i]);
    free(names);
    unsigned char *der = NULL;
    size_t dl = 0;
    if (rc == 0 && trust_pem_der(pem, pl, &der, &dl) < 0) {
        snprintf(why, sizeof why, "the proxy's CA certificate is not one PEM certificate");
        rc = -1;
    }
    if (rc == 0 && (ql == 0 || p12[0] != 0x30)) {
        snprintf(why, sizeof why, "the proxy's trust store is not DER");
        rc = -1;
    }
    if (rc < 0) {
        fprintf(stderr, "[warden] inspecting mode: %s; refusing to start\n", why);
        free(host); free(pem); free(p12); free(der);
        return -1;
    }
    trust_sha_hex(der, dl, g_ca_sha);
    trust_sha_hex(p12, ql, g_trust_p12_sha);
    free(der);
    /* the bundle view: the host's bundle, then the CA */
    bool nl = host[hl - 1] == '\n';
    g_trust_bundle_len = hl + (nl ? 0 : 1) + pl;
    g_trust_bundle = malloc(g_trust_bundle_len);
    if (!g_trust_bundle) { free(host); free(pem); free(p12); return -1; }
    memcpy(g_trust_bundle, host, hl);
    if (!nl) g_trust_bundle[hl] = '\n';
    memcpy(g_trust_bundle + hl + (nl ? 0 : 1), pem, pl);
    free(host);
    g_ca_pem = pem;
    g_ca_pem_len = pl;
    g_trust_p12 = p12;
    g_trust_p12_len = ql;
    /* the agent's environment names them (the agent inherits it) */
    setenv("SSL_CERT_FILE", kViewPath[VIEW_BUNDLE_RUN], 1);
    setenv("REQUESTS_CA_BUNDLE", kViewPath[VIEW_BUNDLE_RUN], 1);
    setenv("CURL_CA_BUNDLE", kViewPath[VIEW_BUNDLE_RUN], 1);
    setenv("NODE_EXTRA_CA_CERTS", kViewPath[VIEW_RUNCA], 1);
    const char *jt = getenv("JAVA_TOOL_OPTIONS");
    char *j = NULL;
    if (asprintf(&j, "%s%s-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12",
                 jt ? jt : "", jt && *jt ? " " : "", kViewPath[VIEW_P12]) > 0) {
        setenv("JAVA_TOOL_OPTIONS", j, 1);
        free(j);
    }
    fprintf(stderr, "[warden] inspecting mode: the run's CA (SHA-256 %s) may sign for %zu name%s; its key "
            "is %s; trust views serve %s and the CA\n", g_ca_sha, g_trust_nnames,
            g_trust_nnames == 1 ? "" : "s", g_trust_secure_heap ? "in the proxy's locked memory"
            : "in the proxy's memory (not locked: the memory-lock limit is too low)", g_trust_host_bundle);
    return 0;
}
