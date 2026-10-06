#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1250.sh — v1.25.0, wildcard host names: the parts built so far
# (docs/security/v1.25-wildcard-host-names.md, sections 1 to 3).
#
#   1. policy grammar: *.<suffix>[:port] after `require warden 1.25`, refused
#      forms, the same answer from the decision procedure and the certificate
#      checker on every case, the matching (one or more labels, never the
#      suffix itself, the port), first-match order with exact names, the
#      cross-check oracle
#   2. wildcards over shared domains refused at load: shared_domains.c against
#      an independent Python statement of the rule on every entry of the Public
#      Suffix List's private section (and a name under each), the ICANN
#      section's public suffixes and its * and ! rules, and the VAREK list; the
#      A-label (punycode) form of every Unicode entry; lint names the entry;
#      the Warden refuses such a policy at startup and, as root, records both
#      lists' SHA-256 in run_start
#   3. the stub resolver (as root): Python, curl, Node (dns.lookup and
#      dns.resolve4), Go, Java and a static musl client resolve a name only a
#      wildcard allows, through the Warden's stub, and connect, decided on the
#      name; a name outside every rule fails within 50 ms and no question for
#      it leaves the host; TCP questions; TXT gets an empty answer and nothing
#      upstream; any other port-53 connect is refused; the audit accepts the
#      run and refuses a dns_stub record forged to another address; a policy
#      with exact names only has no stub
#
# Usage: test_v1250.sh <vdp_check> <vdp_cert_check> <test_v1250_shared> [<warden>]
set -u

VDP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CERT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
SDT="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
WARDEN="${4:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$HERE/tests"
PSL="$HERE/data/public_suffix_list.dat"
VL="$HERE/data/varek_shared_domains.txt"
OUT="$(mktemp -d)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
trap 'rm -rf "$OUT"' EXIT

echo "== 1. policy grammar =="
accepted() {
    printf '%b' "$2" > "$OUT/p.txt"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1 && "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then
        pass "accepted: $1"
    else flunk "accepted: $1 ($("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null | head -1))"; fi
}
refused() {
    printf '%b' "$2" > "$OUT/p.txt"
    local e
    e="$("$VDP" "$OUT/p.txt" analyze 2>&1 >/dev/null)"
    if "$VDP" "$OUT/p.txt" analyze >/dev/null 2>&1; then flunk "refused: $1 (the procedure loaded it)"
    elif "$CERT" "$OUT/p.txt" digest >/dev/null 2>&1; then flunk "refused: $1 (the checker loaded it)"
    elif ! printf '%s' "$e" | grep -qF "$3"; then flunk "refused: $1 (message: $e)"
    else pass "refused: $1"; fi
}
R='require warden 1.25\n'
accepted "a wildcard with a port"          "${R}allow host *.example.com:443\n"
accepted "a wildcard without a port"       "${R}allow host *.example.com\n"
accepted "a wildcard over three labels"    "${R}allow host *.api.example.com\n"
accepted "a wildcard over an A-label"      "${R}allow host *.xn--bcher-kva.example\n"
accepted "a deny wildcard"                 "${R}deny host *.internal.example.com\nallow host *.example.com\n"
accepted "v1.24 names still load"          "${R}allow host api.example.com:443\nallow host 10.0.0.1\n"
refused "a wildcard before 1.25"           'require warden 1.24\nallow host *.example.com\n' "require warden 1.25"
refused "a wildcard over one label"        "${R}allow host *.com\n"                "at least two labels"
refused "'*' inside a name"                "${R}allow host a.*.example.com\n"      "whole leftmost label"
refused "'**.'"                            "${R}allow host **.example.com\n"       "whole leftmost label"
refused "a bare '*'"                       "${R}allow host *\n"                    "whole leftmost label"
refused "'*' as part of a label"           "${R}allow host *a.example.com\n"       "whole leftmost label"
refused "uppercase"                        "${R}allow host *.Example.com\n"        "lowercase"
refused "a U-label"                        "${R}allow host *.b\xc3\xbccher.example\n" "A-labels"
refused "a trailing dot"                   "${R}allow host *.example.com.\n"       "trailing dot"
refused "a bad port"                       "${R}allow host *.example.com:0443\n"   "port"
refused "require 1.26"                     "require warden 1.26\n"                 "this is 1.25"

# Decisions: the procedure's verdict, and the checker on its certificate.
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
printf 'require warden 1.25\ndeny  host *.internal.example.com\nallow host a.example.com:80\nallow host *.example.com:443\nallow host *.example.org\n' > "$OUT/w.txt"
for q in "a.example.com:443 SATISFIED" "x.y.example.com:443 SATISFIED" "example.com:443 UNKNOWN" \
         "a.example.com:80 SATISFIED" "b.example.com:80 UNKNOWN" "db.internal.example.com:443 UNSATISFIED" \
         "a.example.org:8080 SATISFIED" "example.org:8080 UNKNOWN" "aexample.com:443 UNKNOWN" \
         "a.example.com.evil.net:443 UNKNOWN"; do
    set -- $q
    got=$(printf 'host 0 %s\n' "$(hx "$1")" | "$VDP" "$OUT/w.txt" batch | sed -E 's/.*"verdict":"([A-Z]+)".*/\1/')
    if [ "$got" = "$2" ]; then pass "decision $1: $2"; else flunk "decision $1: $got (want $2)"; fi
    if [ "$2" = SATISFIED ]; then
        line=$(printf 'host 0 %s\n' "$(hx "$1")" | "$VDP" "$OUT/w.txt" batch)
        r=$(printf '%s' "$line" | sed -E 's/.*"rule":(-?[0-9]+).*/\1/')
        w=$(printf '%s' "$line" | sed -E 's/.*"w":"([^"]*)".*/\1/')
        c=$(printf 'host 0 %s %s %s\n' "$(hx "$1")" "$r" "$w" | "$CERT" "$OUT/w.txt" batch)
        check "the checker accepts its certificate ($1)" grep -q '"check":"ok"' <<<"$c"
    fi
done
check "the wildcard policy lints clean" "$VDP" "$OUT/w.txt" lint
if python3 -c 'import z3' 2>/dev/null; then
    if python3 "$HERE/tools/smt_crosscheck.py" --vdp "$VDP" --cert "$CERT" --queries 200 "$OUT/w.txt" \
            > "$OUT/cc.out" 2>&1; then pass "cross-check oracle agrees on the wildcard policy"
    else flunk "cross-check oracle agrees on the wildcard policy"; tail -5 "$OUT/cc.out"; fi
else skip "cross-check oracle (pip install -r tools/requirements-crosscheck.txt)"; fi

echo "== 2. wildcards over shared domains =="
"$SDT" "$PSL" "$VL" counts > "$OUT/counts"
check "the lists load ($(cat "$OUT/counts"))" grep -qE '^icann [0-9]{4,} private [0-9]{3,} varek [0-9]+$' "$OUT/counts"
python3 "$T/v1250_psl_oracle.py" "$PSL" "$VL" private-cases > "$OUT/cases"
"$SDT" "$PSL" "$VL" cases < "$OUT/cases" > "$OUT/c.out"
python3 "$T/v1250_psl_oracle.py" "$PSL" "$VL" cases < "$OUT/cases" > "$OUT/p.out"
n=$(wc -l < "$OUT/cases")
d=$(paste -d' ' "$OUT/c.out" "$OUT/p.out" | awk '$1 != $2' | wc -l)
if [ "$n" -gt 10000 ] && [ "$d" = 0 ]; then pass "shared_domains.c and the independent statement agree on $n suffixes"
else flunk "shared_domains.c and the independent statement agree ($d of $n differ)"; fi
python3 - "$PSL" > "$OUT/ulabels" <<'EOF'
import sys
labs = set()
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("//"):
        labs.update(l for l in line.lstrip("!").split(".") if l != "*" and not l.isascii())
print("\n".join(sorted(labs)))
EOF
"$SDT" "$PSL" "$VL" alabel < "$OUT/ulabels" > "$OUT/alab"
python3 -c 'import sys; [print("xn--" + l.strip().encode("punycode").decode()) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]' "$OUT/ulabels" > "$OUT/alab.want"
if [ -s "$OUT/alab" ] && cmp -s "$OUT/alab" "$OUT/alab.want"; then
    pass "every Unicode label in the list gets the right A-label ($(wc -l < "$OUT/alab"))"
else flunk "every Unicode label in the list gets the right A-label"; fi
for c in "com refused" "co.uk refused" "s3.amazonaws.com refused" "bucket.s3.amazonaws.com refused" \
         "cloudfront.net refused" "myorg.github.io refused" "x.compute.amazonaws.com refused" \
         "my.salesforce.com refused" "acme.my.salesforce.com refused" "amazonaws.com refused" \
         "foo.ck refused" "www.ck ok" "city.kawasaki.jp ok" "example.com ok" "example.co.uk ok" \
         "salesforce.com ok" "api.salesforce.com ok"; do
    set -- $c
    got=$(printf '%s\n' "$1" | "$SDT" "$PSL" "$VL" cases)
    if [ "$got" = "$2" ]; then pass "*.$1: $2"; else flunk "*.$1: $got (want $2)"; fi
done
printf 'require warden 1.25\nallow host *.example.com:443\nallow host *.s3.amazonaws.com\nallow host *.acme.my.salesforce.com\ndeny host *.cloudfront.net\n' > "$OUT/s.txt"
"$VDP" "$OUT/s.txt" lint > "$OUT/lint" 2>&1
check "lint refuses a wildcard over the private section, naming the entry" \
    grep -q 's.txt:3: allow host \*.s3.amazonaws.com is refused: s3.amazonaws.com is a shared domain .*private section' "$OUT/lint"
check "lint refuses a wildcard under a VAREK-list entry, naming it" \
    grep -q 's.txt:4: allow host \*.acme.my.salesforce.com is refused: .*under my.salesforce.com.*VAREK list' "$OUT/lint"
if grep -q 's.txt:[25]:' "$OUT/lint"; then flunk "an ordinary wildcard and a deny wildcard pass"
else pass "an ordinary wildcard and a deny wildcard pass"; fi
if [ -n "$WARDEN" ]; then
    "$WARDEN" "$OUT/s.txt" --check-startup > "$OUT/ws" 2>&1
    check "the Warden refuses the policy at startup, naming the entry" \
        grep -q 'allow host \*.s3.amazonaws.com is refused' "$OUT/ws"
    printf 'require warden 1.25\nallow host *.example.com:443\n' > "$OUT/ok.txt"
    check "the Warden accepts an ordinary wildcard" "$WARDEN" "$OUT/ok.txt" --check-startup
    "$WARDEN" "$OUT/s.txt" --psl /nonexistent --check-startup > "$OUT/wn" 2>&1
    check "a list it cannot read stops the Warden" grep -q 'cannot read /nonexistent' "$OUT/wn"
    if [ "$(id -u)" = 0 ]; then
        mkdir -p /tmp/varek_v1250 && chmod 755 /tmp/varek_v1250
        printf 'require warden 1.25\nallow host *.example.com:443\nallow path /tmp/varek_v1250/\n' > "$OUT/run.txt"
        "$WARDEN" "$OUT/run.txt" -- /bin/true > /dev/null 2> "$OUT/run.log"
        psl=$(sha256sum "$PSL" | cut -c1-64); vl=$(sha256sum "$VL" | cut -c1-64)
        check "run_start records both lists' SHA-256" \
            grep -q "\"psl_sha256\":\"$psl\",\"shared_domains_sha256\":\"$vl\"" "$OUT/run.log"
        rm -rf /tmp/varek_v1250
    else skip "run_start (needs root)"; fi
else skip "the Warden's startup checks (no warden binary given)"; fi

echo "== 3. the stub resolver: names a wildcard allows, resolved when asked =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the stub resolver (needs root and the warden binary)"
else
    W=/tmp/varek_v1250w
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cp "$T/v1250_client.py" "$T/v1250_client.js" "$W/"
    chmod 644 "$W"/*
    PORT=$((20000 + RANDOM % 20000))
    HP=$((40000 + RANDOM % 5000))
    SFX=svc.example.com
    printf '{' > "$OUT/zone.json"
    for c in py node go java musl curl tcp txt; do printf '"%s.%s": {"ttl": 30, "a": ["127.0.0.1"]},' "$c" "$SFX"; done >> "$OUT/zone.json"
    printf '"x.example.org": {"ttl": 30, "a": ["127.0.0.1"]}}\n' >> "$OUT/zone.json"
    : > "$OUT/q.log"
    python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
        --ready "$OUT/ready" > "$OUT/dns.out" 2>&1 &
    SERVERS="$!"
    python3 -m http.server "$HP" --bind 127.0.0.1 > /dev/null 2>&1 &
    SERVERS="$SERVERS $!"
    trap 'kill $SERVERS 2>/dev/null; rm -rf "$OUT" "$W"' EXIT
    for _ in $(seq 50); do
        [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('127.0.0.1', $HP), 0.2)" 2>/dev/null && break
        sleep 0.1
    done
    NODE=$(readlink -f "$(command -v node 2>/dev/null)" 2>/dev/null)
    JAVA=$(ls /usr/lib/jvm/java-21-openjdk-*/bin/java 2>/dev/null | head -1)
    [ -n "$JAVA" ] || JAVA=$(readlink -f "$(command -v java 2>/dev/null)" 2>/dev/null)
    PREFIXES="/usr/ /lib /etc/ssl/ /proc/ /sys/ $W/"
    [ -n "$NODE" ] && PREFIXES="$PREFIXES $(dirname "$(dirname "$NODE")")/"
    [ -n "$JAVA" ] && PREFIXES="$PREFIXES $(dirname "$(dirname "$JAVA")")/ /etc/java-21-openjdk/ /etc/java-17-openjdk/"
    POL="$OUT/stub.policy"
    { printf 'require warden 1.25\n'
      printf 'allow host *.%s:%s\n' "$SFX" "$HP"
      printf 'allow host 127.0.0.1:53\n'                    # refused anyway: not the stub
      for d in $PREFIXES; do printf 'allow path %s readonly\n' "$d"; done
      printf 'allow path /etc/ld.so.cache readonly\nallow path /tmp/hsperfdata_nobody/\n'
    } > "$POL"
    agent() { env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POL" --dns-server "127.0.0.1:$PORT" "$@" 2> "$OUT/a.log"; }
    fast() {   # fast <file> <case>: the case failed within 50 ms
        awk -v c="$2" '$1 == "ERR" && $2 == c && $NF < 50 {ok = 1} END {exit !ok}' "$1"
    }

    agent -- /usr/bin/python3 "$W/v1250_client.py" "$HP" "py.$SFX" x.example.org > "$OUT/py.out"
    sed 's/^/     /' "$OUT/py.out"
    check "run_start names the stub"                    grep -q '"dns_stub":"127.53.53.53:53"' "$OUT/a.log"
    check "python (glibc): a name only the wildcard allows resolves through the stub" \
        grep -q '^OK resolve 127.0.0.1 ' "$OUT/py.out"
    check "python: and connects"                         grep -q '^OK http 200 ' "$OUT/py.out"
    check "the connect was decided on the name" \
        grep -q "\"resolved\":\"py.$SFX:$HP\",\"decision_raw\":\"ALLOW\"" "$OUT/a.log"
    check "the name's lookup is a resolution record (dynamic)" \
        grep -q "\"event\":\"resolution\",\"run\":\"[0-9a-f]*\",\"name\":\"py.$SFX\".*\"dynamic\":true" "$OUT/a.log"
    check "the agent's questions went to the stub (dns_stub records)" \
        grep -q '"target":"127.53.53.53:53",.*"rule":"dns_stub"' "$OUT/a.log"
    if fast "$OUT/py.out" unlisted; then pass "a name outside every rule fails within 50 ms"
    else flunk "a name outside every rule fails within 50 ms"; fi
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/a.log"
    python3 - "$OUT/a.log" "$OUT/forged.log" <<'PY'
import hashlib, sys
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out, done = [], False
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        if not done and '"rule":"dns_stub"' in body:
            body = body.replace('"resolved":"127.53.53.53:53"', '"resolved":"127.0.0.1:53"')
            done = True
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
PY
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL" --checker "$CERT" "$OUT/forged.log" > "$OUT/forged.out" 2>&1; then
        flunk "the audit refuses a dns_stub record to another address"
    else check "the audit refuses a dns_stub record to another address" grep -q 'not the stub' "$OUT/forged.out"; fi

    agent -- /usr/bin/python3 "$W/v1250_client.py" raw tcp A "tcp.$SFX" > "$OUT/raw.out"
    agent -- /usr/bin/python3 "$W/v1250_client.py" raw udp TXT "txt.$SFX" >> "$OUT/raw.out"
    agent -- /usr/bin/python3 "$W/v1250_client.py" raw udp A x.example.org >> "$OUT/raw.out"
    agent -- /usr/bin/python3 "$W/v1250_client.py" connect 127.0.0.1 53 >> "$OUT/raw.out"
    sed 's/^/     /' "$OUT/raw.out"
    check "a question over TCP is answered"             grep -q '^OK raw-tcp-A rcode=0 an=1 127.0.0.1 ' "$OUT/raw.out"
    check "a TXT question for an allowed name: an empty answer" \
        grep -q '^OK raw-udp-TXT rcode=0 an=0 ' "$OUT/raw.out"
    check "a question for a name outside every rule: NXDOMAIN" \
        grep -q '^OK raw-udp-A rcode=3 an=0 ' "$OUT/raw.out"
    check "a connect to another port-53 server is refused (dns_refused)" \
        grep -q '^ERR connect 127.0.0.1:53 ' "$OUT/raw.out"

    if command -v curl > /dev/null; then
        agent -- /usr/bin/curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "http://curl.$SFX:$HP/" > "$OUT/curl.out"
        check "curl: fetches from a name only the wildcard allows" grep -qx 200 "$OUT/curl.out"
    else skip "curl (not installed)"; fi

    if [ -n "$NODE" ]; then
        agent -- "$NODE" "$W/v1250_client.js" "$HP" "node.$SFX" x.example.org > "$OUT/node.out"
        sed 's/^/     /' "$OUT/node.out"
        check "node: dns.lookup resolves"            grep -q '^OK resolve 127.0.0.1 ' "$OUT/node.out"
        check "node: and http connects"              grep -q '^OK http 200 ' "$OUT/node.out"
        check "node: dns.resolve4 (its own question) resolves through the stub" \
            grep -q '^OK resolve4 127.0.0.1 ' "$OUT/node.out"
        check "node: a name outside every rule fails (lookup and resolve4)" \
            sh -c "grep -q '^ERR unlisted ' '$OUT/node.out' && grep -q '^ERR resolve4-unlisted ' '$OUT/node.out'"
    else skip "node (not installed)"; fi

    GO=$(command -v go || ls /usr/local/go/bin/go 2>/dev/null)
    if [ -n "$GO" ] && (cd "$T" && CGO_ENABLED=0 GOCACHE="$OUT/gocache" "$GO" build -o "$W/v1250_client_go" \
            v1250_client.go) > /dev/null 2>&1; then
        chmod 755 "$W/v1250_client_go"
        agent -- "$W/v1250_client_go" "$HP" "go.$SFX" x.example.org > "$OUT/go.out"
        sed 's/^/     /' "$OUT/go.out"
        check "go (its own resolver, its own questions): resolves" grep -q '^OK resolve 127.0.0.1 ' "$OUT/go.out"
        check "go: and http connects"                               grep -q '^OK http 200 ' "$OUT/go.out"
        if fast "$OUT/go.out" unlisted; then pass "go: a name outside every rule fails within 50 ms"
        else flunk "go: a name outside every rule fails within 50 ms"; fi
    else skip "go (not installed)"; fi

    JAVAC="$(dirname "$JAVA" 2>/dev/null)/javac"
    if [ -n "$JAVA" ] && [ -x "$JAVAC" ] && "$JAVAC" --release 11 -d "$W" "$T/V1250Client.java" > /dev/null 2>&1; then
        chmod -R a+rX "$W"
        agent -- "$JAVA" -Xshare:off -cp "$W" V1250Client "$HP" "java.$SFX" x.example.org > "$OUT/java.out"
        sed 's/^/     /' "$OUT/java.out"
        check "java: resolves"                   grep -q '^OK resolve 127.0.0.1 ' "$OUT/java.out"
        check "java: and http connects"          grep -q '^OK http 200 ' "$OUT/java.out"
        check "java: a name outside every rule fails" grep -q '^ERR unlisted ' "$OUT/java.out"
    else skip "java (no JDK)"; fi

    if command -v musl-gcc > /dev/null && musl-gcc -static -O2 -o "$W/v1250_client_musl" "$T/v1250_client_musl.c" 2>/dev/null; then
        chmod 755 "$W/v1250_client_musl"
        agent -- "$W/v1250_client_musl" "$HP" "musl.$SFX" x.example.org > "$OUT/musl.out"
        sed 's/^/     /' "$OUT/musl.out"
        check "musl (sendto, unconnected): resolves through the stub" grep -q '^OK resolve 127.0.0.1 ' "$OUT/musl.out"
        check "musl: and connects"                                     grep -q '^OK http 200 ' "$OUT/musl.out"
        if fast "$OUT/musl.out" unlisted; then pass "musl: a name outside every rule fails within 50 ms"
        else flunk "musl: a name outside every rule fails within 50 ms"; fi
        check "musl's sends are dns_stub records" \
            grep -q '"action":"net.send","target":"127.53.53.53:53".*"rule":"dns_stub"' "$OUT/a.log"
    else skip "musl (musl-gcc not installed)"; fi

    sed 's/^/     upstream: /' "$OUT/q.log" | sort | uniq -c | head -20
    if grep -q 'example.org' "$OUT/q.log"; then flunk "no question for a name outside every rule left the host"
    else pass "no question for a name outside every rule left the host"; fi
    if grep -q '^16 ' "$OUT/q.log"; then flunk "no TXT question left the host"
    else pass "no TXT question left the host"; fi

    # Exact names only: no stub, as in v1.24.
    printf 'require warden 1.25\nallow host py.%s:%s\nallow path %s/ readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' \
        "$SFX" "$HP" "$W" > "$OUT/exact.policy"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/exact.policy" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$W/v1250_client.py" "$HP" "py.$SFX" x.example.org > "$OUT/exact.out" 2> "$OUT/e.log"
    check "a policy without wildcards has no stub (and still resolves its exact names)" \
        sh -c "! grep -q 'dns_stub' '$OUT/e.log' && grep -q '^OK http 200 ' '$OUT/exact.out'"
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1250: PASS ($skips skipped)"; else echo "test_v1250: FAIL"; fi
exit "$fail"
