#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1250.sh — v1.25.0, wildcard host names: the parts built so far
# (docs/security/v1.25-wildcard-host-names.md, sections 1 to 4).
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
#   4. budgets (as root): names=, rate= and the label budget hold a DNS-tunnel
#      style client to them (budget refusals are NXDOMAIN, recorded as
#      wildcard_budget, and nothing is looked up); run_start records the
#      budgets; every question is a chained dns_question record; the audit
#      accepts the run and refuses a removed question, budgets that are not
#      the policy's, and a name charged past its budget
#   4b. (as root) 40 names on one address all connect, recorded past 15 as a
#      count and hash the audit rebuilds; a forged resolution fails it; a
#      name that expires unasked is recorded ("retired") and audited so
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
accepted "a wildcard with a port"          "${R}allow host *.example.com:443 acknowledge=dns-channel\n"
accepted "a wildcard without a port"       "${R}allow host *.example.com acknowledge=dns-channel\n"
accepted "a wildcard over three labels"    "${R}allow host *.api.example.com acknowledge=dns-channel\n"
accepted "a wildcard over an A-label"      "${R}allow host *.xn--bcher-kva.example acknowledge=dns-channel\n"
accepted "a deny wildcard"                 "${R}deny host *.internal.example.com\nallow host *.example.com acknowledge=dns-channel\n"
accepted "v1.24 names still load"          "${R}allow host api.example.com:443\nallow host 10.0.0.1\n"
refused "a wildcard before 1.25"           'require warden 1.24\nallow host *.example.com acknowledge=dns-channel\n' "require warden 1.25"
refused "a wildcard over one label"        "${R}allow host *.com acknowledge=dns-channel\n"                "at least two labels"
refused "'*' inside a name"                "${R}allow host a.*.example.com\n"      "whole leftmost label"
refused "'**.'"                            "${R}allow host **.example.com\n"       "whole leftmost label"
refused "a bare '*'"                       "${R}allow host *\n"                    "whole leftmost label"
refused "'*' as part of a label"           "${R}allow host *a.example.com\n"       "whole leftmost label"
refused "uppercase"                        "${R}allow host *.Example.com acknowledge=dns-channel\n"        "lowercase"
refused "a U-label"                        "${R}allow host *.b\xc3\xbccher.example\n" "A-labels"
refused "a trailing dot"                   "${R}allow host *.example.com. acknowledge=dns-channel\n"       "trailing dot"
refused "a bad port"                       "${R}allow host *.example.com:0443 acknowledge=dns-channel\n"   "port"
refused "require 1.27"                     "require warden 1.27\n"                 "this is 1.26"
# Section 4: budgets on a wildcard allow rule
accepted "names= and rate= on a wildcard"  "${R}allow host *.example.com:443 names=64 rate=10 acknowledge=dns-channel\n"
accepted "the largest budgets"             "${R}allow host *.example.com names=100000 rate=10000 acknowledge=dns-channel\n"
refused "a budget on an exact name"        "${R}allow host api.example.com names=5\n"        "only to wildcard allow rules"
refused "a budget on a deny wildcard"      "${R}deny host *.example.com rate=5\n"            "only to wildcard allow rules"
refused "names=0"                          "${R}allow host *.example.com names=0 acknowledge=dns-channel\n"          "names must be 1 to 100000"
refused "names over 100000"                "${R}allow host *.example.com names=100001 acknowledge=dns-channel\n"     "names must be 1 to 100000"
refused "rate over 10000"                  "${R}allow host *.example.com rate=10001 acknowledge=dns-channel\n"       "rate must be 1 to 10000"
refused "a leading zero"                   "${R}allow host *.example.com names=05 acknowledge=dns-channel\n"         "names must be 1 to 100000"
refused "an empty budget"                  "${R}allow host *.example.com names= acknowledge=dns-channel\n"           "names must be 1 to 100000"
refused "a budget given twice"             "${R}allow host *.example.com names=5 names=6 acknowledge=dns-channel\n"  "given twice"
refused "an unknown option"                "${R}allow host *.example.com nams=5 acknowledge=dns-channel\n"           "on a non-path rule"
# acknowledge=dns-channel: every wildcard allow rule must carry it
refused "a wildcard allow without the acknowledgment" "${R}allow host *.example.com:443\n"      "add acknowledge=dns-channel"
refused "the acknowledgment missing on a second rule" "${R}allow host *.example.com acknowledge=dns-channel\nallow host *.example.org names=5\n" "add acknowledge=dns-channel"
accepted "the acknowledgment before the budgets"      "${R}allow host *.example.com acknowledge=dns-channel names=5 rate=2\n"
refused "another acknowledgment"           "${R}allow host *.example.com acknowledge=dns\n"          "the only acknowledgment is acknowledge=dns-channel"
refused "the acknowledgment given twice"   "${R}allow host *.example.com acknowledge=dns-channel acknowledge=dns-channel\n" "given twice"
refused "the acknowledgment on an exact name" "${R}allow host api.example.com acknowledge=dns-channel\n" "only to wildcard allow rules"
refused "the acknowledgment on a deny"     "${R}deny host *.example.com acknowledge=dns-channel\n"   "only to wildcard allow rules"
refused "the acknowledgment on a path rule" "${R}allow path /tmp/ acknowledge=dns-channel\n"         "unknown flag clause"

# Decisions: the procedure's verdict, and the checker on its certificate.
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
printf 'require warden 1.25\ndeny  host *.internal.example.com\nallow host a.example.com:80\nallow host *.example.com:443 acknowledge=dns-channel\nallow host *.example.org acknowledge=dns-channel\n' > "$OUT/w.txt"
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
         "api.salesforce.com ok" \
         "salesforce.com refused" "core.windows.net refused" "windows.net refused" "on.aws refused" \
         "kawasaki.jp refused" "amazonaws.com.cn refused" "wikipedia.org ok" "google.com ok"; do
    # v1.25 review: the last row - a wildcard over the parent of a shared
    # domain covers it (*.salesforce.com covers evil.my.salesforce.com)
    set -- $c
    got=$(printf '%s\n' "$1" | "$SDT" "$PSL" "$VL" cases)
    if [ "$got" = "$2" ]; then pass "*.$1: $2"; else flunk "*.$1: $got (want $2)"; fi
done
printf 'require warden 1.25\nallow host *.example.com:443 acknowledge=dns-channel\nallow host *.s3.amazonaws.com acknowledge=dns-channel\nallow host *.acme.my.salesforce.com acknowledge=dns-channel\ndeny host *.cloudfront.net\n' > "$OUT/s.txt"
"$VDP" "$OUT/s.txt" lint > "$OUT/lint" 2>&1
check "lint refuses a wildcard over the private section, naming the entry" \
    grep -q 's.txt:3: allow host \*.s3.amazonaws.com is refused: s3.amazonaws.com is a shared domain .*private section' "$OUT/lint"
check "lint refuses a wildcard under a VAREK-list entry, naming it" \
    grep -q 's.txt:4: allow host \*.acme.my.salesforce.com is refused: .*under my.salesforce.com.*VAREK list' "$OUT/lint"
printf 'require warden 1.25\nallow host *.salesforce.com:443 acknowledge=dns-channel\n' > "$OUT/sp.txt"
"$VDP" "$OUT/sp.txt" lint > "$OUT/lint2" 2>&1
check "lint refuses a wildcard over the parent of a shared domain, naming it" \
    grep -q 'sp.txt:2: allow host \*.salesforce.com is refused: my.salesforce.com is under salesforce.com.*would cover it' "$OUT/lint2"
if grep -q 's.txt:[25]:' "$OUT/lint"; then flunk "an ordinary wildcard and a deny wildcard pass"
else pass "an ordinary wildcard and a deny wildcard pass"; fi
if [ -n "$WARDEN" ]; then
    "$WARDEN" "$OUT/s.txt" --check-startup > "$OUT/ws" 2>&1
    check "the Warden refuses the policy at startup, naming the entry" \
        grep -q 'allow host \*.s3.amazonaws.com is refused' "$OUT/ws"
    printf 'require warden 1.25\nallow host *.example.com:443 acknowledge=dns-channel\n' > "$OUT/ok.txt"
    check "the Warden accepts an ordinary wildcard" "$WARDEN" "$OUT/ok.txt" --check-startup
    "$WARDEN" "$OUT/s.txt" --psl /nonexistent --check-startup > "$OUT/wn" 2>&1
    check "a list it cannot read stops the Warden" grep -q 'cannot read /nonexistent' "$OUT/wn"
    # v1.25 review: the lists are pinned. A list in data/ that is not the
    # release's stops the Warden; one named with --psl/--shared-domains is
    # used, and run_start says it is not pinned. A cut-off PSL is refused.
    check "the pinned hashes are the shipped lists'" sh -c "
        grep -q \"SD_PSL_SHA256 *\\\"\$(sha256sum '$PSL' | cut -c1-64)\\\"\" '$HERE/shared_domains.h' &&
        grep -q \"SD_VAREK_SHA256 *\\\"\$(sha256sum '$VL' | cut -c1-64)\\\"\" '$HERE/shared_domains.h'"
    mkdir -p "$OUT/inst/data"; cp "$WARDEN" "$OUT/inst/warden"; cp "$PSL" "$OUT/inst/data/"
    grep -v '^my.salesforce.com$' "$VL" > "$OUT/inst/data/varek_shared_domains.txt"
    "$OUT/inst/warden" "$OUT/ok.txt" --check-startup > "$OUT/wp" 2>&1
    check "a list in data/ that is not the release's stops the Warden" \
        grep -q 'varek_shared_domains.txt is not the list this release ships' "$OUT/wp"
    "$WARDEN" "$OUT/ok.txt" --shared-domains "$OUT/inst/data/varek_shared_domains.txt" --check-startup > "$OUT/wq" 2>&1
    check "a list named on the command line is used, and said to be unpinned" \
        sh -c "grep -q 'startup checks passed' '$OUT/wq' && grep -q 'not the ones this release ships' '$OUT/wq'"
    head -c 300000 "$PSL" > "$OUT/cut.dat"
    "$WARDEN" "$OUT/ok.txt" --psl "$OUT/cut.dat" --check-startup > "$OUT/wc" 2>&1
    check "a cut-off Public Suffix List is refused" grep -q 'is not a whole Public Suffix List' "$OUT/wc"
    if [ "$(id -u)" = 0 ]; then
        mkdir -p /tmp/varek_v1250 && chmod 755 /tmp/varek_v1250
        printf 'require warden 1.25\nallow host *.example.com:443 acknowledge=dns-channel\nallow path /tmp/varek_v1250/\n' > "$OUT/run.txt"
        "$WARDEN" "$OUT/run.txt" -- /bin/true > /dev/null 2> "$OUT/run.log"
        psl=$(sha256sum "$PSL" | cut -c1-64); vl=$(sha256sum "$VL" | cut -c1-64)
        check "run_start records both lists' SHA-256" \
            grep -q "\"psl_sha256\":\"$psl\",\"shared_domains_sha256\":\"$vl\"" "$OUT/run.log"
        check "and that they are the lists this release ships" grep -q '"shared_lists_pinned":true' "$OUT/run.log"
        check "run_start reports the Warden as 1.25.0 or later" grep -Eq '"event":"run_start",[^}]*"warden":"1\.(2[5-9]|[3-9][0-9])\.[0-9]+"' "$OUT/run.log"
        check "the policy grammar is reported as the Warden's (v1.25 or later)" grep -Eq 'loaded policy default v1\.(2[5-9]|[3-9][0-9]) ' "$OUT/run.log"
        # v1.25 review: the audit re-checks each wildcard against this
        # release's lists. A Warden given a list without my.salesforce.com
        # loads *.acme.my.salesforce.com; the audit says it must be refused.
        printf 'require warden 1.25\nallow host *.acme.my.salesforce.com:443 acknowledge=dns-channel\nallow path /tmp/varek_v1250/\n' > "$OUT/sf.txt"
        mkdir -p /tmp/varek_v1250 && chmod 755 /tmp/varek_v1250
        "$WARDEN" "$OUT/sf.txt" --shared-domains "$OUT/inst/data/varek_shared_domains.txt" -- /bin/true > /dev/null 2> "$OUT/sf.log"
        python3 "$HERE/tools/varek_audit.py" --policy "$OUT/sf.txt" --checker "$CERT" "$OUT/sf.log" > "$OUT/sf.out" 2>&1
        check "the audit refuses a wildcard the release's lists refuse, whatever list the Warden had" \
            sh -c "grep -q 'a wildcard the Warden must refuse' '$OUT/sf.out' && grep -q 'varek_audit: FAIL' '$OUT/sf.out'"
        check "and notes the lists were the operator's" grep -q 'note: the Warden checked wildcards against shared-domain lists named' "$OUT/sf.out"
        rm -rf /tmp/varek_v1250
    else skip "run_start (needs root)"; fi
else skip "the Warden's startup checks (no warden binary given)"; fi

echo "== 3. the stub resolver: names a wildcard allows, resolved when asked =="
if [ -z "$WARDEN" ] || [ "$(id -u)" != 0 ]; then
    skip "the stub resolver (needs root and the warden binary)"
else
    W=/tmp/varek_v1250w
    rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
    cp "$T/v1250_client.py" "$T/v1250_client.js" "$T/v1250_stall.py" "$W/"
    chmod 644 "$W"/*
    PORT=$((20000 + RANDOM % 20000))
    HP=$((40000 + RANDOM % 5000))
    # v1.24 review: a name never leads to loopback, so the names here resolve
    # to this machine's own address (private or public)
    HOSTIP=$(python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.255.255.255", 1)); print(s.getsockname()[0])')
    SFX=svc.example.com
    printf '{' > "$OUT/zone.json"
    for c in py node go java musl curl tcp txt; do printf '"%s.%s": {"ttl": 30, "a": ["%s"]},' "$c" "$SFX" "$HOSTIP"; done >> "$OUT/zone.json"
    printf '"x.example.org": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" >> "$OUT/zone.json"
    : > "$OUT/q.log"
    python3 "$T/dns_test_server.py" --port "$PORT" --zone "$OUT/zone.json" --log "$OUT/q.log" \
        --ready "$OUT/ready" > "$OUT/dns.out" 2>&1 &
    SERVERS="$!"
    python3 -m http.server "$HP" --bind 0.0.0.0 > /dev/null 2>&1 &
    SERVERS="$SERVERS $!"
    trap 'kill $SERVERS 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$OUT"; rm -rf "$W"' EXIT
    for _ in $(seq 50); do
        [ -e "$OUT/ready" ] && python3 -c "import socket; socket.create_connection(('$HOSTIP', $HP), 0.2)" 2>/dev/null && break
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
      printf 'allow host *.%s:%s acknowledge=dns-channel\n' "$SFX" "$HP"
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
        grep -q "^OK resolve $HOSTIP " "$OUT/py.out"
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
    check "a question over TCP is answered"             grep -q "^OK raw-tcp-A rcode=0 an=1 $HOSTIP " "$OUT/raw.out"
    check "a TXT question for an allowed name: an empty answer" \
        grep -q '^OK raw-udp-TXT rcode=0 an=0 ' "$OUT/raw.out"
    check "a question for a name outside every rule: NXDOMAIN" \
        grep -q '^OK raw-udp-A rcode=3 an=0 ' "$OUT/raw.out"
    check "a connect to another port-53 server is refused (dns_refused)" \
        grep -q '^ERR connect 127.0.0.1:53 ' "$OUT/raw.out"

    # v1.25 review: a TCP connect to the stub that never completes (the agent
    # sets TCP_MD5SIG, so the stub's listener drops its SYNs) must not hold up
    # the Warden, and must end as the kernel's own would.
    echo hi > "$W/f"; chmod 644 "$W/f"
    agent -- /usr/bin/python3 "$W/v1250_stall.py" "$W/f" > "$OUT/stall.out"
    sed 's/^/     /' "$OUT/stall.out"
    check "opens are answered while a stub connect hangs" \
        sh -c "[ \$(awk '\$1 == \"OPEN\" && \$2 < 0.5' '$OUT/stall.out' | wc -l) = 3 ]"
    check "the hung stub connect times out as the kernel's would, blocking again" \
        grep -q '^CONNECT ETIMEDOUT [0-9.]* blocking=1$' "$OUT/stall.out"

    if command -v curl > /dev/null; then
        agent -- /usr/bin/curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 "http://curl.$SFX:$HP/" > "$OUT/curl.out"
        check "curl: fetches from a name only the wildcard allows" grep -qx 200 "$OUT/curl.out"
    else skip "curl (not installed)"; fi

    if [ -n "$NODE" ]; then
        agent -- "$NODE" "$W/v1250_client.js" "$HP" "node.$SFX" x.example.org > "$OUT/node.out"
        sed 's/^/     /' "$OUT/node.out"
        check "node: dns.lookup resolves"            grep -q "^OK resolve $HOSTIP " "$OUT/node.out"
        check "node: and http connects"              grep -q '^OK http 200 ' "$OUT/node.out"
        check "node: dns.resolve4 (its own question) resolves through the stub" \
            grep -q "^OK resolve4 $HOSTIP " "$OUT/node.out"
        check "node: a name outside every rule fails (lookup and resolve4)" \
            sh -c "grep -q '^ERR unlisted ' '$OUT/node.out' && grep -q '^ERR resolve4-unlisted ' '$OUT/node.out'"
    else skip "node (not installed)"; fi

    GO=$(command -v go || ls /usr/local/go/bin/go 2>/dev/null)
    if [ -n "$GO" ] && (cd "$T" && CGO_ENABLED=0 GOCACHE="$OUT/gocache" "$GO" build -o "$W/v1250_client_go" \
            v1250_client.go) > /dev/null 2>&1; then
        chmod 755 "$W/v1250_client_go"
        agent -- "$W/v1250_client_go" "$HP" "go.$SFX" x.example.org > "$OUT/go.out"
        sed 's/^/     /' "$OUT/go.out"
        check "go (its own resolver, its own questions): resolves" grep -q "^OK resolve $HOSTIP " "$OUT/go.out"
        check "go: and http connects"                               grep -q '^OK http 200 ' "$OUT/go.out"
        if fast "$OUT/go.out" unlisted; then pass "go: a name outside every rule fails within 50 ms"
        else flunk "go: a name outside every rule fails within 50 ms"; fi
    else skip "go (not installed)"; fi

    JAVAC="$(dirname "$JAVA" 2>/dev/null)/javac"
    if [ -n "$JAVA" ] && [ -x "$JAVAC" ] && "$JAVAC" --release 11 -d "$W" "$T/V1250Client.java" > /dev/null 2>&1; then
        chmod -R a+rX "$W"
        agent -- "$JAVA" -Xshare:off -cp "$W" V1250Client "$HP" "java.$SFX" x.example.org > "$OUT/java.out"
        sed 's/^/     /' "$OUT/java.out"
        check "java: resolves"                   grep -q "^OK resolve $HOSTIP " "$OUT/java.out"
        check "java: and http connects"          grep -q '^OK http 200 ' "$OUT/java.out"
        check "java: a name outside every rule fails" grep -q '^ERR unlisted ' "$OUT/java.out"
    else skip "java (no JDK)"; fi

    if command -v musl-gcc > /dev/null && musl-gcc -static -O2 -o "$W/v1250_client_musl" "$T/v1250_client_musl.c" 2>/dev/null; then
        chmod 755 "$W/v1250_client_musl"
        agent -- "$W/v1250_client_musl" "$HP" "musl.$SFX" x.example.org > "$OUT/musl.out"
        sed 's/^/     /' "$OUT/musl.out"
        check "musl (sendto, unconnected): resolves through the stub" grep -q "^OK resolve $HOSTIP " "$OUT/musl.out"
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
    # A name a deny rule names under an allowed wildcard: the Warden resolves
    # it (so the deny holds on its addresses, v1.24 review), but the stub must
    # not answer it as if an allow rule named it.
    printf 'require warden 1.25\ndeny host txt.%s\nallow host *.%s:%s acknowledge=dns-channel\nallow path %s/ readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' \
        "$SFX" "$SFX" "$HP" "$W" > "$OUT/denyw.policy"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/denyw.policy" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$W/v1250_client.py" raw udp A "txt.$SFX" > "$OUT/denyw.out" 2> "$OUT/dw.log"
    check "a denied name under an allowed wildcard gets NXDOMAIN from the stub" \
        grep -q '^OK raw-udp-A rcode=3 an=0 ' "$OUT/denyw.out"

    echo "== 4. budgets: the name channel bounded =="
    # Three wildcard rules: a names budget of 5, a rate budget of 3 a minute,
    # and the defaults (256 names, 30 a minute, 63 bytes before the suffix).
    printf '{"ok.d.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" > "$OUT/zone.json"
    : > "$OUT/q.log"
    POL4="$OUT/budget.policy"
    { printf 'require warden 1.25\n'
      printf 'allow host *.t.example.com:%s names=5 rate=100 acknowledge=dns-channel\n' "$HP"
      printf 'allow host *.r.example.com:%s names=100 rate=3 acknowledge=dns-channel\n' "$HP"
      printf 'allow host *.d.example.com:%s acknowledge=dns-channel\n' "$HP"
      printf 'allow path %s readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$W/"
    } > "$POL4"
    # 63 bytes before the suffix (one label), and 64 (two labels: one label
    # may not pass 63 bytes, so glibc would not even ask)
    L63=$(printf 'a%.0s' $(seq 63)); L64="b.$(printf 'a%.0s' $(seq 62))"
    ASK=""
    for i in 0 1 2 3 4 5 6 7 8 9; do ASK="$ASK c$i.t.example.com"; done      # a tunnel: 10 new names
    ASK="$ASK c0.t.example.com"                                             # asked again: no charge
    for i in 0 1 2 3 4 5; do ASK="$ASK c$i.r.example.com"; done             # 6 in well under a minute
    ASK="$ASK $L63.d.example.com $L64.d.example.com x.$L63.d.example.com ok.d.example.com"
    env -i PATH=/usr/bin:/bin timeout 90 "$WARDEN" "$POL4" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$W/v1250_client.py" ask $ASK > "$OUT/ask.out" 2> "$OUT/b.log"
    budget() {   # budget <line> <names|rate|label>: distinct names refused (glibc asks A and AAAA)
        grep "\"event\":\"dns_question\".*\"rule\":\"wildcard_budget\",\"policy_line\":$1,\"budget\":\"$2\"" "$OUT/b.log" |
            grep -o '"name":"[^"]*"' | sort -u | wc -l | tr -d ' '
    }
    upstream() { grep -c "^1 .*\\.$1\\.example\\.com$" "$OUT/q.log"; }
    check "run_start records each wildcard rule's budgets, defaults filled in" \
        grep -q '"wildcard_budgets":\[{"policy_line":2,"names":5,"rate":100,"label":63},{"policy_line":3,"names":100,"rate":3,"label":63},{"policy_line":4,"names":256,"rate":30,"label":63}\]' "$OUT/b.log"
    if [ "$(budget 2 names)" = 5 ] && [ "$(upstream t)" = 5 ]; then
        pass "names=5: a tunnel of 10 new names gets 5 looked up, 5 refused (wildcard_budget)"
    else flunk "names=5: 5 looked up, 5 refused (got $(upstream t) and $(budget 2 names))"; fi
    if [ "$(grep -c '"name":"c0.t.example.com"' "$OUT/b.log")" -ge 3 ] && \
       ! grep -q '"name":"c0.t.example.com".*"wildcard_budget"' "$OUT/b.log"; then
        pass "a name asked again is not charged again"
    else flunk "a name asked again is not charged again"; fi
    if [ "$(budget 3 rate)" = 3 ] && [ "$(upstream r)" = 3 ]; then
        pass "rate=3: 6 new names within a minute get 3 looked up, 3 refused"
    else flunk "rate=3: 3 looked up, 3 refused (got $(upstream r) and $(budget 3 rate))"; fi
    if [ "$(budget 4 label)" = 2 ] && grep -q "^1 $L63.d.example.com$" "$OUT/q.log" && \
       grep -q '^1 ok.d.example.com$' "$OUT/q.log"; then
        pass "the default label budget: 63 bytes before the suffix pass, 64 and more are refused"
    else flunk "the default label budget (63 bytes)"; fi
    check "a refused name gets NXDOMAIN at once"  grep -q "^ERR ask c9.t.example.com gaierror " "$OUT/ask.out"
    check "a name within the budget resolves"    grep -q "^OK ask ok.d.example.com $HOSTIP " "$OUT/ask.out"
    check "every question is a chained dns_question record" \
        sh -c "[ \$(grep -c '\"event\":\"dns_question\".*\"chain\":\"' '$OUT/b.log') -ge 22 ]"
    check "the audit accepts the run, budgets and all" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL4" --checker "$CERT" "$OUT/b.log"
    tamper() { tamper_from "$OUT/b.log" "$@"; }
    tamper_from() {   # tamper_from <log> <python expression on body> <out>: edit records, recompute the chain
        python3 - "$1" "$3" "$2" <<'PY'
import hashlib, sys
src, dst, expr = sys.argv[1], sys.argv[2], sys.argv[3]
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out, state = [], {"done": False}
for line in open(src, encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = eval(expr, {"body": line[:cut], "state": state})
        if body is None:
            continue
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(dst, "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
PY
    }
    refused_by_audit() {   # refused_by_audit <forged log> <message> [policy]
        if python3 "$HERE/tools/varek_audit.py" --policy "${3:-$POL4}" --checker "$CERT" "$1" > "$1.out" 2>&1; then return 1; fi
        grep -q "$2" "$1.out" && ! grep -q Traceback "$1.out"
    }
    tamper '(None if "\"name\":\"c1.t.example.com\"" in body and "\"answer\":\"lookup\"" in body else body)' "$OUT/t1.log"
    check "the audit refuses a stream with a question removed (a lookup nobody asked for)" \
        refused_by_audit "$OUT/t1.log" "with no question sending it upstream"
    tamper 'body.replace("\"names\":5,", "\"names\":50,")' "$OUT/t2.log"
    check "the audit refuses run_start budgets that are not the policy's" \
        refused_by_audit "$OUT/t2.log" "are not the policy's"
    tamper '(body.replace("\"rule\":\"wildcard_budget\",\"policy_line\":2,\"budget\":\"names\",", "\"rule\":\"policy_match\",\"policy_line\":2,\"new\":true,", 1) if not state["done"] and "\"budget\":\"names\"" in body and not state.update(done=True) else body)' "$OUT/t3.log"
    check "the audit refuses a sixth name charged to a names=5 rule" \
        refused_by_audit "$OUT/t3.log" "charged more than its 5 names"
    # v1.25 review: more forged streams the audit must refuse
    tamper '(None if "\"name\":\"c1.t.example.com\"" in body and "dns_question" in body else body.replace("\"dynamic\":true,", "") if "\"name\":\"c1.t.example.com\"" in body else body)' "$OUT/t4.log"
    check "the audit refuses a lookup hidden by dropping its questions and \"dynamic\"" \
        refused_by_audit "$OUT/t4.log" "no host rule names it and no question asked"
    tamper '(body[:body.index("\"mono_ms\":") + 10] + "0" + body[body.index(",", body.index("\"mono_ms\":")):] if "\"name\":\"c5.t.example.com\"" in body and "\"mono_ms\":" in body else body)' "$OUT/t5.log"
    check "the audit refuses questions whose Warden time goes back (a moved rate window)" \
        refused_by_audit "$OUT/t5.log" "earlier than the one before it"
    tamper '(None if "\"event\":\"resolution\"" in body and "\"name\":\"ok.d.example.com\"" in body else body)' "$OUT/t6.log"
    check "the audit refuses a lookup whose answer was removed" \
        refused_by_audit "$OUT/t6.log" "was never answered"
    tamper 'body.replace("\"wildcard_budgets\":[", "\"wildcard_budgets\":5,\"x\":[")' "$OUT/t7.log"
    check "the audit gives a verdict, not a traceback, on a malformed field" \
        refused_by_audit "$OUT/t7.log" "are not the policy's"
    tamper_from "$OUT/e.log" '(body.replace("\"rule\":\"policy_match\"", "\"rule\":\"dns_stub\"") if "\"net.connect\"" in body else body.replace("\"host_name_rules\":true,", "\"host_name_rules\":true,\"dns_stub\":\"127.53.53.53:53\",") if "run_start" in body else body)' "$OUT/t8.log"
    check "the audit refuses a connect forged as a stub connect, with no wildcard rule" \
        refused_by_audit "$OUT/t8.log" "dns_stub" "$OUT/exact.policy"
    tamper_from "$OUT/dw.log" '(body.replace("\"rule\":\"no_rule\",\"policy_line\":-1", "\"rule\":\"policy_match\",\"policy_line\":3").replace("\"answer\":\"nxdomain\"", "\"answer\":\"noerror\",\"addresses\":[]") if "dns_question" in body and "\"name\":\"txt." in body else body)' "$OUT/t9.log"
    check "the audit refuses a denied name recorded as answered by the wildcard" \
        refused_by_audit "$OUT/t9.log" "allows it by no rule" "$OUT/denyw.policy"

    # v1.25 review: a name asked again after its TTL goes upstream again, and
    # that lookup counts against the rule's rate. Through d69e330 it was not
    # charged, so re-asking chosen names carried data out without a bound.
    printf '{' > "$OUT/zone.json"
    for i in 0 1 2 3; do printf '"n%s.rl.example.com": {"ttl": 1, "a": ["%s"]},' "$i" "$HOSTIP"; done >> "$OUT/zone.json"
    printf '"ok.d.example.com": {"ttl": 30, "a": ["%s"]}}\n' "$HOSTIP" >> "$OUT/zone.json"
    : > "$OUT/q.log"
    { printf 'require warden 1.25\nallow host *.rl.example.com:%s names=10 rate=4 acknowledge=dns-channel\n' "$HP"
      printf 'allow path %s readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$W/"
    } > "$OUT/rl.policy"
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/rl.policy" --dns-server "127.0.0.1:$PORT" \
        --dns-ttl-min 1 --dns-grace-max 1 -- /usr/bin/python3 "$W/v1250_client.py" ask \
        n0.rl.example.com n1.rl.example.com n2.rl.example.com n3.rl.example.com sleep:2.2 \
        n0.rl.example.com n1.rl.example.com n2.rl.example.com n3.rl.example.com > "$OUT/rl.out" 2> "$OUT/rl.log"
    check "names asked again after their TTL charge rate=4: 4 lookups upstream in the minute, not 8" \
        sh -c "[ \$(grep '^1 ' '$OUT/q.log' | grep -c '\.rl\.example\.com\$') = 4 ]"
    check "and the re-asks past it are refused (wildcard_budget, rate)" \
        grep -q '"rule":"wildcard_budget","policy_line":2,"budget":"rate"' "$OUT/rl.log"
    check "the audit accepts the run" \
        python3 "$HERE/tools/varek_audit.py" --policy "$OUT/rl.policy" --checker "$CERT" "$OUT/rl.log"

    echo "== 4b. many names on one address, and names that expire unasked =="
    # 40 per-tenant names served from one address (as a CDN serves them):
    # through v1.24 a connect was refused past 15 names (too_many_names).
    printf '{' > "$OUT/zone.json"
    for i in $(seq 0 39); do printf '"n%s.many.example.com": {"ttl": 300, "a": ["%s"]},' "$i" "$HOSTIP"; done >> "$OUT/zone.json"
    printf '"x.short.example.com": {"ttl": 1, "a": ["%s"]}, "y.short.example.com": {"ttl": 300, "a": ["%s"]}}\n' "$HOSTIP" "$HOSTIP" >> "$OUT/zone.json"
    POL5="$OUT/many.policy"
    { printf 'require warden 1.25\n'
      printf 'allow host *.many.example.com:%s names=100 rate=100 acknowledge=dns-channel\n' "$HP"   # 40 new names in seconds
      printf 'allow host *.short.example.com:%s acknowledge=dns-channel\n' "$HP"
      printf 'allow path %s readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$W/"
    } > "$POL5"
    NAMES=""
    for i in $(seq 0 39); do NAMES="$NAMES n$i.many.example.com"; done
    env -i PATH=/usr/bin:/bin timeout 120 "$WARDEN" "$POL5" --dns-server "127.0.0.1:$PORT" \
        -- /usr/bin/python3 "$W/v1250_client.py" fetch "$HP" $NAMES > "$OUT/many.out" 2> "$OUT/m.log"
    check "40 names on one address: every fetch succeeds" \
        sh -c "[ \$(grep -c '^OK fetch n[0-9]*.many.example.com 200 ' '$OUT/many.out') = 40 ]"
    check "past 15 names a connect records their number and hash" \
        grep -q '"candidates_n":41,"candidates_sha256":"[0-9a-f]\{64\}"' "$OUT/m.log"
    check "and the audit rebuilds them from the resolution records" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL5" --checker "$CERT" "$OUT/m.log"
    # Forged: one name's resolution moved to another address, chain recomputed.
    python3 - "$OUT/m.log" "$OUT/m_forged.log" "$HOSTIP" <<'PY'
import hashlib, sys
head = hashlib.sha256(b"VAREK-LOG-CHAIN-1").digest()
out = []
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    if line.startswith("{") and ',"chain":"' in line:
        cut = line.index(',"chain":"')
        body = line[:cut]
        if '"event":"resolution"' in body and '"name":"n7.many.example.com"' in body:
            body = body.replace('"addresses":["' + sys.argv[3] + '"]', '"addresses":["198.51.100.9"]')
        head = hashlib.sha256(head + body.encode("utf-8", "surrogateescape")).digest()
        line = body + ',"chain":"' + head.hex() + line[cut + 10 + 64:]
    out.append(line)
open(sys.argv[2], "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
PY
    if python3 "$HERE/tools/varek_audit.py" --policy "$POL5" --checker "$CERT" "$OUT/m_forged.log" > "$OUT/mf.out" 2>&1; then
        flunk "the audit refuses hashed candidates that are not the address's names"
    else check "the audit refuses hashed candidates that are not the address's names" \
        grep -q 'hashed candidates are not' "$OUT/mf.out"; fi
    # A name looked up on demand whose TTL passes unasked: its addresses go into
    # grace, recorded ("retired"), and a later connect to the same address under
    # another name is audited against that, not against the stale answer.
    env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$POL5" --dns-server "127.0.0.1:$PORT" \
        --dns-ttl-min 1 --dns-grace-max 1 -- /usr/bin/python3 "$W/v1250_client.py" fetch "$HP" \
        x.short.example.com sleep:4 y.short.example.com > "$OUT/short.out" 2> "$OUT/s.log"
    check "both fetches succeed"   sh -c "[ \$(grep -c '^OK fetch .* 200 ' '$OUT/short.out') = 2 ]"
    check "a name that expired unasked is a resolution record (\"retired\")" \
        grep -q '"name":"x.short.example.com","a":"retired","aaaa":"retired","addresses":\[\]' "$OUT/s.log"
    check "and the audit accepts the later connect" \
        python3 "$HERE/tools/varek_audit.py" --policy "$POL5" --checker "$CERT" "$OUT/s.log"
    # v1.25 review: an agent could make an honest run fail the audit. Grace
    # was recorded in whole seconds, so names whose grace ended together near
    # a connect could not be told in or out, and more than 12 such names was a
    # problem. The Warden now records each end of grace (grace_end).
    printf '{' > "$OUT/zone.json"
    for i in $(seq 0 19); do printf '"e%s.edge.example.com": {"ttl": 1, "a": ["%s"]},' "$i" "$HOSTIP"; done >> "$OUT/zone.json"
    printf '"y.edge.example.com": {"ttl": 300, "a": ["%s"]}}\n' "$HOSTIP" >> "$OUT/zone.json"
    { printf 'require warden 1.25\nallow host *.edge.example.com:%s names=100 rate=100 acknowledge=dns-channel\n' "$HP"
      printf 'allow path %s readonly\nallow path /usr/ readonly\nallow path /lib readonly\nallow path /etc/ld.so.cache readonly\n' "$W/"
    } > "$OUT/edge.policy"
    EDGE=""; for i in $(seq 0 19); do EDGE="$EDGE e$i.edge.example.com"; done
    for wait in 1.3 1.6 2.0; do
        env -i PATH=/usr/bin:/bin timeout 60 "$WARDEN" "$OUT/edge.policy" --dns-server "127.0.0.1:$PORT" \
            --dns-ttl-min 1 --dns-grace-max 1 -- /usr/bin/python3 "$W/v1250_client.py" fetch "$HP" $EDGE \
            "sleep:$wait" y.edge.example.com > /dev/null 2> "$OUT/edge.log"
        check "20 names ending their grace together $wait s before a connect: the audit accepts the run" \
            python3 "$HERE/tools/varek_audit.py" --policy "$OUT/edge.policy" --checker "$CERT" "$OUT/edge.log"
    done
    rm -rf "$W"
fi

echo
if [ "$fail" = 0 ]; then echo "test_v1250: PASS ($skips skipped)"; else echo "test_v1250: FAIL"; fi
exit "$fail"
