#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1250.sh — v1.25.0, wildcard host names: the parts built so far
# (docs/security/v1.25-wildcard-host-names.md, sections 1 and 2).
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

echo
if [ "$fail" = 0 ]; then echo "test_v1250: PASS ($skips skipped)"; else echo "test_v1250: FAIL"; fi
exit "$fail"
