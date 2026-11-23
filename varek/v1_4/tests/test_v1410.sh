#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1410.sh — regression test for VAREK v1.41: no cryptography of its own.
#
#   1. The crypto backend (varek_fips.c) alone: known answers (SHA-256,
#      SHA-384, RFC 6979's ECDSA P-384 signatures), the verdict stream's
#      message signed and verified, a key that is not P-384 refused; and with
#      the Defense build's switch, init refuses on a host not in FIPS mode
#      (fail closed) and succeeds, the FIPS provider active, on one that is.
#   2. No libsodium: no binary links it, no source includes it; no source
#      carries a hash of its own (SHA-256's constants appear nowhere in C).
#   3. The Defense build (make DEFENSE=1), in a copy of the tree: the egress
#      proxy links no TLS or crypto library and holds none of inspecting
#      mode's code; the Warden, warden-secrets and varek_keygen carry the FIPS
#      gate. Off FIPS mode the Warden refuses to supervise or even lint, and
#      varek_keygen refuses to make a key; in FIPS mode the Warden's run is
#      audited with --require-fips.
#   4. Inspecting mode left out (the switch alone, so this runs on any host):
#      a policy that says `proxy inspect` is refused on every path that loads
#      one, and `proxy on` is not.
#
# Usage: ./test_v1410.sh   (as root, from varek/v1_4, after `make all`)
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
fail=0
pass() { printf '  %-6s %s\n' PASS "$1"; }
flunk() { printf '  %-6s %s\n' FAIL "$1"; fail=1; }
skip() { printf '  %-6s %s\n' SKIP "$1"; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FIPS=0; [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = 1 ] && FIPS=1
echo "host: $(uname -r), kernel FIPS mode: $([ $FIPS = 1 ] && echo on || echo off), $(openssl version 2>/dev/null)"
printf 'require warden 1.26\nproxy inspect\nallow host example.com:443\nallow path /usr/lib/\n' > "$T/inspect.txt"
printf 'require warden 1.26\nproxy on\nallow host example.com:443\nallow path /usr/lib/\n' > "$T/sni.txt"

echo "== 1. the crypto backend alone =="
"$HERE/tools/varek_keygen" "$T/k" > /dev/null && pass "varek_keygen makes a P-384 key" || flunk "varek_keygen"
cc -I"$HERE" -O2 -Wall -Wextra -Werror -o "$T/st" "$HERE/tests/vfips_selftest.c" "$HERE/varek_fips.c" -lcrypto \
  && o="$("$T/st" "$T/k")" && pass "self-test: known answers, RFC 6979, round trip ($(grep -c PASS <<<"$o") checks)" \
  || { flunk "self-test"; echo "$o" | grep -v PASS; }
cc -I"$HERE" -O2 -Wall -Wextra -Werror -DVAREK_REQUIRE_FIPS -o "$T/stf" "$HERE/tests/vfips_selftest.c" "$HERE/varek_fips.c" -lcrypto \
  && o="$("$T/stf" "$T/k")" \
  && pass "Defense switch: $([ $FIPS = 1 ] && echo 'init succeeds in FIPS mode, inside the FIPS provider' || echo 'init refuses off FIPS mode (fail closed)')" \
  || { flunk "Defense switch self-test"; echo "$o" | grep -v PASS; }

echo "== 2. no libsodium, no hash of its own =="
bad=""
for b in warden warden-proxy warden-secrets tools/vdp_check tools/vdp_cert_check tools/varek_keygen; do
    [ -x "$HERE/$b" ] || { bad="$bad $b(not built)"; continue; }
    ldd "$HERE/$b" 2>/dev/null | grep -q libsodium && bad="$bad $b"
done
[ -z "$bad" ] && pass "no binary links libsodium" || flunk "linked to libsodium (or missing):$bad"
inc="$(grep -rlE '#include <sodium\.h>|\bcrypto_sign_[a-z]|\bcrypto_hash_sha|\bsodium_[a-z]' --include=*.c --include=*.h "$HERE" "$ROOT/v1_6" "$ROOT/v1_7" 2>/dev/null)"
[ -z "$inc" ] && pass "no C source uses libsodium" || flunk "libsodium in: $inc"
py="$(grep -rlE 'find_library\("sodium"\)|crypto_sign_detached' --include=*.py "$HERE/tools" 2>/dev/null)"
[ -z "$py" ] && pass "no tool reaches libsodium (ctypes)" || flunk "libsodium from Python in: $py"
own="$(grep -rlE '0x428a2f98|0x6a09e667|0xcbbb9d5d' --include=*.c --include=*.h "$HERE" "$ROOT/v1_6" "$ROOT/v1_7" 2>/dev/null)"
[ -z "$own" ] && pass "no C source carries SHA-2's constants (no hash of VAREK's own)" || flunk "a hash of its own in: $own"

echo "== 3. the Defense build =="
mkdir -p "$T/tree/varek"
cp -a "$ROOT/v1_6" "$ROOT/v1_7" "$T/tree/" && cp -a "$HERE" "$T/tree/varek/v1_4"
DEF="$T/tree/varek/v1_4"
if make -s -C "$DEF" clean > /dev/null 2>&1 && make -s -C "$DEF" DEFENSE=1 warden warden-proxy warden-secrets tools/varek_keygen \
        tools/vdp_cert_check > "$T/def.log" 2>&1; then
    grep -qiE 'warning|error' "$T/def.log" && flunk "the Defense build warns: $(head -2 "$T/def.log")" \
      || pass "make DEFENSE=1 builds, no warnings"
else
    flunk "make DEFENSE=1"; tail -5 "$T/def.log"
fi
if [ -x "$DEF/warden-proxy" ]; then
    ldd "$DEF/warden-proxy" | grep -qE 'libssl|libcrypto' && flunk "the Defense proxy links a TLS or crypto library" \
      || pass "the Defense proxy links no TLS or crypto library ($(ldd "$DEF/warden-proxy" | grep -oE 'lib[a-z0-9]+\.so' | sort -u | tr '\n' ' '))"
    sym="$(nm -D "$DEF/warden-proxy" | grep -E ' U (SSL_|EVP_|X509|BIO_|PEM_|OPENSSL_)' | head -3)"
    fn="$(nm "$DEF/warden-proxy" 2>/dev/null | grep -wE 'tls_begin|tls_step|ca_go|gate_run|mcp_verdict|pca_make_ca' | head -3)"
    [ -z "$sym$fn" ] && pass "... and holds none of inspecting mode's code (no TLS calls, no CA)" || flunk "inspect code in the Defense proxy: $sym $fn"
fi
for b in warden warden-secrets tools/varek_keygen; do
    strings "$DEF/$b" 2>/dev/null | grep -q "this Defense build runs only" && pass "$b carries the FIPS gate" || flunk "$b: no FIPS gate"
done
strings "$HERE/warden" | grep -q "this Defense build runs only" && flunk "the core Warden carries the Defense gate" \
  || pass "the core Warden does not carry it"
POL="$HERE/policies/cybersecurity.policy.txt"
if [ $FIPS = 0 ]; then
    o="$("$DEF/warden" "$POL" -- /bin/true 2>&1)"; rc=$?
    [ $rc -ne 0 ] && grep -q "refusing to start: the FIPS provider is not active" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
      && pass "off FIPS mode the Defense Warden refuses to supervise (rc $rc)" || flunk "Defense Warden off FIPS mode: $o"
    o="$("$DEF/warden" "$POL" --check-startup 2>&1)"
    grep -q "refusing to start" <<<"$o" && ! grep -q "startup checks passed" <<<"$o" \
      && pass "... or to lint a policy (nothing is hashed outside the FIPS module)" || flunk "Defense --check-startup off FIPS mode"
    "$DEF/tools/varek_keygen" "$T/dk" > /dev/null 2>&1; rc=$?
    [ $rc -ne 0 ] && [ ! -e "$T/dk" ] && pass "... and varek_keygen makes no key" || flunk "Defense varek_keygen off FIPS mode"
    skip "the Defense Warden's audited run (needs a host in FIPS mode: tests/fips_acceptance.sh)"
else
    o="$("$DEF/warden" "$POL" --check-startup 2>&1)"
    grep -q "startup checks passed" <<<"$o" && pass "in FIPS mode the Defense Warden starts" || flunk "Defense Warden in FIPS mode: $(tail -1 <<<"$o")"
    "$DEF/tools/varek_keygen" "$T/dk" > /dev/null && pass "... and varek_keygen makes its key in the FIPS module" || flunk "Defense keygen"
    mkdir -p "$T/d"; for i in 1 2 3; do echo "f$i" > "$T/d/f$i"; done
    sed "s#/tmp/varek_v1160#$T/d#g" "$HERE/tests/v1160_policy.txt" > "$T/p.txt"
    timeout 30 "$DEF/warden" "$T/p.txt" --sign-key "$T/dk" --anchor "$T/anchor" --checkpoint-every 2 \
        -- /bin/cat "$T/d/f1" "$T/d/f2" "$T/d/f3" > /dev/null 2> "$T/v"
    grep -q '"crypto_provider":"fips"' "$T/v" && pass "the run's run_start says crypto_provider fips" || flunk "crypto_provider in FIPS mode"
    o="$(python3 "$HERE/tools/varek_audit.py" --policy "$T/p.txt" --checker "$DEF/tools/vdp_cert_check" --pubkey "$T/dk.pub" \
          --anchor "$T/anchor" --require-fips "$T/v" 2>&1)"
    grep -q "integrity: signed, anchored" <<<"$o" && grep -q "varek_audit: PASS" <<<"$o" \
      && pass "audit --require-fips: PASS, signed, anchored, the chain and signatures the FIPS provider's" \
      || { flunk "audit --require-fips"; grep PROBLEM <<<"$o" | head -3; }
    o="$("$DEF/warden" "$T/inspect.txt" --check-startup 2>&1)"
    grep -q "does not include the egress proxy's TLS-inspecting mode" <<<"$o" && ! grep -q "startup checks passed" <<<"$o" \
      && pass "the Defense Warden refuses a policy that says \`proxy inspect\`" || flunk "Defense Warden, proxy inspect"
fi

echo "== 4. inspecting mode left out (the switch alone) =="
NI="$T/ni"; mkdir -p "$NI/varek"; cp -a "$ROOT/v1_6" "$ROOT/v1_7" "$NI/" && cp -a "$HERE" "$NI/varek/v1_4"
if make -s -C "$NI/varek/v1_4" clean > /dev/null 2>&1 && \
   make -s -C "$NI/varek/v1_4" warden warden-proxy CFLAGS='-O2 -Wall -Wextra -Wpedantic -Wno-unused-parameter -D_GNU_SOURCE -std=gnu11 -I../../v1_6 -I../../v1_7 -DVAREK_NO_TLS_INSPECT' \
        > "$T/ni.log" 2>&1; then
    o="$("$NI/varek/v1_4/warden" "$T/inspect.txt" --check-startup 2>&1)"
    grep -q "does not include the egress proxy's TLS-inspecting mode" <<<"$o" && ! grep -q "startup checks passed" <<<"$o" \
      && pass "a policy that says \`proxy inspect\` is refused at load" || flunk "proxy inspect: $(tail -1 <<<"$o")"
    o="$("$NI/varek/v1_4/warden" "$T/inspect.txt" -- /bin/true 2>&1)"
    grep -q "does not include the egress proxy's TLS-inspecting mode" <<<"$o" && ! grep -q "supervising pid=" <<<"$o" \
      && pass "... and a run under it never starts (no fallback to uninspected)" || flunk "proxy inspect, run"
    o="$("$NI/varek/v1_4/warden" "$T/sni.txt" --check-startup 2>&1)"
    grep -q "startup checks passed" <<<"$o" && pass "\`proxy on\` (host and port, by SNI) is accepted" || flunk "proxy on: $(tail -1 <<<"$o")"
else
    flunk "the inspect-less build"; tail -5 "$T/ni.log"
fi

echo
if [ "$fail" -eq 0 ]; then echo "test_v1410: PASS"; else echo "test_v1410: FAIL"; fi
exit "$fail"
