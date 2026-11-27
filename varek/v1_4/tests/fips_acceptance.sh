#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# fips_acceptance.sh — VAREK v1.41: the Defense build's acceptance on RHEL 9
# in FIPS mode, with its evidence kept.
#
# Run on the RHEL 9 machine in FIPS mode, as root, from a checkout:
#     cd varek/v1_4 && sudo make fips-acceptance OUT=/root/varek-fips-evidence
# It refuses to run on a host that is not in FIPS mode. It builds in a copy of
# the tree (and `make all` in this one), and changes nothing else on the host.
#
#   1. The host: the kernel in FIPS mode; fips-mode-setup and the system crypto
#      policy say FIPS; OpenSSL's fips provider active; the openssl packages'
#      versions (the module's, to name its CMVP certificate).
#   2. The Defense build (make DEFENSE=1), in a copy of the tree: no warnings;
#      each binary's SHA-256 and what it links.
#   3. tests/test_v1410.sh: the backend, no libsodium, the Defense build in FIPS
#      mode (the Defense Warden starts; its run's run_start says
#      crypto_provider fips; varek_audit --require-fips passes), and a policy
#      with `proxy inspect` refused.
#   4. tests/test_v1160.sh with the Defense binaries: the audit chain (signed,
#      anchored, every forgery caught), its hashing and signing the FIPS
#      provider's.
#   5. tests/test_v1161.sh with the Defense binaries: the preflight.
#   6. tests/test_v1281.sh with this checkout's binaries, which in FIPS mode
#      activate the FIPS provider too: the user's token verified by
#      warden-secrets through it, RS384, PS384 and ES384 among them (EdDSA
#      skipped where Ed25519 is not offered). The core binaries, as the
#      Defense build refuses the credential rules the suite also uses.
#   7. The audit's own crypto in FIPS mode (Python): hashlib refuses MD5 for
#      security; cryptography's ECDSA P-384 verifies RFC 6979's vectors; whether
#      Ed25519 is offered (if not, logs of v1.40 or earlier are checked on a
#      host not in FIPS mode; the audit says so, not that they are forged).
#   8. For information: EdDSA (JWT tokens checked by warden-secrets) in the FIPS
#      provider.
# Everything goes to OUT/varek-fips-acceptance-HOST-DATE/, with SUMMARY.txt
# (one PASS/FAIL/INFO line each, then the result), and to a .tar.gz of it.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "fips_acceptance.sh: run as root (sudo make fips-acceptance)" >&2; exit 2; }
if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" != 1 ]; then
    echo "fips_acceptance.sh: this host is not in FIPS mode (/proc/sys/crypto/fips_enabled is not 1)." >&2
    echo "  On RHEL 9: sudo fips-mode-setup --enable && sudo reboot, then run this again." >&2
    exit 2
fi
# What the build and the audit need, named now rather than as failures halfway
# through: the build packages, and python3-cryptography, which v1.41's
# varek_audit.py verifies signatures with (a fresh RHEL 9 has neither).
missing=""
for p in gcc make git tar python3 libseccomp-devel openssl-devel python3-cryptography; do
    rpm -q "$p" > /dev/null 2>&1 || missing="$missing $p"
done
if [ -n "$missing" ]; then
    echo "fips_acceptance.sh: not installed:$missing" >&2
    echo "  sudo dnf install -y$missing, and run this again." >&2
    exit 2
fi
# The test probes (tests/v1160_probe and the like) are static by design, so the
# host needs its C library's static archive; on RHEL that is glibc-static, from
# CodeReady Builder. Said now, not as a link error halfway through.
if ! printf 'int main(void){return 0;}\n' | cc -static -x c -o /dev/null - 2>/dev/null; then
    echo "fips_acceptance.sh: no static C library (the test probes are built static)." >&2
    echo "  On RHEL 9 on EC2 (RHUI): sudo dnf config-manager --set-enabled codeready-builder-for-rhel-9-rhui-rpms" >&2
    echo "  (elsewhere: sudo subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms)" >&2
    echo "  then: sudo dnf install -y glibc-static, and run this again." >&2
    exit 2
fi
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTBASE="${1:-$PWD/varek-fips-evidence}"
E="$OUTBASE/varek-fips-acceptance-$(hostname -s)-$STAMP"
mkdir -p "$E"
S="$E/SUMMARY.txt"
fail=0
line() { printf '%-5s %s\n' "$1" "$2" | tee -a "$S"; }
ok()   { line PASS "$1"; }
bad()  { line FAIL "$1"; fail=1; }
note() { line INFO "$1"; }
{
    echo "VAREK Defense build (v1.41 and later): acceptance on RHEL 9 in FIPS mode"
    echo "host $(hostname -f 2>/dev/null || hostname), $(date -u)"
    # safe.directory: this runs as root on a checkout another user owns
    echo "checkout $(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse HEAD 2>/dev/null || echo '(not a git checkout)')" \
         "$(git -c safe.directory="$ROOT" -C "$ROOT" describe --tags --always --dirty 2>/dev/null)"
    echo
} > "$S"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "== 1. the host ==" | tee -a "$S"
{ cat /etc/redhat-release /etc/os-release; uname -a; } > "$E/host.txt" 2>&1
grep -qE 'Red Hat Enterprise Linux.* 9\.' /etc/redhat-release 2>/dev/null && ok "RHEL 9: $(cat /etc/redhat-release)" \
  || note "not RHEL 9 itself: $(cat /etc/redhat-release 2>/dev/null || grep PRETTY /etc/os-release)"
ok "the kernel is in FIPS mode (/proc/sys/crypto/fips_enabled = 1)"
if command -v fips-mode-setup > /dev/null; then
    fips-mode-setup --check > "$E/fips-mode-setup.txt" 2>&1
    grep -q "FIPS mode is enabled" "$E/fips-mode-setup.txt" && ok "fips-mode-setup --check: FIPS mode is enabled" \
      || bad "fips-mode-setup --check: $(head -1 "$E/fips-mode-setup.txt")"
fi
pol="$(update-crypto-policies --show 2>/dev/null)"
case "$pol" in FIPS*) ok "system crypto policy: $pol" ;; *) bad "system crypto policy: ${pol:-unknown} (FIPS expected)" ;; esac
openssl version -a > "$E/openssl-version.txt" 2>&1
openssl list -providers > "$E/openssl-providers.txt" 2>&1
awk '/^ *fips$/{f=1} f && /status: active/{print; exit}' "$E/openssl-providers.txt" | grep -q active \
  && ok "OpenSSL's fips provider is active ($(awk '/^ *fips$/{f=1} f && /version:/{print $2; exit}' "$E/openssl-providers.txt"))" \
  || bad "OpenSSL's fips provider is not active (see openssl-providers.txt)"
rpm -q openssl openssl-libs openssl-fips-provider openssl-fips-provider-so python3-cryptography > "$E/packages.txt" 2>&1
note "module packages: $(grep -v 'not installed' "$E/packages.txt" | tr '\n' ' ')(the CMVP certificate is named by the openssl-libs / fips provider version)"

echo "== 2. the Defense build ==" | tee -a "$S"
make -s -C "$HERE" all tests/v1281_sub > "$E/build-core.txt" 2>&1 && ok "make all (this checkout)" || bad "make all: $(tail -2 "$E/build-core.txt")"
mkdir -p "$T/tree/varek"; cp -a "$ROOT/v1_6" "$ROOT/v1_7" "$T/tree/"; cp -a "$HERE" "$T/tree/varek/v1_4"
DEF="$T/tree/varek/v1_4"
make -s -C "$DEF" clean > /dev/null 2>&1
if make -C "$DEF" DEFENSE=1 all tests/v1160_probe > "$E/build-defense.txt" 2>&1; then
    grep -qiE '(^|: )(warning|error):' "$E/build-defense.txt" && bad "make DEFENSE=1 warns (build-defense.txt)" \
      || ok "make DEFENSE=1 all: built, no warnings"
else
    bad "make DEFENSE=1 all: $(tail -3 "$E/build-defense.txt")"
fi
for b in warden warden-proxy warden-secrets tools/vdp_check tools/vdp_cert_check tools/varek_keygen; do
    [ -x "$DEF/$b" ] || continue
    printf '%s  %s\n' "$(sha256sum "$DEF/$b" | cut -d' ' -f1)" "$b" >> "$E/defense-binaries.sha256"
    { echo "== $b"; ldd "$DEF/$b"; } >> "$E/defense-linkage.txt" 2>&1
done
grep -q libsodium "$E/defense-linkage.txt" && bad "a Defense binary links libsodium" || ok "no Defense binary links libsodium"
awk '/^== warden-proxy$/{f=1;next} /^== /{f=0} f' "$E/defense-linkage.txt" | grep -qE 'libssl|libcrypto' \
  && bad "the Defense egress proxy links a TLS or crypto library" || ok "the Defense egress proxy links no TLS or crypto library"

echo "== 3. test_v1410 (in FIPS mode) ==" | tee -a "$S"
"$HERE/tests/test_v1410.sh" > "$E/test_v1410.txt" 2>&1 && ok "test_v1410: PASS ($(grep -c '  PASS' "$E/test_v1410.txt") checks)" \
  || bad "test_v1410: FAIL ($(grep '  FAIL' "$E/test_v1410.txt" | head -3 | tr '\n' ';'))"
grep -q "audit --require-fips: PASS" "$E/test_v1410.txt" && ok "a Defense run audited with --require-fips: PASS (its chain and signatures the FIPS provider's)" \
  || bad "the Defense run's --require-fips audit (test_v1410.txt)"

echo "== 4. test_v1160, the audit chain, with the Defense binaries ==" | tee -a "$S"
"$DEF/tests/test_v1160.sh" "$DEF/warden" "$DEF/tools/vdp_check" "$DEF/tools/vdp_cert_check" "$DEF/tools/varek_keygen" \
    "$DEF/tests/v1160_probe" > "$E/test_v1160-defense.txt" 2>&1 \
  && ok "test_v1160 (Defense, FIPS mode): PASS ($(grep -c '  PASS' "$E/test_v1160-defense.txt") checks)" \
  || bad "test_v1160 (Defense): FAIL ($(grep '  FAIL' "$E/test_v1160-defense.txt" | head -3 | tr '\n' ';'))"
grep -q 'run_start names the crypto provider (fips)' "$E/test_v1160-defense.txt" && ok "... run_start says crypto_provider fips" \
  || bad "... run_start's crypto_provider was not fips"

echo "== 5. test_v1161, the preflight, with the Defense binaries ==" | tee -a "$S"
"$DEF/tests/test_v1161.sh" "$DEF/warden" "$DEF/tools/vdp_cert_check" > "$E/test_v1161-defense.txt" 2>&1 \
  && ok "test_v1161 (Defense): PASS" || bad "test_v1161 (Defense): FAIL ($(grep '  FAIL' "$E/test_v1161-defense.txt" | head -3 | tr '\n' ';'))"

echo "== 6. test_v1281, the user's token through the FIPS provider (this checkout's binaries) ==" | tee -a "$S"
"$HERE/tests/test_v1281.sh" "$HERE/tools/vdp_check" "$HERE/tools/vdp_cert_check" "$HERE/warden" > "$E/test_v1281.txt" 2>&1 \
  && ok "test_v1281 (FIPS mode): PASS ($(grep -c '  PASS' "$E/test_v1281.txt") checks, $(grep -c '  SKIP' "$E/test_v1281.txt") skipped)" \
  || bad "test_v1281 (FIPS mode): FAIL ($(grep '  FAIL' "$E/test_v1281.txt" | head -3 | tr '\n' ';'))"
for a in RS384:rsa1 PS384:rsa1 ES384:ec384; do
    grep -q "PASS   a ${a%%:*} token: verified with the issuer's key ${a##*:}" "$E/test_v1281.txt" \
      && ok "... a ${a%%:*} token verified in FIPS mode" || bad "... a ${a%%:*} token in FIPS mode (test_v1281.txt)"
done

echo "== 7. the audit's own crypto (Python) in FIPS mode ==" | tee -a "$S"
python3 - "$HERE/tools" > "$E/python-fips.txt" 2>&1 <<'EOF'
import hashlib, sys
sys.path.insert(0, sys.argv[1])
try:
    hashlib.md5(b"x"); print("MD5 FOR-SECURITY: ALLOWED")
except ValueError:
    print("MD5 FOR-SECURITY: REFUSED")
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import varek_ed25519 as v
pub = bytes.fromhex("04" "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
                    "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720")
sig = encode_dss_signature(0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
                           0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8)
print("P384 RFC6979:", "VERIFIES" if v.verify_p384(pub, b"sample", sig) else "FAILS")
print("ED25519 OFFERED:", "YES" if v.ed25519_available() else "NO")
EOF
grep -q "MD5 FOR-SECURITY: REFUSED" "$E/python-fips.txt" && ok "Python's hashlib is in FIPS mode (MD5 refused for security)" \
  || bad "Python's hashlib is not in FIPS mode ($(head -1 "$E/python-fips.txt"))"
grep -q "P384 RFC6979: VERIFIES" "$E/python-fips.txt" && ok "the audit's ECDSA P-384 verifies RFC 6979's vector in FIPS mode" \
  || bad "the audit's ECDSA P-384 in FIPS mode ($(grep P384 "$E/python-fips.txt" || tail -1 "$E/python-fips.txt"))"
if ! grep -q "ED25519 OFFERED:" "$E/python-fips.txt"; then
    # the check stopped before it asked (an import failed): say why, and not
    # that Ed25519 is offered
    bad "the audit's Python crypto could not be checked ($(tail -1 "$E/python-fips.txt"); python-fips.txt)"
elif grep -q "ED25519 OFFERED: NO" "$E/python-fips.txt"; then
    o="$(python3 "$HERE/tools/varek_audit.py" --policy "$HERE/tests/v140_fixture/policy.txt" --checker "$HERE/tools/vdp_cert_check" \
          --pubkey "$HERE/tests/v140_fixture/log.key.pub" "$HERE/tests/v140_fixture/verdicts.log" 2>&1)"
    echo "$o" > "$E/v140-log-in-fips-mode.txt"
    grep -q "cannot be checked here" <<<"$o" && ! grep -q "signature does not verify" <<<"$o" \
      && ok "Ed25519 not offered in FIPS mode: a v1.40 log is reported as not checkable here, not as forged" \
      || bad "a v1.40 log in FIPS mode (v140-log-in-fips-mode.txt)"
else
    note "Ed25519 is offered here even in FIPS mode: v1.40 logs can be checked on this host"
fi

echo "== 8. for information ==" | tee -a "$S"
openssl list -signature-algorithms -provider fips > "$E/fips-signature-algorithms.txt" 2>&1
grep -qi ed25519 "$E/fips-signature-algorithms.txt" \
  && note "the fips provider lists ED25519 (approved or not: see fips-signature-algorithms.txt); EdDSA JWTs for warden-secrets may verify" \
  || note "the fips provider offers no ED25519: warden-secrets refuses EdDSA-signed JWTs here (RS256 and ES256/ES384 work)"

{
    echo
    if [ "$fail" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
} | tee -a "$S"
tar -C "$OUTBASE" -czf "$E.tar.gz" "$(basename "$E")" && echo "evidence: $E.tar.gz" | tee -a "$S"
exit "$fail"
