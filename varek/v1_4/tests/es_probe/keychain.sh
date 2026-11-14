#!/bin/bash
# SPDX-License-Identifier: MIT
#
# keychain.sh — on the Mac, as ec2-user (not root): the Developer ID key and
# certificate into a keychain of their own, for codesign
# (docs/security/macos-endpoint-security.md, Prerequisites).
#
#   keychain.sh KEY CERT
#
# KEY    the private key the signing request was made with (varek-devid.key)
# CERT   the certificate Apple issued for it (.cer, DER or PEM)
#
# The key and the certificate are joined in a .p12 that exists only for the
# import and is deleted after it. The keychain and the .p12 get random
# passwords made here, which no one types or keeps: the keychain stays
# unlocked for 6 hours, then build_sign.sh is run again after this. Apple's
# Developer ID intermediates are imported with them, for the chain.
set -euo pipefail
KEY="${1:?usage: keychain.sh KEY CERT}" CERT="${2:?usage: keychain.sh KEY CERT}"
die() { printf 'keychain.sh: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || die "run as ec2-user, not root (codesign uses that user's keychains)"
[ -r "$KEY" ] && [ -r "$CERT" ] || die "cannot read $KEY or $CERT"
OSSL=/usr/bin/openssl                    # macOS's own: its .p12 is one the keychain imports
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
chmod 700 "$W"
if "$OSSL" x509 -inform DER -in "$CERT" -out "$W/cert.pem" 2>/dev/null; then :; else
    "$OSSL" x509 -in "$CERT" -out "$W/cert.pem" || die "$CERT is not a certificate"
fi
# the certificate is the key's: the same public key
[ "$("$OSSL" x509 -in "$W/cert.pem" -noout -pubkey | "$OSSL" sha256)" = \
  "$("$OSSL" pkey -in "$KEY" -pubout | "$OSSL" sha256)" ] || die "the certificate is not for this key"
"$OSSL" x509 -in "$W/cert.pem" -noout -subject
KP="$("$OSSL" rand -hex 24)" PP="$("$OSSL" rand -hex 24)"
"$OSSL" pkcs12 -export -inkey "$KEY" -in "$W/cert.pem" -out "$W/signing.p12" -passout "pass:$PP"
KC=varek-signing.keychain
security delete-keychain "$KC" 2>/dev/null || true
security create-keychain -p "$KP" "$KC"
security set-keychain-settings -lut 21600 "$KC"
security unlock-keychain -p "$KP" "$KC"
for ca in DeveloperIDG2CA.cer DeveloperIDCA.cer; do
    curl -fsSL -o "$W/$ca" "https://www.apple.com/certificateauthority/$ca"
    security import "$W/$ca" -k "$KC" >/dev/null 2>&1 || true
done
security import "$W/signing.p12" -k "$KC" -P "$PP" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KP" "$KC" > /dev/null
# the user's search list, with this keychain added
security list-keychains -d user -s "$KC" $(security list-keychains -d user | tr -d '"')
security find-identity -v -p codesigning "$KC"
echo "keychain.sh: done; give build_sign.sh the identity's name above (\"Developer ID Application: ...\")"
