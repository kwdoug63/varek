#!/bin/bash
# SPDX-License-Identifier: MIT
#
# build_sign.sh — on the Mac, as ec2-user: es_probe built, put in an app
# bundle with the provisioning profile, and signed with the Developer ID
# identity and the Endpoint Security entitlement
# (docs/security/macos-endpoint-security.md).
#
#   build_sign.sh PROFILE IDENTITY [OUT]
#
# PROFILE   the Developer ID provisioning profile for ai.soberagents.varek.warden
# IDENTITY  the signing identity's name, as keychain.sh printed it
# OUT       where the bundle goes (default ~/es_probe)
#
# A restricted entitlement is honored only from a binary in a bundle whose
# embedded profile grants it, signed by a certificate the profile names:
# the bundle's identifier, the profile's application identifier and the
# entitlements signed in must agree, and this checks that they do.
set -euo pipefail
PROFILE="${1:?usage: build_sign.sh PROFILE IDENTITY [OUT]}" ID="${2:?usage: build_sign.sh PROFILE IDENTITY [OUT]}"
OUT="${3:-$HOME/es_probe}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_ID=ai.soberagents.varek.warden
die() { printf 'build_sign.sh: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" != 0 ] || die "run as ec2-user, not root"
mkdir -p "$OUT"
PB=/usr/libexec/PlistBuddy
security cms -D -i "$PROFILE" > "$OUT/profile.plist" || die "$PROFILE is not a provisioning profile"
TEAM="$($PB -c 'Print :TeamIdentifier:0' "$OUT/profile.plist")"
APPID="$($PB -c 'Print :Entitlements:com.apple.application-identifier' "$OUT/profile.plist")"
ES="$($PB -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$OUT/profile.plist" 2>/dev/null || true)"
[ "$APPID" = "$TEAM.$BUNDLE_ID" ] || die "the profile is for $APPID, not $TEAM.$BUNDLE_ID"
[ "$ES" = true ] || die "the profile does not grant com.apple.developer.endpoint-security.client"
echo "build_sign.sh: profile for $APPID (team $TEAM), Endpoint Security granted"

APP="$OUT/VarekESProbe.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
clang -O2 -Wall -Wextra -fblocks -o "$APP/Contents/MacOS/varek-es-probe" "$HERE/es_probe.c" -lEndpointSecurity -lbsm
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleExecutable</key><string>varek-es-probe</string>
  <key>CFBundleName</key><string>VAREK ES probe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
cat > "$OUT/es.entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key><string>$TEAM.$BUNDLE_ID</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAM</string>
  <key>com.apple.developer.endpoint-security.client</key><true/>
</dict>
</plist>
EOF
codesign --force --options runtime --timestamp --entitlements "$OUT/es.entitlements" --sign "$ID" "$APP"
codesign --verify --strict --verbose=2 "$APP"
codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null || codesign -d --entitlements - "$APP"
echo "build_sign.sh: $APP/Contents/MacOS/varek-es-probe (run it as root)"
