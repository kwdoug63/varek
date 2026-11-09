#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# collect.sh VERSION SBOM_DIR OUT_DIR — the files of VAREK's GitHub Release
# for vVERSION, gathered from what container-release.yml has already
# published and signed for that tag. Nothing is built: the charts are pulled
# from ghcr.io as pushed, the bills of materials are the release run's own,
# and each published artifact's cosign signature is verified (keyless, the
# identity container-release.yml@refs/tags/vVERSION) before it is listed.
#
# Writes to OUT_DIR:
#   varek-VERSION.tgz, varek-crds-VERSION.tgz   the Helm charts, as published
#   sbom.cdx.json, sbom-node-amd64.cdx.json,
#   sbom-node-arm64.cdx.json                    the images' bills of materials
#   varek-VERSION-artifacts.txt                 each published artifact's
#                                               reference and digest
#   SHA256SUMS                                  the files above
#
# Needs helm, cosign, docker (buildx imagetools), sha256sum; the registry
# readable (public packages need no login).
set -euo pipefail
[ $# = 3 ] || { echo "usage: collect.sh VERSION SBOM_DIR OUT_DIR" >&2; exit 2; }
VERSION="$1" SBOMS="$2" OUT="$3"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "collect.sh: not a version: $VERSION" >&2; exit 2; }
OWNER="${OWNER:-kwdoug63}" REPO="${REPO:-kwdoug63/varek}"
IMAGE="ghcr.io/$OWNER/varek" NODE="ghcr.io/$OWNER/varek-node" CHARTS="ghcr.io/$OWNER/charts"
ID="https://github.com/$REPO/.github/workflows/container-release.yml@refs/tags/v$VERSION"
ISS=https://token.actions.githubusercontent.com
mkdir -p "$OUT"
verify() { cosign verify --certificate-identity "$ID" --certificate-oidc-issuer "$ISS" "$1" > /dev/null; }
digest_of() { docker buildx imagetools inspect "$1" | awk '$1 == "Digest:" {print $2; exit}'; }

: > "$OUT/varek-$VERSION-artifacts.txt"
for ref in "$IMAGE:$VERSION" "$NODE:$VERSION"; do
    d="$(digest_of "$ref")"
    [[ "$d" == sha256:* ]] || { echo "collect.sh: no digest for $ref" >&2; exit 1; }
    verify "${ref%:*}@$d"
    echo "${ref%:*}@$d  $ref" >> "$OUT/varek-$VERSION-artifacts.txt"
done
for c in varek varek-crds; do
    helm pull "oci://$CHARTS/$c" --version "$VERSION" -d "$OUT" 2>&1 | tee "$OUT/.pull.txt"
    d="$(sed -n 's/^Digest: //p' "$OUT/.pull.txt")"
    [[ "$d" == sha256:* ]] || { echo "collect.sh: helm pull gave no digest for $c" >&2; exit 1; }
    verify "$CHARTS/$c@$d"
    [ -f "$OUT/$c-$VERSION.tgz" ] || { echo "collect.sh: no $c-$VERSION.tgz" >&2; exit 1; }
    echo "$CHARTS/$c@$d  oci://$CHARTS/$c:$VERSION" >> "$OUT/varek-$VERSION-artifacts.txt"
done
rm -f "$OUT/.pull.txt"
for f in sbom.cdx.json sbom-node-amd64.cdx.json sbom-node-arm64.cdx.json; do
    [ -s "$SBOMS/$f" ] || { echo "collect.sh: no $SBOMS/$f" >&2; exit 1; }
    cp "$SBOMS/$f" "$OUT/$f"
done
(cd "$OUT" && sha256sum -- *.tgz *.cdx.json "varek-$VERSION-artifacts.txt" > SHA256SUMS)
cat "$OUT/varek-$VERSION-artifacts.txt" "$OUT/SHA256SUMS"
