#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Build the VAREK Enterprise AMI in the AWS account your credentials point at
# (AWS CloudShell in the seller account works as is).
#
#   ./build.sh --version 1.23.0 --packs ~/varek-packs --product-id <product ID>
#   ./build.sh --version 1.23.0 --packs ~/varek-packs --test     # no license check
#
# --packs is a directory of Enterprise *.policy.txt files. They are licensed
# content and are never committed to this repository.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null) || {
    echo "build.sh: run it from a git checkout of kwdoug63/varek" >&2; exit 1; }
MARK="Licensed to VAREK Enterprise subscribers"

version="" packs="" product_id="" region="us-east-1" subnet="" test=0 dims="" issuer=""
usage() { sed -n '4,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
need() { [ -n "${2:-}" ] || { echo "build.sh: $1 needs a value" >&2; usage 2; }; }
while [ $# -gt 0 ]; do
    case "$1" in
        --version) need "$@"; version=$2; shift 2 ;;
        --packs) need "$@"; packs=$2; shift 2 ;;
        --product-id) need "$@"; product_id=$2; shift 2 ;;
        --dimensions) need "$@"; dims=$2; shift 2 ;;   # comma-separated, highest tier first
        --region) need "$@"; region=$2; shift 2 ;;
        --subnet) need "$@"; subnet=$2; shift 2 ;;
        --issuer-fingerprint) need "$@"; issuer=$2; shift 2 ;;  # testing only, see README
        --test) test=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "build.sh: unknown option $1" >&2; usage 2 ;;
    esac
done

die() { echo "build.sh: $*" >&2; exit 1; }
[ -n "$version" ] || die "--version is required (e.g. 1.23.0)"
[ -n "$packs" ] && [ -d "$packs" ] || die "--packs must be a directory of Enterprise *.policy.txt files"
packs=$(cd "$packs" && pwd)   # absolute, so the git checks below see the real path
if [ "$test" -eq 0 ]; then
    # The product ID for License Manager: a GUID per AWS docs, or the portal's prod-... ID.
    [[ "$product_id" =~ ^(prod-[a-z0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$ ]] ||
        die "--product-id is required: the product ID from the Marketplace portal (or --test)"
else
    product_id=""
fi
command -v packer >/dev/null || die "packer is not installed; see README.md, 'Install Packer'"
aws sts get-caller-identity >/dev/null 2>&1 || die "no AWS credentials (run this in AWS CloudShell, or set a profile)"
# AWS Marketplace can't take an encrypted AMI, and account-wide default EBS
# encryption overrides the template's encrypted = false.
if [ "$(aws ec2 get-ebs-encryption-by-default --region "$region" --query EbsEncryptionByDefault --output text)" = "True" ]; then
    die "EBS encryption by default is on in $region; Marketplace needs an unencrypted AMI. Turn it off for the build (EC2 console > Settings > EBS encryption), then back on."
fi

shopt -s nullglob
files=("$packs"/*.policy.txt)
[ "${#files[@]}" -gt 0 ] || die "no *.policy.txt files in $packs"
for f in "${files[@]}"; do
    head -n 20 "$f" | grep -q "$MARK" || die "$(basename "$f") is not marked '$MARK'"
    if git -C "$REPO" ls-files --error-unmatch "$f" >/dev/null 2>&1; then
        die "$(basename "$f") is tracked in git; Enterprise packs must stay out of the repo"
    fi
done

if [ -n "$(git -C "$REPO" status --porcelain -- varek/v1_4 v1_6 v1_7)" ]; then
    echo "build.sh: note: uncommitted changes are NOT in the image (it builds from HEAD)" >&2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -C "$REPO" archive --format=tar.gz -o "$work/varek-src.tar.gz" HEAD varek/v1_4 v1_6 v1_7
commit=$(git -C "$REPO" rev-parse --short HEAD)

dim_var=()
if [ -n "$dims" ]; then
    dim_var=(-var "dimensions=[\"${dims//,/\",\"}\"]")
fi

echo "Building VAREK Enterprise $version (commit $commit) in $region"
echo "  packs: ${files[*]##*/}"
echo "  product: ${product_id:-none (test image)}"
cd "$HERE"
packer init .
args=(-var "varek_version=$version" -var "source_tarball=$work/varek-src.tar.gz"
      -var "packs_dir=$packs" -var "product_id=$product_id" -var "issuer_fingerprint=$issuer"
      -var "region=$region" -var "subnet_id=$subnet" "${dim_var[@]}")
packer validate "${args[@]}" .
packer build -color=false "${args[@]}" .

ami=$(python3 -c 'import json; b=json.load(open("manifest.json"))["builds"][-1]; print(b["artifact_id"].split(":")[1])')
echo
echo "AMI ready: $ami ($region)"
echo "Next: in the AWS Marketplace Management Portal, add it as a version of the product"
echo "      (README.md, 'Hand the AMI to AWS Marketplace')."
