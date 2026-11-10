#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# preflight_check.sh — Red Hat's container certification checks (preflight,
# github.com/redhat-openshift-ecosystem/openshift-preflight) on images built
# here, before they are published. Each image is pushed to a registry on this
# host (preflight reads an image from a registry, never from Docker), checked,
# and its results kept in OUT/<image>/<arch>/results.json.
#
#   packaging/container/preflight_check.sh IMAGE...      (local images, e.g. varek varek-node)
#
# Every check must pass but RunAsNonRoot: both images run as root (the Warden
# needs its capabilities; the node agent is privileged on the node,
# docs/security/node-agent-privilege.md), and their certification projects
# set host-level access to Privileged, under which Red Hat reviews that
# instead of preflight. ALLOW names the checks let fail (space-separated).
# CI (container.yml) runs it; set PREFLIGHT to the preflight binary.
set -euo pipefail
PREFLIGHT="${PREFLIGHT:-preflight}"
RT="${RT:-docker}"
OUT="${OUT:-preflight-out}"
PORT="${PORT:-5000}"
ALLOW="${ALLOW:-RunAsNonRoot}"
# registry:2, by its index digest (2026-11-01)
REGISTRY_IMAGE="${REGISTRY_IMAGE:-docker.io/library/registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373}"
[ $# -gt 0 ] || { echo "usage: preflight_check.sh IMAGE..." >&2; exit 2; }
command -v "$PREFLIGHT" > /dev/null || { echo "preflight_check: no $PREFLIGHT on the PATH" >&2; exit 2; }

reg="localhost:$PORT"
name="varek-preflight-registry-$$"
"$RT" run -d --rm --name "$name" -p "127.0.0.1:$PORT:5000" "$REGISTRY_IMAGE" > /dev/null
trap '"$RT" rm -f "$name" > /dev/null 2>&1 || true' EXIT
for _ in $(seq 30); do curl -fsS "http://$reg/v2/" > /dev/null 2>&1 && break; sleep 1; done

mkdir -p "$OUT"
fail=0
for img in "$@"; do
    base="${img%%:*}"; base="${base##*/}"
    # a release-like tag: HasUniqueTag refuses an image tagged latest alone
    ref="$reg/$base:preflight"
    "$RT" tag "$img" "$ref"
    "$RT" push -q "$ref" > /dev/null
    dir="$OUT/$base"
    mkdir -p "$dir"
    echo "== $img ($ref)"
    rc=0
    "$PREFLIGHT" check container "$ref" --insecure --artifacts "$dir" --logfile "$dir/preflight.log" \
        > "$dir/preflight.out" 2>&1 || rc=$?
    res="$(find "$dir" -name results.json | head -1)"
    if [ -z "$res" ]; then
        echo "  FAIL   preflight wrote no results (exit $rc):"
        tail -20 "$dir/preflight.out" | sed 's/^/     /'
        fail=1
        continue
    fi
    ALLOW="$ALLOW" python3 - "$res" <<'EOF' || fail=1
import json, os, sys
r = json.load(open(sys.argv[1]))["results"]
allow = set(os.environ["ALLOW"].split())
bad = 0
for c in r.get("passed") or []:
    print(f"  PASS   {c['name']}")
for c in r.get("failed") or []:
    if c["name"] in allow:
        print(f"  PASS   {c['name']}: fails, as expected (host-level access Privileged)")
    else:
        bad = 1
        print(f"  FAIL   {c['name']}: {c.get('description', '')}")
        for k in ("help", "suggestion"):
            if c.get(k):
                print(f"           {c[k]}")
for c in r.get("errors") or []:
    bad = 1
    print(f"  FAIL   {c['name']}: the check could not run ({c.get('description', '')})")
if not (r.get("passed") or r.get("failed") or r.get("errors")):
    bad = 1
    print("  FAIL   no check ran")
sys.exit(bad)
EOF
done
[ "$fail" = 0 ] && echo "preflight_check: PASS" || echo "preflight_check: FAIL"
exit "$fail"
