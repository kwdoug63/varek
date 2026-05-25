#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1_6/integration_test.sh — exercises the patched v1.4 Warden's
# v1.6 plan-verification path end to end.
#
# Assumes the warden_v1_4.patch has been applied (otherwise the
# build will fail at the --plan reference).
#
# Run from the repo root:   ./v1_6/integration_test.sh
# Run from anywhere:        env REPO_ROOT=/path/to/varek ./v1_6/integration_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
WARDEN_DIR="${REPO_ROOT}/varek/v1_4"
V1_6_DIR="${SCRIPT_DIR}"

if [[ ! -f "${WARDEN_DIR}/warden.c" ]]; then
    echo "ERROR: ${WARDEN_DIR}/warden.c not found." >&2
    echo "Set REPO_ROOT to the directory containing varek/ and v1_6/." >&2
    exit 2
fi

if ! grep -q "VAREK v1.6 plan-graph integration" "${WARDEN_DIR}/warden.c"; then
    echo "ERROR: ${WARDEN_DIR}/warden.c has not been patched." >&2
    echo "Apply v1_6/warden_v1_4.patch from the repo root first." >&2
    exit 2
fi

echo "[integration] building patched warden..."
( cd "${WARDEN_DIR}" && make warden >/dev/null )

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

cat > "${TMP}/policy.txt" <<EOF
allow path /var/data/
allow exec /usr/bin/python3
deny  host api.example.com
EOF

cat > "${TMP}/plan_allowed.txt" <<EOF
action load file_open    /var/data/input.json
action exec process_exec /usr/bin/python3
edge load exec
EOF

cat > "${TMP}/plan_denied.txt" <<EOF
action load file_open    /var/data/input.json
action exec process_exec /usr/bin/python3
action post net_connect  api.example.com:443
edge load exec
edge exec post
EOF

fails=0

echo "[integration] case 1: denied plan must NOT fork target"
out="$("${WARDEN_DIR}/warden" "${TMP}/policy.txt" --plan "${TMP}/plan_denied.txt" -- /bin/true 2>&1 || true)"
if ! grep -q 'plan rejected (UNSATISFIED)' <<<"${out}"; then
    echo "FAIL: expected 'plan rejected (UNSATISFIED)' in output"
    echo "${out}"
    fails=$((fails + 1))
fi
if ! grep -q '"suppressed_node":"post"' <<<"${out}"; then
    echo "FAIL: expected pathology record naming 'post' as suppressed"
    echo "${out}"
    fails=$((fails + 1))
fi
if grep -q 'supervising pid=' <<<"${out}"; then
    echo "FAIL: target was forked despite plan rejection"
    echo "${out}"
    fails=$((fails + 1))
fi

echo "[integration] case 2: authorized plan emits SATISFIED record"
out="$("${WARDEN_DIR}/warden" "${TMP}/policy.txt" --plan "${TMP}/plan_allowed.txt" -- /bin/true 2>&1 || true)"
if ! grep -q '"decision":"SATISFIED"' <<<"${out}"; then
    echo "FAIL: expected SATISFIED pathology record"
    echo "${out}"
    fails=$((fails + 1))
fi
if ! grep -q 'plan authorized (2 actions)' <<<"${out}"; then
    echo "FAIL: expected 'plan authorized (2 actions)' message"
    echo "${out}"
    fails=$((fails + 1))
fi

echo "[integration] case 3: no --plan flag preserves v1.4 behavior"
out="$("${WARDEN_DIR}/warden" "${TMP}/policy.txt" -- /bin/true 2>&1 || true)"
if grep -q 'plan_verify' <<<"${out}"; then
    echo "FAIL: plan_verify record appeared without --plan flag"
    echo "${out}"
    fails=$((fails + 1))
fi

echo "[integration] case 4: parse error reported with file:line"
echo "garbage 1 2 3" > "${TMP}/bad_plan.txt"
out="$("${WARDEN_DIR}/warden" "${TMP}/policy.txt" --plan "${TMP}/bad_plan.txt" -- /bin/true 2>&1 || true)"
if ! grep -q 'plan load failed' <<<"${out}"; then
    echo "FAIL: expected 'plan load failed' on malformed plan"
    echo "${out}"
    fails=$((fails + 1))
fi

if [[ $fails -eq 0 ]]; then
    echo "[integration] all cases passed"
    exit 0
else
    echo "[integration] ${fails} failure(s)"
    exit 1
fi
