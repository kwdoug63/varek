#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# node_check.sh — v1.34 step 6 (docs/security/v1.34-kubernetes.md): the node
# image (packaging/container/Containerfile, --target node) checked as the Helm
# chart (packaging/helm/varek) runs it, before it is published: each command
# the chart names is there and runs, the launcher is static (the runtime binds
# it into images that have no libc of its), and the Warden writes a policy's
# filter as the webhook's user (65532, no capability) as well as root.
# CI (container.yml) and the release (container-release.yml) run it.
#
#   packaging/container/node_check.sh IMAGE
set -euo pipefail
IMAGE="${1:?usage: node_check.sh IMAGE}"
RT="${RT:-docker}"
fail=0
ok() { echo "  PASS   $1"; }
no() { echo "  FAIL   $1"; fail=1; }
run() { "$RT" run --rm --network none "$@"; }

# each command the chart's DaemonSet and Deployment name (the exporter's script by python3)
for f in /opt/varek/warden /opt/varek/warden-secrets /opt/varek/varek-init /opt/varek/varek-nri /opt/varek/varek-admission \
         /opt/varek/varek-svid \
         /opt/varek/tools/vdp_cert_check /opt/varek/tools/varek_node_export.py; do
    t=-x; case "$f" in *.py) t=-r ;; esac
    if run --entrypoint /bin/sh "$IMAGE" -c "test $t $f"; then ok "$f is there"; else no "$f is missing"; fi
done
# the launcher: static (no interpreter in its program headers), and it refuses with no command
INTERP='import struct, sys
b = open(sys.argv[1], "rb").read()
assert b[:4] == b"\x7fELF" and b[4] == 2
phoff, phentsize, phnum = struct.unpack_from("<Q", b, 32)[0], *struct.unpack_from("<HH", b, 54)
sys.exit(1 if any(struct.unpack_from("<I", b, phoff + i * phentsize)[0] == 3 for i in range(phnum)) else 0)'
if run "$IMAGE" python3 -c "$INTERP" /opt/varek/varek-init; then
    ok "varek-init names no loader (static)"
else
    no "varek-init is not static"
fi
out="$(run "$IMAGE" /opt/varek/varek-init 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 2 ] && grep -q '^usage: varek-init -- COMMAND' <<<"$out"; then ok "varek-init runs (usage, exit 2)"; else no "varek-init: exit $rc: $out"; fi
# v1.36 step 11 (review): the credential helper and the SVID fetcher run, not
# only are there: each refuses a call with no arguments, exit 2, in its own words
out="$(run "$IMAGE" /opt/varek/warden-secrets 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 2 ] && grep -q '^warden-secrets: the Warden starts this program' <<<"$out"; then ok "warden-secrets runs (refused by hand, exit 2)"; else no "warden-secrets: exit $rc: $out"; fi
out="$(run "$IMAGE" /opt/varek/varek-svid 2>&1)" && rc=0 || rc=$?
if [ "$rc" = 2 ] && grep -q '^usage: varek-svid -socket ADMIN_SOCKET -pid PID -out FILE' <<<"$out"; then ok "varek-svid runs (usage, exit 2)"; else no "varek-svid: exit $rc: $out"; fi
# the plugin and the webhook: each flag the chart passes
out="$(run "$IMAGE" /opt/varek/varek-nri -h 2>&1 || true)"
for f in -warden -policies -listener -launcher -socket -sync; do
    grep -q -- "^  $f" <<<"$out" || { no "varek-nri has no $f"; out=; }
done
[ -n "$out" ] && ok "varek-nri runs and takes the chart's flags"
out="$(run "$IMAGE" /opt/varek/varek-admission -h 2>&1 || true)"
for f in -warden -tls-cert -tls-key -listen; do
    grep -q -- "^  $f" <<<"$out" || { no "varek-admission has no $f"; out=; }
done
[ -n "$out" ] && ok "varek-admission runs and takes the chart's flags"
# the Warden writes a filter, as root (the plugin) and as the webhook's user
for user in 0 65532; do
    if run --user "$user" --cap-drop ALL --entrypoint /bin/sh "$IMAGE" -c \
        "printf 'require warden 1.29\nallow path /tmp/\n' > /tmp/p.policy && /opt/varek/warden /tmp/p.policy --oci-filter 2>/dev/null" |
        python3 -c 'import json, sys; d = json.load(sys.stdin); sys.exit(0 if d["defaultAction"] == "SCMP_ACT_ERRNO" and d["syscalls"] else 1)'; then
        ok "the Warden writes a policy's filter as user $user"
    else
        no "the Warden writes no filter as user $user"
    fi
done
# the exporter's interpreter
if run "$IMAGE" python3 /opt/varek/tools/varek_node_export.py --help > /dev/null 2>&1; then ok "the exporter runs"; else no "the exporter does not run"; fi

[ "$fail" = 0 ] && echo "node_check: PASS" || echo "node_check: FAIL"
exit "$fail"
