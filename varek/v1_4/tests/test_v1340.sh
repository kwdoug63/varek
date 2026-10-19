#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test_v1340.sh — VAREK v1.34 step 2: the node agent
# (docs/security/v1.34-kubernetes.md). A container runc starts under the
# Warden's filter in OCI's form, its listenerPath the node agent's socket
# (warden POLICY --node-agent SOCKET --node-streams DIR):
#   1. the node agent's options: --node-streams required, no agent, no check;
#   2. a container, its command a static probe (tests/v1340_probe.c), as user
#      65534 with no new privileges and a read-only root: a read the policy
#      allows, one it does not name and a write it does not allow, its own
#      /proc/self (in the container's /proc), a connect and a second launch,
#      each decided in the container's view; its stream (DIR/<container>...):
#      run_start names the container, its command and user; the command is
#      the first launch; the runtime's own calls before it are counted;
#   3. a second container under the same node agent, its own stream;
#   4. refused at the start, the container ended: a policy with what this
#      step does not carry (a host-name rule), a command named without an
#      absolute path, a container with new privileges allowed.
#
#   test_v1340.sh VDP_CHECK VDP_CERT_CHECK WARDEN
set -u
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
RUNC="${RUNC:-$(command -v runc || true)}"
[ -z "$RUNC" ] && [ -x /usr/libexec/crio/runc ] && RUNC=/usr/libexec/crio/runc
B="" AGENTS=""
cleanup() {
    for a in $AGENTS; do kill "$a" 2>/dev/null; done
    if [ -n "$B" ]; then for c in "$B"/state/*; do [ -e "$c" ] && "$RUNC" --root "$B/state" delete -f "${c##*/}" >/dev/null 2>&1; done; fi
    [ -n "${KEEP:-}" ] && echo "kept $B" || { [ -n "$B" ] && rm -rf "$B"; }
}
trap cleanup EXIT

echo "== 1. the node agent's options =="
if [ -z "$WARDEN" ]; then skip "the options (needs the warden binary)"; else
    check "--node-agent without --node-streams is refused" sh -c "'$WARDEN' /dev/null --node-agent /tmp/x.sock; [ \$? = 2 ]"
    check "... and with an agent to start" sh -c "'$WARDEN' /dev/null --node-agent /tmp/x.sock --node-streams /tmp -- /bin/true; [ \$? = 2 ]"
fi

case "$(uname -m)" in x86_64) ARCH=SCMP_ARCH_X86_64 ;; aarch64) ARCH=SCMP_ARCH_AARCH64 ;; *) ARCH="" ;; esac
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ -z "$RUNC" ] || [ -z "$ARCH" ] || ! command -v python3 >/dev/null ||
   ! gcc -static -O2 -o /tmp/varek_v1340_probe.$$ "$HERE/tests/v1340_probe.c" 2>/dev/null ||
   ! gcc -O2 -I"$HERE" -o /tmp/varek_v1340_ocif.$$ "$HERE/tests/v1340_oci_filter.c" -lseccomp 2>/dev/null; then
    rm -f /tmp/varek_v1340_probe.$$ /tmp/varek_v1340_ocif.$$
    skip "containers under the node agent (need root, the warden, runc, python3, a static gcc and libseccomp)"
    echo; [ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"; [ "$fail" = 0 ]; exit
fi
B="$(mktemp -d /tmp/varek_v1340.XXXXXX)"; chmod 755 "$B"
mkdir -p "$B/streams" "$B/state" "$B/f" "$B/rootfs/data" "$B/rootfs/proc" "$B/rootfs/dev" "$B/rootfs/tmp"
mv /tmp/varek_v1340_probe.$$ "$B/rootfs/probe"; mv /tmp/varek_v1340_ocif.$$ "$B/ocif"
chmod 755 "$B/rootfs/probe"
echo "allowed content" > "$B/rootfs/data/allowed"; echo "secret" > "$B/rootfs/data/denied"; chmod 644 "$B/rootfs/data/"*
"$B/ocif" 1 "$B/f" > /dev/null || { flunk "the filter's OCI form"; exit 1; }
printf 'allow path /data/allowed readonly\nallow path /proc/self/status readonly\n' > "$B/p.txt"
printf 'require warden 1.24\nallow path /data/allowed readonly\nallow host example.com:443\n' > "$B/p_names.txt"

# a bundle: NAME POLICY-SOCKET ARGV0 NNP
bundle() {
    mkdir -p "$B/b-$1" && (cd "$B/b-$1" && "$RUNC" spec >/dev/null)
    python3 - "$B/b-$1/config.json" "$B/f/oci.json" "$2" "$3" "$4" "$ARCH" "$B/rootfs" <<'PY'
import json, sys
cfg, flt, sock, argv0, nnp, arch, root = sys.argv[1:]
c = json.load(open(cfg)); f = json.load(open(flt))
f.pop("warden_badarch", None); f["architectures"] = [arch]
for s in f["syscalls"]: s.pop("nr", None)
f["listenerPath"] = sock; f["listenerMetadata"] = "varek-test/" + cfg.split("/")[-2]
c["process"].update(terminal=False, args=[argv0], env=["PATH=/"], user={"uid": 65534, "gid": 65534},
                    noNewPrivileges=nnp == "1", cwd="/")
c["root"] = {"path": root, "readonly": True}
c["linux"]["seccomp"] = f
json.dump(c, open(cfg, "w"))
PY
}
# an agent: NAME POLICY
agent() {
    mkdir -p "$B/streams-$1"
    "$WARDEN" "$2" --node-agent "$B/$1.sock" --node-streams "$B/streams-$1" > "$B/$1.log" 2>&1 &
    AGENTS="$AGENTS $!"
    for _ in $(seq 50); do [ -S "$B/$1.sock" ] && return 0; sleep 0.1; done
    return 1
}
run() { (cd "$B/b-$1" && timeout 60 "$RUNC" --root "$B/state" run "v1340-$1" > "$B/$1.out" 2>&1); echo $? > "$B/$1.rc"; sleep 0.5; }
stream() { ls "$B/streams-$1"/v1340-$2.*.jsonl 2>/dev/null | head -1; }
said() { grep -qx "$2" "$B/$1.out"; }
rec() { python3 - "$(stream "$1" "$2")" "$3" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
sys.exit(0 if eval(sys.argv[2], {"R": recs, "S": [r for r in recs if r.get("event") == "run_start"],
                                  "E": [r for r in recs if r.get("event") == "run_end"]}) else 1)
PY
}

echo "== 2. a container under the node agent =="
check "the node agent listens" agent a "$B/p.txt"
bundle one "$B/a.sock" /probe 1
run one
sed 's/^/     /' "$B/one.out"
check "the container's command ran (the first launch)" grep -q '^read_allowed:' "$B/one.out"
check "a read the policy allows" said one "read_allowed: ok allowed content"
check "a read it does not name is refused" said one "read_denied: EACCES"
check "a write it does not allow is refused" said one "write_allowed: EACCES"
check "its own /proc/self, in the container's /proc" sh -c "grep -q '^proc_self: ok Name:' '$B/one.out'"
check "a connect with no rule is refused" said one "connect: EACCES"
check "a second launch is refused (launches not decided)" said one "exec_again: EACCES"
S1="$(stream a one)"
check "its stream, named by the container" test -s "$S1"
check "run_start names the container, its command and its user" rec a one \
    'S and S[0]["node"]["container"] == "v1340-one" and S[0]["node"]["command"] == "/probe" and S[0]["node"]["uid"] == 65534 and S[0]["node"]["metadata"] == "varek-test/b-one"'
check "the command is the first launch" rec a one 'any(r.get("rule") == "bootstrap_exec_allow" and r.get("target") == "/probe" for r in R)'
check "the refused read is decided by name in the container's view" rec a one \
    'any(r.get("target") == "/data/denied" and r.get("resolved") == "/data/denied" and r.get("decision_final") == "DENY" for r in R)'
check "run_end counts the runtime's own calls before the command" rec a one 'E and E[0]["runtime_calls_before_exec"] > 0 and E[0]["exit_status"] == -1'

echo "== 3. a second container under the same node agent =="
bundle two "$B/a.sock" /probe 1
run two
check "it ran, decided the same" said two "read_denied: EACCES"
check "its own stream" sh -c "[ -s '$(stream a two)' ] && [ '$(stream a two)' != '$S1' ]"

echo "== 4. refused at the start, the container ended =="
check "a second node agent, with a host-name rule in its policy" agent n "$B/p_names.txt"
bundle names "$B/n.sock" /probe 1
run names
check "a policy with what this step does not carry: refused, the container ended" sh -c \
    "! grep -q '^read_allowed' '$B/names.out' && grep -q 'refused: host-name rules (with step 4, the pod.s network) is not carried' '$(stream n names)'"
bundle rel "$B/a.sock" probe 1
run rel
check "a command named without an absolute path: refused" sh -c \
    "! grep -q '^read_allowed' '$B/rel.out' && grep -q 'must be named by an absolute path' '$(stream a rel)'"
bundle nnp "$B/a.sock" /probe 0
run nnp
check "a container with new privileges allowed: refused" sh -c \
    "! grep -q '^read_allowed' '$B/nnp.out' && grep -q 'without no_new_privs' '$(stream a nnp)'"
check "the node agent is still listening" sh -c "kill -0 ${AGENTS%% *} 2>/dev/null || kill -0 \$(echo $AGENTS | cut -d' ' -f1)"

echo
[ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"
[ "$fail" = 0 ]
