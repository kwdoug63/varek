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
#      allows, one it does not name, one it allows of a file only root may
#      read (opened as the container's user), a write it does not allow, its own
#      /proc/self (in the container's /proc), a connect and a second launch,
#      each decided in the container's view; its stream (DIR/<container>...):
#      run_start names the container, its command and user; the command is
#      the first launch; the runtime's own calls before it are counted;
#   3. a second container under the same node agent, its own stream;
#   4. refused at the start, the container ended: a policy with what this
#      step does not carry (a host-name rule), a command named without an
#      absolute path, a container with new privileges allowed, a container
#      holding capabilities (step 7), a container running as root;
#   5. the listener (review): a supervisor killed ends its container; a
#      socket in a directory others can reach is
#      refused; a state sent by a process that is not the runtime, with a
#      descriptor that is not a seccomp listener, naming a process, is
#      refused and that process is not killed.
# Step 3 (the launcher, varek_init.c; policies by name; D4):
#   6. the filter in OCI's form (warden POLICY --oci-filter) is step 1's,
#      rule for rule, with the pod's four entries; a node agent with a
#      directory of policies and the launcher; a container whose command is
#      /varek/init -- /probe launch, under a policy that decides launches: the
#      launcher applies the launch set, a program the policy allows runs, one
#      it does not and a copy written to /work (noexec) are refused, an i386
#      call kills the whole process (without the launcher, only its thread);
#      a policy that decides no launch, with the launcher; refused: no policy
#      name, a name with no file, a bad name, /varek/init not the node's
#      launcher, a writable root, a writable mount without noexec, a volume
#      mounted twice, the launcher under a node agent that has none, decided
#      launches without the launcher; the launcher with no view refuses.
# Step 4 (D5, the pod's network):
#   7. a network namespace standing in for a pod's (10.77.0.1 on its
#      loopback, a DNS server and an HTTP server in it), the container's
#      resolv.conf naming that DNS server: under a policy naming a host and a
#      wildcard, the hosts view gives the name's address (resolved through
#      the pod's DNS server, from the pod's network), a GET to it is dialed
#      from there, a connect to an address no name has is refused, the stub is
#      named by the resolv.conf view and answers a wildcard name, which is
#      then reached; a second container in the same pod gets the stub at the
#      next address; the audit accepts both streams; with the proxy on, the
#      name's synthetic address reaches the server through the proxy, and a
#      name no rule allows gets no address.
# Step 5 (D7, D8):
#   6 (more). the policies of the pod's namespace (POLICY_DIR/<namespace>/),
#      the policy copied beside the stream (read-only) and run from there; a
#      container without the plugin's SHA-256 of its policy, or with another
#      one, refused;
#   8. evidence: a node agent signing with the node's key and anchoring; two
#      containers: the audit verifies each stream with the node's public key
#      and the anchor, which holds both runs' checkpoints; the streams root's
#      (0600), the policies read-only; the node exporter
#      (tools/varek_node_export.py) gives both runs as OCSF.
# v1.35 step 4c (D11):
#   9. plans under the node agent: --oci-filter with the pod's plan
#      (--plan) or none (--no-plan, refused under `require plan`), a plan
#      with a step the node agent does not carry refused; a pod's plan
#      (varek.dev/plan) decided in the container's view and the run held to
#      it (a read no step covers refused, outside_plan), the plan copied
#      beside the stream, run_start naming it, the audit; refused: no plan
#      under `require plan`, a plan the policy does not allow, an mcp_call
#      step, another SHA-256 or none, no such plan, one policy file.
# v1.36 step 4 (docs/security/v1.36-kubernetes-parity.md, D1 and D2):
#  10. credentials under the node agent: --oci-filter against the cluster's
#      VarekCredential list (given, refused for another namespace or another
#      source, the names in its output); a container whose policy names a
#      file store in a Secret's volume (a link into ..data) under
#      --node-credentials, and one a Vault store that listens on the node's
#      loopback only (warden-secrets reaches it from the node's network, not
#      the pod's): each fetched, the proxy holding it, the container's
#      placeholder (VAREK_CRED_<NAME>, as the NRI plugin sets it) the one
#      run_start records; a plan's credential step carried; refused: a
#      credential not given to the namespace, from another source, a file
#      outside the directory, no placeholder, two, a malformed one, one
#      policy file.
# v1.36 step 5 (D3, D4):
#  11. sub-agents and confined MCP servers under the node agent: a sub-agent
#      and a confined server (mcp server NAME exec PATH), each launched by a
#      child of the container's first process: each in a group the
#      supervisor made below the container's own (as the launched process
#      reads its /proc/self/cgroup), each call attributed to it (obo), the
#      server held to its own rules, each launch settled; --oci-filter
#      carries the policy, and a plan's subagent steps and an mcp_call to a
#      stdio server (UNKNOWN, the plan refused, as on a host); refused: a
#      sub-agent launched by the container's first process itself
#      (subagent_first_process), a policy that could write the container's
#      control groups.
# v1.36 step 6 (D5):
#  12. the on-behalf-of chain under the node agent: a pod naming its user's
#      token (varek.dev/on-behalf-of), its Secret volume where the kubelet
#      keeps it (a stand-in kubelet directory, KEY -> ..data/KEY), and the
#      agent's SVID from a stand-in varek-svid (asked by the container's
#      process id, the node agent's own SPIFFE ID left out): each verified by
#      warden-secrets as on a host, run_start naming the user and the
#      agent's SPIFFE ID, the copies gone once read, the audit; --oci-filter
#      carries `require on-behalf-of`; refused: no token under `require
#      on-behalf-of`, no volume on the node, a key that leads out of it, a
#      token not root's, an expired token, an SVID SPIRE does not give, the
#      chain given to the node agent itself.
#
#   test_v1340.sh VDP_CHECK VDP_CERT_CHECK WARDEN [VAREK_INIT]
set -u
CERT="${2:-}"
[ -n "$CERT" ] && CERT="$(cd "$(dirname "$CERT")" && pwd)/$(basename "$CERT")"
WARDEN="${3:-}"
[ -n "$WARDEN" ] && WARDEN="$(cd "$(dirname "$WARDEN")" && pwd)/$(basename "$WARDEN")"
LAUNCHER="${4:-}"
[ -n "$LAUNCHER" ] && LAUNCHER="$(cd "$(dirname "$LAUNCHER")" && pwd)/$(basename "$LAUNCHER")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
fail=0 skips=0
pass()  { printf '  PASS   %s\n' "$1"; }
flunk() { printf '  FAIL   %s\n' "$1"; fail=1; }
skip()  { printf '  SKIP   %s\n' "$1"; skips=$((skips + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else flunk "$d"; fi; }
RUNC="${RUNC:-$(command -v runc || true)}"
[ -z "$RUNC" ] && [ -x /usr/libexec/crio/runc ] && RUNC=/usr/libexec/crio/runc
B="" AGENTS="" SERVERS=""
cleanup() {
    for a in $AGENTS $SERVERS; do kill "$a" 2>/dev/null; done
    [ -n "$B" ] && [ -e "$B/netns" ] && umount "$B/netns" 2>/dev/null
    if [ -n "$B" ]; then for c in "$B"/state/*; do [ -e "$c" ] && "$RUNC" --root "$B/state" delete -f "${c##*/}" >/dev/null 2>&1; done; fi
    [ -n "${KEEP:-}" ] && echo "kept $B" || { [ -n "$B" ] && rm -rf "$B"; }
}
trap cleanup EXIT

echo "== 1. the node agent's options =="
if [ -z "$WARDEN" ]; then skip "the options (needs the warden binary)"; else
    check "--node-agent without --node-streams is refused" sh -c "'$WARDEN' /dev/null --node-agent /tmp/x.sock; [ \$? = 2 ]"
    check "... and with an agent to start" sh -c "'$WARDEN' /dev/null --node-agent /tmp/x.sock --node-streams /tmp -- /bin/true; [ \$? = 2 ]"
    check "... and with --writable-exec (a pod's mounts are checked: D4)" sh -c \
        "'$WARDEN' /dev/null --node-agent /tmp/x.sock --node-streams /tmp --writable-exec; [ \$? = 2 ]"
    check "--node-launcher without --node-agent is refused" sh -c "'$WARDEN' /dev/null --node-launcher /bin/true -- /bin/true; [ \$? = 2 ]"
    check "--oci-filter with an agent to start is refused" sh -c "'$WARDEN' /dev/null --oci-filter -- /bin/true; [ \$? = 2 ]"
fi

case "$(uname -m)" in x86_64) ARCH=SCMP_ARCH_X86_64 ;; aarch64) ARCH=SCMP_ARCH_AARCH64 ;; *) ARCH="" ;; esac
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ -z "$RUNC" ] || [ -z "$ARCH" ] || ! command -v python3 >/dev/null ||
   ! gcc -static -O2 -o /tmp/varek_v1340_probe.$$ "$HERE/tests/v1340_probe.c" -lpthread 2>/dev/null ||
   ! gcc -O2 -I"$HERE" -o /tmp/varek_v1340_ocif.$$ "$HERE/tests/v1340_oci_filter.c" -lseccomp 2>/dev/null ||
   ! gcc -O2 -o /tmp/varek_v1340_rt.$$ "$HERE/tests/v1340_runtime.c" 2>/dev/null; then
    rm -f /tmp/varek_v1340_probe.$$ /tmp/varek_v1340_ocif.$$ /tmp/varek_v1340_rt.$$
    skip "containers under the node agent (need root, the warden, runc, python3, a static gcc and libseccomp)"
    echo; [ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"; [ "$fail" = 0 ]; exit
fi
B="$(mktemp -d /tmp/varek_v1340.XXXXXX)"; chmod 755 "$B"
mkdir -p "$B/streams" "$B/state" "$B/f" "$B/rootfs/data" "$B/rootfs/proc" "$B/rootfs/dev" "$B/rootfs/tmp"
mkdir -m 700 "$B/s"                          # the sockets' directory: root's alone
mv /tmp/varek_v1340_probe.$$ "$B/rootfs/probe"; mv /tmp/varek_v1340_ocif.$$ "$B/ocif"; mv /tmp/varek_v1340_rt.$$ "$B/rt"
chmod 755 "$B/rootfs/probe"
echo "allowed content" > "$B/rootfs/data/allowed"; echo "secret" > "$B/rootfs/data/denied"; chmod 644 "$B/rootfs/data/"*
echo "root's" > "$B/rootfs/data/rootonly"; chmod 600 "$B/rootfs/data/rootonly"
"$B/ocif" 1 "$B/f" > /dev/null || { flunk "the filter's OCI form"; exit 1; }
printf 'allow path /data/allowed readonly\nallow path /data/rootonly readonly\nallow path /proc/self/status readonly\n' > "$B/p.txt"
printf 'require warden 1.24\nallow path /data/allowed readonly\nallow host example.com:443\n' > "$B/p_names.txt"

# a bundle: NAME POLICY-SOCKET ARGV0 NNP [UID]
bundle() {
    mkdir -p "$B/b-$1" && (cd "$B/b-$1" && "$RUNC" spec >/dev/null)
    python3 - "$B/b-$1/config.json" "$B/f/oci.json" "$2" "$3" "$4" "$ARCH" "$B/rootfs" "${5:-65534}" "${6:-}" <<'PY'
import json, sys
cfg, flt, sock, argv0, nnp, arch, root, uid, caps = sys.argv[1:]
c = json.load(open(cfg)); f = json.load(open(flt))
f.pop("warden_badarch", None); f["architectures"] = [arch]
for s in f["syscalls"]: s.pop("nr", None)
f["listenerPath"] = sock; f["listenerMetadata"] = "varek-test/" + cfg.split("/")[-2]
c["process"].update(terminal=False, args=argv0.split(), env=["PATH=/"], user={"uid": int(uid), "gid": int(uid)},
                    noNewPrivileges=nnp == "1", cwd="/")
c["root"] = {"path": root, "readonly": True}
c["linux"]["seccomp"] = f
if caps != "caps":   # as a pod's securityContext drops them (runc's own spec keeps three)
    c["process"]["capabilities"] = {k: [] for k in ("bounding", "effective", "permitted", "inheritable", "ambient")}
json.dump(c, open(cfg, "w"))
PY
}
# an agent: NAME POLICY [OPTION...]
agent() {
    local n="$1" pol="$2"
    shift 2
    mkdir -p "$B/streams-$n"
    "$WARDEN" "$pol" --node-agent "$B/s/$n.sock" --node-streams "$B/streams-$n" "$@" > "$B/$n.log" 2>&1 &
    AGENTS="$AGENTS $!"
    for _ in $(seq 50); do [ -S "$B/s/$n.sock" ] && return 0; sleep 0.1; done
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
bundle one "$B/s/a.sock" /probe 1
run one
sed 's/^/     /' "$B/one.out"
check "the container's command ran (the first launch)" grep -q '^read_allowed:' "$B/one.out"
check "a read the policy allows" said one "read_allowed: ok allowed content"
check "a read it does not name is refused" said one "read_denied: EACCES"
check "a write it does not allow is refused" said one "write_allowed: EACCES"
check "a file it allows that only root may read: refused (opened as the container's user)" said one "read_rootonly: EACCES"
check "its own /proc/self, in the container's /proc" sh -c "grep -q '^proc_self: ok Name:' '$B/one.out'"
check "a connect with no rule is refused" said one "connect: EACCES"
check "a second launch is refused (launches not decided)" said one "exec_again: EACCES"
S1="$(stream a one)"
check "its stream, named by the container" test -s "$S1"
check "run_start names the container, its command, its user, and that files are opened as it" rec a one \
    'S and S[0]["node"]["container"] == "v1340-one" and S[0]["node"]["command"] == "/probe" and S[0]["node"]["uid"] == 65534 and S[0]["node"]["metadata"] == "varek-test/b-one" and S[0]["node"]["opens_as_agent"] is True'
check "the command is the first launch" rec a one 'any(r.get("rule") == "bootstrap_exec_allow" and r.get("target") == "/probe" for r in R)'
check "the refused read is decided by name in the container's view" rec a one \
    'any(r.get("target") == "/data/denied" and r.get("resolved") == "/data/denied" and r.get("decision_final") == "DENY" for r in R)'
check "run_end counts the runtime's own calls before the command" rec a one 'E and E[0]["runtime_calls_before_exec"] > 0 and E[0]["exit_status"] == -1'

echo "== 3. a second container under the same node agent =="
bundle two "$B/s/a.sock" /probe 1
run two
check "it ran, decided the same" said two "read_denied: EACCES"
check "its own stream" sh -c "[ -s '$(stream a two)' ] && [ '$(stream a two)' != '$S1' ]"

echo "== 4. refused at the start, the container ended =="
check "a second node agent, with a host-name rule in its policy" agent n "$B/p_names.txt"
bundle names "$B/s/n.sock" /probe 1
run names
check "a policy naming hosts, in a container whose resolv.conf names no nameserver: refused, the container ended" sh -c \
    "! grep -q '^read_allowed' '$B/names.out' && grep -q 'names no IPv4 nameserver' '$(stream n names)'"
bundle rel "$B/s/a.sock" probe 1
run rel
check "a command named without an absolute path: refused" sh -c \
    "! grep -q '^read_allowed' '$B/rel.out' && grep -q 'must be named by an absolute path' '$(stream a rel)'"
bundle nnp "$B/s/a.sock" /probe 0
run nnp
check "a container with new privileges allowed: refused" sh -c \
    "! grep -q '^read_allowed' '$B/nnp.out' && grep -q 'without no_new_privs' '$(stream a nnp)'"
# step 7 (found by the sweep): capabilities, which runc's own spec gives a
# user other than root (a pod's are dropped, capabilities: drop: [ALL])
bundle caps "$B/s/a.sock" /probe 1 65534 caps
run caps
check "a container holding capabilities: refused, naming them" sh -c \
    "! grep -q '^read_allowed' '$B/caps.out' && grep -q 'the container holds capabilities (effective' '$(stream a caps)'"
bundle root "$B/s/a.sock" /probe 1 0
run root
check "a container running as root: refused" sh -c \
    "! grep -q '^read_allowed' '$B/root.out' && grep -q 'runs as root' '$(stream a root)'"

echo "== 5. the listener =="
bundle wait "$B/s/a.sock" "/probe wait" 1
( run wait ) &
for _ in $(seq 100); do grep -q '^waiting' "$B/wait.out" 2>/dev/null && break; sleep 0.1; done
SUP="$(stream a wait | sed 's/.*\.\([0-9]*\)\.jsonl$/\1/')"
[ -n "$SUP" ] && kill -9 "$SUP"
for _ in $(seq 100); do [ -s "$B/wait.rc" ] && break; sleep 0.1; done
check "a supervisor killed: its container ended (the listener holds the container)" sh -c \
    "grep -q '^waiting' '$B/wait.out' && [ -s '$B/wait.rc' ] && grep -q 'supervisor $SUP ended (signal 9): its container ended' '$B/a.log'"
mkdir -m 755 "$B/open"
"$WARDEN" "$B/p.txt" --node-agent "$B/open/x.sock" --node-streams "$B/streams" > "$B/open.log" 2>&1; orc=$?
check "a socket in a directory others can reach: refused at the start" sh -c \
    "[ $orc != 0 ] && grep -q 'must be root.s, with no access for others' '$B/open.log' && [ ! -S '$B/open/x.sock' ]"
sleep 300 & VICTIM=$!
python3 - "$B/s/a.sock" "$VICTIM" > "$B/forge.out" 2>&1 <<'PY'
import json, os, socket, sys
r, w = os.pipe()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
st = {"ociVersion": "1.2.1", "fds": ["seccompFd"], "pid": int(sys.argv[2]), "metadata": "",
      "state": {"ociVersion": "1.2.1", "id": "forged", "status": "creating", "pid": int(sys.argv[2]), "bundle": "/nonexistent"}}
socket.send_fds(s, [json.dumps(st).encode()], [r])
s.close()
PY
# (the node agent's line, waited for: a loaded host takes more than a second)
for _ in $(seq 100); do grep -q 'a connection refused: the descriptor' "$B/a.log" && break; sleep 0.1; done
check "a state from a process that is not the runtime: refused" grep -q 'a connection refused: the descriptor sent is not a seccomp listener' "$B/a.log"
check "... and the process it names is not killed" kill -0 "$VICTIM"
# the peer read as the connection is taken: under containerd runc create
# sends the state and ends, its shim reaps it, and its child is the shim's
# (kind, in CI); tests/v1340_runtime.c stands in for both, the node agent
# held on another connection until the runtime has ended. Ended but not yet
# reaped (a zombie, its parent read): taken, its supervisor going on to the
# bundle the stand-in lacks, and said in the node agent's log. Reaped
# before it could be read (nothing then ties it to the process it names,
# review): refused
"$B/rt" "$B/s/a.sock" gone zombie > "$B/rt.out" 2>&1; rrc=$?
for _ in $(seq 100); do cat "$B"/streams-a/gone.*.jsonl 2>/dev/null | grep -q 'container gone refused' && break; sleep 0.1; done
check "a runtime that ended once it sent the state, not yet reaped: its child taken" sh -c \
    "[ $rrc = 0 ] && cat '$B'/streams-a/gone.*.jsonl | grep -q 'container gone refused: cannot read the bundle'"
check "... and the node agent's log says it was taken by the runtime's parent" \
    grep -q "the runtime (pid [0-9]*) ended before it could be read; its container's process $(head -1 "$B/rt.out" 2>/dev/null) taken by the runtime's parent" "$B/a.log"
"$B/rt" "$B/s/a.sock" reaped reaped > "$B/rt2.out" 2>&1; rrc2=$?
for _ in $(seq 100); do grep -q 'was reaped before it could be read' "$B/a.log" && break; sleep 0.1; done
check "a runtime reaped before it could be read: refused, and its child not taken" sh -c \
    "[ $rrc2 = 0 ] && grep -q \"ended and was reaped before it could be read: nothing ties it to the process the state names ($(head -1 "$B/rt2.out" 2>/dev/null))\" '$B/a.log' && ! ls '$B'/streams-a/reaped.* > /dev/null 2>&1"
# ended, its parent not where the runtime runs (another mount namespace):
# what another root process's zombie would show; refused
unshare -m "$B/rt" "$B/s/a.sock" elsewhere zombie > "$B/rt3.out" 2>&1; rrc3=$?
for _ in $(seq 100); do grep -q "the runtime's process the peer leaves" "$B/a.log" && break; sleep 0.1; done
check "a runtime that ended, its parent in another mount namespace: refused" sh -c \
    "[ $rrc3 = 0 ] && grep -q \"the runtime's process the peer leaves (it ended before it could be read) (pid [0-9]*, rt) is not in the node's mount namespace\" '$B/a.log' && ! ls '$B'/streams-a/elsewhere.* > /dev/null 2>&1"
# a peer sending a byte a second: let go at 5 s for the whole state (review:
# 5 s a read let it hold the listener), and the next connection served
python3 - "$B/s/a.sock" > "$B/slow.out" 2>&1 <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
t0 = time.monotonic()
try:
    for _ in range(12):
        s.send(b"{")
        time.sleep(1)
except OSError:
    pass
print("held %.1f" % (time.monotonic() - t0))
PY
check "a peer sending a byte a second: let go within 5 s of the whole state" sh -c \
    "awk '/^held/ { exit !(\$2 < 8) }' '$B/slow.out'"
# a peer in another mount namespace, from its start
python3 - "$B/s/a.sock" "$VICTIM" > "$B/peer.out" 2>&1 <<'PY'
import ctypes, json, os, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(0x00020000) != 0:    # CLONE_NEWNS
    sys.exit("unshare: " + os.strerror(ctypes.get_errno()))
r, w = os.pipe()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
st = {"ociVersion": "1.2.1", "fds": ["seccompFd"], "pid": int(sys.argv[2]), "metadata": "",
      "state": {"ociVersion": "1.2.1", "id": "peer", "status": "creating", "pid": int(sys.argv[2]), "bundle": "/nonexistent"}}
socket.send_fds(s, [json.dumps(st).encode()], [r])
s.shutdown(socket.SHUT_WR)    # the state whole, as the runtime's (it reads to the end)
s.settimeout(10)
try:
    s.recv(1)    # alive until the node agent has read the peer and closed
except OSError:
    pass
PY
for _ in $(seq 100); do grep -q "is not in the node's mount namespace nor the node agent's" "$B/a.log" && break; sleep 0.1; done
check "a peer in another mount namespace: refused" \
    grep -q "a connection refused: the peer (pid [0-9]*, python3) is not in the node's mount namespace nor the node agent's (not the node's runtime" "$B/a.log"
kill "$VICTIM" 2>/dev/null
check "the node agent is still listening" sh -c "kill -0 ${AGENTS%% *} 2>/dev/null || kill -0 \$(echo $AGENTS | cut -d' ' -f1)"

echo "== 6. the launcher, policies by name, decided launches (step 3) =="
if [ -z "$LAUNCHER" ] || [ ! -x "$LAUNCHER" ] || ! printf 'int main(void){return 0;}\n' | gcc -static -O2 -x c -o "$B/rootfs/ok" - 2>/dev/null; then
    skip "the launcher (needs varek-init, built by make varek-init, and a static gcc)"
else
    cp "$B/rootfs/ok" "$B/rootfs/no"; ln "$B/rootfs/ok" "$B/rootfs/ok2"
    cp "$LAUNCHER" "$B/varek-init"; cp "$LAUNCHER" "$B/other-init"; chmod 755 "$B/varek-init" "$B/other-init"
    mkdir -p "$B/rootfs/varek" "$B/rootfs/work" "$B/rootfs/work2"; touch "$B/rootfs/varek/init"
    mkdir -m 777 "$B/work"
    # step 5: the policies of the pod's namespace (team-a), as the plugin writes them
    mkdir -m 755 "$B/pol" "$B/pol/team-a"
    P="$B/pol/team-a"
    cp "$B/p.txt" "$P/plain.policy"
    printf 'require warden 1.29\nallow path /data/allowed readonly\nallow path /ok readonly\nallow path /work/\nallow exec /ok\nallow exec /ok2\n' > "$P/launch.policy"
    chmod 644 "$P/"*.policy
    "$WARDEN" "$P/launch.policy" --oci-filter > "$B/f/launch.json" 2>/dev/null
    "$WARDEN" "$P/plain.policy" --oci-filter > "$B/f/plain.json" 2>/dev/null
    check "--oci-filter: the filter step 1 measured, rule for rule; then Landlock, and every call it names no rule for notified" \
        python3 - "$B/f/oci.json" "$B/f/launch.json" <<'PY'
import json, sys
a, b = (json.load(open(x)) for x in sys.argv[1:3])
for s in a["syscalls"]: s.pop("nr", None)
n = len(a["syscalls"])
ruled = {x for s in a["syscalls"] for x in s["names"]}
rest = b["syscalls"][n + 1:]
sys.exit(0 if a["syscalls"] == b["syscalls"][:n] and a["defaultAction"] == b["defaultAction"] and b["defaultErrnoRet"] == 1 and
         b["syscalls"][n] == {"names": ["landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"],
                              "action": "SCMP_ACT_ALLOW", "args": []} and
         all(len(e["names"]) == 1 and e["action"] == "SCMP_ACT_NOTIFY" and not e["args"] and e["names"][0] not in ruled for e in rest) and
         "seccomp" in {e["names"][0] for e in rest} else 1)
PY
    check "... before 1.29, fstatfs among them (runc's last steps call it; the Warden's filter admits it from 1.29)" python3 -c \
        'import json, sys; sys.exit(0 if {"names": ["fstatfs"], "action": "SCMP_ACT_NOTIFY", "args": []} in json.load(open(sys.argv[1]))["syscalls"] else 1)' "$B/f/plain.json"
    if gcc -O2 -I"$HERE" -o "$B/bpfrun" "$HERE/tests/v1340_bpf_run.c" "$HERE/warden_oci.c" -lseccomp 2>/dev/null; then
        check "the node agent's BPF interpreter answers as step 1's, on the Warden's filter (before 1.29 and from it)" sh -c \
            "python3 '$HERE/tests/v1340_bpf_check.py' '$B/bpfrun' 0 '$B' && python3 '$HERE/tests/v1340_bpf_check.py' '$B/bpfrun' 1 '$B'"
    else
        flunk "tests/v1340_bpf_run.c builds"
    fi
    # a bundle with the launcher: NAME SOCKET FILTER POLICY-NAME|- ARGS [OPTION...]
    #   rw-root, work-exec (/work without noexec), twice (/work2: /work's directory again, read-only),
    #   other-init (another copy of the launcher at /varek/init); step 5: the annotations the
    #   plugin adds (the pod's namespace team-a, the policy's SHA-256), or no-sha, bad-sha
    lbundle() {
        local name="$1" sock="$2" filt="$3" ann="$4" args="$5"
        shift 5
        mkdir -p "$B/b-$name" && (cd "$B/b-$name" && "$RUNC" spec >/dev/null)
        python3 - "$B/b-$name/config.json" "$filt" "$sock" "$ARCH" "$B" "$ann" "$args" "$@" <<'PY'
import json, sys
cfg, flt, sock, arch, B, ann, args = sys.argv[1:8]
opts = set(sys.argv[8:])
c = json.load(open(cfg)); f = json.load(open(flt))
f.pop("varekCredentials", None)      # v1.36 step 4: the plugin's, not the runtime's
f["architectures"] = [arch]; f["listenerPath"] = sock; f["listenerMetadata"] = "varek-test/" + cfg.split("/")[-2]
c["process"].update(terminal=False, args=args.split(), env=["PATH=/"], user={"uid": 65534, "gid": 65534},
                    noNewPrivileges=True, cwd="/")
# v1.36 step 4: env=NAME=VALUE, as the NRI plugin sets a credential's placeholder
c["process"]["env"] += [o[4:] for o in sorted(opts) if o.startswith("env=")]
c["root"] = {"path": B + "/rootfs", "readonly": "rw-root" not in opts}
c["linux"]["seccomp"] = f
c["process"]["capabilities"] = {k: [] for k in ("bounding", "effective", "permitted", "inheritable", "ambient")}
if ann != "-":
    import hashlib, os
    pf = B + "/pol/team-a/" + ann + ".policy"
    sha = hashlib.sha256(open(pf, "rb").read()).hexdigest() if os.path.isfile(pf) else "0" * 64
    c["annotations"] = {"varek.dev/policy": ann, "varek.dev/pod-namespace": "team-a"}
    # v1.36 step 6: uid=UID (varek.dev/pod-uid, the plugin's), obo=SECRET (varek.dev/on-behalf-of)
    for o in opts:
        if o.startswith("uid="): c["annotations"]["varek.dev/pod-uid"] = o[4:]
        if o.startswith("obo="): c["annotations"]["varek.dev/on-behalf-of"] = o[4:]
    if "no-sha" not in opts: c["annotations"]["varek.dev/policy-sha256"] = "f" * 64 if "bad-sha" in opts else sha
    # v1.35 step 4c: the pod's plan (plan=NAME), as the plugin adds it, or plan-no-sha, plan-bad-sha
    for o in opts:
        if o.startswith("plan="):
            pl = B + "/pol/team-a/" + o[5:] + ".plan"
            c["annotations"]["varek.dev/plan"] = o[5:]
            psha = hashlib.sha256(open(pl, "rb").read()).hexdigest() if os.path.isfile(pl) else "0" * 64
            if "plan-no-sha" not in opts: c["annotations"]["varek.dev/plan-sha256"] = "e" * 64 if "plan-bad-sha" in opts else psha
for m in c["mounts"]:
    if m["destination"] == "/dev": m["options"].append("noexec")      # as the NRI plugin makes it
c["mounts"].append({"destination": "/varek/init", "type": "bind", "source": B + ("/other-init" if "other-init" in opts else "/varek-init"),
                    "options": ["bind", "ro", "nosuid", "nodev"]})
c["mounts"].append({"destination": "/work", "type": "bind", "source": B + "/work",
                    "options": ["rbind", "rw", "nosuid", "nodev"] + ([] if "work-exec" in opts else ["noexec"])})
if "cg2" in opts:     # v1.36 step 5: the cgroup filesystem as a cgroup v2 node mounts it (on a hybrid host too)
    for m in c["mounts"]:
        if m["destination"] == "/sys/fs/cgroup": m.update(type="cgroup2", source="cgroup2")
if "twice" in opts:
    c["mounts"].append({"destination": "/work2", "type": "bind", "source": B + "/work", "options": ["rbind", "ro", "nosuid", "nodev"]})
json.dump(c, open(cfg, "w"))
PY
    }
    # refused at the start: AGENT NAME WHY (a pattern in its stream); the command never ran
    refused() { ! grep -q '^read_allowed\|^launch_ok\|^varek-init: Landlock' "$B/$2.out" && grep -q "$3" "$(stream "$1" "$2")"; }
    check "a node agent with a directory of policies and the launcher" agent l "$B/pol" --node-launcher "$B/varek-init"
    lbundle launch "$B/s/l.sock" "$B/f/launch.json" launch "/varek/init -- /probe launch"
    run launch
    sed 's/^/     /' "$B/launch.out"
    check "the launcher applied the launch set and ran the command" \
        grep -q '^varek-init: Landlock ABI [0-9]*, a launch set of [0-9]* file(s) applied; running /probe$' "$B/launch.out"
    check "a program the policy allows to launch ran" said launch "launch_ok: ran"
    check "... and its hardlink, which the policy allows too (each name given to Landlock)" said launch "launch_ok2: ran"
    check "one it does not allow: refused" said launch "launch_no: EACCES"
    check "a copy written to /work (noexec) and launched: refused" sh -c \
        "grep -qx 'copy: ok' '$B/launch.out' && grep -qx 'launch_written: EACCES' '$B/launch.out'"
    if [ "$ARCH" = SCMP_ARCH_X86_64 ]; then
        check "an i386 call from a second thread kills the whole process (the launcher's filter)" said launch "arch32: process killed"
        bundle archx "$B/s/a.sock" "/probe arch" 1
        run archx
        check "... without the launcher, only its thread (the runtime's filter: what the launcher adds)" said archx "arch32: thread only"
    fi
    check "run_start: the policy by its name, the launcher, the launch set built in the container's view" rec l launch \
        'S and S[0]["node"]["policy"] == "launch" and S[0]["node"]["launcher"] is True and {"/probe", "/ok"} <= {e["path"] for e in S[0]["exec_ruleset"]} and "/no" not in {e["path"] for e in S[0]["exec_ruleset"]} and S[0]["noexec"] and S[0]["noexec"][0]["path"] == "/work" and {"/probe", "/ok", "/ok2"} <= set(S[0]["node"]["launch_paths"])'
    check "the command is the first launch; the launcher's own calls let through, counted" rec l launch \
        '[r for r in R if r.get("rule") == "bootstrap_exec_allow"][0]["target"] == "/probe" and E and E[0]["launcher_calls_before_exec"] > 0'
    check "the launches recorded: /ok allowed, /no and the copy refused" rec l launch \
        'any(r.get("action") == "process.exec" and r.get("target") == "/ok" and r.get("decision_final") == "ALLOW" for r in R) and all(any(r.get("action") == "process.exec" and r.get("target") == t and r.get("decision_final") == "DENY" for r in R) for t in ("/no", "/work/copy"))'
    lbundle plain "$B/s/l.sock" "$B/f/plain.json" plain "/varek/init -- /probe"
    run plain
    check "a policy that decides no launch, with the launcher: the command ran, a second launch refused" sh -c \
        "grep -qx 'read_allowed: ok allowed content' '$B/plain.out' && grep -qx 'exec_again: EACCES' '$B/plain.out'"
    check "... its launch set the command alone" rec l plain '[e["why"] for e in S[0]["exec_ruleset"]] == ["bootstrap"] and S[0]["node"]["policy"] == "plain"'
    PC="$(stream l plain | sed 's/\.jsonl$/.policy/')"
    check "the policy, from the pod's namespace, copied beside the stream (read-only) and run from there (step 5)" sh -c \
        "cmp -s '$PC' '$P/plain.policy' && [ \"\$(stat -c %a '$PC')\" = 400 ] && grep -q '\"policy_path\":\"$PC\"' '$(stream l plain)'"
    # step 7 (found by the sweep): the audit takes the launcher's launch set
    # (the command alone) and Landlock under a policy that decides no launch
    if [ -n "$CERT" ]; then
        check "... and the audit accepts its stream (the launcher's launch set, under a policy without launches)" \
            python3 "$HERE/tools/varek_audit.py" --policy "$PC" --checker "$CERT" "$(stream l plain)"
    fi
    lbundle nosha "$B/s/l.sock" "$B/f/plain.json" plain "/varek/init -- /probe" no-sha; run nosha
    check "a container without the plugin's SHA-256 of its policy: refused" refused l nosha 'not given its filter by VAREK.s NRI plugin'
    lbundle badsha "$B/s/l.sock" "$B/f/plain.json" plain "/varek/init -- /probe" bad-sha; run badsha
    check "... with another one (the policy changed after the plugin wrote the filter): refused" refused l badsha 'is not the one the NRI plugin wrote'
    check "... the runtime's calls its filter names no rule for let through before the command, refused after (counted)" rec l plain \
        'E and E[0]["runtime_calls_before_exec"] > 0 and E[0]["calls_not_admitted"] >= 0'
    lbundle noname "$B/s/l.sock" "$B/f/plain.json" - "/varek/init -- /probe"; run noname
    check "a container that names no policy: refused" refused l noname 'names no policy'
    lbundle unknown "$B/s/l.sock" "$B/f/plain.json" nosuch "/varek/init -- /probe"; run unknown
    check "a policy name with no file: refused" refused l unknown 'no policy named nosuch'
    lbundle badname "$B/s/l.sock" "$B/f/plain.json" Bad_Name "/varek/init -- /probe"; run badname
    check "a name not of a-z, 0-9 and -: refused" refused l badname 'is not 1 to 63 of'
    lbundle other "$B/s/l.sock" "$B/f/launch.json" launch "/varek/init -- /probe launch" other-init; run other
    check "/varek/init not the node's launcher (another copy of it): refused" refused l other "not the node's launcher"
    lbundle rwroot "$B/s/l.sock" "$B/f/launch.json" launch "/varek/init -- /probe launch" rw-root; run rwroot
    check "D4: a writable root: refused" refused l rwroot 'root file system is writable'
    lbundle workexec "$B/s/l.sock" "$B/f/launch.json" launch "/varek/init -- /probe launch" work-exec; run workexec
    check "D4: a writable mount without noexec: refused" refused l workexec 'writable mount /work is not noexec'
    lbundle twice "$B/s/l.sock" "$B/f/launch.json" launch "/varek/init -- /probe launch" twice; run twice
    check "D4: a volume mounted twice, once writable: refused" refused l twice 'mount /work2 allows execution and shows files its writable mount /work'
    lbundle nol "$B/s/a.sock" "$B/f/plain.json" plain "/varek/init -- /probe"; run nol
    check "the launcher's command under a node agent with no launcher: refused" refused a nol 'this node agent has none'
    check "a node agent with one policy that decides launches" agent d "$P/launch.policy" --node-launcher "$B/varek-init"
    bundle direct "$B/s/d.sock" "/probe launch" 1; run direct
    check "decided launches without the launcher: refused" refused d direct 'decided launches without the launcher'
    check "the launcher with no node agent serving its view refuses to run the command" sh -c \
        "'$B/varek-init' -- /bin/true 2>/dev/null; [ \$? = 126 ]"
fi

echo "== 7. the pod's network (step 4) =="
if ! command -v unshare > /dev/null || ! command -v nsenter > /dev/null || ! touch "$B/netns" ||
   ! unshare --net="$B/netns" true 2>/dev/null; then
    skip "the pod's network (needs unshare and nsenter)"
else
    # the pod's network: its loopback up, 10.77.0.1 on it (netlink: no ip here)
    nsenter --net="$B/netns" python3 - <<'PY'
import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fl = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH14s", b"lo", 0, bytes(14)))[:18])[1]
fcntl.ioctl(s, 0x8914, struct.pack("16sH14s", b"lo", fl | 0x1 | 0x40, bytes(14)))          # IFF_UP, IFF_RUNNING
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
for ip in ("10.77.0.1", "10.77.0.2"):       # the server's, and one no name resolves to
    a = socket.inet_aton(ip)
    body = struct.pack("BBBBI", socket.AF_INET, 32, 0, 0, socket.if_nametoindex("lo")) + \
        struct.pack("HH4s", 8, 2, a) + struct.pack("HH4s", 8, 1, a)                     # IFA_LOCAL, IFA_ADDRESS
    nl.send(struct.pack("IHHII", 16 + len(body), 20, 0x1 | 0x4 | 0x200 | 0x400, 1, 0) + body)   # RTM_NEWADDR
    assert struct.unpack("i", nl.recv(4096)[16:20])[0] == 0
PY
    mkdir -p "$B/www" "$B/rootfs/etc"; echo hello > "$B/www/index.html"
    echo "nameserver 127.0.0.1" > "$B/rootfs/etc/resolv.conf"; chmod 644 "$B/rootfs/etc/resolv.conf"
    printf '{"svc.test": {"ttl": 30, "a": ["10.77.0.1"]}, "a.wild.test": {"ttl": 30, "a": ["10.77.0.1"]}, "b.wild.test": {"ttl": 30, "a": ["10.77.0.1"]}}\n' > "$B/zone.json"
    nsenter --net="$B/netns" python3 "$HERE/tests/dns_test_server.py" --port 53 --zone "$B/zone.json" --log "$B/dns.log" \
        --ready "$B/dns.ready" > "$B/dns.out" 2>&1 &
    SERVERS="$SERVERS $!"
    nsenter --net="$B/netns" python3 -m http.server 80 --bind 0.0.0.0 --directory "$B/www" > "$B/http.out" 2>&1 &
    SERVERS="$SERVERS $!"
    for _ in $(seq 50); do [ -e "$B/dns.ready" ] && grep -q 'Serving HTTP' "$B/http.out" 2>/dev/null && break; sleep 0.1; done
    in_pod() {   # the bundle NAME joins the pod's network namespace
        python3 - "$B/b-$1/config.json" "$B/netns" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["linux"]["namespaces"] = [n for n in c["linux"]["namespaces"] if n["type"] != "network"] + [{"type": "network", "path": sys.argv[2]}]
json.dump(c, open(sys.argv[1], "w"))
PY
    }
    printf 'require warden 1.25\nallow host svc.test:80\nallow host *.wild.test:80 acknowledge=dns-channel\n' > "$B/p_net.txt"
    printf 'require warden 1.26\nproxy on\nproxy ports 80\nallow host svc.test:80\n' > "$B/p_px.txt"
    check "a node agent with a policy naming a host and a wildcard" agent net "$B/p_net.txt"
    bundle neta "$B/s/net.sock" "/probe net svc.test a.wild.test hold" 1; in_pod neta
    bundle netb "$B/s/net.sock" "/probe net svc.test b.wild.test" 1; in_pod netb
    ( run neta ) &
    RA=$!
    for _ in $(seq 100); do grep -q '^get_wild' "$B/neta.out" 2>/dev/null && break; sleep 0.1; done
    run netb
    wait "$RA"
    sed 's/^/     /' "$B/neta.out"
    check "the name the policy allows, in the hosts view, resolved through the pod's DNS server" sh -c \
        "grep -qx 'hosts: 10.77.0.1 svc.test' '$B/neta.out' && grep -q 'svc.test' '$B/dns.log'"
    check "... a GET to it, dialed from the pod's network" said neta "get_allowed: HTTP/1.0 200 OK"
    check "a connect to an address no rule or allowed name has: refused" said neta "numeric: EACCES"
    check "the stub, named by the resolv.conf view" said neta "stub: 127.53.53.53"
    check "a wildcard name asked of the stub, then reached" said neta "get_wild: HTTP/1.0 200 OK"
    check "run_start: the pod's DNS server, from its resolv.conf; the stub" rec net neta \
        'S[0]["node"]["pod_dns"] == "127.0.0.1:53" and S[0]["dns_stub"] == "127.53.53.53:53"'
    check "a second container in the pod: the stub at the next address, its names answered" sh -c \
        "grep -qx 'stub: 127.53.53.54' '$B/netb.out' && grep -qx 'get_wild: HTTP/1.0 200 OK' '$B/netb.out'"
    check "... in its run_start" rec net netb 'S[0]["dns_stub"] == "127.53.53.54:53"'
    if [ -n "$CERT" ]; then
        check "the audit accepts both streams (the stub at either address)" sh -c \
            "python3 '$HERE/tools/varek_audit.py' --policy '$B/p_net.txt' --checker '$CERT' '$(stream net neta)' &&
             python3 '$HERE/tools/varek_audit.py' --policy '$B/p_net.txt' --checker '$CERT' '$(stream net netb)'"
    fi
    if [ -x "$HERE/warden-proxy" ]; then
        check "a node agent with the proxy on" agent px "$B/p_px.txt"
        # (a connect by number on a proxied port goes to the proxy, which decides by the request's name: v1.26)
        bundle pxa "$B/s/px.sock" "/probe net svc.test a.wild.test" 1; in_pod pxa
        run pxa
        sed 's/^/     /' "$B/pxa.out"
        check "with the proxy: the name's synthetic address, reached through the proxy" sh -c \
            "grep -q '^hosts: ' '$B/pxa.out' && ! grep -qx 'hosts: 10.77.0.1 svc.test' '$B/pxa.out' && ! grep -qx 'hosts: none svc.test' '$B/pxa.out' &&
             grep -qx 'get_allowed: HTTP/1.0 200 OK' '$B/pxa.out'"
        check "... handed to the proxy, which dialed the server from the pod's network" rec px pxa \
            'any(r.get("rule") == "proxy_handoff" and r.get("target", "").startswith("198.18.") for r in R) and any(r.get("action") == "net.proxy" and r.get("rule") == "proxy_dialed" and r.get("dialed") == "10.77.0.1:80" for r in R)'
        check "... a name no rule allows: no address" said pxa "get_wild: no address"
    else
        skip "the proxy in the pod's network (needs warden-proxy: make warden-proxy)"
    fi
fi

echo "== 8. evidence (step 5, D8) =="
if [ ! -x "$HERE/tools/varek_keygen" ] || [ -z "$CERT" ]; then
    skip "evidence (needs tools/varek_keygen and the certificate checker)"
else
    "$HERE/tools/varek_keygen" "$B/nodekey" > /dev/null 2>&1
    : > "$B/anchor"; chmod 600 "$B/anchor"
    check "a node agent signing with the node's key, anchored" agent e "$B/p.txt" --sign-key "$B/nodekey" \
        --anchor "$B/anchor" --checkpoint-every 4
    bundle ev1 "$B/s/e.sock" /probe 1; run ev1
    bundle ev2 "$B/s/e.sock" /probe 1; run ev2
    E1="$(stream e ev1)" E2="$(stream e ev2)"
    check "each container's stream signed with the node's key and anchored: the audit verifies both" sh -c \
        "python3 '$HERE/tools/varek_audit.py' --policy '${E1%.jsonl}.policy' --checker '$CERT' --pubkey '$B/nodekey.pub' --anchor '$B/anchor' '$E1' &&
         python3 '$HERE/tools/varek_audit.py' --policy '${E2%.jsonl}.policy' --checker '$CERT' --pubkey '$B/nodekey.pub' --anchor '$B/anchor' '$E2'"
    R1="$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")][0]["run"])' "$E1")"
    R2="$(python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")][0]["run"])' "$E2")"
    check "the anchor holds both runs' checkpoints" sh -c "grep -q '$R1' '$B/anchor' && grep -q '$R2' '$B/anchor' && [ '$R1' != '$R2' ]"
    check "the streams root's and 0600, the policies beside them read-only" sh -c \
        "[ \"\$(stat -c '%u %a' '$E1')\" = '0 600' ] && [ \"\$(stat -c '%u %a' '${E1%.jsonl}.policy')\" = '0 400' ]"
    python3 "$HERE/tools/varek_node_export.py" --streams "$B/streams-e" --once --checker "$CERT" \
        --pubkey "$B/nodekey.pub" --anchor "$B/anchor" --device node-1 -o "$B/ocsf.jsonl" \
        --state "$B/export.state" --max-followers 1 > "$B/export.out" 2>&1; xrc=$?
    # step 8 review (S3): each run's last event the audit's, and it passed
    check "the node exporter gives both runs as OCSF, each event an object, each run's audit passed" python3 - "$B/ocsf.jsonl" "$xrc" "$R1" "$R2" <<'PY'
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
audits = {}
for e in ev:
    v = e.get("unmapped", {}).get("varek", {}) if isinstance(e, dict) else {}
    if v.get("event") == "audit":
        audits[e.get("metadata", {}).get("correlation_uid") or json.dumps(e)] = v["audit"].get("passed")
txt = [json.dumps(e) for e in ev]
ok = sys.argv[2] == "0" and all(isinstance(e, dict) and "class_uid" in e for e in ev) and \
     all(any(r in t for t in txt) for r in sys.argv[3:]) and len(audits) == 2 and all(p is True for p in audits.values())
sys.exit(0 if ok else 1)
PY
    # T1: the streams done written down, and not exported again
    python3 "$HERE/tools/varek_node_export.py" --streams "$B/streams-e" --once --checker "$CERT" \
        --pubkey "$B/nodekey.pub" --anchor "$B/anchor" --device node-1 -o "$B/ocsf2.jsonl" \
        --state "$B/export.state" > "$B/export2.out" 2>&1
    check "... the streams done in its state, not exported again when it starts again" sh -c \
        "[ \"\$(wc -l < '$B/export.state')\" = 2 ] && [ ! -s '$B/ocsf2.jsonl' ]"
fi

echo "== 9. plans under the node agent (v1.35 step 4c, D11) =="
if [ -z "$WARDEN" ] || ! declare -f lbundle > /dev/null; then
    skip "plans under the node agent (need the launcher, as section 6)"
else
    check "--node-agent with --plan is refused (each pod names its own)" sh -c \
        "'$WARDEN' '$B/pol' --node-agent '$B/s/x.sock' --node-streams '$B/streams' --plan /dev/null; [ \$? = 2 ]"
    printf 'require warden 1.35\nrequire plan\nallow path /data/allowed readonly\nallow path /data/denied readonly\nallow path /ok readonly\nallow path /work/\nallow exec /ok\n' > "$P/held.policy"
    printf 'plan 1.35\naction a file_open /data/allowed open=read\n' > "$P/held.plan"
    printf 'plan 1.35\naction a file_open /data/rootonly open=read\n' > "$P/over.plan"
    printf 'plan 1.35\naction a file_open /data/allowed open=read\naction m mcp_call http://10.0.0.1:8080/mcp method=tools/call name=x\n' > "$P/mcp.plan"
    chmod 644 "$P/"*.policy "$P/"*.plan
    "$WARDEN" "$P/held.policy" --oci-filter --plan "$P/held.plan" > "$B/f/held.json" 2> "$B/f/held.err"; hrc=$?
    "$WARDEN" "$P/held.policy" --oci-filter > "$B/f/held0.json" 2>/dev/null
    check "--oci-filter --plan: the pod's plan read; the filter the policy's own" sh -c "[ $hrc = 0 ] && cmp -s '$B/f/held.json' '$B/f/held0.json'"
    "$WARDEN" "$P/held.policy" --oci-filter --no-plan > /dev/null 2> "$B/f/np.err"; nrc=$?
    check "--oci-filter --no-plan under \`require plan\`: refused, said why" sh -c \
        "[ $nrc = 1 ] && grep -q 'a pod under it names its plan (varek.dev/plan)' '$B/f/np.err'"
    check "... under a policy without it: written" sh -c "'$WARDEN' '$P/plain.policy' --oci-filter --no-plan > /dev/null 2>&1"
    "$WARDEN" "$P/held.policy" --oci-filter --plan "$P/mcp.plan" > /dev/null 2> "$B/f/mcp.err"; mrc=$?
    check "--oci-filter --plan with an mcp_call step: carried (v1.36 step 5), the plan read" sh -c "[ $mrc = 0 ]"
    check "--oci-filter with --plan and --no-plan: refused" sh -c \
        "'$WARDEN' '$P/held.policy' --oci-filter --plan '$P/held.plan' --no-plan > /dev/null 2>&1; [ \$? = 2 ]"
    lbundle held "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=held; run held
    sed 's/^/     /' "$B/held.out"
    check "a pod's plan: the command ran, a read a step covers answered" said held "read_allowed: ok allowed content"
    check "... a read the policy allows and no step covers: refused, outside_plan" sh -c \
        "grep -qx 'read_denied: EACCES' '$B/held.out' && grep -F '\"resolved\":\"/data/denied\"' '$(stream l held)' | grep -q '\"decision_raw\":\"ALLOW\",\"decision_final\":\"DENY\",\"rule\":\"outside_plan\"'"
    HC="$(stream l held | sed 's/\.jsonl$/.plan/')"
    check "the plan, from the pod's namespace, copied beside the stream (read-only); run_start names it and holds the run to the copy" sh -c \
        "cmp -s '$HC' '$P/held.plan' && [ \"\$(stat -c %a '$HC')\" = 400 ]" 
    check "... run_start: the plan by its name, the hold on its copy" rec l held \
        'S and S[0]["node"]["plan"] == "held" and S[0]["hold"]["plan"].endswith(".plan") and S[0]["hold"]["plan"] == "'"$HC"'"'
    if [ -n "$CERT" ]; then
        check "... and the audit accepts its stream (a held run under the node agent)" \
            python3 "$HERE/tools/varek_audit.py" --policy "$(stream l held | sed 's/\.jsonl$/.policy/')" --checker "$CERT" "$(stream l held)"
    fi
    lbundle noplan "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe"; run noplan
    check "\`require plan\`, a pod naming no plan: refused" refused l noplan 'its pod names no plan'
    lbundle over "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=over; run over
    check "a plan with a step the policy does not allow: refused, its records in the stream" sh -c \
        "! grep -q '^read_allowed' '$B/over.out' && grep -q 'its plan is refused' '$(stream l over)' && grep -q '\"event\":\"plan_gate\"' '$(stream l over)'"
    lbundle mcp "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=mcp; run mcp
    check "a plan with an mcp_call step: decided as on a host (UNKNOWN: the policy allows no MCP call), the plan refused" sh -c \
        "! grep -q '^read_allowed' '$B/mcp.out' && grep -q 'plan: mcp_call step \"http://10.0.0.1:8080/mcp\" is UNKNOWN' '$(stream l mcp)' && grep -q 'its plan is refused' '$(stream l mcp)'"
    lbundle pbad "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=held plan-bad-sha; run pbad
    check "a plan not the one the plugin checked (another SHA-256): refused" refused l pbad 'the plan .* is not the one the NRI plugin'
    lbundle pnosha "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=held plan-no-sha; run pnosha
    check "a plan without the plugin's SHA-256 of it: refused" refused l pnosha 'with it (no varek.dev/plan-sha256'
    lbundle pnone "$B/s/l.sock" "$B/f/held.json" held "/varek/init -- /probe" plan=nosuch; run pnone
    check "a plan name with no file: refused" refused l pnone 'no plan named nosuch'
    lbundle p1 "$B/s/a.sock" "$B/f/plain.json" plain "/varek/init -- /probe" plan=held; run p1
    check "a plan under a node agent with one policy file: refused" refused a p1 'this node agent has one policy'
fi

echo "== 10. credentials under the node agent (v1.36 step 4, D1 and D2) =="
if [ -z "$WARDEN" ] || ! declare -f lbundle > /dev/null || ! declare -f in_pod > /dev/null || [ ! -x "$HERE/warden-secrets" ] ||
   [ ! -x "$HERE/warden-proxy" ] || ! python3 -c 'import cryptography' 2>/dev/null; then
    skip "credentials under the node agent (need the launcher and the pod's network, as sections 6 and 7, warden-secrets, warden-proxy and python3-cryptography)"
else
    # the stores (tests/v1280_stores.py), on the node's own loopback: not in the pod's network
    SD="$B/stores"; mkdir -p "$SD"
    python3 "$HERE/tests/v1280_stores.py" "$SD" > "$SD/server.out" 2>&1 &
    SERVERS="$SERVERS $!"
    for _ in $(seq 100); do [ -f "$SD/ports" ] && break; sleep 0.1; done
    read -r HP _ < "$SD/ports"
    cp "$SD/ca.pem" "$B/ca.pem"; chmod 644 "$B/ca.pem"
    printf 's.test-token-v1280\n' > "$B/vt"; chmod 600 "$B/vt"
    printf 'vault_addr = https://127.0.0.1:%s\nvault_token_file = %s/vt\nvault_ca = %s/ca.pem\n' "$HP" "$B" "$B" > "$B/secrets.conf"
    chmod 600 "$B/secrets.conf"
    # the chart's credentials directory, a Secret's volume in it: KEY -> ..data/KEY, ..data -> ..<time>/
    C="$B/creds"; V="$C/gh/..2026_10_27_10_00_00.1"
    mkdir -p "$V"; chmod 755 "$C" "$V"; chmod 1777 "$C/gh"
    printf 'file-value-1234\n' > "$V/token"; chmod 400 "$V/token"
    ln -s ..2026_10_27_10_00_00.1 "$C/gh/..data"; ln -s ..data/token "$C/gh/token"
    printf 'v\n' > "$B/outside"; chmod 400 "$B/outside"
    # cpol NAME CREDENTIAL SOURCE: a policy of team-a naming one credential
    cpol() { printf 'require warden 1.28\nproxy inspect\ncredential %s from %s\nallow path /data/allowed readonly\nallow host svc.test:443\nallow request GET https://svc.test/x credential=%s header=X-K\n' \
                    "$2" "$3" "$2" > "$P/$1.policy"; chmod 644 "$P/$1.policy"; }
    cpol cfile gh "file:$C/gh/token"
    cpol cvault vgh "vault:secret/data/agents/gh#token"
    cpol cother og "file:$C/gh/token"
    cpol csrc os "file:$C/gh/token"
    cpol cout ou "file:$B/outside"
    # the cluster's VarekCredential resources, as the plugin's sync lists them
    printf '# VarekCredential resources\ngh\tteam-a,team-c\tfile:%s/gh/token\tgh-file\nvgh\tteam-a\tvault:secret/data/agents/gh#token\tgh-vault\nog\tteam-b\tfile:%s/gh/token\tother-team\nos\tteam-a\tvault:secret/data/os#x\tother-source\nou\tteam-a\tfile:%s/outside\toutside\n' \
        "$C" "$C" "$B" > "$B/pol/.credentials"
    chmod 644 "$B/pol/.credentials"
    L="$B/pol/.credentials"
    "$WARDEN" "$P/cfile.policy" --oci-filter --no-plan --credential-list "$L" --pod-namespace team-a > "$B/f/cfile.json" 2> "$B/f/cfile.err"; frc=$?
    check "--oci-filter: a credential the list gives the pod's namespace; its name in the output (varekCredentials)" sh -c \
        "[ $frc = 0 ] && python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); sys.exit(0 if d[\"varekCredentials\"] == [\"gh\"] and d[\"syscalls\"] else 1)' '$B/f/cfile.json'"
    check "... without the list: refused" sh -c "! '$WARDEN' '$P/cfile.policy' --oci-filter --no-plan > /dev/null 2>&1"
    # ocirefused POLICY NAMESPACE WHY: --oci-filter exits 1 and says why
    ocirefused() { "$WARDEN" "$P/$1.policy" --oci-filter --no-plan --credential-list "$L" --pod-namespace "$2" > /dev/null 2> "$B/f/$1.$2.err"
                   [ $? = 1 ] && grep -q "$3" "$B/f/$1.$2.err"; }
    check "... for another namespace: refused, said why" ocirefused cfile team-b 'not given to namespace team-b'
    check "... from another source than its VarekCredential's: refused" ocirefused csrc team-a 'names another source'
    printf 'plan 1.35\naction c credential gh\n' > "$P/cplan.plan"; chmod 644 "$P/cplan.plan"
    check "... a plan with a credential step: carried now" "$WARDEN" "$P/cfile.policy" --oci-filter --plan "$P/cplan.plan" --credential-list "$L" --pod-namespace team-a
    PH="varek_ph_gh_$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
    PHV="varek_ph_vgh_$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')"
    check "a node agent with the cluster's credentials directory (--node-credentials) and warden-secrets' configuration" \
        agent cr "$B/pol" --node-launcher "$B/varek-init" --node-credentials "$C" --secrets-conf "$B/secrets.conf"
    # cbundle NAME POLICY [OPTION...]: the container in the pod's network, printing its placeholder
    cbundle() { local n="$1" pol="$2" var="$3"; shift 3
                lbundle "$n" "$B/s/cr.sock" "$B/f/cfile.json" "$pol" "/varek/init -- /probe env $var" "$@"; in_pod "$n"; run "$n"; }
    crefused() { ! grep -q '^env:' "$B/$1.out" && grep -q "$2" "$(stream cr "$1")"; }
    cbundle cf cfile VAREK_CRED_GH "env=VAREK_CRED_GH=$PH"
    sed 's/^/     /' "$B/cf.out"
    check "a file store in a Secret's volume: the container ran, its placeholder the plugin's" said cf "env: $PH"
    check "... fetched by warden-secrets (the link followed), held by the proxy" sh -c \
        "grep -q 'credential gh from file:$C/gh/token: fetched, 15 bytes' '$(stream cr cf)' && grep -q 'credentials: 1 held by the proxy' '$(stream cr cf)'"
    check "... run_start: the credential, and its placeholder's SHA-256 the container's" rec cr cf \
        'S and S[0]["credentials"][0]["name"] == "gh" and S[0]["credentials"][0]["length"] == 15 and S[0]["credentials"][0]["placeholder_sha256"] == "'"$(printf %s "$PH" | sha256sum | cut -c1-64)"'"'
    check "... no value in the stream" sh -c "! grep -q 'file-value-1234' '$(stream cr cf)'"
    : > "$SD/requests.log"
    cbundle cv cvault VAREK_CRED_VGH "env=VAREK_CRED_VGH=$PHV"
    check "a Vault store on the node's loopback only: fetched from the node's network (not the pod's), the container ran" sh -c \
        "grep -qx 'env: $PHV' '$B/cv.out' && grep -q 'credential vgh from vault:secret/data/agents/gh#token: fetched, 20 bytes' '$(stream cr cv)' &&
         grep -q 'vault GET /v1/secret/data/agents/gh token=ok' '$SD/requests.log'"
    cbundle co cother VAREK_CRED_OG "env=VAREK_CRED_OG=varek_ph_og_${PH#varek_ph_gh_}"
    check "refused: a credential its VarekCredential gives another namespace (D2)" crefused co 'is not given to namespace team-a'
    cbundle cs csrc VAREK_CRED_OS "env=VAREK_CRED_OS=varek_ph_os_${PH#varek_ph_gh_}"
    check "refused: a source other than its VarekCredential's" crefused cs 'names another source'
    cbundle cu cout VAREK_CRED_OU "env=VAREK_CRED_OU=varek_ph_ou_${PH#varek_ph_gh_}"
    check "refused: a file store outside the node's credentials directory (D1)" crefused cu 'is not under the node.s credentials directory'
    cbundle cn cfile VAREK_CRED_GH
    check "refused: no placeholder in the container's environment" crefused cn 'has no placeholder for credential gh'
    cbundle c2 cfile VAREK_CRED_GH "env=VAREK_CRED_GH=$PH" "env=VAREK_CRED_GH=varek_ph_gh_${PHV#varek_ph_vgh_}"
    check "refused: two placeholders for it" crefused c2 'has more than one placeholder for credential gh'
    cbundle cb cfile VAREK_CRED_GH "env=VAREK_CRED_GH=varek_ph_gh_short"
    check "refused: a placeholder not of the plugin's form" crefused cb 'has no placeholder for credential gh'
    check "a node agent with one policy file, naming a credential" agent c1 "$P/cfile.policy" --node-launcher "$B/varek-init" --node-credentials "$C"
    lbundle c1a "$B/s/c1.sock" "$B/f/cfile.json" - "/varek/init -- /probe env VAREK_CRED_GH" "env=VAREK_CRED_GH=$PH"; in_pod c1a; run c1a
    check "refused: credentials under one policy file (no VarekCredential list beside it)" sh -c \
        "! grep -q '^env:' '$B/c1a.out' && grep -q 'this node agent has one policy' '$(stream c1 c1a)'"
fi

echo "== 11. sub-agents and confined MCP servers under the node agent (v1.36 step 5, D3 and D4) =="
if [ -z "$WARDEN" ] || ! declare -f lbundle > /dev/null ||
   ! printf '%s\n' '#include <errno.h>' '#include <fcntl.h>' '#include <stdio.h>' '#include <string.h>' '#include <unistd.h>' \
       'static void r(const char *n, const char *p) { int fd = open(p, O_RDONLY); printf("%s %s: %s\n", n, p, fd >= 0 ? "ok" : errno == EACCES ? "EACCES" : strerror(errno)); if (fd >= 0) close(fd); }' \
       'int main(int c, char **v) { setvbuf(stdout, NULL, _IONBF, 0); const char *n = strrchr(v[0], 0x2f); n = n ? n + 1 : v[0];' \
       '  r(n, "/data/allowed"); r(n, "/data/denied"); char b[4096]; int fd = open("/proc/self/cgroup", O_RDONLY); ssize_t k = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;' \
       '  b[k > 0 ? k : 0] = 0; char *l = strstr(b, "0::"); if (l) { l[strcspn(l, "\n")] = 0; printf("%s cgroup: %s\n", n, l + 3); } else printf("%s cgroup: none\n", n); return 0; }' |
     gcc -static -O2 -x c -o "$B/rootfs/sub" - 2>/dev/null; then
    skip "sub-agents under the node agent (need the launcher, as section 6, and a static gcc)"
else
    cp "$B/rootfs/sub" "$B/rootfs/srv"; chmod 755 "$B/rootfs/sub" "$B/rootfs/srv"
    printf 'require warden 1.31\nmcp server files exec /srv\nallow path /data/allowed readonly\nallow path /proc/self/cgroup readonly\nallow path /data/denied readonly for=files\nallow path /proc/self/cgroup readonly for=files\nallow path /work/\nallow exec /sub subagent=reader\n' > "$P/sub.policy"
    { cat "$P/sub.policy"; printf 'allow path /sys/fs/cgroup/\n'; } > "$P/subw.policy"
    printf 'plan 1.35\naction s1 subagent reader\naction s2 subagent files\naction r1 file_open /data/allowed open=read\naction r2 file_open /proc/self/cgroup open=read\naction r3 file_open /data/denied open=read as=files\naction r4 file_open /proc/self/cgroup open=read as=files\n' > "$P/sub.plan"
    printf 'plan 1.35\naction s1 subagent reader\naction m mcp_call stdio:files\n' > "$P/stdio.plan"
    chmod 644 "$P/"*.policy "$P/"*.plan
    "$WARDEN" "$P/sub.policy" --oci-filter > "$B/f/sub.json" 2> "$B/f/sub.err"; src=$?
    check "--oci-filter: a policy naming a sub-agent and a confined MCP server, carried (v1.36 step 5)" sh -c "[ $src = 0 ] && [ -s '$B/f/sub.json' ]"
    check "... with a plan of subagent steps, and one with an mcp_call to a stdio server (read; decided in the container's view)" sh -c \
        "'$WARDEN' '$P/sub.policy' --oci-filter --plan '$P/sub.plan' > /dev/null 2>&1 && '$WARDEN' '$P/sub.policy' --oci-filter --plan '$P/stdio.plan' > /dev/null 2>&1"
    lbundle sub "$B/s/l.sock" "$B/f/sub.json" sub "/varek/init -- /probe sub"; run sub
    sed 's/^/     /' "$B/sub.out"
    SS="$(stream l sub)"
    CG="$(python3 -c 'import json, sys; print(next(json.loads(l) for l in open(sys.argv[1]) if "\"event\":\"run_start\"" in l)["on_behalf_of"]["agent"]["cgroup"])' "$SS" 2>/dev/null)"
    check "the sub-agent and the confined server ran, each launched by a child of the container's first process" sh -c \
        "grep -qx 'launch_sub: ran' '$B/sub.out' && grep -qx 'launch_srv: ran' '$B/sub.out'"
    check "run_start: the run's control group (on_behalf_of.agent.cgroup) is the container's own (the runtime's)" sh -c \
        "[ -n '$CG' ] && grep -q 'sub-agents: the run.s control group $CG, the container.s' '$SS'"
    check "each in a group made below the container's (its /proc/self/cgroup: reader-1, files-1)" sh -c \
        "grep -Eq '^sub cgroup: (.*/)?reader-1\$' '$B/sub.out' && grep -Eq '^srv cgroup: (.*/)?files-1\$' '$B/sub.out'"
    check "... the launch records name them, under the container's group" rec l sub \
        '[r for r in R if r.get("subagent") == "reader#1" and r.get("cgroup") == "'"$CG"'/reader-1"] and [r for r in R if r.get("subagent") == "files#1" and r.get("mcp_server") and r.get("confined") and r.get("cgroup") == "'"$CG"'/files-1"]'
    check "the sub-agent's calls attributed to it (obo), decided by the agent's rules" sh -c \
        "grep -qx 'sub /data/allowed: ok' '$B/sub.out' && grep -qx 'sub /data/denied: EACCES' '$B/sub.out'" 
    check "... in its records" rec l sub \
        '[r for r in R if r.get("resolved") == "/data/allowed" and r.get("decision_final") == "ALLOW" and r.get("obo") == ["agent", "subagent:reader#1"]]'
    check "the confined server held to its own rules (its records: obo files#1)" sh -c \
        "grep -qx 'srv /data/allowed: EACCES' '$B/sub.out' && grep -qx 'srv /data/denied: ok' '$B/sub.out'"
    check "... in its records" rec l sub \
        '[r for r in R if r.get("resolved") == "/data/denied" and r.get("decision_final") == "ALLOW" and r.get("obo") == ["agent", "subagent:files#1"]]'
    check "each launch settled (subagent_settled: launched)" rec l sub \
        'sorted(r["subagent"] for r in R if r.get("event") == "subagent_settled" and r.get("result") == "launched") == ["files#1", "reader#1"]'
    check "the supervisor removed the groups it made" sh -c "! grep -q 'could not remove the run.s control groups' '$SS'"
    if [ -n "$CERT" ]; then
        check "... and the audit accepts the stream" python3 "$HERE/tools/varek_audit.py" --policy "$(echo "$SS" | sed 's/\.jsonl$/.policy/')" --checker "$CERT" "$SS"
    fi
    lbundle self "$B/s/l.sock" "$B/f/sub.json" sub "/varek/init -- /probe subself"; run self
    check "refused: a sub-agent launched by the container's first process itself (subagent_first_process)" sh -c \
        "grep -qx 'subself: EACCES' '$B/self.out' && grep -F '\"target\":\"/sub\"' '$(stream l self)' | grep -q '\"rule\":\"subagent_first_process\"'"
    if [ -n "$CERT" ]; then
        check "... and the audit accepts the stream (a refusal the Warden writes)" \
            python3 "$HERE/tools/varek_audit.py" --policy "$(stream l self | sed 's/\.jsonl$/.policy/')" --checker "$CERT" "$(stream l self)"
    fi
    lbundle splan "$B/s/l.sock" "$B/f/sub.json" sub "/varek/init -- /probe sub" plan=sub; run splan
    check "a pod's plan of subagent steps: decided, the run held to it, the sub-agent and the server ran" sh -c \
        "grep -qx 'sub /data/allowed: ok' '$B/splan.out' && grep -qx 'srv /data/denied: ok' '$B/splan.out' && grep -q 'the run is held to its plan' '$(stream l splan)'"
    lbundle sstdio "$B/s/l.sock" "$B/f/sub.json" sub "/varek/init -- /probe sub" plan=stdio; run sstdio
    check "a plan with an mcp_call to a stdio server: UNKNOWN, as on a host (D4 (b)), the plan refused" sh -c \
        "! grep -q '^launch_sub' '$B/sstdio.out' && grep -q 'a stdio MCP server.s calls are not decided' '$(stream l sstdio)' && grep -q 'its plan is refused' '$(stream l sstdio)'"
    "$WARDEN" "$P/subw.policy" --oci-filter > "$B/f/subw.json" 2>/dev/null
    lbundle subw "$B/s/l.sock" "$B/f/subw.json" subw "/varek/init -- /probe sub" cg2; run subw
    check "refused: a policy that lets the agent write the container's control groups" refused l subw 'with sub-agents named, the control groups must be out of the agent.s reach'
fi

echo "== 12. the on-behalf-of chain under the node agent (v1.36 step 6, D5) =="
if [ -z "$WARDEN" ] || ! declare -f lbundle > /dev/null || [ ! -x "$HERE/warden-secrets" ] || ! python3 -c 'import cryptography' 2>/dev/null; then
    skip "the on-behalf-of chain under the node agent (needs the launcher, as section 6, warden-secrets and python3-cryptography)"
else
    I="$B/idp"; mkdir -p "$I"; chmod 755 "$I"
    python3 "$HERE/tests/v1281_idp.py" serve "$I" > "$I/serve.out" 2>&1 &
    SERVERS="$SERVERS $!"
    for _ in $(seq 100); do [ -f "$I/port" ] && break; sleep 0.1; done
    ISS="https://127.0.0.1:$(cat "$I/port")"
    python3 "$HERE/tests/v1281_idp.py" svid "$I"
    chmod 644 "$I/ca.pem" "$I"/bundle*.pem
    printf 'oidc_ca = %s/ca.pem\n' "$I" > "$B/obo.conf"; chmod 600 "$B/obo.conf"
    printf 'require warden 1.29\nrequire on-behalf-of\ntrust issuer %s audience varek-agent\ntrust spiffe example.test bundle %s/bundle.pem\nallow path /data/allowed readonly\n' \
        "$ISS" "$I" > "$P/obo.policy"
    printf 'require warden 1.29\ntrust issuer %s audience varek-agent\nallow path /data/allowed readonly\n' "$ISS" > "$P/oboopt.policy"
    chmod 644 "$P/obo.policy" "$P/oboopt.policy"
    # the kubelet's directory, as it keeps a pod's Secret volume: KEY -> ..data/KEY, ..data -> ..<time>/
    K="$B/kubelet"
    kvol() {   # UID [TOKEN-CASE]: the pod's varek-obo volume, its token minted by the stand-in issuer
        local v="$K/pods/$1/volumes/kubernetes.io~secret/varek-obo"
        mkdir -p "$v/..2026_10_28_10_00_00.1"; chmod 755 "$K" "$K/pods" "$K/pods/$1" "$K/pods/$1/volumes" "$(dirname "$v")" 2>/dev/null
        python3 "$HERE/tests/v1281_idp.py" mint "$I" "${2:-es256}" > "$v/..2026_10_28_10_00_00.1/token"
        chmod 644 "$v/..2026_10_28_10_00_00.1/token"
        ln -sfn ..2026_10_28_10_00_00.1 "$v/..data"; ln -sfn ..data/token "$v/token"
    }
    U1=0a1b2c3d-0000-4000-8000-000000000001
    kvol "$U1"
    # a stand-in varek-svid: says how it was asked, and gives the stand-in authority's SVID
    printf '#!/bin/sh\necho "$*" >> %s/svid.args\nwhile [ $# -gt 0 ]; do case "$1" in -out) out="$2" ;; esac; shift 2; done\n[ -n "${VAREK_TEST_SVID_FAIL:-}" ] && { echo "varek-svid: no SVID for the process" >&2; exit 1; }\numask 077; cp %s/svid-good.pem "$out"\n' "$B" "$I" > "$B/fake-svid"
    chmod 755 "$B/fake-svid"; : > "$B/svid.args"
    check "--oci-filter: a policy that says \`require on-behalf-of\`, carried (v1.36 step 6)" sh -c "'$WARDEN' '$P/obo.policy' --oci-filter > '$B/f/obo.json' 2> '$B/f/obo.err'"
    check "a node agent with the kubelet's directory (--node-kubelet) and SPIRE's (--node-spire-socket, --node-spire-self)" \
        agent ob "$B/pol" --node-launcher "$B/varek-init" --node-kubelet "$K" --node-spire-socket "$B/spire.sock" \
        --node-spire-self spiffe://example.test/varek-node --node-svid-helper "$B/fake-svid" --secrets-conf "$B/obo.conf"
    ob() { lbundle "$1" "$B/s/ob.sock" "$B/f/obo.json" "$2" "/varek/init -- /probe" "${@:3}"; run "$1"; }
    ob ob1 obo "uid=$U1" obo=alice-token
    sed 's/^/     /' "$B/ob1.out"
    OS="$(stream ob ob1)"
    check "a pod acting for its user: the command ran, a read the policy allows answered" said ob1 "read_allowed: ok allowed content"
    check "... the user's token from its Secret volume on the node, verified by warden-secrets" \
        grep -q 'on behalf of alice@example.test (issuer .*): token verified (ES256, key ec1)' "$OS"
    check "... the agent's SVID from SPIRE, verified against the trust bundle" grep -q 'agent spiffe://example.test/agents/coder: SVID verified' "$OS"
    check "... run_start names the user and the agent's SPIFFE ID" rec ob ob1 \
        'S and S[0]["on_behalf_of"]["user"]["subject"] == "alice@example.test" and S[0]["on_behalf_of"]["agent"]["spiffe_id"] == "spiffe://example.test/agents/coder"'
    OP="$(python3 -c 'import json,sys; print(next(json.loads(l) for l in open(sys.argv[1]) if "\"event\":\"run_start\"" in l)["node"]["pid"])' "$OS" 2>/dev/null)"
    check "... varek-svid asked by the container's process id, the node agent's own SPIFFE ID left out" sh -c \
        "[ -n '$OP' ] && grep -qx -- '-socket $B/spire.sock -pid $OP -out $(cd "$B/s" && pwd -P)/v1340-ob1.svid -not spiffe://example.test/varek-node' '$B/svid.args'"
    check "... the copies of the token and the SVID gone once read" sh -c "! ls '$B/s' | grep -q '\\.obo\$\\|\\.svid\$'"
    TOK="$(cat "$K/pods/$U1/volumes/kubernetes.io~secret/varek-obo/token")"
    check "... the token nowhere in the stream" sh -c "! grep -qF -- '${TOK##*.}' '$OS'"
    if [ -n "$CERT" ]; then
        check "... and the audit accepts the stream" python3 "$HERE/tools/varek_audit.py" --policy "${OS%.jsonl}.policy" --checker "$CERT" "$OS"
    fi
    orefused() { ! grep -q '^read_allowed' "$B/$1.out" && grep -q "$2" "$(stream ob "$1")"; }
    ob ob2 obo "uid=$U1"
    check "refused: \`require on-behalf-of\`, and its pod names no user's token" orefused ob2 'names no user.s token (varek.dev/on-behalf-of'
    ob ob3 obo uid=0a1b2c3d-0000-4000-8000-0000000000ff obo=alice-token
    check "refused: the pod's token volume not on the node" orefused ob3 'is not on the node'
    U4=0a1b2c3d-0000-4000-8000-000000000004; kvol "$U4"
    printf 'elsewhere\n' > "$B/outside-token"; chmod 600 "$B/outside-token"
    ln -sfn "$B/outside-token" "$K/pods/$U4/volumes/kubernetes.io~secret/varek-obo/token"
    ob ob4 obo "uid=$U4" obo=alice-token
    check "refused: a token key that leads out of its volume" orefused ob4 'holds no key token inside it'
    U5=0a1b2c3d-0000-4000-8000-000000000005; kvol "$U5"
    chown 65534 "$K/pods/$U5/volumes/kubernetes.io~secret/varek-obo/..data/token"
    ob ob5 obo "uid=$U5" obo=alice-token
    check "refused: a token that is not root's" orefused ob5 'is not a file of root.s'
    U6=0a1b2c3d-0000-4000-8000-000000000006; kvol "$U6" expired
    ob ob6 obo "uid=$U6" obo=alice-token
    check "refused: an expired token (warden-secrets, as on a host)" orefused ob6 "the user's token: .*expired"
    VAREK_TEST_SVID_FAIL=1 agent obf "$B/pol" --node-launcher "$B/varek-init" --node-kubelet "$K" \
        --node-spire-socket "$B/spire.sock" --node-svid-helper "$B/fake-svid" --secrets-conf "$B/obo.conf"
    lbundle ob7 "$B/s/obf.sock" "$B/f/obo.json" obo "/varek/init -- /probe" "uid=$U1" obo=alice-token; run ob7
    check "refused: an SVID the node's SPIRE agent does not give" sh -c \
        "! grep -q '^read_allowed' '$B/ob7.out' && grep -q 'cannot get the pod.s SVID from the node.s SPIRE agent' '$(stream obf ob7)' && grep -q 'varek-svid: no SVID for the process' '$(stream obf ob7)'"
    "$WARDEN" "$P/oboopt.policy" --oci-filter > "$B/f/oboopt.json" 2>/dev/null
    lbundle ob8 "$B/s/ob.sock" "$B/f/oboopt.json" oboopt "/varek/init -- /probe" "uid=$U1"; run ob8
    check "a policy that trusts an issuer, its pod naming no token: runs, for no user (as on a host)" sh -c \
        "grep -qx 'read_allowed: ok allowed content' '$B/ob8.out' && ! grep -q 'on behalf of' '$(stream ob ob8)'"
    check "refused: --on-behalf-of or --agent-svid given to the node agent itself (each pod names its own)" sh -c \
        "'$WARDEN' '$B/pol' --node-agent '$B/s/x2.sock' --node-streams '$B/streams' --on-behalf-of '$B/obo.conf' > /dev/null 2>&1; [ \$? = 2 ] &&
         '$WARDEN' '$B/pol' --node-agent '$B/s/x2.sock' --node-streams '$B/streams' --agent-svid '$B/obo.conf' > /dev/null 2>&1; [ \$? = 2 ]"
fi

echo
[ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"
[ "$fail" = 0 ]
