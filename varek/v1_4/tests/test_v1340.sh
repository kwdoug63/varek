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
#      running as root;
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
#
#   test_v1340.sh VDP_CHECK VDP_CERT_CHECK WARDEN [VAREK_INIT]
set -u
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
    check "... and with --writable-exec (a pod's mounts are checked: D4)" sh -c \
        "'$WARDEN' /dev/null --node-agent /tmp/x.sock --node-streams /tmp --writable-exec; [ \$? = 2 ]"
    check "--node-launcher without --node-agent is refused" sh -c "'$WARDEN' /dev/null --node-launcher /bin/true -- /bin/true; [ \$? = 2 ]"
    check "--oci-filter with an agent to start is refused" sh -c "'$WARDEN' /dev/null --oci-filter -- /bin/true; [ \$? = 2 ]"
fi

case "$(uname -m)" in x86_64) ARCH=SCMP_ARCH_X86_64 ;; aarch64) ARCH=SCMP_ARCH_AARCH64 ;; *) ARCH="" ;; esac
if [ "$(id -u)" != 0 ] || [ -z "$WARDEN" ] || [ -z "$RUNC" ] || [ -z "$ARCH" ] || ! command -v python3 >/dev/null ||
   ! gcc -static -O2 -o /tmp/varek_v1340_probe.$$ "$HERE/tests/v1340_probe.c" -lpthread 2>/dev/null ||
   ! gcc -O2 -I"$HERE" -o /tmp/varek_v1340_ocif.$$ "$HERE/tests/v1340_oci_filter.c" -lseccomp 2>/dev/null; then
    rm -f /tmp/varek_v1340_probe.$$ /tmp/varek_v1340_ocif.$$
    skip "containers under the node agent (need root, the warden, runc, python3, a static gcc and libseccomp)"
    echo; [ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"; [ "$fail" = 0 ]; exit
fi
B="$(mktemp -d /tmp/varek_v1340.XXXXXX)"; chmod 755 "$B"
mkdir -p "$B/streams" "$B/state" "$B/f" "$B/rootfs/data" "$B/rootfs/proc" "$B/rootfs/dev" "$B/rootfs/tmp"
mkdir -m 700 "$B/s"                          # the sockets' directory: root's alone
mv /tmp/varek_v1340_probe.$$ "$B/rootfs/probe"; mv /tmp/varek_v1340_ocif.$$ "$B/ocif"
chmod 755 "$B/rootfs/probe"
echo "allowed content" > "$B/rootfs/data/allowed"; echo "secret" > "$B/rootfs/data/denied"; chmod 644 "$B/rootfs/data/"*
echo "root's" > "$B/rootfs/data/rootonly"; chmod 600 "$B/rootfs/data/rootonly"
"$B/ocif" 1 "$B/f" > /dev/null || { flunk "the filter's OCI form"; exit 1; }
printf 'allow path /data/allowed readonly\nallow path /data/rootonly readonly\nallow path /proc/self/status readonly\n' > "$B/p.txt"
printf 'require warden 1.24\nallow path /data/allowed readonly\nallow host example.com:443\n' > "$B/p_names.txt"

# a bundle: NAME POLICY-SOCKET ARGV0 NNP [UID]
bundle() {
    mkdir -p "$B/b-$1" && (cd "$B/b-$1" && "$RUNC" spec >/dev/null)
    python3 - "$B/b-$1/config.json" "$B/f/oci.json" "$2" "$3" "$4" "$ARCH" "$B/rootfs" "${5:-65534}" <<'PY'
import json, sys
cfg, flt, sock, argv0, nnp, arch, root, uid = sys.argv[1:]
c = json.load(open(cfg)); f = json.load(open(flt))
f.pop("warden_badarch", None); f["architectures"] = [arch]
for s in f["syscalls"]: s.pop("nr", None)
f["listenerPath"] = sock; f["listenerMetadata"] = "varek-test/" + cfg.split("/")[-2]
c["process"].update(terminal=False, args=argv0.split(), env=["PATH=/"], user={"uid": int(uid), "gid": int(uid)},
                    noNewPrivileges=nnp == "1", cwd="/")
c["root"] = {"path": root, "readonly": True}
c["linux"]["seccomp"] = f
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
check "a policy with what this step does not carry: refused, the container ended" sh -c \
    "! grep -q '^read_allowed' '$B/names.out' && grep -q 'refused: host-name rules (with step 4, the pod.s network) is not carried' '$(stream n names)'"
bundle rel "$B/s/a.sock" probe 1
run rel
check "a command named without an absolute path: refused" sh -c \
    "! grep -q '^read_allowed' '$B/rel.out' && grep -q 'must be named by an absolute path' '$(stream a rel)'"
bundle nnp "$B/s/a.sock" /probe 0
run nnp
check "a container with new privileges allowed: refused" sh -c \
    "! grep -q '^read_allowed' '$B/nnp.out' && grep -q 'without no_new_privs' '$(stream a nnp)'"
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
sleep 1
check "a state from a process that is not the runtime: refused" grep -q 'a connection refused: the descriptor sent is not a seccomp listener' "$B/a.log"
check "... and the process it names is not killed" kill -0 "$VICTIM"
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
    mkdir -m 755 "$B/pol"
    cp "$B/p.txt" "$B/pol/plain.policy"
    printf 'require warden 1.29\nallow path /data/allowed readonly\nallow path /ok readonly\nallow path /work/\nallow exec /ok\nallow exec /ok2\n' > "$B/pol/launch.policy"
    chmod 644 "$B/pol/"*.policy
    "$WARDEN" "$B/pol/launch.policy" --oci-filter > "$B/f/launch.json" 2>/dev/null
    "$WARDEN" "$B/pol/plain.policy" --oci-filter > "$B/f/plain.json" 2>/dev/null
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
    #   other-init (another copy of the launcher at /varek/init)
    lbundle() {
        local name="$1" sock="$2" filt="$3" ann="$4" args="$5"
        shift 5
        mkdir -p "$B/b-$name" && (cd "$B/b-$name" && "$RUNC" spec >/dev/null)
        python3 - "$B/b-$name/config.json" "$filt" "$sock" "$ARCH" "$B" "$ann" "$args" "$@" <<'PY'
import json, sys
cfg, flt, sock, arch, B, ann, args = sys.argv[1:8]
opts = set(sys.argv[8:])
c = json.load(open(cfg)); f = json.load(open(flt))
f["architectures"] = [arch]; f["listenerPath"] = sock; f["listenerMetadata"] = "varek-test/" + cfg.split("/")[-2]
c["process"].update(terminal=False, args=args.split(), env=["PATH=/"], user={"uid": 65534, "gid": 65534},
                    noNewPrivileges=True, cwd="/")
c["root"] = {"path": B + "/rootfs", "readonly": "rw-root" not in opts}
c["linux"]["seccomp"] = f
if ann != "-": c["annotations"] = {"varek.dev/policy": ann}
for m in c["mounts"]:
    if m["destination"] == "/dev": m["options"].append("noexec")      # as the NRI plugin makes it
c["mounts"].append({"destination": "/varek/init", "type": "bind", "source": B + ("/other-init" if "other-init" in opts else "/varek-init"),
                    "options": ["bind", "ro", "nosuid", "nodev"]})
c["mounts"].append({"destination": "/work", "type": "bind", "source": B + "/work",
                    "options": ["rbind", "rw", "nosuid", "nodev"] + ([] if "work-exec" in opts else ["noexec"])})
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
    check "a node agent with one policy that decides launches" agent d "$B/pol/launch.policy" --node-launcher "$B/varek-init"
    bundle direct "$B/s/d.sock" "/probe launch" 1; run direct
    check "decided launches without the launcher: refused" refused d direct 'decided launches without the launcher'
    check "the launcher with no node agent serving its view refuses to run the command" sh -c \
        "'$B/varek-init' -- /bin/true 2>/dev/null; [ \$? = 126 ]"
fi

echo
[ "$fail" = 0 ] && echo "test_v1340: PASS ($skips skipped)" || echo "test_v1340: FAIL"
[ "$fail" = 0 ]
