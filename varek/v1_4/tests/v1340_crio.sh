#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# v1340_crio.sh — v1.34 step 3 (docs/security/v1.34-kubernetes.md): the NRI
# plugin (k8s/cmd/varek-nri), the node agent and the launcher (varek-init)
# together under CRI-O, as step 1's sixth measurement ran their stand-ins.
# On a host with CRI-O 1.35 or later (NRI on), crictl and Go, as root, from a
# checkout of this branch. The node agent takes each pod's policy by name
# from a directory; four pods of the busybox image, each as user 65534 with
# every capability dropped, no new privileges and the RuntimeDefault profile
# (as Pod Security's "restricted" level requires):
#   A  annotated varek.dev/policy: busybox, its root read-only: the plugin's
#      filter replaces RuntimeDefault, the launcher runs first and applies the
#      launch set; inside, a read the policy allows and one it does not, a
#      program it allows to launch and one it does not, a copy written to
#      /work (noexec) and launched; its stream in the node agent's directory;
#   B  not annotated: left as it is;
#   C  annotated, its root writable: refused by the node agent (D4);
#   D  annotated with a policy that does not exist: refused by the plugin
#      (the container is not created).
# Under each runtime CRI-O has of crun and runc (--runtimes). The summary is
# DIR/summary.txt (default /var/tmp/varek-crio).
#
#   varek/v1_4/tests/v1340_crio.sh [--out DIR] [--runtimes "crun runc"]
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/var/tmp/varek-crio RUNTIMES="crun runc"
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --runtimes) RUNTIMES="$2"; shift 2 ;;
        *) echo "v1340_crio.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "v1340_crio.sh: run as root" >&2; exit 2; }
for t in crio crictl go gcc make python3; do
    command -v "$t" > /dev/null || { echo "v1340_crio.sh: $t is needed" >&2; exit 2; }
done
POD_IMG=mirror.gcr.io/library/busybox:1.36
rm -rf "$OUT"; mkdir -p "$OUT"
SUM="$OUT/summary.txt" fail=0
say() { echo "$*" | tee -a "$SUM"; }
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then say "  PASS   $d"; else say "  FAIL   $d"; fail=1; fi; }
say "v1340_crio.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); $(crio --version 2>/dev/null | head -1); commit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"

echo "== building the Warden, the launcher and the plugin"
make -s -C "$HERE" warden varek-init > "$OUT/build.log" 2>&1 &&
    (cd "$HERE/k8s" && go build -o "$OUT/varek-nri" ./cmd/varek-nri) >> "$OUT/build.log" 2>&1 ||
    { tail -20 "$OUT/build.log"; echo "v1340_crio.sh: the build failed" >&2; exit 1; }
install -m 755 "$HERE/warden" "$OUT/warden"; install -m 755 "$HERE/varek-init" "$OUT/varek-init"
# step 5: the policies of the pods' namespace (varek), as the plugin's -sync writes them
mkdir -m 755 "$OUT/policies" "$OUT/policies/varek" "$OUT/streams"; mkdir -m 700 "$OUT/sock"
# busybox's commands are hardlinks of one file, and its shell runs some
# without a launch: each name is its own rule (through overlayfs a Landlock
# rule on one name does not cover another, so the launcher is given each),
# and each check below launches its program (exec in a subshell)
cat > "$OUT/policies/varek/busybox.policy" <<'EOF'
require warden 1.29
allow path /bin/ readonly
allow path /lib/ readonly
allow path /lib64/ readonly
allow path /etc/ld.so.cache readonly
allow path /etc/hostname readonly
allow path /proc/self/ readonly
allow path /dev/null
allow path /work/
allow exec /bin/sh
allow exec /bin/cat
allow exec /bin/cp
allow exec /bin/true
allow exec /bin/sleep
EOF
chmod 644 "$OUT/policies/varek/busybox.policy"

if [ ! -S /var/run/crio/crio.sock ]; then
    crio > "$OUT/crio.log" 2>&1 &
    for _ in $(seq 100); do [ -S /var/run/crio/crio.sock ] && break; sleep 0.2; done
fi
crictl pull "$POD_IMG" > "$OUT/pull.log" 2>&1 || { cat "$OUT/pull.log"; echo "v1340_crio.sh: the image did not pull" >&2; exit 1; }
"$OUT/warden" "$OUT/policies" --node-agent "$OUT/sock/node.sock" --node-streams "$OUT/streams" \
    --node-launcher "$OUT/varek-init" > "$OUT/node-agent.log" 2>&1 &
AGENT=$!
"$OUT/varek-nri" -warden "$OUT/warden" -policies "$OUT/policies" -listener "$OUT/sock/node.sock" \
    -launcher "$OUT/varek-init" > "$OUT/varek-nri.log" 2>&1 &
PLUGIN=$!
trap 'kill $PLUGIN $AGENT 2>/dev/null' EXIT
for _ in $(seq 50); do grep -q '^varek-nri: runtime' "$OUT/varek-nri.log" && break; sleep 0.2; done
say "  plugin: $(grep -m1 '^varek-nri: runtime' "$OUT/varek-nri.log" || echo "NOT registered: $(tail -1 "$OUT/varek-nri.log")")"

# The checks pod A runs inside, as its user (the shell's builtins where the
# policy allows no launch)
CHECK='while read -r k v; do case "$k" in Seccomp:|NoNewPrivs:) echo "$k $v" ;; esac; done < /proc/self/status
(exec /bin/cat /etc/hostname) > /dev/null 2>&1; echo "read_allowed: $?"
(exec /bin/cat /etc/passwd) > /dev/null 2>&1; echo "read_denied: $?"
(exec /bin/true); echo "launch_allowed: $?"
(exec /bin/ls /) > /dev/null 2>&1; echo "launch_denied: $?"
(exec /bin/cp /bin/true /work/copy) 2>/dev/null; (exec /work/copy) 2>/dev/null; echo "launch_written: $?"
(exec /bin/sleep 1)'

for rt in $RUNTIMES; do
    say "== $rt"
    for pod in a:busybox:true b::true c:busybox:false d:nosuch:true; do
        IFS=: read -r name pol ro <<< "$pod"
        W="$OUT/work-$rt-$name"; mkdir -p "$W"; chmod 1777 "$W"
        python3 - "$rt" "$name" "$pol" "$ro" "$POD_IMG" "$CHECK" "$W" "$OUT" <<'EOF'
import json, sys, uuid
rt, name, pol, ro, img, check, work, out = sys.argv[1:]
pod = {"metadata": {"name": f"varek-{name}-{rt}", "namespace": "varek", "uid": str(uuid.uuid4()), "attempt": 0},
       "log_directory": out, "linux": {"security_context": {"namespace_options": {"network": 2, "pid": 1}}}}
if pol:
    pod["annotations"] = {"varek.dev/policy": pol}
ctr = {"metadata": {"name": "agent"}, "image": {"image": img}, "command": ["/bin/sh", "-c", check],
       "log_path": f"agent-{rt}-{name}.log", "mounts": [{"container_path": "/work", "host_path": work}],
       "linux": {"security_context": {"namespace_options": {"network": 2, "pid": 1},
                                      "run_as_user": {"value": 65534}, "readonly_rootfs": ro == "true",
                                      "no_new_privs": True, "capabilities": {"drop_capabilities": ["ALL"]},
                                      "seccomp": {"profile_type": 0}}}}
json.dump(pod, open(f"{out}/pod-{rt}-{name}.json", "w"))
json.dump(ctr, open(f"{out}/ctr-{rt}-{name}.json", "w"))
EOF
        L="$OUT/$rt-$name"
        : > "$L.log"
        P="$(crictl runp --runtime "$rt" "$OUT/pod-$rt-$name.json" 2> "$L.runp")"
        [ -z "$P" ] && { say "  pod $name: runp failed: $(tail -1 "$L.runp")"; fail=1; continue; }
        C="$(crictl create "$P" "$OUT/ctr-$rt-$name.json" "$OUT/pod-$rt-$name.json" 2> "$L.create")"
        if [ -n "$C" ]; then
            crictl start "$C" > /dev/null 2> "$L.start"
            for _ in $(seq 60); do
                [ "$(crictl inspect -o go-template --template '{{.status.state}}' "$C" 2>/dev/null)" = CONTAINER_EXITED ] && break
                sleep 1
            done
            crictl logs "$C" > "$L.log" 2>&1
            echo "$C" > "$L.id"
        fi
        sed "s/^/     $name: /" "$L.log" | tee -a "$SUM" > /dev/null
        crictl stopp "$P" > /dev/null 2>&1; crictl rmp "$P" > /dev/null 2>&1
    done
    in_log() { grep -q "$2" "$OUT/$rt-$1.log"; }
    stream() { ls "$OUT"/streams/"$(cat "$OUT/$rt-$1.id" 2>/dev/null)".*.jsonl 2>/dev/null | head -1; }
    check "A: the plugin's filter (Seccomp 2), the launcher first, then the pod's command" sh -c \
        "grep -q '^Seccomp: 2' '$OUT/$rt-a.log' && grep -q '^varek-init: Landlock ABI [0-9]*, a launch set of [0-9]* file(s) applied; running /bin/sh' '$OUT/$rt-a.log'"
    check "A: a read the policy allows, and one it does not (refused)" sh -c \
        "grep -qx 'read_allowed: 0' '$OUT/$rt-a.log' && grep -q '^read_denied: [1-9]' '$OUT/$rt-a.log'"
    check "A: a program the policy allows to launch ran; one it does not, refused" sh -c \
        "grep -qx 'launch_allowed: 0' '$OUT/$rt-a.log' && grep -q '^launch_denied: [1-9]' '$OUT/$rt-a.log'"
    check "A: a copy written to /work (noexec) and launched: refused" grep -q '^launch_written: [1-9]' "$OUT/$rt-a.log"
    check "A: its stream, named by the container: the pod, the policy by its name, each name of busybox given to Landlock" python3 -c '
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
s = [r for r in recs if r.get("event") == "run_start"][0]["node"]
sys.exit(0 if s["policy"] == "busybox" and s["launcher"] is True and s["pod"]["name"] == "varek-a-'"$rt"'" and
         s["pod"]["namespace"] == "varek" and {"/bin/sh", "/bin/cat", "/bin/cp", "/bin/true", "/bin/sleep"} <= set(s["launch_paths"]) else 1)' "$(stream a)"
    check "B (not annotated): left as it is, its command ran" sh -c \
        "grep -qx 'launch_denied: 0' '$OUT/$rt-b.log' && ! grep -q varek-init '$OUT/$rt-b.log'"
    check "C (a writable root): refused by the node agent (D4), its command never ran" sh -c \
        "! grep -q '^read_allowed' '$OUT/$rt-c.log' && grep -q 'root file system is writable' '$(stream c)'"
    check "D (no such policy): refused by the plugin, the container not created" sh -c \
        "[ ! -s '$OUT/$rt-d.id' ] && grep -q 'no policy named nosuch' '$OUT/$rt-d.create'"
done
echo
[ "$fail" = 0 ] && say "v1340_crio: PASS" || say "v1340_crio: FAIL"
[ "$fail" = 0 ]
