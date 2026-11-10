#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# crio_trial.sh — v1.34 step 9 (docs/security/v1.34-kubernetes.md): the
# 24-hour runs' agent (pod_agent.py) and policy (policy_v1340.txt) checked on one
# host before a cluster's run: the agent in the python:3.12-bookworm image,
# in a pod CRI-O runs (its own network and PID namespaces, a bridge network),
# as user 65534 with every capability dropped, no new privileges, VAREK's
# unsupervised profile, under the NRI plugin (varek-nri) and the node agent,
# its stream signed with a node key and anchored. The services it calls
# (servers.py) run on the host, on the bridge's address. It passes when:
#   - every turn of work was done (files, python3, git, the allowed service);
#   - every probe held (/etc/shadow, outside its project, its own program,
#     the denied service by name and by address, the instance metadata);
#   - the denied service saw no request; the allowed one, the agent's;
#   - the stream, named by the container, is audited: signed, anchored,
#     each decision under its policy.
#
#   sudo varek/v1_4/tests/soak_v1340/crio_trial.sh [--seconds 120] [--interval 2] [--runtime runc] [--out DIR]
#
# As root, on a host with CRI-O 1.35 or later (NRI on), crictl, Go, gcc and
# python3, from this checkout. The summary is DIR/summary.txt (default
# /var/tmp/varek-soak-trial).
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
SOAK="$HERE/tests/soak_v1340"
OUT=/var/tmp/varek-soak-trial SECONDS_RUN=120 RT=runc INTERVAL=2
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --seconds) SECONDS_RUN="$2"; shift 2 ;;
        --runtime) RT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "crio_trial.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ "$(id -u)" = 0 ] || { echo "crio_trial.sh: run as root" >&2; exit 2; }
for t in crio crictl go gcc make python3; do
    command -v "$t" > /dev/null || { echo "crio_trial.sh: $t is needed" >&2; exit 2; }
done
IMG=mirror.gcr.io/library/python:3.12-bookworm
BR=10.89.0.1
rm -rf "$OUT"; mkdir -p "$OUT"
SUM="$OUT/summary.txt" fail=0
say() { echo "$*" | tee -a "$SUM"; }
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then say "  PASS   $d"; else say "  FAIL   $d"; fail=1; fi; }
say "crio_trial.sh $(TZ=America/Chicago date '+%Y-%m-%d %H:%M %Z'); $(uname -sr); $(crio --version 2>/dev/null | head -1); commit $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"

echo "== building the Warden, the launcher, the plugin and the tools"
make -s -C "$HERE" warden varek-init tools/varek_keygen tools/vdp_cert_check > "$OUT/build.log" 2>&1 &&
    (cd "$HERE/k8s" && go build -o "$OUT/varek-nri" ./cmd/varek-nri) >> "$OUT/build.log" 2>&1 ||
    { tail -20 "$OUT/build.log"; echo "crio_trial.sh: the build failed" >&2; exit 1; }
install -m 755 "$HERE/warden" "$OUT/warden"; install -m 755 "$HERE/varek-init" "$OUT/varek-init"
"$HERE/tools/varek_keygen" "$OUT/node.key" > /dev/null
mkdir -m 755 "$OUT/policies" "$OUT/policies/soak" "$OUT/streams"; mkdir -m 700 "$OUT/sock"
sed "s/@ALLOWED@/$BR:8080/" "$SOAK/policy_v1340.txt" > "$OUT/policies/soak/agent.policy"
chmod 644 "$OUT/policies/soak/agent.policy"
mkdir -p "$OUT/seccomp/varek" "$OUT/code" "$OUT/work" "$OUT/outside"
echo '{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[]}' > "$OUT/seccomp/varek/unsupervised.json"
install -m 644 "$SOAK/pod_agent.py" "$OUT/code/pod_agent.py"
chmod 1777 "$OUT/work"; chmod 755 "$OUT/outside"

CNI=""
if [ -z "$(ls /etc/cni/net.d 2>/dev/null)" ]; then
    CNI=/etc/cni/net.d/10-varek-test.conflist
    mkdir -p /etc/cni/net.d
    cat > "$CNI" <<'EOF'
{"cniVersion": "1.0.0", "name": "varek-test", "plugins": [
  {"type": "bridge", "bridge": "varek-test0", "isGateway": true, "ipMasq": false,
   "ipam": {"type": "host-local", "ranges": [[{"subnet": "10.89.0.0/24"}]]}},
  {"type": "loopback"}]}
EOF
fi
if [ ! -S /var/run/crio/crio.sock ]; then
    crio > "$OUT/crio.log" 2>&1 &
    for _ in $(seq 100); do [ -S /var/run/crio/crio.sock ] && break; sleep 0.2; done
fi
crictl -t 600s pull "$IMG" > "$OUT/pull.log" 2>&1 || { cat "$OUT/pull.log"; echo "crio_trial.sh: the image did not pull" >&2; exit 1; }
"$OUT/warden" "$OUT/policies" --node-agent "$OUT/sock/node.sock" --node-streams "$OUT/streams" \
    --node-launcher "$OUT/varek-init" --sign-key "$OUT/node.key" --checkpoint-every 16 \
    --anchor "$OUT/streams/anchor" > "$OUT/node-agent.log" 2>&1 &
AGENT=$!
"$OUT/varek-nri" -warden "$OUT/warden" -policies "$OUT/policies" -listener "$OUT/sock/node.sock" \
    -launcher "$OUT/varek-init" > "$OUT/varek-nri.log" 2>&1 &
PLUGIN=$!
P=""
cleanup() {
    [ -n "$P" ] && { crictl stopp "$P" > /dev/null 2>&1; crictl rmp "$P" > /dev/null 2>&1; }
    kill $PLUGIN $AGENT ${SRV_A:-} ${SRV_D:-} 2>/dev/null
    [ -n "$CNI" ] && rm -f "$CNI"
}
trap cleanup EXIT
for _ in $(seq 50); do grep -q '^varek-nri: runtime' "$OUT/varek-nri.log" && break; sleep 0.2; done
say "  plugin: $(grep -m1 '^varek-nri: runtime' "$OUT/varek-nri.log" || echo "NOT registered: $(tail -1 "$OUT/varek-nri.log")")"

echo "== the pod ($SECONDS_RUN s)"
python3 - "$OUT" "$IMG" "$SECONDS_RUN" "$BR" "$INTERVAL" <<'EOF'
import json, sys, uuid
out, img, secs, br, interval = sys.argv[1:]
ns = {"network": 0, "pid": 1}
pod = {"metadata": {"name": "soak-agent", "namespace": "soak", "uid": str(uuid.uuid4()), "attempt": 0},
       "log_directory": out, "annotations": {"varek.dev/policy": "agent"},
       "linux": {"security_context": {"namespace_options": ns}}}
cmd = ["/usr/local/bin/python3", "/varek-soak/pod_agent.py", "--interval", interval, "--seconds", secs,
       "--probe-every", "3", "--outside", "/outside", "--project", "/work/project",
       "--allowed", f"http://{br}:8080/", "--denied", f"http://denied.example.test:8081/",
       "--denied-ip", f"http://{br}:8081/"]
ctr = {"metadata": {"name": "agent"}, "image": {"image": img}, "command": cmd, "log_path": "agent.log",
       "envs": [{"key": "HOME", "value": "/work"}, {"key": "GIT_CONFIG_NOSYSTEM", "value": "1"},
                {"key": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
       "mounts": [{"container_path": "/work", "host_path": f"{out}/work"},
                  {"container_path": "/outside", "host_path": f"{out}/outside"},
                  {"container_path": "/varek-soak", "host_path": f"{out}/code", "readonly": True}],
       "linux": {"security_context": {"namespace_options": ns, "run_as_user": {"value": 65534},
                                      "run_as_group": {"value": 65534}, "readonly_rootfs": True,
                                      "no_new_privs": True, "capabilities": {"drop_capabilities": ["ALL"]},
                                      "seccomp": {"profile_type": 2,
                                                  "localhost_ref": f"{out}/seccomp/varek/unsupervised.json"}}}}
json.dump(pod, open(f"{out}/pod.json", "w"))
json.dump(ctr, open(f"{out}/ctr.json", "w"))
EOF
P="$(crictl -t 600s runp --runtime "$RT" "$OUT/pod.json" 2> "$OUT/runp.err")"
[ -n "$P" ] || { tail -3 "$OUT/runp.err"; echo "crio_trial.sh: the pod did not start" >&2; exit 1; }
# the services, on the bridge (up once the pod's network made it)
python3 "$SOAK/servers.py" --name allowed --port 8080 > "$OUT/allowed.jsonl" 2>&1 &
SRV_A=$!
python3 "$SOAK/servers.py" --name denied --port 8081 > "$OUT/denied.jsonl" 2>&1 &
SRV_D=$!
sleep 1
C="$(crictl -t 600s create "$P" "$OUT/ctr.json" "$OUT/pod.json" 2> "$OUT/create.err")"
[ -n "$C" ] || { tail -3 "$OUT/create.err"; echo "crio_trial.sh: the container was refused" >&2; exit 1; }
crictl -t 60s start "$C" > /dev/null 2> "$OUT/start.err"
for _ in $(seq $((SECONDS_RUN + 120))); do
    [ "$(crictl inspect -o go-template --template '{{.status.state}}' "$C" 2>/dev/null)" = CONTAINER_EXITED ] && break
    sleep 1
done
crictl logs "$C" > "$OUT/agent.jsonl" 2> "$OUT/agent.err"
IP="$(crictl inspectp -o go-template --template '{{.status.network.ip}}' "$P" 2>/dev/null)"
sleep 2

echo "== the checks"
check "the agent ran to its end: every turn of work done (files, python3, git, the allowed service)" python3 - "$OUT/agent.jsonl" <<'EOF'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
work = [r for r in recs if r.get("task") == "work"]
bad = [r for r in work if not r.get("ok")]
for r in bad[:5]:
    print(r, file=sys.stderr)
sys.exit(0 if recs and recs[0].get("ok") and recs[-1].get("end") and work and not bad and
         any(r.get("commit") for r in work) else 1)
EOF
check "every probe held (shadow, outside, own program, denied by name and address, metadata)" python3 - "$OUT/agent.jsonl" <<'EOF'
import json, sys
pr = [json.loads(l) for l in open(sys.argv[1]) if l.startswith('{"t"') and '"probe"' in l]
kinds = {r["probe"] for r in pr}
sys.exit(0 if pr and all(r.get("held") for r in pr) and len(kinds) == 6 else 1)
EOF
check "the denied service saw no request from the pod; the allowed one, the agent's" python3 - "$OUT" "$IP" <<'EOF'
import json, sys
out, ip = sys.argv[1:]
def reqs(n):
    return [json.loads(l) for l in open(f"{out}/{n}.jsonl") if l.startswith("{") and '"path"' in l]
sys.exit(0 if ip and not reqs("denied") and any(r["client"] == ip for r in reqs("allowed")) else 1)
EOF
S="$(ls "$OUT"/streams/*.jsonl 2>/dev/null | head -1)"
check "its stream audited: signed with the node key, anchored, each decision under its policy" \
    python3 "$HERE/tools/varek_audit.py" --policy "${S%.jsonl}.policy" --checker "$HERE/tools/vdp_cert_check" \
    --pubkey "$OUT/node.key.pub" --anchor "$OUT/streams/anchor" "$S"
python3 "$HERE/tools/varek_audit.py" --policy "${S%.jsonl}.policy" --checker "$HERE/tools/vdp_cert_check" \
    --pubkey "$OUT/node.key.pub" --anchor "$OUT/streams/anchor" "$S" > "$OUT/audit.txt" 2>&1
python3 - "$OUT/agent.jsonl" "$S" <<'EOF' | tee -a "$SUM"
import collections, json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.startswith("{")]
work = [r for r in recs if r.get("task") == "work"]
pr = collections.Counter((r["probe"], r.get("result")) for r in recs if "probe" in r)
st = [json.loads(l) for l in open(sys.argv[2]) if l.startswith("{")]
dec = collections.Counter(r.get("decision_final") for r in st if "decision_final" in r)
print(f"  turns {len(work)} (commits {sum(1 for r in work if r.get('commit'))}); probes {dict(pr)}")
print(f"  stream {len(st)} records; decisions {dict(dec)}")
EOF
echo
[ "$fail" = 0 ] && say "crio_trial: PASS" || say "crio_trial: FAIL"
[ "$fail" = 0 ]
