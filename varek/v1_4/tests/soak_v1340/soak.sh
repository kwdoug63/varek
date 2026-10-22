#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# soak.sh — v1.34 step 9 (docs/security/v1.34-kubernetes.md), the ship gate:
# a 24-hour run on a cluster (Amazon EKS, OpenShift; kind for a trial) of
# supervised agents, as the chart installs VAREK and a team runs its pods:
#   - one long agent pod on each node (pod_agent.py: an agent's work in its
#     project, files, python3, git, a cluster service its policy names) for
#     the whole run, a turn a minute, every tenth turn a probe;
#   - a short Job every --short-every minutes (a minute of turns and
#     probes): containers started and ended under the node agent all run;
#   - both in a namespace enforcing Pod Security's "restricted" level that
#     requires a policy (varek.dev/policy-required), each pod naming the
#     VarekPolicy `agent` and VAREK's unsupervised profile;
#   - the services they call (servers.py), unsupervised, in a namespace of
#     their own: one the policy names, one it does not.
# Every --sample seconds it records the pods, the finished pods' logs, each
# node's VAREK processes' memory (read in the node agent's container); each
# node's exporter log is followed throughout for its audit events and its
# errors. At the end it collects each node's streams and anchor
# and runs soak_check.py, which judges the run and writes report.txt.
#
#   varek/v1_4/tests/soak_v1340/soak.sh --image REPO:TAG [--digest sha256:...]
#        [--hours 24] [--interval 60] [--short-every 15] [--sample 300]
#        [--openshift] [--out DIR] [--check-only DIR]
#
# Against the cluster kubectl's current context names, with helm and python3
# where this runs, and this checkout's tools/varek_keygen and
# tools/vdp_cert_check built (make -C varek/v1_4 all). --image is the node
# image (packaging/container/Containerfile --target node) the nodes can
# pull; --digest pins it. --openshift: CRI-O, the chart's SCCs, the agents'
# user given by the namespace (README.md). The run's directory is DIR
# (default /var/tmp/varek-soak-k8s-<time>); DIR/report.txt holds the verdict.
# --check-only DIR runs soak_check.py again on a run already collected.
#
# It installs the chart as the release `varek` in varek-system and makes the
# namespaces varek-soak and varek-soak-svc; it removes nothing (README.md:
# what to remove, and the cluster).
set -u
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SOAK="$HERE/tests/soak_v1340"
IMAGE="" DIGEST="" HOURS=24 INTERVAL=60 SHORT_EVERY=15 SAMPLE=300 OPENSHIFT=0 OUT="" CHECK_ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --digest) DIGEST="$2"; shift 2 ;;
        --hours) HOURS="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --short-every) SHORT_EVERY="$2"; shift 2 ;;
        --sample) SAMPLE="$2"; shift 2 ;;
        --openshift) OPENSHIFT=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --check-only) CHECK_ONLY="$2"; shift 2 ;;
        -h|--help) sed -n '3,/^set -u$/{/^#/p}' "$0"; exit 0 ;;
        *) echo "soak.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
if [ -n "$CHECK_ONLY" ]; then
    exec python3 "$SOAK/soak_check.py" "$CHECK_ONLY" --tools "$HERE/tools"
fi
[ -n "$IMAGE" ] || { echo "usage: soak.sh --image REPO:TAG [options] (--help)" >&2; exit 2; }
# the chart pins the image by it: a digest no registry has is pods that never pull
[ -z "$DIGEST" ] || [[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    { echo "soak.sh: --digest takes sha256: and 64 hex digits (the one docker push printed), not '$DIGEST'" >&2; exit 2; }
for t in kubectl helm python3; do command -v "$t" > /dev/null || { echo "soak.sh: $t is needed" >&2; exit 2; }; done
[ -x "$HERE/tools/varek_keygen" ] && [ -x "$HERE/tools/vdp_cert_check" ] ||
    { echo "soak.sh: build the tools first (make -C varek/v1_4 all)" >&2; exit 2; }
OUT="${OUT:-/var/tmp/varek-soak-k8s-$(date +%Y%m%d-%H%M)}"
[ -e "$OUT" ] && { echo "soak.sh: $OUT exists (give another --out)" >&2; exit 2; }
mkdir -p "$OUT/logs" "$OUT/samples" "$OUT/exporter" "$OUT/streams" "$OUT/manifests"
NS=varek-system AG=varek-soak SVC=varek-soak-svc
AGENT_IMG=mirror.gcr.io/library/python:3.12-bookworm
LOG="$OUT/soak.log"
say() { echo "[$(TZ=America/Chicago date '+%H:%M:%S %Z')] $*" | tee -a "$LOG"; }
die() { say "soak.sh: $*"; exit 1; }
K() { kubectl "$@"; }

# --- 1. the cluster
say "soak.sh: $HOURS h on $(K config current-context 2>/dev/null); out $OUT; commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
K get nodes -o json > "$OUT/nodes.json" || die "kubectl cannot reach the cluster"
python3 - "$OUT/nodes.json" "$OUT/nodes.txt" <<'EOF' || die "the nodes cannot run the node agent (nodes.txt)"
import json, re, sys
nodes = json.load(open(sys.argv[1]))["items"]
out, bad = [], []
for n in nodes:
    i = n["status"]["nodeInfo"]
    ready = any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])
    rt = i["containerRuntimeVersion"]
    m = re.match(r"(containerd|cri-o)://v?(\d+)\.(\d+)", rt)
    ok = m and ((m[1] == "containerd" and (int(m[2]), int(m[3])) >= (2, 2)) or
                (m[1] == "cri-o" and (int(m[2]), int(m[3])) >= (1, 35)))
    line = f"{n['metadata']['name']}\t{i['architecture']}\t{rt}\t{i['kubeletVersion']}\t{i['osImage']}\t{i['kernelVersion']}\tready={ready}"
    # a node the agents cannot be placed on (a control plane's taint) runs no long agent
    if any(t.get("effect") in ("NoSchedule", "NoExecute") for t in n["spec"].get("taints", [])):
        print(line + "\t(tainted: no long agent)", file=sys.stderr)
        continue
    out.append(line)
    if not (ready and ok and i["architecture"] == "amd64"):
        bad.append(line)
open(sys.argv[2], "w").write("\n".join(out) + "\n")
print("\n".join(out))
sys.exit(1 if bad or not nodes else 0)
EOF
sed 's/^/  node: /' "$OUT/nodes.txt" | tee -a "$LOG"
NODES=($(cut -f1 "$OUT/nodes.txt"))

# --- 2. the chart
"$HERE/tools/varek_keygen" "$OUT/node.key" > /dev/null
K create namespace "$NS" > /dev/null 2>&1
K label namespace "$NS" --overwrite pod-security.kubernetes.io/enforce=privileged > /dev/null
K -n "$NS" delete secret varek-node-key > /dev/null 2>&1
K -n "$NS" create secret generic varek-node-key --from-file=key="$OUT/node.key" --from-file=key.pub="$OUT/node.key.pub" > /dev/null ||
    die "the node key's Secret"
REPO="${IMAGE%:*}" TAG="${IMAGE##*:}"
SETS=(--set image.repository="$REPO" --set image.tag="$TAG" --set signing.secretName=varek-node-key
      --set anchor.enabled=true)
[ -n "$DIGEST" ] && SETS+=(--set image.digest="$DIGEST")
[ "$OPENSHIFT" = 1 ] && SETS+=(--set runtime=cri-o --set openshift.enabled=true)
say "installing the chart (${SETS[*]})"
helm upgrade --install varek "$ROOT/packaging/helm/varek" -n "$NS" --wait --timeout 10m "${SETS[@]}" > "$OUT/helm.log" 2>&1 ||
    { tail -20 "$OUT/helm.log" | tee -a "$LOG"; die "the chart did not install"; }
# the node agent reads the node's key at its start, and an upgrade that changes
# only the Secret starts nothing again: on a run after another, its pods would
# go on signing with the last run's key. They are started again with this one.
DS="$(K -n "$NS" get ds -l app.kubernetes.io/component=node -o name)"
K -n "$NS" rollout restart "$DS" > /dev/null &&
    K -n "$NS" rollout status "$DS" --timeout 10m >> "$LOG" 2>&1 || die "the node agent's pods did not start again"
K -n "$NS" get pods -o wide >> "$LOG"
for _ in $(seq 60); do
    n=$(for p in $(K -n "$NS" get pod -l app.kubernetes.io/component=node -o name); do
            K -n "$NS" logs "$p" -c plugin 2>/dev/null | grep -m1 '^varek-nri: runtime'; done | wc -l)
    [ "$n" -ge "${#NODES[@]}" ] && break; sleep 5
done
[ "$n" -ge "${#NODES[@]}" ] || die "the plugin did not register on every node ($n of ${#NODES[@]})"
for p in $(K -n "$NS" get pod -l app.kubernetes.io/component=node -o name); do
    say "  $(K -n "$NS" logs "$p" -c plugin | grep -m1 '^varek-nri: runtime')"
done

# --- 3. the services, the policy, the agents' namespace
for n in "$SVC" "$AG"; do K create namespace "$n" > /dev/null 2>&1; done
K label namespace "$SVC" --overwrite pod-security.kubernetes.io/enforce=restricted > /dev/null
K label namespace "$AG" --overwrite pod-security.kubernetes.io/enforce=restricted varek.dev/policy-required=true > /dev/null
K -n "$SVC" create configmap soak-code --from-file="$SOAK/servers.py" --dry-run=client -o json | K apply -f - > /dev/null
K -n "$AG" create configmap soak-code --from-file="$SOAK/pod_agent.py" --dry-run=client -o json | K apply -f - > /dev/null
if [ "$OPENSHIFT" = 1 ]; then
    # the agents' service account may use the chart's supervised SCC
    K -n "$AG" create rolebinding varek-supervised --clusterrole=varek-supervised-scc --serviceaccount="$AG:default" \
        --dry-run=client -o json | K apply -f - > /dev/null
fi
python3 - "$OUT/manifests" "$AGENT_IMG" "$SVC" <<'EOF'
import json, sys
out, img, ns = sys.argv[1:]
items = []
for name in ("allowed", "denied"):
    lab = {"app": name}
    items += [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": ns},
               "spec": {"replicas": 1, "selector": {"matchLabels": lab}, "template": {"metadata": {"labels": lab}, "spec": {
                   "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                   "containers": [{"name": name, "image": img,
                                   "command": ["python3", "-u", "/code/servers.py", "--name", name, "--port", "8080"],
                                   "ports": [{"containerPort": 8080}],
                                   "securityContext": {"allowPrivilegeEscalation": False, "runAsUser": 65534,
                                                       "capabilities": {"drop": ["ALL"]}},
                                   "readinessProbe": {"tcpSocket": {"port": 8080}},
                                   "volumeMounts": [{"name": "code", "mountPath": "/code"}]}],
                   "volumes": [{"name": "code", "configMap": {"name": "soak-code"}}]}}}},
              {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns},
               "spec": {"selector": lab, "ports": [{"port": 8080, "targetPort": 8080}]}}]
json.dump({"apiVersion": "v1", "kind": "List", "items": items}, open(f"{out}/services.json", "w"), indent=1)
EOF
K apply -f "$OUT/manifests/services.json" > /dev/null || die "the services"
K -n "$SVC" rollout status deploy/allowed --timeout=10m > /dev/null && K -n "$SVC" rollout status deploy/denied --timeout=10m > /dev/null ||
    die "the services did not start"
DENIED_IP="$(K -n "$SVC" get svc denied -o jsonpath='{.spec.clusterIP}')"
ALLOWED_HOST="allowed.$SVC.svc.cluster.local:8080"
sed "s/@ALLOWED@/$ALLOWED_HOST/" "$SOAK/policy.txt" > "$OUT/policy.txt"
python3 - "$OUT/policy.txt" "$AG" > "$OUT/manifests/policy.json" <<'EOF'
import json, sys
print(json.dumps({"apiVersion": "varek.dev/v1alpha1", "kind": "VarekPolicy",
                  "metadata": {"name": "agent", "namespace": sys.argv[2]}, "spec": {"policy": open(sys.argv[1]).read()}}))
EOF
K apply -f "$OUT/manifests/policy.json" > "$OUT/policy.apply" 2>&1 || { cat "$OUT/policy.apply" | tee -a "$LOG"; die "the policy was refused"; }
sleep 10                                # the plugin's -sync writes it to each node

# --- 4. the agents
START=$(date +%s)
# the exporter's audit events and its errors, each node's followed across the
# kubelet's rotations of its log (10 MiB: a minute or two of a busy node's
# events), of which kubectl logs alone reads only the last; a pod replaced
# is found again, and what a reconnection reads twice is taken once
START_ISO="$(date -u -d @"$START" +%Y-%m-%dT%H:%M:%SZ)"
follow_exporter() {
    local node="$1" p
    while [ ! -e "$OUT/.done" ]; do
        p="$(K -n "$NS" get pod -l app.kubernetes.io/component=node --field-selector spec.nodeName="$node" \
             -o name 2>/dev/null | head -1)"
        # kubectl itself, not K: a child of this loop, ended with it
        [ -n "$p" ] && kubectl -n "$NS" logs -f "$p" -c exporter --since-time="$START_ISO" 2>/dev/null |
            grep --line-buffered -E '"event":"audit"|^[^{]' >> "$OUT/exporter/$node.jsonl"
        sleep 5
    done
}
FOLLOWERS=()
for n in "${NODES[@]}"; do follow_exporter "$n" & FOLLOWERS+=($!); done
stop_followers() { touch "$OUT/.done"; for f in "${FOLLOWERS[@]}"; do pkill -P "$f" 2>/dev/null; kill "$f" 2>/dev/null; done; }
trap stop_followers EXIT
END=$((START + $(python3 -c "print(int(float('$HOURS') * 3600))")))
python3 - "$OUT" "$AGENT_IMG" "$AG" "$SVC" "$DENIED_IP" "$HOURS" "$INTERVAL" "$SHORT_EVERY" "$OPENSHIFT" "${NODES[@]}" <<'EOF'
import json, sys
out, img, ns, svc, denied_ip, hours, interval, short_every, openshift, *nodes = sys.argv[1:]
long_s = int(float(hours) * 3600)
def pod_spec(args, node=None):
    sc = {"runAsNonRoot": True, "runAsGroup": 65534 if openshift == "0" else 1000,
          "seccompProfile": {"type": "Localhost", "localhostProfile": "varek/unsupervised.json"}}
    if openshift == "0":
        sc["runAsUser"] = 65534                     # on OpenShift the namespace's user (its SCC)
    spec = {"restartPolicy": "Never", "securityContext": sc, "enableServiceLinks": False,
            "containers": [{"name": "agent", "image": img,
                            "command": ["/usr/local/bin/python3", "/varek-soak/pod_agent.py"] + args +
                                       ["--outside", "/outside", "--project", "/work/project",
                                        "--allowed", f"http://allowed.{svc}.svc.cluster.local:8080/",
                                        "--denied", f"http://denied.{svc}.svc.cluster.local:8080/",
                                        "--denied-ip", f"http://{denied_ip}:8080/"],
                            "env": [{"name": "HOME", "value": "/work"}, {"name": "GIT_CONFIG_NOSYSTEM", "value": "1"},
                                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "512Mi"}},
                            "volumeMounts": [{"name": "work", "mountPath": "/work"},
                                             {"name": "outside", "mountPath": "/outside"},
                                             {"name": "code", "mountPath": "/varek-soak", "readOnly": True}]}],
            "volumes": [{"name": "work", "emptyDir": {}}, {"name": "outside", "emptyDir": {}},
                        {"name": "code", "configMap": {"name": "soak-code"}}]}
    if node:
        spec["nodeSelector"] = {"kubernetes.io/hostname": node}
    return spec
ann = {"varek.dev/policy": "agent"}
items = [{"apiVersion": "v1", "kind": "Pod",
          "metadata": {"name": f"long-{i}", "namespace": ns, "annotations": ann, "labels": {"soak": "long"}},
          "spec": pod_spec(["--interval", interval, "--seconds", str(long_s), "--probe-every", "10"], n)}
         for i, n in enumerate(nodes)]
items.append({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "short", "namespace": ns},
              "spec": {"schedule": f"*/{short_every} * * * *", "concurrencyPolicy": "Forbid",
                       "successfulJobsHistoryLimit": 3, "failedJobsHistoryLimit": 50,
                       "jobTemplate": {"spec": {"backoffLimit": 0, "activeDeadlineSeconds": 600, "template": {
                           "metadata": {"annotations": ann, "labels": {"soak": "short"}},
                           "spec": pod_spec(["--interval", "5", "--seconds", "60", "--probe-every", "4"])}}}}})
json.dump({"apiVersion": "v1", "kind": "List", "items": items}, open(f"{out}/manifests/agents.json", "w"), indent=1)
json.dump({"hours": float(hours), "interval": float(interval), "short_every": int(short_every), "nodes": nodes,
           "denied_ip": denied_ip, "openshift": openshift == "1"}, open(f"{out}/meta.json", "w"))
EOF
K apply -f "$OUT/manifests/agents.json" > "$OUT/agents.apply" 2>&1 || { cat "$OUT/agents.apply" | tee -a "$LOG"; die "the agents were refused"; }
python3 - "$OUT/meta.json" "$START" "$END" "$IMAGE" "$DIGEST" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))
m.update(start=int(sys.argv[2]), end=int(sys.argv[3]), image=sys.argv[4], digest=sys.argv[5])
json.dump(m, open(sys.argv[1], "w"))
EOF
say "the agents started: ${#NODES[@]} long (one a node), a short Job every $SHORT_EVERY min; until $(TZ=America/Chicago date -d @$END '+%Y-%m-%d %H:%M %Z')"

# --- 5. the samples
TARPY='import sys, tarfile
t = tarfile.open(fileobj=sys.stdout.buffer, mode="w|")
t.add("/var/log/varek", arcname=".")
t.close()'
MEMPY='import json, os, sys, time
out = []
for p in os.listdir("/proc"):
    if not p.isdigit(): continue
    try:
        st = dict(l.split(":", 1) for l in open(f"/proc/{p}/status") if ":" in l)
        cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
    except OSError:
        continue
    name = st["Name"].strip()
    exe = os.path.basename(cmd[0].decode(errors="replace")) if cmd and cmd[0] else name
    arg = " ".join(c.decode(errors="replace") for c in cmd[1:3])
    if name in ("warden", "varek-nri", "varek-admission") or (name.startswith("python") and "varek_" in arg):
        out.append({"pid": int(p), "ppid": int(st["PPid"]), "name": name, "arg": arg[:120],
                    "rss_kb": int(st.get("VmRSS", "0 kB").split()[0])})
print(json.dumps({"t": time.time(), "procs": out}))'
sample() {
    K -n "$AG" get pods -o json > "$OUT/samples/pods.json.tmp" 2>/dev/null && mv "$OUT/samples/pods.json.tmp" "$OUT/samples/pods.json"
    python3 - "$OUT" <<'EOF'
import json, os, subprocess, sys, time
out = sys.argv[1]
try:
    pods = json.load(open(f"{out}/samples/pods.json"))["items"]
except (OSError, ValueError):
    pods = []
row = {"t": time.time(), "pods": []}
for p in pods:
    st = (p.get("status") or {})
    cs = (st.get("containerStatuses") or [{}])[0]
    name = p["metadata"]["name"]
    row["pods"].append({"name": name, "phase": st.get("phase"), "node": p["spec"].get("nodeName"),
                        "restarts": cs.get("restartCount", 0), "kind": p["metadata"].get("labels", {}).get("soak")})
    if st.get("phase") in ("Succeeded", "Failed") and not os.path.exists(f"{out}/logs/{name}.jsonl"):
        with open(f"{out}/logs/{name}.jsonl", "w") as f:
            subprocess.run(["kubectl", "-n", "varek-soak", "logs", name], stdout=f, stderr=subprocess.DEVNULL)
        json.dump(p, open(f"{out}/logs/{name}.pod.json", "w"))
with open(f"{out}/samples/pods.jsonl", "a") as f:
    f.write(json.dumps(row) + "\n")
EOF
    for p in $(K -n "$NS" get pod -l app.kubernetes.io/component=node -o name 2>/dev/null); do
        node="$(K -n "$NS" get "$p" -o jsonpath='{.spec.nodeName}')"
        K -n "$NS" exec "$p" -c node-agent -- python3 -c "$MEMPY" 2>/dev/null |
            python3 -c 'import json,sys; r=json.loads(sys.stdin.read()); r["node"]=sys.argv[1]; print(json.dumps(r))' "$node" \
            >> "$OUT/samples/mem.jsonl" 2>/dev/null
    done
}
while [ "$(date +%s)" -lt "$END" ]; do
    sample
    left=$(( (END - $(date +%s)) / 60 ))
    say "  sample: $(python3 -c 'import json,collections,sys; r=[json.loads(l) for l in open(sys.argv[1])][-1]; print(dict(collections.Counter((p["kind"],p["phase"]) for p in r["pods"])))' "$OUT/samples/pods.jsonl" 2>/dev/null); ${left} min left"
    sleep "$SAMPLE"
done

# --- 6. the end: the agents end, the Jobs stop, the streams are collected
say "the run's time is up: waiting for the long agents to end"
K -n "$AG" patch cronjob short -p '{"spec":{"suspend":true}}' > /dev/null
for _ in $(seq 120); do
    left="$(K -n "$AG" get pods -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' | grep -c -E 'Running|Pending')"
    [ "$left" = 0 ] && break; sleep 10
done
# the exporter audits each stream whole at its end: minutes for a day's
# (README.md); wait until each agent pod's run has its audit's event
for _ in $(seq 120); do
    sample > /dev/null 2>&1
    python3 - "$OUT" <<'EOF' && break
import glob, json, sys
out = sys.argv[1]
done = set()
for f in glob.glob(f"{out}/exporter/*.jsonl"):
    for l in open(f, errors="replace"):
        if '"event": "audit"' in l or '"event":"audit"' in l:
            try:
                e = json.loads(l)
            except ValueError:
                continue
            done.add((e.get("metadata") or {}).get("correlation_uid"))
# every run: the short Jobs' pods kept as they ended, and a long agent a node
short = [f for f in glob.glob(f"{out}/logs/*.pod.json")
         if json.load(open(f))["metadata"].get("labels", {}).get("soak") == "short"]
want = len(short) + len(json.load(open(f"{out}/meta.json"))["nodes"])
sys.exit(0 if len(done) >= want else 1)
EOF
    sleep 10
done
sample
for p in $(K -n "$AG" get pods -o name); do      # every pod's log, those not yet kept
    n="${p#pod/}"; [ -s "$OUT/logs/$n.jsonl" ] || K -n "$AG" logs "$n" > "$OUT/logs/$n.jsonl" 2>/dev/null
    K -n "$AG" get "$p" -o json > "$OUT/logs/$n.pod.json"
done
for d in allowed denied; do K -n "$SVC" logs "deploy/$d" > "$OUT/$d.jsonl" 2>/dev/null; done
K -n "$NS" get pods -o json > "$OUT/varek-pods.json"
for p in $(K -n "$NS" get pod -l app.kubernetes.io/component=node -o name); do
    node="$(K -n "$NS" get "$p" -o jsonpath='{.spec.nodeName}')"
    mkdir -p "$OUT/streams/$node"
    # the node image has no tar (UBI minimal): its python3 writes the archive
    K -n "$NS" exec "$p" -c node-agent -- python3 -c "$TARPY" 2>"$OUT/streams/$node.copy.err" | tar -C "$OUT/streams/$node" -xf - ||
        say "soak.sh: the streams of $node were not all copied"
    K -n "$NS" logs "$p" -c node-agent > "$OUT/streams/$node.node-agent.log" 2>/dev/null
    K -n "$NS" logs "$p" -c plugin > "$OUT/streams/$node.plugin.log" 2>/dev/null
done
cp "$OUT/node.key.pub" "$OUT/streams/node.key.pub"
say "collected; judging"
python3 "$SOAK/soak_check.py" "$OUT" --tools "$HERE/tools" 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
