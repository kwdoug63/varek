# SPDX-License-Identifier: MIT
"""Tests for VAREK's Helm chart (v1.34 step 6, docs/security/v1.34-kubernetes.md,
section 3): packaging/helm/varek rendered by `helm template` under each of its
settings, and what the node agent, the plugin and the webhook require of it
checked in what it renders. Run with `make test-varek-chart` (HELM names helm;
KUBECONFORM, if set, also checks each render against Kubernetes' schemas).
The chart installed on a cluster is step 7's (kind in CI)."""
import base64
import json
import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CHART = os.path.join(ROOT, "packaging", "helm", "varek")
HELM = os.environ.get("HELM") or shutil.which("helm")
KUBECONFORM = os.environ.get("KUBECONFORM")
KUBE = "1.31.0"
NS = "varek-system"

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed (HELM names it)")


def helm(*args, ok=True):
    p = subprocess.run([HELM, *args], capture_output=True, text=True, check=False)
    if ok:
        assert p.returncode == 0, p.stderr
    return p


def render(*sets, ok=True):
    args = ["template", "t", CHART, "-n", NS, "--kube-version", KUBE, "--include-crds"]
    for s in sets:
        args += ["--set", s]
    p = helm(*args, ok=ok)
    if not ok:
        return p
    if KUBECONFORM:
        k = subprocess.run([KUBECONFORM, "-strict", "-summary", "-kubernetes-version", KUBE,
                            "-ignore-missing-schemas"], input=p.stdout, capture_output=True, text=True, check=False)
        assert k.returncode == 0, k.stdout + k.stderr
    return [d for d in yaml.safe_load_all(p.stdout) if d]


def one(docs, kind, name=None):
    found = [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    assert len(found) == 1, (kind, name, [d["metadata"]["name"] for d in found])
    return found[0]


def kinds(docs):
    return sorted(d["kind"] for d in docs)


def pod(docs, kind):
    return one(docs, kind)["spec"]["template"]["spec"]


def ctr(spec, name, init=False):
    return [c for c in spec["initContainers" if init else "containers"] if c["name"] == name][0]


def arg(c, flag):
    cmd = c["command"]
    return cmd[cmd.index(flag) + 1]


def mounts(c):
    return {m["mountPath"]: m for m in c.get("volumeMounts", [])}


def volumes(spec):
    return {v["name"]: v for v in spec["volumes"]}


def host_path(spec, c, path):
    """the node's path a container's path is, by its mount"""
    for mp, m in sorted(mounts(c).items(), key=lambda kv: -len(kv[0])):
        if path == mp or path.startswith(mp.rstrip("/") + "/"):
            v = volumes(spec)[m["name"]]
            assert "hostPath" in v, (path, v)
            return v["hostPath"]["path"] + path[len(mp):]
    raise AssertionError(f"{c['name']}: {path} is on no mount")


def test_lint_strict():
    p = helm("lint", "--strict", CHART, "--kube-version", KUBE)
    assert "0 chart(s) failed" in p.stdout, p.stdout


def test_the_default_render():
    docs = render()
    assert kinds(docs) == ["ClusterRole", "ClusterRole", "ClusterRoleBinding", "ClusterRoleBinding",
                           "CustomResourceDefinition", "CustomResourceDefinition", "CustomResourceDefinition", "DaemonSet", "Deployment",
                           "MutatingWebhookConfiguration", "PodDisruptionBudget", "Secret",
                           "Service", "ServiceAccount", "ServiceAccount", "ValidatingWebhookConfiguration"]
    for d in docs:
        if d["kind"] not in ("CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding",
                             "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
            assert d["metadata"]["namespace"] == NS, d["metadata"]
    images = {c["image"] for k in ("DaemonSet", "Deployment") for key in ("containers", "initContainers")
              for c in pod(docs, k).get(key, [])}
    # the image's tag is the chart's appVersion, which a release sets to its tag
    app = yaml.safe_load(open(os.path.join(CHART, "Chart.yaml")))["appVersion"]
    assert images == {f"ghcr.io/kwdoug63/varek-node:{app}"}


def test_each_path_is_the_nodes_own():
    """the runtime binds the launcher and dials the listener by the paths
    the plugin names (it opens neither), which are the node agent's: each
    path the node agent and the plugin open is the same path on the node"""
    spec = pod(render(), "DaemonSet")
    agent, plugin = ctr(spec, "node-agent"), ctr(spec, "plugin")
    for c, flag in ((agent, "--node-agent"), (agent, "--node-streams"), (agent, "--node-launcher"),
                    (plugin, "-socket"), (plugin, "-policies")):
        path = arg(c, flag)
        assert host_path(spec, c, path) == path, (c["name"], flag, path)
    assert agent["command"][1] == arg(plugin, "-policies") == "/var/lib/varek/policies"
    assert arg(agent, "--node-launcher") == arg(plugin, "-launcher") == "/opt/varek/bin/varek-init"
    assert arg(agent, "--node-agent") == arg(plugin, "-listener") == "/run/varek-node/node.sock"
    assert arg(plugin, "-socket") == "/var/run/nri/nri.sock"
    assert "-sync" in plugin["command"]
    # the init container installs the launcher where both name it
    init = ctr(spec, "prepare", init=True)
    script = init["command"][-1]
    assert "/host/bin/varek-init" in script and host_path(spec, init, "/host/bin") == "/opt/varek/bin"


def test_the_unsupervised_profile():
    """step 8 review (G-1): VAREK's unsupervised profile, every call refused,
    put whole under the kubelet's seccomp root, where each container of a
    supervised pod names it (the webhook requires it) and the plugin
    replaces it"""
    spec = pod(render(), "DaemonSet")
    init = ctr(spec, "prepare", init=True)
    script = init["command"][-1]
    assert host_path(spec, init, "/host/seccomp/varek/unsupervised.json") == "/var/lib/kubelet/seccomp/varek/unsupervised.json"
    m = re.search(r"printf '%s\\n' '(\{.*\})' > /host/seccomp/varek/\.unsupervised\.json\.new", script)
    assert m, script
    assert json.loads(m.group(1)) == {"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1, "syscalls": []}
    assert "mv -f /host/seccomp/varek/.unsupervised.json.new /host/seccomp/varek/unsupervised.json" in script
    spec = pod(render("node.seccompRoot=/var/lib/k/seccomp"), "DaemonSet")
    assert volumes(spec)["seccomp"]["hostPath"]["path"] == "/var/lib/k/seccomp"
    # v1.36 (D8): the release's image is for amd64 and arm64, so every Linux node gets the node agent
    assert spec["nodeSelector"] == {"kubernetes.io/os": "linux"}


def test_the_exporters_state():
    spec = pod(render(), "DaemonSet")
    ex = ctr(spec, "exporter")
    assert host_path(spec, ex, arg(ex, "--state")) == "/var/lib/varek/export/done"
    assert arg(ex, "--max-followers") == "64"
    assert "-m 0700 /host/socket /host/streams /host/control /host/export" in ctr(spec, "prepare", init=True)["command"][-1]


def test_runtime_handlers_and_dns():
    spec = pod(render(), "DaemonSet")
    assert arg(ctr(spec, "plugin"), "-runtime-handlers") == "runc,crun"
    # helm template sees no cluster: no DNS service looked up, none given
    assert "--dns-server" not in ctr(spec, "node-agent")["command"]
    spec = pod(render("node.dnsServer=10.96.0.10:53"), "DaemonSet")
    assert arg(ctr(spec, "node-agent"), "--dns-server") == "10.96.0.10:53"
    spec = pod(render("node.dnsServer=none"), "DaemonSet")
    assert "--dns-server" not in ctr(spec, "node-agent")["command"]
    c = ctr(pod(render(), "Deployment"), "admission")
    assert "-runtime-classes" not in c["command"]
    c = ctr(pod(render("admission.runtimeClasses={runc,fast}"), "Deployment"), "admission")
    assert arg(c, "-runtime-classes") == "runc,fast"


def test_who_may_write_what():
    spec = pod(render(), "DaemonSet")
    assert spec["hostPID"] is True and not spec.get("hostNetwork")
    agent, plugin, exporter = (ctr(spec, n) for n in ("node-agent", "plugin", "exporter"))
    assert agent["securityContext"]["privileged"] is True
    # the policies: written by the plugin's -sync only; the launcher by the init container only
    assert mounts(agent)["/var/lib/varek/policies"]["readOnly"] is True
    assert not mounts(plugin)["/var/lib/varek/policies"].get("readOnly")
    assert mounts(agent)["/opt/varek/bin"]["readOnly"] is True
    assert mounts(exporter)["/var/log/varek"]["readOnly"] is True
    state = mounts(agent)["/run/containerd"]
    assert state["readOnly"] is True and state["mountPropagation"] == "HostToContainer"
    for c in (plugin, exporter):
        sc = c["securityContext"]
        assert sc["capabilities"] == {"drop": ["ALL"]} and sc["allowPrivilegeEscalation"] is False
        assert sc["readOnlyRootFilesystem"] is True
        # the pod shares the node's PID namespace (the node agent's): theirs filtered still
        assert sc["seccompProfile"] == {"type": "RuntimeDefault"}
    init = ctr(spec, "prepare", init=True)
    assert set(init["securityContext"]["capabilities"]["add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    script = init["command"][-1]
    assert re.search(r"-m 0700 /host/socket /host/streams /host/control", script)
    assert re.search(r"-m 0755 /host/policies /host/bin", script)
    # written whole, then renamed over the old one
    assert "mv -f /host/bin/.varek-init.new /host/bin/varek-init" in script
    assert spec["tolerations"] == [{"operator": "Exists"}] and spec["priorityClassName"] == "system-node-critical"


def test_the_runtime_chooses_the_state_directory():
    for runtime, state in (("containerd", "/run/containerd"), ("cri-o", "/run/containers")):
        spec = pod(render(f"runtime={runtime}"), "DaemonSet")
        assert volumes(spec)["state"]["hostPath"]["path"] == state
        assert state in mounts(ctr(spec, "node-agent"))
    p = render("runtime=docker", ok=False)
    assert p.returncode != 0 and 'runtime "docker": give containerd or cri-o' in p.stderr


def test_signing_and_the_anchor():
    spec = pod(render(), "DaemonSet")
    agent, exporter = ctr(spec, "node-agent"), ctr(spec, "exporter")
    assert "--sign-key" not in agent["command"] and "--anchor" not in agent["command"]
    assert "key" not in volumes(spec)
    spec = pod(render("signing.secretName=varek-key", "signing.checkpointEvery=64", "anchor.enabled=true"), "DaemonSet")
    agent, exporter = ctr(spec, "node-agent"), ctr(spec, "exporter")
    key = arg(agent, "--sign-key")
    # a file (subPath), not the Secret volume's link: the Warden opens its key O_NOFOLLOW
    m = mounts(agent)[key]
    assert m["subPath"] == "key" and m["readOnly"] is True
    assert volumes(spec)["key"]["secret"] == {"secretName": "varek-key", "defaultMode": 0o400}
    assert arg(agent, "--checkpoint-every") == "64"
    assert mounts(exporter)[arg(exporter, "--pubkey")]["subPath"] == "key.pub"
    assert key not in mounts(exporter), "the exporter is given the public key only"
    assert arg(agent, "--anchor") == arg(exporter, "--anchor") == "/var/log/varek/anchor"


def test_the_exporter_is_optional():
    spec = pod(render("exporter.enabled=false"), "DaemonSet")
    assert [c["name"] for c in spec["containers"]] == ["node-agent", "plugin"]


def test_a_digest_pins_every_image():
    d = "sha256:" + "ab" * 32
    docs = render(f"image.digest={d}", "image.tag=9.9.9")
    for k in ("DaemonSet", "Deployment"):
        s = pod(docs, k)
        for c in s["containers"] + s.get("initContainers", []):
            assert c["image"] == f"ghcr.io/kwdoug63/varek-node@{d}"


def test_the_webhook():
    docs = render("admission.excludeNamespaces={kube-system,monitoring}")
    vwc = one(docs, "ValidatingWebhookConfiguration")
    hooks = {h["name"]: h for h in vwc["webhooks"]}
    assert set(hooks) == {"varekpolicy.varek.dev", "varekplan.varek.dev", "varekcredential.varek.dev",
                          "pod.varek.dev", "pod-required.varek.dev"}
    secret = one(docs, "Secret")
    assert secret["type"] == "kubernetes.io/tls"
    svc = one(docs, "Service")
    for h in hooks.values():
        cc = h["clientConfig"]
        assert cc["service"] == {"name": svc["metadata"]["name"], "namespace": NS,
                                 "path": "/" + h["name"].split(".")[0], "port": 443}
        assert cc["caBundle"] == secret["data"]["ca.crt"]
        assert h["failurePolicy"] == "Fail" and h["sideEffects"] == "None"
    assert hooks["varekpolicy.varek.dev"]["rules"][0]["resources"] == ["varekpolicies"]
    assert hooks["varekpolicy.varek.dev"]["rules"][0]["operations"] == ["CREATE", "UPDATE"]
    # v1.35 step 4c (D11): the plans
    assert hooks["varekplan.varek.dev"]["rules"] == [{"apiGroups": ["varek.dev"], "apiVersions": ["v1alpha1"],
                                                       "operations": ["CREATE", "UPDATE"], "resources": ["varekplans"]}]
    assert "namespaceSelector" not in hooks["varekplan.varek.dev"]
    # v1.36 step 4 (D2): the credentials, cluster-scoped, each checked
    assert hooks["varekcredential.varek.dev"]["rules"] == [{"apiGroups": ["varek.dev"], "apiVersions": ["v1alpha1"],
                                                            "operations": ["CREATE", "UPDATE"],
                                                            "resources": ["varekcredentials"]}]
    assert "namespaceSelector" not in hooks["varekcredential.varek.dev"]
    for name in ("pod.varek.dev", "pod-required.varek.dev"):
        # G-3: an update is sent too (the annotation is not changed)
        assert hooks[name]["rules"][0]["operations"] == ["CREATE", "UPDATE"]
    for name, op in (("pod.varek.dev", "NotIn"), ("pod-required.varek.dev", "In")):
        ex = hooks[name]["namespaceSelector"]["matchExpressions"]
        assert {"key": "varek.dev/policy-required", "operator": op, "values": ["true"]} in ex
        # the chart's own namespace is never checked: its pods start while the webhook is down
        assert {"key": "kubernetes.io/metadata.name", "operator": "NotIn",
                "values": [NS, "kube-system", "monitoring"]} in ex
    # the certificate names the service, and the CA signed it
    pem = base64.b64decode(secret["data"]["tls.crt"])
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    ca = base64.b64decode(secret["data"]["ca.crt"])
    try:
        from cryptography import x509
    except ImportError:
        return
    cert, cacert = x509.load_pem_x509_certificate(pem), x509.load_pem_x509_certificate(ca)
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert f"t-admission.{NS}.svc" in names
    assert cert.issuer == cacert.subject
    cacert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               *_padding(cert))


def _padding(cert):
    from cryptography.hazmat.primitives.asymmetric import padding
    return padding.PKCS1v15(), cert.signature_hash_algorithm


def test_the_webhooks_pod():
    docs = render()
    pdb = one(docs, "PodDisruptionBudget")
    assert pdb["spec"]["minAvailable"] == 1
    assert "PodDisruptionBudget" not in kinds(render("admission.replicas=1"))
    spec = pod(docs, "Deployment")
    anti = spec["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]["podAffinityTerm"]
    assert anti["topologyKey"] == "kubernetes.io/hostname"
    assert anti["labelSelector"]["matchLabels"] == pdb["spec"]["selector"]["matchLabels"]
    c = ctr(spec, "admission")
    assert spec["securityContext"]["runAsNonRoot"] is True and spec["securityContext"]["runAsUser"] == 65532
    assert c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert arg(c, "-warden") == "/opt/varek/warden"
    assert c["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert mounts(c)[os.path.dirname(arg(c, "-tls-cert"))]["readOnly"] is True


def test_the_webhooks_certificate_three_ways():
    docs = render("admission.tls.certManager.enabled=true", "admission.tls.certManager.issuerName=ca")
    assert "Secret" not in kinds(docs)
    cert = one(docs, "Certificate")
    assert cert["spec"]["issuerRef"] == {"kind": "Issuer", "name": "ca"}
    assert f"t-admission.{NS}.svc" in cert["spec"]["dnsNames"]
    vwc = one(docs, "ValidatingWebhookConfiguration")
    assert vwc["metadata"]["annotations"]["cert-manager.io/inject-ca-from"] == f"{NS}/t-admission"
    assert all("caBundle" not in h["clientConfig"] for h in vwc["webhooks"])
    p = render("admission.tls.certManager.enabled=true", ok=False)
    assert p.returncode != 0 and "issuerName" in p.stderr
    # a Secret of the operator's: its CA is needed (helm template sees no cluster)
    p = render("admission.tls.secretName=mine", ok=False)
    assert p.returncode != 0 and "give admission.tls.caBundle" in p.stderr
    docs = render("admission.tls.secretName=mine", "admission.tls.caBundle=Q0E=")
    assert "Secret" not in kinds(docs)
    assert all(h["clientConfig"]["caBundle"] == "Q0E=" for h in one(docs, "ValidatingWebhookConfiguration")["webhooks"])
    assert volumes(pod(docs, "Deployment"))["tls"]["secret"]["secretName"] == "mine"


def test_rbac_reads_only():
    docs = render()
    rules = {d["metadata"]["name"]: d["rules"] for d in docs if d["kind"] == "ClusterRole"}
    res = ["varekpolicies", "varekplans"]                    # v1.35 step 4c: the plans too
    # v1.36 step 4 (D2): the node lists and watches the credentials; the webhook lists them
    cred = ["varekcredentials"]
    # v1.36 step 7 (D7b): the plugin gets a pod, for its service account (a flow policy's session)
    assert rules == {"t-node": [{"apiGroups": ["varek.dev"], "resources": res, "verbs": ["get", "list", "watch"]},
                                {"apiGroups": ["varek.dev"], "resources": cred, "verbs": ["get", "list", "watch"]},
                                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
                     "t-admission": [{"apiGroups": ["varek.dev"], "resources": res, "verbs": ["get"]},
                                     {"apiGroups": ["varek.dev"], "resources": cred, "verbs": ["list"]}]}
    for b in (d for d in docs if d["kind"] == "ClusterRoleBinding"):
        assert b["subjects"] == [{"kind": "ServiceAccount", "name": b["roleRef"]["name"], "namespace": NS}]
    assert pod(docs, "DaemonSet")["serviceAccountName"] == "t-node"
    assert pod(docs, "Deployment")["serviceAccountName"] == "t-admission"


def test_openshift():
    docs = render("openshift.enabled=true", "runtime=cri-o")
    scc = one(docs, "SecurityContextConstraints", "t-node")
    assert scc["users"] == [f"system:serviceaccount:{NS}:t-node"]
    assert scc["allowPrivilegedContainer"] and scc["allowHostPID"] and scc["allowHostDirVolumePlugin"]
    assert not scc["allowHostNetwork"]
    spec = pod(docs, "DaemonSet")
    init = ctr(spec, "prepare", init=True)
    assert set(init["securityContext"]["capabilities"]["add"]) <= set(scc["allowedCapabilities"])
    used = {next(k for k in v if k != "name") for v in spec["volumes"]} | {"projected"}
    assert used <= set(scc["volumes"]), used - set(scc["volumes"])
    # the webhook under restricted-v2: the namespace's user, none of the chart's
    sc = pod(docs, "Deployment")["securityContext"]
    assert sc["runAsNonRoot"] is True and "runAsUser" not in sc and "runAsGroup" not in sc
    assert "SecurityContextConstraints" not in kinds(render())
    # step 9: the node's own as spc_t (SELinux: the node's paths, the NRI
    # socket), the launcher labelled for containers
    for c in (ctr(spec, "prepare", init=True), ctr(spec, "plugin"), ctr(spec, "exporter")):
        assert c["securityContext"]["seLinuxOptions"] == {"type": "spc_t"}, c["name"]
    assert "chcon -t container_ro_file_t /host/bin/.varek-init.new" in ctr(spec, "prepare", init=True)["command"][-1]
    assert "seLinuxOptions" not in ctr(pod(render(), "DaemonSet"), "plugin")["securityContext"]
    # supervised pods: restricted-v2 with the unsupervised profile admitted,
    # used through a ClusterRole a namespace binds
    sup = one(docs, "SecurityContextConstraints", "t-supervised")
    assert sup["seccompProfiles"] == ["runtime/default", "localhost/varek/unsupervised.json"]
    assert sup["requiredDropCapabilities"] == ["ALL"] and not sup["allowPrivilegeEscalation"]
    assert sup["runAsUser"] == {"type": "MustRunAsRange"} and not sup["allowHostDirVolumePlugin"]
    assert sup["users"] == [] and sup["groups"] == []
    role = one(docs, "ClusterRole", "t-supervised-scc")
    assert role["rules"] == [{"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
                              "resourceNames": ["t-supervised"], "verbs": ["use"]}]


def test_the_crd_names_what_the_node_agent_takes():
    docs = render()
    kube = open(os.path.join(ROOT, "varek", "v1_4", "k8s", "internal", "kube", "kube.go")).read()
    go = re.search(r"var Name = regexp\.MustCompile\(`([^`]*)`\)", kube).group(1)
    # v1.35 step 4c (D11): VarekPlan beside VarekPolicy, its text spec.plan
    for name, kind, field in (("varekpolicies.varek.dev", "VarekPolicy", "policy"), ("varekplans.varek.dev", "VarekPlan", "plan")):
        crd = one(docs, "CustomResourceDefinition", name)
        assert crd["spec"]["scope"] == "Namespaced" and crd["spec"]["names"]["kind"] == kind
        v = crd["spec"]["versions"][0]
        assert v["name"] == "v1alpha1" and v["served"] and v["storage"]
        rule = v["schema"]["openAPIV3Schema"]["x-kubernetes-validations"][0]["rule"]
        assert f"matches('{go}')" in rule, (rule, go)
        spec = v["schema"]["openAPIV3Schema"]["properties"]["spec"]
        assert spec["required"] == [field] and spec["properties"][field]["type"] == "string"


def _conf(docs):
    """warden-secrets' configuration the chart writes, as key = value"""
    text = one(docs, "Secret", "t-node-secrets-conf")["stringData"]["secrets.conf"]
    return dict(l.split(" = ", 1) for l in text.splitlines() if l and not l.startswith("#"))


def test_credentials():
    """v1.36 step 4 (D1, D2): a file: source under the node agent's directory,
    each Secret there; warden-secrets' configuration for vault: and aws-sm:,
    each sign-in's token the kubelet projects for the node agent"""
    docs = render()
    spec = pod(docs, "DaemonSet")
    agent = ctr(spec, "node-agent")
    assert arg(agent, "--node-credentials") == "/var/lib/varek/credentials"
    assert "--secrets-conf" not in agent["command"]
    assert "t-node-secrets-conf" not in {d["metadata"]["name"] for d in docs if d["kind"] == "Secret"}
    # the webhook names a file: source by the node agent's directory
    assert arg(ctr(pod(docs, "Deployment"), "admission"), "-credentials-dir") == "/var/lib/varek/credentials"

    docs = render("credentials.secrets={gh-token,db}", "credentials.vault.addr=https://vault:8200",
                  "credentials.vault.caSecret=vca", "credentials.vault.kubernetesAuth.role=agents",
                  "credentials.aws.region=us-east-2", "credentials.aws.roleArn=arn:aws:iam::1:role/r")
    spec = pod(docs, "DaemonSet")
    agent, m, v = ctr(spec, "node-agent"), mounts(ctr(spec, "node-agent")), volumes(spec)
    for s in ("gh-token", "db"):
        mp = m[f"/var/lib/varek/credentials/{s}"]
        assert mp["readOnly"] and v[mp["name"]]["secret"] == {"secretName": s, "defaultMode": 0o400}
    conf = arg(agent, "--secrets-conf")
    assert conf == "/etc/varek/secrets/secrets.conf"
    assert v[m[os.path.dirname(conf)]["name"]]["secret"] == {"secretName": "t-node-secrets-conf", "defaultMode": 0o400}
    c = _conf(docs)
    assert c == {"vault_addr": "https://vault:8200", "vault_ca": "/etc/varek/vault-ca/ca.crt",
                 "vault_k8s_role": "agents", "vault_k8s_jwt_file": "/var/run/varek/tokens/vault/token",
                 "vault_k8s_mount": "kubernetes", "aws_region": "us-east-2",
                 "aws_role_arn": "arn:aws:iam::1:role/r",
                 "aws_web_identity_token_file": "/var/run/varek/tokens/aws/token"}
    # each key is one warden-secrets reads
    helper = open(os.path.join(ROOT, "varek", "v1_4", "warden_secrets_helper.c")).read()
    assert set(c) <= set(re.findall(r"\bK\((\w+)\)", helper)), set(c) - set(re.findall(r"\bK\((\w+)\)", helper))
    # each file it names is on a mount: the CA, and each token, projected with its audience
    assert v[m["/etc/varek/vault-ca"]["name"]]["secret"]["secretName"] == "vca"
    for key, aud in (("vault_k8s_jwt_file", "vault"), ("aws_web_identity_token_file", "sts.amazonaws.com")):
        vol = v[m[os.path.dirname(c[key])]["name"]]["projected"]
        assert vol["defaultMode"] == 0o400
        assert vol["sources"] == [{"serviceAccountToken": {"audience": aud, "expirationSeconds": vol["sources"][0]["serviceAccountToken"]["expirationSeconds"],
                                                           "path": os.path.basename(c[key])}}]
    # OpenShift admits each of these volumes
    sdocs = render("openshift.enabled=true", "runtime=cri-o", "credentials.secrets={gh-token}",
                   "credentials.vault.addr=https://vault:8200", "credentials.vault.kubernetesAuth.role=agents")
    used = {next(k for k in x if k != "name") for x in pod(sdocs, "DaemonSet")["volumes"]}
    assert used <= set(one(sdocs, "SecurityContextConstraints", "t-node")["volumes"])

    # EKS Pod Identity: the node's agent, with the token its audience names
    docs = render("credentials.aws.podIdentity=true")
    c = _conf(docs)
    assert c == {"aws_container_credentials_uri": "http://169.254.170.23/v1/credentials",
                 "aws_container_token_file": "/var/run/varek/tokens/aws/token"}
    spec = pod(docs, "DaemonSet")
    vol = volumes(spec)[mounts(ctr(spec, "node-agent"))["/var/run/varek/tokens/aws"]["name"]]
    assert vol["projected"]["sources"][0]["serviceAccountToken"]["audience"] == "pods.eks.amazonaws.com"
    # the node's instance role: a region alone, and no token
    docs = render("credentials.aws.region=us-east-2")
    assert _conf(docs) == {"aws_region": "us-east-2"}
    assert "/var/run/varek/tokens/aws" not in mounts(ctr(pod(docs, "DaemonSet"), "node-agent"))

    for sets, why in ((("credentials.aws.roleArn=arn:aws:iam::1:role/r", "credentials.aws.podIdentity=true"), "not both"),
                      (("credentials.vault.kubernetesAuth.role=agents",), "need vault.addr"),
                      (("credentials.vault.caSecret=vca",), "need vault.addr")):
        p = render(*sets, ok=False)
        assert p.returncode != 0 and why in p.stderr, (sets, p.stderr)


def test_on_behalf_of():
    """v1.36 step 6 (D5): a pod acting for a user. The mutating hook gives it
    its token's volume and the init container (the node image); the node
    agent reads the kubelet's copy, by the same path on the node, seen as
    the kubelet mounts it; its SVID from the SPIRE agent's admin socket"""
    docs = render("admission.excludeNamespaces={kube-system,monitoring}", "image.digest=sha256:" + "a" * 64)
    image = "ghcr.io/kwdoug63/varek-node@sha256:" + "a" * 64
    mwc = one(docs, "MutatingWebhookConfiguration")
    assert [h["name"] for h in mwc["webhooks"]] == ["pod-mutate.varek.dev"]
    h = mwc["webhooks"][0]
    secret = one(docs, "Secret")
    assert h["clientConfig"]["service"] == {"name": "t-admission", "namespace": NS, "path": "/pod-mutate", "port": 443}
    assert h["clientConfig"]["caBundle"] == secret["data"]["ca.crt"]
    assert h["rules"] == [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]
    assert h["reinvocationPolicy"] == "Never" and h["failurePolicy"] == "Fail" and h["sideEffects"] == "None"
    # every namespace's pods but the excluded (a namespace that requires a policy too)
    assert h["namespaceSelector"]["matchExpressions"] == [
        {"key": "kubernetes.io/metadata.name", "operator": "NotIn", "values": [NS, "kube-system", "monitoring"]}]
    vwc = one(docs, "ValidatingWebhookConfiguration")
    for v in vwc["webhooks"]:
        if v["name"].startswith("pod"):
            assert v["rules"][0]["resources"] == ["pods", "pods/ephemeralcontainers"], v["name"]
    adm = ctr(pod(docs, "Deployment"), "admission")
    assert arg(adm, "-obo-image") == image and arg(adm, "-obo-user") == "65534"
    spec = pod(docs, "DaemonSet")
    agent, plugin = ctr(spec, "node-agent"), ctr(spec, "plugin")
    assert arg(plugin, "-obo-image") == image
    assert arg(agent, "--node-kubelet") == "/var/lib/kubelet"
    m = mounts(agent)["/var/lib/kubelet/pods"]
    assert m["readOnly"] is True and m["mountPropagation"] == "HostToContainer"
    assert host_path(spec, agent, "/var/lib/kubelet/pods") == "/var/lib/kubelet/pods"
    assert "--node-spire-socket" not in agent["command"] and "/etc/varek/spire-bundle" not in mounts(agent)
    # SPIRE: the admin socket's directory, the node agent's own ID, the bundle
    sock = "/run/spire/admin-sockets/admin.sock"
    me = "spiffe://example.org/ns/varek-system/sa/t-node"
    spec = pod(render("spire.adminSocket=" + sock, "spire.self=" + me, "spire.bundleConfigMap=spire-bundle"), "DaemonSet")
    agent = ctr(spec, "node-agent")
    assert arg(agent, "--node-spire-socket") == sock and arg(agent, "--node-spire-self") == me
    assert host_path(spec, agent, sock) == sock
    # projected (in memory): a configMap volume's directory is the node's, writable by all
    assert volumes(spec)[mounts(agent)["/etc/varek/spire-bundle"]["name"]]["projected"]["sources"] == [
        {"configMap": {"name": "spire-bundle"}}]
    assert mounts(agent)["/etc/varek/spire-bundle"]["readOnly"] is True
    p = render("spire.self=" + me, ok=False)
    assert p.returncode != 0 and "spire.self: give spire.adminSocket too" in p.stderr
    # the issuers' CA: the cluster's own (kube-root-ca.crt), in warden-secrets' configuration
    docs = render("onBehalfOf.issuerCaConfigMap=kube-root-ca.crt")
    agent, spec = ctr(pod(docs, "DaemonSet"), "node-agent"), pod(docs, "DaemonSet")
    assert _conf(docs)["oidc_ca"] == "/etc/varek/issuer-ca/ca.crt"
    assert arg(agent, "--secrets-conf") == "/etc/varek/secrets/secrets.conf"
    v = volumes(spec)[mounts(agent)["/etc/varek/issuer-ca"]["name"]]["projected"]
    assert v["sources"] == [{"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]
    assert "configMap" not in volumes(spec)[mounts(agent)["/etc/varek/issuer-ca"]["name"]]
    assert "issuer-ca" not in volumes(pod(render(), "DaemonSet"))
    # the init container's user: the value, or on OpenShift the namespace's
    assert arg(ctr(pod(render("onBehalfOf.user=1001"), "Deployment"), "admission"), "-obo-user") == "1001"
    assert arg(ctr(pod(render("openshift.enabled=true", "runtime=cri-o"), "Deployment"), "admission"), "-obo-user") == "0"


def test_dry_run_flow_policy_and_trust_bundles():
    """v1.36 step 7 (D6, D7, D7b): the VarekPolicy's fields; a flow policy's
    breaker table on the node (root's host path); the trust bundles'
    ConfigMap, projected (in memory: a configMap volume's directory is the
    node's, writable by all)"""
    docs = render()
    crd = one(docs, "CustomResourceDefinition", "varekpolicies.varek.dev")
    props = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
    assert props["dryRun"]["type"] == "boolean" and props["flowPolicy"]["type"] == "string"
    kube = open(os.path.join(ROOT, "varek", "v1_4", "k8s", "internal", "kube", "kube.go")).read()
    go = re.search(r"var TrustKey = regexp\.MustCompile\(`([^`]*)`\)", kube).group(1)
    assert props["trustBundle"]["pattern"] == go, (props["trustBundle"], go)
    spec = pod(docs, "DaemonSet")
    agent = ctr(spec, "node-agent")
    assert arg(agent, "--node-flow-state") == "/var/lib/varek/flow"
    assert host_path(spec, agent, "/var/lib/varek/flow") == "/var/lib/varek/flow"
    assert "--node-trust-bundles" not in agent["command"] and "/etc/varek/trust-bundles" not in mounts(agent)
    spec = pod(render("trustBundles.configMap=corp-roots", "flowPolicy.stateDir=/var/lib/varek/breaker"), "DaemonSet")
    agent = ctr(spec, "node-agent")
    assert arg(agent, "--node-trust-bundles") == "/etc/varek/trust-bundles"
    assert arg(agent, "--node-flow-state") == "/var/lib/varek/breaker"
    m = mounts(agent)["/etc/varek/trust-bundles"]
    assert m["readOnly"] is True
    v = volumes(spec)[m["name"]]
    assert v["projected"]["sources"] == [{"configMap": {"name": "corp-roots"}}] and "configMap" not in v


def test_stream_rotation():
    """v1.36 step 8 (D9): the node agent rotates each stream at the chart's
    size, given in bytes as a whole number (never as a float); 0, none"""
    agent = ctr(pod(render(), "DaemonSet"), "node-agent")
    assert arg(agent, "--node-stream-rotate") == "268435456"
    agent = ctr(pod(render("streams.rotateBytes=1073741824"), "DaemonSet"), "node-agent")
    assert arg(agent, "--node-stream-rotate") == "1073741824"
    agent = ctr(pod(render("streams.rotateBytes=0"), "DaemonSet"), "node-agent")
    assert "--node-stream-rotate" not in agent["command"]


def test_the_varekcredential_crd():
    crd = one(render(), "CustomResourceDefinition", "varekcredentials.varek.dev")
    assert crd["spec"]["scope"] == "Cluster" and crd["spec"]["names"]["kind"] == "VarekCredential"
    v = crd["spec"]["versions"][0]
    assert v["name"] == "v1alpha1" and v["served"] and v["storage"]
    spec = v["schema"]["openAPIV3Schema"]["properties"]["spec"]
    assert spec["required"] == ["credential", "source", "namespaces"]
    # the names and sources the node agent takes (k8s/internal/kube/credentials.go)
    go = open(os.path.join(ROOT, "varek", "v1_4", "k8s", "internal", "kube", "credentials.go")).read()
    name = re.search(r"var CredentialName = regexp\.MustCompile\(`([^`]*)`\)", go).group(1)
    assert spec["properties"]["credential"]["pattern"] == name
    src = spec["properties"]["source"]
    assert src["pattern"] == "^(file|vault|aws-sm):[!-~]+$" and src["maxLength"] == len("aws-sm:") + 1024
    assert spec["properties"]["namespaces"]["minItems"] == 1


def test_the_chart_version_is_the_wardens():
    chart = yaml.safe_load(open(os.path.join(CHART, "Chart.yaml")))
    assert chart["version"] == chart["appVersion"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", chart["version"])


def test_ci_and_the_release_build_check_and_sign_the_node_image_and_the_chart():
    wf = os.path.join(ROOT, ".github", "workflows")
    ci = " ".join(s.get("run", "") for s in yaml.safe_load(open(os.path.join(wf, "container.yml")))["jobs"]["image"]["steps"])
    assert "--target node" in ci and "node_check.sh" in ci
    ci = " ".join(s.get("run", "") for s in yaml.safe_load(open(os.path.join(wf, "warden-build.yml")))["jobs"]["build"]["steps"])
    assert "test-varek-chart" in ci and "KUBECONFORM=" in ci and re.search(r"kubeconform@v\d+\.\d+\.\d+", ci)
    jobs = yaml.safe_load(open(os.path.join(wf, "container-release.yml")))["jobs"]
    rel = jobs["publish"]["steps"]
    run = [s.get("run", "") for s in rel]
    joined = " ".join(run)
    # v1.36 (D8): arm64's node image built and checked on the arm64 runner, before publish
    arm = jobs["node-arm64"]
    assert arm["runs-on"] == "ubuntu-24.04-arm" and jobs["publish"]["needs"] == "node-arm64"
    armrun = " ".join(s.get("run", "") for s in arm["steps"])
    for w in ("--target node", 'node_check.sh "$NODE:$VERSION-arm64"', "= linux/arm64 ]",
              'docker push "$NODE:$VERSION-arm64"', '"digest=$digest" >> "$GITHUB_OUTPUT"'):
        assert w in armrun, w
    assert "cosign" not in armrun and "id-token" not in arm["permissions"]
    for w in ("--target node", 'node_check.sh "$NODE:$VERSION-amd64"', "= linux/amd64 ]", 'docker push "$NODE:$VERSION-amd64"',
              'docker buildx imagetools create -t "$NODE:$VERSION" "$amd64" "$ARM64"',
              "platforms.py node-index.json linux/amd64 linux/arm64", 'cosign sign --yes --recursive "$node"',
              'cosign attest --yes --type cyclonedx --predicate "sbom-node-$a.cdx.json" "$d"', "helm lint --strict",
              "helm package", 'helm push', 'cosign sign --yes "$CHARTS/varek@$d"',
              '"$NODE_DIGEST" > /dev/null', 'for d in "$NODE_AMD64" "$NODE_ARM64"', '"$CHART_DIGEST" > /dev/null',
              'docker buildx imagetools create -t "$NODE:$t" "$NODE_DIGEST"'):
        assert w in joined, w
    # helm pinned; the chart's version the tag's; its image the digest just signed
    assert re.search(r"helm\.sh/helm/v3/cmd/helm@v\d+\.\d+\.\d+", joined)
    assert "for f in version appVersion" in joined and 'd="${NODE_DIGEST#*@}"' in joined
    # each in order: published, then signed, then verified, then the tags moved
    at = lambda w: next(i for i, r in enumerate(run) if w in r)
    assert at('docker push "$NODE:$VERSION-amd64"') < at("helm package") < at("helm push") < at('"$CHART_DIGEST" > /dev/null') < at('imagetools create -t "$NODE:$t"')
    # the platforms checked before the image for both is signed
    pub = run[at("platforms.py")]
    assert pub.index("platforms.py") < pub.index("cosign sign")
