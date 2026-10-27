// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

// a stand-in for the Warden: it refuses a policy holding "bad"; v1.35: a
// plan holding "mcp_call" (--plan), and --no-plan for a policy holding
// "require plan"; v1.36: a policy's first credential (credential NAME from
// SRC) not given to --pod-namespace from SRC by --credential-list
const fakeWarden = `#!/bin/sh
pol="$1"; shift
grep -q bad "$pol" && { echo "[warden] policy $pol:2: a bad line" >&2; exit 1; }
[ "$1" = --oci-filter ] || exit 2; shift
plan= noplan= list= ns=
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) plan="$2"; shift 2 ;;
    --no-plan) noplan=1; shift ;;
    --credential-list) list="$2"; shift 2 ;;
    --pod-namespace) ns="$2"; shift 2 ;;
    *) exit 2 ;;
  esac
done
[ -n "$plan" ] && grep -q mcp_call "$plan" && { echo "[warden] --oci-filter: the plan $plan: the node agent does not carry mcp_call steps yet (step m)" >&2; exit 1; }
[ -n "$noplan" ] && grep -q 'require plan' "$pol" && { echo "[warden] --oci-filter: the policy says require plan: a pod under it names its plan (varek.dev/plan)" >&2; exit 1; }
c=$(sed -n 's/^credential \([a-z_]*\) from \(.*\)$/\1 \2/p' "$pol" | head -1)
if [ -n "$c" ]; then
  [ -n "$list" ] && [ -n "$ns" ] || { echo "[warden] --oci-filter: the policy names credentials: give --credential-list FILE --pod-namespace NS" >&2; exit 1; }
  name=${c%% *} src=${c#* }
  awk -F'\t' -v n="$name" -v s="$src" -v ns="$ns" '$1 == n && $3 == s { k = split($2, a, ","); for (i = 1; i <= k; i++) if (a[i] == ns) ok = 1 } END { exit !ok }' "$list" ||
    { echo "[warden] --oci-filter: credential $name (line 1) is not given to namespace $ns (D2)" >&2; exit 1; }
  echo '{"varekCredentials":["'"$name"'"]}'
  exit 0
fi
echo '{}'
`

// "ns/name" -> policy text; "plan:ns/name" -> plan text (v1.35); v1.36:
// "cred:RESOURCE" -> "CREDENTIAL SOURCE NS,NS" (a VarekCredential)
type fakeAPI map[string]string

func (f fakeAPI) get(key, ns, name string, plan bool) (*kube.Policy, error) {
	t, ok := f[key]
	if !ok {
		return nil, nil
	}
	p := &kube.Policy{}
	p.Metadata.Namespace, p.Metadata.Name = ns, name
	if plan {
		p.Spec.Plan = t
	} else {
		p.Spec.Policy = t
	}
	return p, nil
}

func (f fakeAPI) GetPolicy(_ context.Context, ns, name string) (*kube.Policy, error) {
	return f.get(ns+"/"+name, ns, name, false)
}

func (f fakeAPI) GetPlan(_ context.Context, ns, name string) (*kube.Policy, error) {
	return f.get("plan:"+ns+"/"+name, ns, name, true)
}

func (f fakeAPI) ListCredentials(context.Context) ([]*kube.Policy, error) {
	var out []*kube.Policy
	for k, v := range f {
		if r, ok := strings.CutPrefix(k, "cred:"); ok {
			x := strings.Fields(v)
			c := &kube.Policy{}
			c.Metadata.Name, c.Spec.Credential, c.Spec.Source, c.Spec.Namespaces = r, x[0], x[1], strings.Split(x[2], ",")
			out = append(out, c)
		}
	}
	return out, nil
}

func testServer(t *testing.T, warden string) *server {
	if warden == "" {
		warden = filepath.Join(t.TempDir(), "warden")
		if err := os.WriteFile(warden, []byte(fakeWarden), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return newServer(warden, fakeAPI{
		"team-a/agent":  "allow path /tmp/\n",
		"team-a/launch": "require warden 1.29\nallow path /tmp/\nallow exec /bin/true\n",
		"team-a/broken": "allow path /tmp/\nbad\n",
		// v1.35 step 4c
		"team-a/needs":     "require warden 1.35\nrequire plan\nallow path /tmp/\n",
		"team-a/held":      "require warden 1.35\nallow path /tmp/\n", // step 9: a plan needs a 1.35 policy
		"plan:team-a/p1":   "plan 1.35\naction a file_open /tmp/x\n",
		"plan:team-a/pmcp": "plan 1.35\naction m mcp_call http://10.0.0.1/mcp\n",
		// v1.36 step 4 (D2)
		"team-a/creds":  "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n",
		"team-b/creds":  "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n",
		"cred:gh-token": "gh file:/var/lib/varek/credentials/gh/token team-a,team-c",
	}, "runc, crun")
}

// post one AdmissionReview to path; allowed, and the message
func post(t *testing.T, s *server, path, ns string, obj interface{}) (bool, string) {
	return postOp(t, s, path, ns, "CREATE", obj, nil)
}

func postOp(t *testing.T, s *server, path, ns, op string, obj, old interface{}) (bool, string) {
	b, _ := json.Marshal(obj)
	var ob []byte
	if old != nil {
		ob, _ = json.Marshal(old)
	}
	in, _ := json.Marshal(review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
		Request: &request{UID: "u-1", Namespace: ns, Operation: op, Object: b, OldObject: ob}})
	rec := httptest.NewRecorder()
	s.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(in)))
	var out review
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Response == nil || out.Response.UID != "u-1" {
		t.Fatalf("%s: the answer does not read: %s", path, rec.Body.String())
	}
	if out.Response.Status != nil {
		return out.Response.Allowed, out.Response.Status.Message
	}
	return out.Response.Allowed, ""
}

func vp(name, text string) map[string]interface{} {
	return map[string]interface{}{"metadata": map[string]string{"name": name, "namespace": "team-a"},
		"spec": map[string]string{"policy": text}}
}

func TestVarekPolicy(t *testing.T) {
	s := testServer(t, "")
	for _, c := range []struct {
		what, name, text, why string
	}{
		{"a policy the Warden loads", "agent", "allow path /tmp/\n", ""},
		{"a name the node agent does not take", "Agent.v2", "allow path /tmp/\n", "is not 1 to 63"},
		{"an empty policy", "agent", "  \n", "is empty"},
		{"a policy the Warden refuses, its reason given", "agent", "allow path /tmp/\nbad\n", "refuses this policy: policy line 2: a bad line"},
	} {
		ok, msg := post(t, s, "/varekpolicy", "team-a", vp(c.name, c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}

func f(b bool) *bool   { return &b }
func n(v int64) *int64 { return &v }

func agentPod(policy string, edit func(*pod)) pod {
	var p pod
	p.Metadata.Name, p.Metadata.Namespace = "p", "team-a"
	if policy != "" {
		p.Metadata.Annotations = map[string]string{annotation: policy}
	}
	p.Spec.SecurityContext = &secCtx{SeccompProfile: &seccompRef{Type: "Localhost", LocalhostProfile: unsupervised}}
	p.Spec.Containers = []container{{Name: "agent", Command: []string{"/usr/bin/agent"},
		SecurityContext: &secCtx{AllowPrivilegeEscalation: f(false), RunAsNonRoot: f(true), ReadOnlyRootFilesystem: f(true),
			Capabilities: &caps{Drop: []string{"ALL"}}}}}
	if edit != nil {
		edit(&p)
	}
	return p
}

func TestPod(t *testing.T) {
	s := testServer(t, "")
	sc := func(p *pod) *secCtx { return p.Spec.Containers[0].SecurityContext }
	for _, c := range []struct {
		what, path, policy string
		edit               func(*pod)
		why                string
	}{
		{"a pod naming no policy", "/pod", "", nil, ""},
		{"... in a namespace that requires one", "/pod-required", "", nil, "requires every pod to name its policy"},
		{"a pod as the node agent requires", "/pod", "agent", nil, ""},
		{"... in a namespace that requires a policy", "/pod-required", "agent", nil, ""},
		{"a policy that decides launches, with a read-only root", "/pod", "launch", nil, ""},
		{"a policy name that is not one", "/pod", "Agent_1", nil, "is not 1 to 63"},
		{"no such policy in the namespace", "/pod", "nosuch", nil, "no VarekPolicy nosuch in namespace team-a"},
		{"a policy the Warden refuses", "/pod", "broken", nil, "refuses its policy broken"},
		{"privilege escalation not turned off", "/pod", "agent", func(p *pod) { sc(p).AllowPrivilegeEscalation = nil }, "allowPrivilegeEscalation must be false"},
		{"root", "/pod", "agent", func(p *pod) { sc(p).RunAsNonRoot = nil; sc(p).RunAsUser = n(0) }, "runs as root"},
		{"no user said", "/pod", "agent", func(p *pod) { sc(p).RunAsNonRoot = nil }, "runAsNonRoot"},
		{"a user from the pod's context", "/pod", "agent", func(p *pod) {
			sc(p).RunAsNonRoot = nil
			p.Spec.SecurityContext.RunAsUser = n(1000)
		}, ""},
		{"group root", "/pod", "agent", func(p *pod) { sc(p).RunAsGroup = n(0) }, "its group is root"},
		{"a command by a relative path", "/pod", "agent", func(p *pod) { p.Spec.Containers[0].Command = []string{"python"} }, "absolute path"},
		{"decided launches with a writable root", "/pod", "launch", func(p *pod) { sc(p).ReadOnlyRootFilesystem = f(false) }, "must be read-only"},
		{"the node's network", "/pod", "agent", func(p *pod) { p.Spec.HostNetwork = true }, "hostNetwork"},
		{"capabilities not dropped", "/pod", "agent", func(p *pod) { sc(p).Capabilities = nil }, "capabilities must drop ALL"},
		{"one added back", "/pod", "agent", func(p *pod) { sc(p).Capabilities.Add = []string{"NET_RAW"} }, "adds capabilities [NET_RAW]"},
		{"an init container checked too", "/pod", "agent", func(p *pod) {
			p.Spec.InitContainers = []container{{Name: "init", SecurityContext: &secCtx{RunAsNonRoot: f(true),
				Capabilities: &caps{Drop: []string{"ALL"}}}}}
		}, "container init: allowPrivilegeEscalation"},
		// step 8 review
		{"no seccomp profile", "/pod", "agent", func(p *pod) { p.Spec.SecurityContext = nil }, "seccompProfile must be {type: Localhost"},
		{"the runtime's default profile for one container", "/pod", "agent", func(p *pod) {
			sc(p).SeccompProfile = &seccompRef{Type: "RuntimeDefault"}
		}, "container agent: its seccompProfile must be"},
		{"another Localhost profile", "/pod", "agent", func(p *pod) {
			p.Spec.SecurityContext.SeccompProfile.LocalhostProfile = "varek/other.json"
		}, "seccompProfile must be"},
		{"the profile given on the container", "/pod", "agent", func(p *pod) {
			p.Spec.SecurityContext = nil
			sc(p).SeccompProfile = &seccompRef{Type: "Localhost", LocalhostProfile: unsupervised}
		}, ""},
		{"a shared PID namespace", "/pod", "agent", func(p *pod) { p.Spec.ShareProcessNamespace = f(true) }, "shareProcessNamespace"},
		{"DNS servers of its own", "/pod", "agent", func(p *pod) { p.Spec.DNSPolicy = "None" }, "names DNS servers of its own"},
		{"... added to the cluster's", "/pod", "agent", func(p *pod) {
			p.Spec.DNSConfig = &struct {
				Nameservers []string `json:"nameservers"`
			}{Nameservers: []string{"203.0.113.5"}}
		}, "dnsConfig.nameservers"},
		{"a sandboxed runtime class", "/pod", "agent", func(p *pod) { k := "kata"; p.Spec.RuntimeClassName = &k }, `runtime class "kata"`},
		{"a runtime class that runs the filter", "/pod", "agent", func(p *pod) { k := "crun"; p.Spec.RuntimeClassName = &k }, ""},
		{"supplementary group root", "/pod", "agent", func(p *pod) { p.Spec.SecurityContext.SupplementalGroups = []int64{5, 0} }, "supplementalGroups hold group 0"},
		{"fsGroup root", "/pod", "agent", func(p *pod) { p.Spec.SecurityContext.FSGroup = n(0) }, "fsGroup is 0"},
	} {
		ok, msg := post(t, s, c.path, "team-a", agentPod(c.policy, c.edit))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}

// G-3: an update keeps the annotation as it was; nothing else is checked again
func TestPodUpdate(t *testing.T) {
	s := testServer(t, "")
	gone := agentPod("nosuch", nil)
	for _, c := range []struct {
		what     string
		old, new pod
		why      string
	}{
		{"the annotation unchanged, its policy gone", gone, gone, ""},
		{"the annotation removed", agentPod("agent", nil), agentPod("", nil), "not added, changed or removed"},
		{"the annotation changed", agentPod("agent", nil), agentPod("launch", nil), "not added, changed or removed"},
		{"the annotation added", agentPod("", nil), agentPod("agent", nil), "not added, changed or removed"},
	} {
		for _, path := range []string{"/pod", "/pod-required"} {
			ok, msg := postOp(t, s, path, "team-a", "UPDATE", c.new, c.old)
			if ok != (c.why == "") || !strings.Contains(msg, c.why) {
				t.Errorf("%s (%s): allowed %v, %q", c.what, path, ok, msg)
			}
		}
	}
}

// W2: a verdict is kept by the policy's hash; a check that did not finish is not kept
func TestCheckKept(t *testing.T) {
	d := t.TempDir()
	count := filepath.Join(d, "count")
	w := filepath.Join(d, "warden")
	os.WriteFile(w, []byte("#!/bin/sh\necho x >> "+count+"\ngrep -q slow \"$1\" && exec sleep 5\necho '{}'\n"), 0o755)
	s := newServer(w, fakeAPI{}, "")
	s.check(context.Background(), "allow path /tmp/\n", "team-a")
	s.check(context.Background(), "allow path /tmp/\n", "team-a")
	if b, _ := os.ReadFile(count); strings.Count(string(b), "x") != 1 {
		t.Errorf("a policy checked again: %q", b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if c := s.check(ctx, "slow\n", "team-a"); !strings.Contains(c.why, "did not finish") {
		t.Errorf("a check past its time: %+v", c)
	}
	if len(s.cache) != 1 {
		t.Errorf("a check that did not finish is kept: %d kept", len(s.cache))
	}
}

func TestDecidesLaunches(t *testing.T) {
	for text, want := range map[string]bool{"allow path /tmp/\n": false, "require warden 1.26\n": false,
		"require warden 1.27\n": true, "  require warden 1.31\n": true, "require warden 2.0\n": true, "# require warden 1.29\n": false,
		"require\vwarden\f1.29\r\n": true, "\trequire warden\t1.27\n": true} {
		if decidesLaunches(text) != want {
			t.Errorf("%q: not %v", text, want)
		}
	}
}

// The real Warden, when VAREK_WARDEN names it (make test-varek-k8s)
func TestRealWarden(t *testing.T) {
	w := os.Getenv("VAREK_WARDEN")
	if w == "" {
		t.Skip("VAREK_WARDEN is not set")
	}
	s := testServer(t, w)
	for _, c := range []struct {
		what, text, why string
	}{
		{"a policy it loads", "require warden 1.29\nallow path /tmp/\n", ""},
		{"one it does not parse", "allow pathh /tmp/\n", "refuses this policy"},
		// v1.36 step 4 (D2): credentials, checked against the cluster's VarekCredential resources
		{"a credential given to the namespace", "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n", ""},
		{"one no VarekCredential gives", "require warden 1.28\nproxy on\ncredential k from file:/etc/varek/creds/k\nallow host api.example.com:443\n", "is given by no VarekCredential"},
		{"one from another source", "require warden 1.28\nproxy on\ncredential gh from vault:secret/gh#t\nallow host api.github.com:443\n", "names another source"},
	} {
		ok, msg := post(t, s, "/varekpolicy", "team-a", vp("agent", c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	// v1.35 step 4c: plans, as the Warden reads them
	for _, c := range []struct {
		what, text, why string
	}{
		{"a plan it reads", "plan 1.35\naction a file_open /tmp/x open=read\n", ""},
		{"one it does not", "plan 1.36\n", "refuses this plan"},
		{"an mcp_call step, which the node agent does not carry yet", "plan 1.35\naction m mcp_call http://10.0.0.1:8080/mcp\n",
			"does not carry mcp_call steps yet (step m)"},
	} {
		ok, msg := post(t, s, "/varekplan", "team-a", vplan("p1", c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("needs", nil)); ok || !strings.Contains(msg, "names its plan (varek.dev/plan)") {
		t.Errorf("`require plan`, a pod naming no plan: allowed %v, %q", ok, msg)
	}
}

// v1.35 step 4c (D11): a VarekPlan, and a pod's plan with its policy
func vplan(name, text string) map[string]interface{} {
	return map[string]interface{}{"metadata": map[string]string{"name": name, "namespace": "team-a"},
		"spec": map[string]string{"plan": text}}
}

func TestVarekPlan(t *testing.T) {
	s := testServer(t, "")
	for _, c := range []struct {
		what, name, text, why string
	}{
		{"a plan the Warden reads", "p1", "plan 1.35\naction a file_open /tmp/x\n", ""},
		{"a name the node agent does not take", "P_1", "plan 1.35\n", "is not 1 to 63"},
		{"an empty plan", "p1", " \n", "the plan is empty"},
		{"a step the node agent does not carry", "p1", "plan 1.35\naction m mcp_call http://10.0.0.1/mcp\n",
			"refuses this plan: --oci-filter: the plan: the node agent does not carry mcp_call steps yet"},
	} {
		ok, msg := post(t, s, "/varekplan", "team-a", vplan(c.name, c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}

func TestPodPlan(t *testing.T) {
	s := testServer(t, "")
	withPlan := func(policy, plan string) pod {
		p := agentPod(policy, nil)
		if p.Metadata.Annotations == nil {
			p.Metadata.Annotations = map[string]string{}
		}
		p.Metadata.Annotations[planAnnotation] = plan
		return p
	}
	for _, c := range []struct {
		what string
		p    pod
		why  string
	}{
		{"a pod with its plan", withPlan("held", "p1"), ""},
		{"a plan under a policy before 1.35 (a node before 1.35 would not hold it)", withPlan("agent", "p1"),
			"does not say `require warden 1.35`"},
		{"`require plan`, the pod's plan named", withPlan("needs", "p1"), ""},
		{"`require plan`, no plan named", agentPod("needs", nil), "refuses its policy needs: --oci-filter: the policy says require plan"},
		{"no such plan in the namespace", withPlan("held", "nosuch"), "no VarekPlan nosuch in namespace team-a"},
		{"a plan name that is not one", withPlan("held", "P_1"), "its plan name \"P_1\""},
		{"a plan the Warden refuses with the policy", withPlan("held", "pmcp"), "refuses its policy held with its plan pmcp"},
		{"a plan and no policy", withPlan("", "p1"), "names a plan (varek.dev/plan) and no policy"},
	} {
		ok, msg := post(t, s, "/pod", "team-a", c.p)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	for _, c := range []struct {
		what     string
		old, new pod
		why      string
	}{
		{"the plan unchanged", withPlan("agent", "p1"), withPlan("agent", "p1"), ""},
		{"the plan changed", withPlan("agent", "p1"), withPlan("agent", "p2"), "varek.dev/plan annotation is set when the pod is created"},
		{"the plan added", agentPod("agent", nil), withPlan("agent", "p1"), "varek.dev/plan annotation is set when the pod is created"},
	} {
		ok, msg := postOp(t, s, "/pod", "team-a", "UPDATE", c.new, c.old)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}

// v1.36 step 4 (D2): a VarekCredential, and the credentials a policy names
func vcred(name, cred, source string, ns ...string) map[string]interface{} {
	return map[string]interface{}{"metadata": map[string]string{"name": name},
		"spec": map[string]interface{}{"credential": cred, "source": source, "namespaces": ns}}
}

func TestVarekCredential(t *testing.T) {
	s := testServer(t, "")
	s.credDir = "/var/lib/varek/credentials"
	for _, c := range []struct {
		what string
		obj  map[string]interface{}
		why  string
	}{
		{"a file under the credentials directory", vcred("gh-token", "gh", "file:/var/lib/varek/credentials/gh/token", "team-a"), ""},
		{"a Vault secret's field", vcred("db", "db", "vault:database/creds/ro#password", "team-a", "team-b"), ""},
		{"an AWS secret", vcred("stripe", "stripe", "aws-sm:arn:aws:secretsmanager:us-east-1:111122223333:secret:s-AbC", "team-a"), ""},
		{"a credential's name a policy cannot write", vcred("x", "GH-token", "file:/var/lib/varek/credentials/x", "team-a"), "is not a credential's name"},
		{"a source that is not a store", vcred("x", "x", "env:X", "team-a"), "is not file:PATH, vault:PATH#FIELD or aws-sm:ARN"},
		{"a source with a space", vcred("x", "x", "file:/var/lib/varek/credentials/a b", "team-a"), "no space"},
		{"a Vault source with no field", vcred("x", "x", "vault:secret/data/x", "team-a"), "names its field"},
		{"no namespace", vcred("x", "x", "file:/var/lib/varek/credentials/x"), "names no namespace"},
		{"a namespace that is not one", vcred("x", "x", "file:/var/lib/varek/credentials/x", "Team_A"), "is not 1 to 63"},
		{"a file outside the credentials directory", vcred("x", "x", "file:/etc/shadow", "team-a"), "under /var/lib/varek/credentials"},
		{"a file named through ..", vcred("x", "x", "file:/var/lib/varek/credentials/../../../etc/shadow", "team-a"), "named plainly"},
	} {
		ok, msg := post(t, s, "/varekcredential", "", c.obj)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	if ok, _ := postOp(t, s, "/varekcredential", "", "DELETE", map[string]interface{}{}, nil); !ok {
		t.Error("a VarekCredential's deletion refused")
	}
}

func TestCredentialsGiven(t *testing.T) {
	s := testServer(t, "")
	pol := "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n"
	if ok, msg := post(t, s, "/varekpolicy", "team-a", vp("creds", pol)); !ok {
		t.Errorf("a policy naming a credential given to its namespace: refused: %q", msg)
	}
	b := vp("creds", pol)
	b["metadata"] = map[string]string{"name": "creds", "namespace": "team-b"}
	if ok, msg := post(t, s, "/varekpolicy", "team-b", b); ok || !strings.Contains(msg, "is not given to namespace team-b") {
		t.Errorf("a policy naming a credential not given to its namespace: allowed %v, %q", ok, msg)
	}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("creds", nil)); !ok {
		t.Errorf("a pod whose policy names a credential given to its namespace: refused: %q", msg)
	}
	bp := agentPod("creds", func(p *pod) { p.Metadata.Namespace = "team-b" })
	if ok, msg := post(t, s, "/pod", "team-b", bp); ok || !strings.Contains(msg, "is not given to namespace team-b") {
		t.Errorf("a pod whose policy names a credential not given to its namespace: allowed %v, %q", ok, msg)
	}
}
