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

// v1.36 step 7: --dry-run for a policy naming credentials, and a flow
// policy holding "nobudget" or given with --no-plan, are refused too.
//
// a stand-in for the Warden: it refuses a policy holding "bad"; v1.35: a
// plan holding "nosuchkind" (--plan; v1.36 step 5: a plan that does not
// read, as every kind of step is carried), and --no-plan for a policy holding
// "require plan"; v1.36: a policy's first credential (credential NAME from
// SRC) not given to --pod-namespace from SRC by --credential-list
const fakeWarden = `#!/bin/sh
pol="$1"; shift
grep -q bad "$pol" && { echo "[warden] policy $pol:2: a bad line" >&2; exit 1; }
[ "$1" = --oci-filter ] || exit 2; shift
plan= noplan= list= ns= dry= flow=
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) plan="$2"; shift 2 ;;
    --no-plan) noplan=1; shift ;;
    --dry-run) dry=1; shift ;;
    --flow-policy) flow="$2"; shift 2 ;;
    --credential-list) list="$2"; shift 2 ;;
    --pod-namespace) ns="$2"; shift 2 ;;
    *) exit 2 ;;
  esac
done
[ -n "$dry" ] && grep -q credential "$pol" && { echo "[warden] --oci-filter: --dry-run with a policy that names credentials is refused" >&2; exit 1; }
[ -n "$flow" ] && grep -q nobudget "$flow" && { echo "[warden] --flow-policy $flow declares no session_refusal_budget. refusing to start" >&2; exit 1; }
[ -n "$flow" ] && [ -n "$noplan" ] && { echo "[warden] --oci-filter: the policy has a flow policy, which checks a plan: a pod under it names its plan (varek.dev/plan)" >&2; exit 1; }
[ -n "$plan" ] && grep -q nosuchkind "$plan" && { echo "[warden] --oci-filter: the plan $plan: the plan does not read: line 2: an unknown kind of step" >&2; exit 1; }
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
		"plan:team-a/pbad": "plan 1.35\naction m nosuchkind /x\n",
		// v1.36 step 4 (D2)
		"team-a/creds":  "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n",
		"team-b/creds":  "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n",
		"cred:gh-token": "gh file:/var/lib/varek/credentials/gh/token team-a,team-c",
		// v1.36 step 6 (D5)
		"team-a/obo": "require warden 1.29\nrequire on-behalf-of\ntrust issuer https://idp.example/ audience varek-agent\nallow path /tmp/\n",
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
		// v1.36 step 5 (D4): carried, decided as on a host when the pod starts
		{"an mcp_call step", "plan 1.35\naction m mcp_call http://10.0.0.1:8080/mcp\n", ""},
	} {
		ok, msg := post(t, s, "/varekplan", "team-a", vplan("p1", c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("needs", nil)); ok || !strings.Contains(msg, "names its plan (varek.dev/plan)") {
		t.Errorf("`require plan`, a pod naming no plan: allowed %v, %q", ok, msg)
	}
	// v1.36 step 6 (D5): a policy that says `require on-behalf-of`, loaded and
	// carried; a pod under it acts for a user, as the webhook gives it
	obo := "require warden 1.29\nrequire on-behalf-of\ntrust issuer https://idp.example/ audience varek-agent\nallow path /tmp/\n"
	if ok, msg := post(t, s, "/varekpolicy", "team-a", vp("obo", obo)); !ok {
		t.Errorf("a policy that says `require on-behalf-of`: %q", msg)
	}
	s.oboImage = "registry.example/varek-node@sha256:abc"
	if ok, msg := post(t, s, "/pod", "team-a", oboPod(t, s, "obo", nil)); !ok {
		t.Errorf("a pod acting for a user under it: %q", msg)
	}
	// v1.36 step 7 (D6, D7b): a dry run and a flow policy, as the Warden checks them
	flow := "varek_policy 1\nlabel SECRET 0\nsticky SECRET\nrefusal_budget 2\nsession_refusal_budget 3\non_exhaustion deny\n" +
		"unknown_disposition deny\nrule file_open\n  match target /data/denied\n  origin SECRET\n"
	for _, c := range []struct {
		what string
		text string
		spec map[string]interface{}
		why  string
	}{
		{"a dry run", "require warden 1.29\nallow path /tmp/\n", map[string]interface{}{"dryRun": true}, ""},
		{"a dry run with credentials", "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n",
			map[string]interface{}{"dryRun": true}, "--dry-run with a policy that names credentials is refused"},
		{"a flow policy it certifies", "require warden 1.35\nallow path /tmp/\n", map[string]interface{}{"flowPolicy": flow}, ""},
		{"one without a session_refusal_budget", "require warden 1.35\nallow path /tmp/\n",
			map[string]interface{}{"flowPolicy": strings.Replace(flow, "session_refusal_budget 3\n", "", 1)}, "declares no session_refusal_budget"},
		{"a dry run with a flow policy", "require warden 1.35\nallow path /tmp/\n", map[string]interface{}{"dryRun": true, "flowPolicy": flow},
			"--dry-run with a flow policy"},
	} {
		ok, msg := post(t, s, "/varekpolicy", "team-a", vpx("agent", c.text, c.spec))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
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
		{"a plan the Warden does not read", "p1", "plan 1.35\naction m nosuchkind /x\n",
			"refuses this plan: --oci-filter: the plan: the plan does not read"},
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
		{"a plan the Warden refuses with the policy", withPlan("held", "pbad"), "refuses its policy held with its plan pbad"},
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

// v1.36 step 6 (D5): a pod acting for a user, as the mutating hook gives it
// (the patch applied, and the API server's defaults)
func oboPod(t *testing.T, s *server, policy string, edit func(m map[string]interface{})) map[string]interface{} {
	t.Helper()
	p := agentPod(policy, nil)
	p.Metadata.Annotations[oboAnnotation] = "alice-token"
	b, _ := json.Marshal(p)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	spec := m["spec"].(map[string]interface{})
	spec["volumes"] = []interface{}{s.oboVolume("alice-token")}
	c := s.oboContainer()
	c["imagePullPolicy"], c["terminationMessagePath"] = "IfNotPresent", "/dev/termination-log"
	c["volumeMounts"] = append(c["volumeMounts"].([]interface{}), map[string]interface{}{"name": "kube-api-access-x",
		"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true})
	spec["initContainers"] = []interface{}{c}
	if edit != nil {
		edit(m)
	}
	return m
}

func mutateOps(t *testing.T, s *server, obj interface{}) (bool, string, []patchOp) {
	t.Helper()
	b, _ := json.Marshal(obj)
	in, _ := json.Marshal(review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
		Request: &request{UID: "u-1", Namespace: "team-a", Operation: "CREATE", Object: b}})
	rec := httptest.NewRecorder()
	s.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pod-mutate", bytes.NewReader(in)))
	var out review
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Response == nil || out.Response.UID != "u-1" {
		t.Fatalf("/pod-mutate: the answer does not read: %s", rec.Body.String())
	}
	var ops []patchOp
	if out.Response.Patch != nil {
		if out.Response.PatchType == nil || *out.Response.PatchType != "JSONPatch" {
			t.Errorf("a patch without its type: %s", rec.Body.String())
		}
		if err := json.Unmarshal(out.Response.Patch, &ops); err != nil {
			t.Fatalf("the patch: %v", err)
		}
	}
	msg := ""
	if out.Response.Status != nil {
		msg = out.Response.Status.Message
	}
	return out.Response.Allowed, msg, ops
}

func TestPodMutate(t *testing.T) {
	s := testServer(t, "")
	acting := agentPod("obo", func(p *pod) { p.Metadata.Annotations[oboAnnotation] = "alice-token" })
	if ok, msg, _ := mutateOps(t, s, acting); ok || !strings.Contains(msg, "-obo-image") {
		t.Errorf("no image for the init container: allowed %v, %q", ok, msg)
	}
	s.oboImage = "registry.example/varek-node@sha256:abc"
	ok, msg, ops := mutateOps(t, s, acting)
	if !ok || len(ops) != 2 || ops[0].Path != "/spec/volumes" || ops[1].Path != "/spec/initContainers" {
		t.Fatalf("the volume and the init container given: %v %q %+v", ok, msg, ops)
	}
	vol, _ := json.Marshal(ops[0].Value)
	if !strings.Contains(string(vol), `"secretName":"alice-token"`) || !strings.Contains(string(vol), `"key":"token","path":"token"`) {
		t.Errorf("the volume: %s", vol)
	}
	ctr, _ := json.Marshal(ops[1].Value)
	for _, w := range []string{`"name":"varek-obo"`, `"image":"registry.example/varek-node@sha256:abc"`, `"command":["/bin/true"]`,
		`"mountPath":"/var/run/varek-obo"`, `"readOnly":true`, `"runAsUser":65534`, `"type":"RuntimeDefault"`} {
		if !strings.Contains(string(ctr), w) {
			t.Errorf("the init container: %s not in %s", w, ctr)
		}
	}
	// a pod with init containers and volumes of its own: added to theirs
	more := agentPod("obo", func(p *pod) {
		p.Metadata.Annotations[oboAnnotation] = "alice-token"
		p.Spec.InitContainers = []container{{Name: "setup"}}
	})
	m := map[string]interface{}{}
	b, _ := json.Marshal(more)
	json.Unmarshal(b, &m)
	m["spec"].(map[string]interface{})["volumes"] = []interface{}{map[string]interface{}{"name": "data", "emptyDir": map[string]interface{}{}}}
	if ok, _, ops := mutateOps(t, s, m); !ok || len(ops) != 2 || ops[0].Path != "/spec/volumes/-" || ops[1].Path != "/spec/initContainers/0" {
		t.Errorf("added to the pod's own: %+v", ops)
	}
	// as the webhook gave it already: nothing more
	if ok, msg, ops := mutateOps(t, s, oboPod(t, s, "obo", nil)); !ok || len(ops) != 0 {
		t.Errorf("given already: %v %q %+v", ok, msg, ops)
	}
	s.oboUser = 0
	if _, _, ops := mutateOps(t, s, acting); len(ops) != 2 {
		t.Errorf("-obo-user 0: %+v", ops)
	} else if c, _ := json.Marshal(ops[1].Value); strings.Contains(string(c), "runAsUser") {
		t.Errorf("-obo-user 0: the platform's user (OpenShift's), not one given: %s", c)
	}
	s.oboUser = oboNobody
	for _, c := range []struct {
		what string
		obj  interface{}
		why  string
	}{
		{"a pod acting for no one", agentPod("obo", nil), ""},
		{"a pod naming no policy", agentPod("", func(p *pod) { p.Metadata.Annotations = map[string]string{oboAnnotation: "x"} }), ""},
		{"not a Secret's name", agentPod("obo", func(p *pod) { p.Metadata.Annotations[oboAnnotation] = "Alice/x" }), "not a Secret's name"},
		{"a volume of the name, its own", oboPod(t, s, "obo", func(m map[string]interface{}) {
			m["spec"].(map[string]interface{})["volumes"] = []interface{}{map[string]interface{}{"name": oboName, "emptyDir": map[string]interface{}{}}}
		}), "its volume varek-obo is not the webhook's"},
		{"an init container of the name, its own", oboPod(t, s, "obo", func(m map[string]interface{}) {
			m["spec"].(map[string]interface{})["initContainers"].([]interface{})[0].(map[string]interface{})["command"] = []string{"/bin/sh"}
		}), "its init container varek-obo is not the webhook's"},
		{"a container of the name", agentPod("obo", func(p *pod) {
			p.Metadata.Annotations[oboAnnotation] = "alice-token"
			p.Spec.Containers[0].Name = oboName
		}), "the name is the webhook's init container's"},
	} {
		ok, msg, ops := mutateOps(t, s, c.obj)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) || (c.why == "" && len(ops) != 0) {
			t.Errorf("%s: allowed %v, %q, %+v", c.what, ok, msg, ops)
		}
	}
	// an update is not changed
	b, _ = json.Marshal(acting)
	if ops, why := s.mutate(&request{Operation: "UPDATE", Object: b}); len(ops) != 0 || why != "" {
		t.Errorf("an update: %+v %q", ops, why)
	}
}

func TestPodOnBehalfOf(t *testing.T) {
	s := testServer(t, "")
	s.oboImage = "registry.example/varek-node@sha256:abc"
	spec := func(m map[string]interface{}) map[string]interface{} { return m["spec"].(map[string]interface{}) }
	initc := func(m map[string]interface{}) map[string]interface{} {
		return spec(m)["initContainers"].([]interface{})[0].(map[string]interface{})
	}
	isc := func(m map[string]interface{}) map[string]interface{} {
		return initc(m)["securityContext"].(map[string]interface{})
	}
	for _, c := range []struct {
		what   string
		policy string
		edit   func(m map[string]interface{})
		why    string
	}{
		{"as the webhook gives it", "obo", nil, ""},
		{"... under a policy that does not require it", "agent", nil, ""},
		{"`require on-behalf-of`, acting for no one", "obo", func(m map[string]interface{}) {
			delete(m["metadata"].(map[string]interface{})["annotations"].(map[string]interface{}), oboAnnotation)
		}, "says `require on-behalf-of`, and it names no user's token"},
		{"no volume", "obo", func(m map[string]interface{}) { delete(spec(m), "volumes") }, "has not the token's volume"},
		{"no init container", "obo", func(m map[string]interface{}) { delete(spec(m), "initContainers") }, "has not the token's volume and init container"},
		{"the volume of another Secret", "obo", func(m map[string]interface{}) { spec(m)["volumes"] = []interface{}{s.oboVolume("bob")} }, "is not the webhook's"},
		{"the volume optional", "obo", func(m map[string]interface{}) {
			spec(m)["volumes"].([]interface{})[0].(map[string]interface{})["secret"].(map[string]interface{})["optional"] = true
		}, "is not the webhook's"},
		{"the volume twice", "obo", func(m map[string]interface{}) {
			spec(m)["volumes"] = append(spec(m)["volumes"].([]interface{}), s.oboVolume("alice-token"))
		}, "once each"},
		{"another image", "obo", func(m map[string]interface{}) { initc(m)["image"] = "evil:latest" }, "its image is not"},
		{"another command", "obo", func(m map[string]interface{}) {
			initc(m)["command"] = []string{"/bin/sh", "-c", "cat /var/run/varek-obo/token"}
		}, "its command is not"},
		{"args", "obo", func(m map[string]interface{}) { initc(m)["args"] = []string{"x"} }, "it has args"},
		{"an environment", "obo", func(m map[string]interface{}) { initc(m)["env"] = []interface{}{} }, "it has env"},
		{"a lifecycle hook", "obo", func(m map[string]interface{}) { initc(m)["lifecycle"] = map[string]interface{}{} }, "it has lifecycle"},
		{"a sidecar", "obo", func(m map[string]interface{}) { initc(m)["restartPolicy"] = "Always" }, "it has restartPolicy"},
		{"a writable mount", "obo", func(m map[string]interface{}) {
			initc(m)["volumeMounts"] = []interface{}{map[string]interface{}{"name": oboName, "mountPath": oboMount}}
		}, "is not read-only"},
		{"as root", "obo", func(m map[string]interface{}) { isc(m)["runAsUser"] = 0 }, "securityContext is not the webhook's"},
		{"privilege escalation", "obo", func(m map[string]interface{}) { delete(isc(m), "allowPrivilegeEscalation") }, "securityContext is not the webhook's"},
		{"a capability added", "obo", func(m map[string]interface{}) {
			isc(m)["capabilities"] = map[string]interface{}{"drop": []string{"ALL"}, "add": []string{"DAC_READ_SEARCH"}}
		}, "securityContext is not the webhook's"},
		{"the unsupervised profile (which the plugin does not replace for it)", "obo", func(m map[string]interface{}) {
			isc(m)["seccompProfile"] = map[string]interface{}{"type": "Localhost", "localhostProfile": unsupervised}
		}, "securityContext is not the webhook's"},
		{"the agent mounting the token's volume", "obo", func(m map[string]interface{}) {
			c := spec(m)["containers"].([]interface{})[0].(map[string]interface{})
			c["volumeMounts"] = []interface{}{map[string]interface{}{"name": oboName, "mountPath": "/t", "readOnly": true}}
		}, "container agent mounts varek-obo"},
		{"the init container's user from the platform (-obo-user 0)", "obo", func(m map[string]interface{}) {
			delete(isc(m), "runAsUser")
			delete(isc(m), "runAsGroup")
		}, ""},
		// v1.36 step 11 (review)
		{"the API server's service account mount too", "obo", func(m map[string]interface{}) {
			initc(m)["volumeMounts"] = append(initc(m)["volumeMounts"].([]interface{}),
				map[string]interface{}{"name": "kube-api-access-x7k2p", "mountPath": saMount, "readOnly": true})
		}, ""},
		{"a volume of the pod's at /bin", "obo", func(m map[string]interface{}) {
			initc(m)["volumeMounts"] = append(initc(m)["volumeMounts"].([]interface{}),
				map[string]interface{}{"name": "tools", "mountPath": "/bin", "readOnly": true})
		}, "it mounts tools at /bin"},
		{"the token's volume twice", "obo", func(m map[string]interface{}) {
			initc(m)["volumeMounts"] = append(initc(m)["volumeMounts"].([]interface{}),
				map[string]interface{}{"name": oboName, "mountPath": oboMount, "readOnly": true})
		}, "once"},
		{"an SELinux type", "obo", func(m map[string]interface{}) {
			isc(m)["seLinuxOptions"] = map[string]interface{}{"type": "spc_t"}
		}, "seLinuxOptions name a type"},
		{"the platform's SELinux level", "obo", func(m map[string]interface{}) {
			isc(m)["seLinuxOptions"] = map[string]interface{}{"level": "s0:c26,c5"}
		}, ""},
		{"AppArmor unconfined", "obo", func(m map[string]interface{}) {
			isc(m)["appArmorProfile"] = map[string]interface{}{"type": "Unconfined"}
		}, "appArmorProfile is not the runtime's default"},
		{"an unmasked /proc", "obo", func(m map[string]interface{}) { isc(m)["procMount"] = "Unmasked" }, "procMount is not Default"},
		{"a Windows option", "obo", func(m map[string]interface{}) { isc(m)["windowsOptions"] = map[string]interface{}{} }, "securityContext has windowsOptions"},
		{"the token's Secret as another volume", "obo", func(m map[string]interface{}) {
			spec(m)["volumes"] = append(spec(m)["volumes"].([]interface{}),
				map[string]interface{}{"name": "t2", "secret": map[string]interface{}{"secretName": "alice-token"}})
		}, "its volume t2 is the user's token's Secret alice-token too"},
		{"the token's Secret projected", "obo", func(m map[string]interface{}) {
			spec(m)["volumes"] = append(spec(m)["volumes"].([]interface{}), map[string]interface{}{"name": "t3",
				"projected": map[string]interface{}{"sources": []interface{}{map[string]interface{}{"secret": map[string]interface{}{"name": "alice-token"}}}}})
		}, "its volume t3 projects the user's token's Secret alice-token"},
		{"the token's Secret in the agent's env", "obo", func(m map[string]interface{}) {
			c := spec(m)["containers"].([]interface{})[0].(map[string]interface{})
			c["env"] = []interface{}{map[string]interface{}{"name": "T", "valueFrom": map[string]interface{}{
				"secretKeyRef": map[string]interface{}{"name": "alice-token", "key": "token"}}}}
		}, "container agent's environment names the user's token's Secret alice-token"},
		{"the token's Secret in the agent's envFrom", "obo", func(m map[string]interface{}) {
			c := spec(m)["containers"].([]interface{})[0].(map[string]interface{})
			c["envFrom"] = []interface{}{map[string]interface{}{"secretRef": map[string]interface{}{"name": "alice-token"}}}
		}, "container agent's environment names the user's token's Secret alice-token"},
		{"another Secret in the agent's env", "obo", func(m map[string]interface{}) {
			c := spec(m)["containers"].([]interface{})[0].(map[string]interface{})
			c["envFrom"] = []interface{}{map[string]interface{}{"secretRef": map[string]interface{}{"name": "app-config"}}}
		}, ""},
	} {
		ok, msg := post(t, s, "/pod", "team-a", oboPod(t, s, c.policy, c.edit))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("", func(p *pod) {
		p.Metadata.Annotations = map[string]string{oboAnnotation: "alice-token"}
	})); ok || !strings.Contains(msg, "names no policy") {
		t.Errorf("acting for a user under no policy: allowed %v, %q", ok, msg)
	}
	// an update: the annotation fixed; no ephemeral container added that mounts the volume
	old := oboPod(t, s, "obo", nil)
	for _, c := range []struct {
		what string
		edit func(m map[string]interface{})
		why  string
	}{
		{"unchanged", nil, ""},
		{"the annotation removed", func(m map[string]interface{}) {
			delete(m["metadata"].(map[string]interface{})["annotations"].(map[string]interface{}), oboAnnotation)
		}, "not added, changed or removed"},
		{"the annotation changed", func(m map[string]interface{}) {
			m["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})[oboAnnotation] = "bob"
		}, "not added, changed or removed"},
		{"an ephemeral container mounting the volume", func(m map[string]interface{}) {
			spec(m)["ephemeralContainers"] = []interface{}{map[string]interface{}{"name": "debug",
				"volumeMounts": []interface{}{map[string]interface{}{"name": oboName, "mountPath": "/t"}}}}
		}, "container debug, added, mounts varek-obo"},
		{"an ephemeral container of its own", func(m map[string]interface{}) {
			spec(m)["ephemeralContainers"] = []interface{}{map[string]interface{}{"name": "debug"}}
		}, ""},
		{"an ephemeral container naming the token's Secret", func(m map[string]interface{}) {
			spec(m)["ephemeralContainers"] = []interface{}{map[string]interface{}{"name": "debug",
				"envFrom": []interface{}{map[string]interface{}{"secretRef": map[string]interface{}{"name": "alice-token"}}}}}
		}, "ephemeral container debug's environment names the user's token's Secret"},
		{"the init container's image changed", func(m map[string]interface{}) { initc(m)["image"] = "evil:latest" },
			"its init container varek-obo is the webhook's, and not changed after"},
	} {
		ok, msg := postOp(t, s, "/pod", "team-a", "UPDATE", oboPod(t, s, "obo", c.edit), old)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("an update, %s: allowed %v, %q", c.what, ok, msg)
		}
	}
	if !requireOBO.MatchString("allow path /x\n  require\ton-behalf-of\n") || requireOBO.MatchString("# require on-behalf-of\n") ||
		requireOBO.MatchString("require on-behalf-ofx\n") {
		t.Error("the `require on-behalf-of` line")
	}
}

// v1.36 step 7 (D6, D7, D7b): a VarekPolicy's dry run, flow policy and trust bundle
func vpx(name, text string, spec map[string]interface{}) map[string]interface{} {
	spec["policy"] = text
	return map[string]interface{}{"metadata": map[string]string{"name": name, "namespace": "team-a"}, "spec": spec}
}

func TestVarekPolicyDryFlowTrust(t *testing.T) {
	s := testServer(t, "")
	creds := "require warden 1.28\nproxy on\ncredential gh from file:/var/lib/varek/credentials/gh/token\nallow host api.github.com:443\n"
	for _, c := range []struct {
		what string
		text string
		spec map[string]interface{}
		why  string
	}{
		{"a dry run", "allow path /tmp/\n", map[string]interface{}{"dryRun": true}, ""},
		{"a dry run with credentials: refused by the Warden", creds, map[string]interface{}{"dryRun": true}, "--dry-run with a policy that names credentials"},
		{"a flow policy the Warden loads", "allow path /tmp/\n", map[string]interface{}{"flowPolicy": "varek_policy 1\n"}, ""},
		{"one it refuses, its reason given", "allow path /tmp/\n", map[string]interface{}{"flowPolicy": "nobudget\n"},
			"the flow policy declares no session_refusal_budget"},
		{"a trust bundle", "allow path /tmp/\n", map[string]interface{}{"trustBundle": "corp-ca.pem"}, ""},
		{"a trust bundle that is not a key", "allow path /tmp/\n", map[string]interface{}{"trustBundle": "../ca.pem"}, "is not a ConfigMap's key"},
	} {
		ok, msg := post(t, s, "/varekpolicy", "team-a", vpx("agent", c.text, c.spec))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	// a pod under a policy with a flow policy names its plan
	s.api = fakeFlowAPI{fakeAPI{"plan:team-a/p1": "plan 1.35\naction a file_open /tmp/x\n"}}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("flowy", nil)); ok || !strings.Contains(msg, "names its plan") {
		t.Errorf("a flow policy, a pod naming no plan: allowed %v, %q", ok, msg)
	}
	if ok, msg := post(t, s, "/pod", "team-a", agentPod("flowy", func(p *pod) { p.Metadata.Annotations[planAnnotation] = "p1" })); !ok {
		t.Errorf("a flow policy, a pod naming its plan: %q", msg)
	}
}

// fakeAPI, with team-a/flowy a policy that has a flow policy
type fakeFlowAPI struct{ fakeAPI }

func (f fakeFlowAPI) GetPolicy(ctx context.Context, ns, name string) (*kube.Policy, error) {
	if ns+"/"+name != "team-a/flowy" {
		return f.fakeAPI.GetPolicy(ctx, ns, name)
	}
	p := &kube.Policy{}
	p.Metadata.Namespace, p.Metadata.Name = ns, name
	p.Spec.Policy, p.Spec.FlowPolicy = "require warden 1.35\nallow path /tmp/\n", "varek_policy 1\n"
	return p, nil
}

// v1.36 step 9 (D10): a node's key, admitted only from its node
func TestVarekNodeKey(t *testing.T) {
	s := testServer(t, "")
	key := strings.Repeat("ab", 32)
	agent := "system:serviceaccount:varek:varek-node"
	nk := func(node, name string) *kube.NodeKey {
		k := kube.NewNodeKey(node, key)
		if name != "" {
			k.Metadata.Name = name
		}
		return k
	}
	podBound := true
	ask := func(op string, k, old *kube.NodeKey, user, node string) (bool, string) {
		b, _ := json.Marshal(k)
		var ob []byte
		if old != nil {
			ob, _ = json.Marshal(old)
		}
		u := userInfo{Username: user}
		if node != "" {
			u.Extra = map[string][]string{nodeNameExtra: {node}}
			if podBound {
				u.Extra[podNameExtra], u.Extra[podUIDExtra] = []string{"varek-node-x7k2p"}, []string{"u-9"}
			}
		}
		in, _ := json.Marshal(review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
			Request: &request{UID: "u-1", Operation: op, Object: b, OldObject: ob, UserInfo: u}})
		rec := httptest.NewRecorder()
		s.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vareknodekey", bytes.NewReader(in)))
		var out review
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Response == nil {
			t.Fatalf("the answer does not read: %s", rec.Body.String())
		}
		if out.Response.Status != nil {
			return out.Response.Allowed, out.Response.Status.Message
		}
		return out.Response.Allowed, ""
	}
	if ok, msg := ask("CREATE", nk("node-1", ""), nil, agent, "node-1"); ok || !strings.Contains(msg, "-node-agent-sa") {
		t.Errorf("a webhook not given the node agent's account admits a key: %v %q", ok, msg)
	}
	s.nodeAgent = agent
	for _, c := range []struct {
		what       string
		k          *kube.NodeKey
		user, node string
		why        string
	}{
		{"the node agent, from the node it names", nk("node-1", ""), agent, "node-1", ""},
		{"the node agent, for another node", nk("node-2", ""), agent, "node-1", "the token was given on node-1, the key names node-2"},
		{"the node agent, its token naming no node", nk("node-1", ""), agent, "", "the token was given on , the key names node-1"},
		{"another account, from the node", nk("node-1", ""), "system:serviceaccount:team-a:default", "node-1", "only by the node agent"},
		{"an administrator", nk("node-1", ""), "kubernetes-admin", "", "only by the node agent"},
		{"named for another key", nk("node-1", "node-1-0000000000000000"), agent, "node-1", "named for its node and key: node-1-abababababababab"},
		{"a node's name Kubernetes would not give", nk("Node_1", ""), agent, "Node_1", "is not a node's name"},
	} {
		ok, msg := ask("CREATE", c.k, nil, c.user, c.node)
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
	bad := nk("node-1", "")
	bad.Spec.PublicKey = "AB" + key[2:]
	if ok, msg := ask("CREATE", bad, nil, agent, "node-1"); ok || !strings.Contains(msg, "64 lowercase hex") {
		t.Errorf("a key not as the Warden writes it: %v %q", ok, msg)
	}
	// never changed; labels and the like may be
	other := nk("node-1", "")
	other.Spec.PublicKey = strings.Repeat("cd", 32)
	if ok, msg := ask("UPDATE", nk("node-1", ""), other, "kubernetes-admin", ""); ok || !strings.Contains(msg, "is not changed") {
		t.Errorf("a key changed: %v %q", ok, msg)
	}
	if ok, msg := ask("UPDATE", nk("node-1", ""), nk("node-1", ""), "kubernetes-admin", ""); !ok {
		t.Errorf("an update leaving the key as it was refused: %q", msg)
	}
	// v1.36 step 11 (review): a token bound to the node alone; an owner; the node agent's own update
	podBound = false
	if ok, msg := ask("CREATE", nk("node-1", ""), nil, agent, "node-1"); ok || !strings.Contains(msg, "names no pod") {
		t.Errorf("a token bound to a node, not a pod: %v %q", ok, msg)
	}
	podBound = true
	owned := nk("node-1", "")
	b, _ := json.Marshal(owned)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	m["metadata"].(map[string]interface{})["ownerReferences"] = []interface{}{map[string]interface{}{"kind": "Pod", "name": "x"}}
	b, _ = json.Marshal(m)
	json.Unmarshal(b, owned)
	for _, op := range []string{"CREATE", "UPDATE"} {
		in, _ := json.Marshal(review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
			Request: &request{UID: "u-1", Operation: op, Object: b, OldObject: b, UserInfo: userInfo{Username: "kubernetes-admin"}}})
		rec := httptest.NewRecorder()
		s.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/vareknodekey", bytes.NewReader(in)))
		if !strings.Contains(rec.Body.String(), "has no owner") {
			t.Errorf("%s: a key given an owner: %s", op, rec.Body.String())
		}
	}
	if ok, msg := ask("UPDATE", nk("node-1", ""), nk("node-1", ""), agent, "node-1"); ok || !strings.Contains(msg, "does not change") {
		t.Errorf("the node agent updating its key: %v %q", ok, msg)
	}
	if ok, msg := ask("DELETE", &kube.NodeKey{}, nil, agent, "node-1"); ok || !strings.Contains(msg, "a node does not remove") {
		t.Errorf("a node removing a key: %v %q", ok, msg)
	}
	if ok, _ := ask("DELETE", &kube.NodeKey{}, nil, "kubernetes-admin", ""); !ok {
		t.Error("an administrator's removal of a key refused")
	}
}
