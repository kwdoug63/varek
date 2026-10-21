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

	"varek.dev/varek-k8s/internal/kube"
)

// a stand-in for the Warden: it refuses a policy holding "bad"
const fakeWarden = `#!/bin/sh
grep -q bad "$1" && { echo "[warden] policy $1:2: a bad line" >&2; exit 1; }
[ "$2" = --oci-filter ] || exit 2
echo '{}'
`

type fakeAPI map[string]string // "ns/name" -> policy text

func (f fakeAPI) GetPolicy(_ context.Context, ns, name string) (*kube.Policy, error) {
	t, ok := f[ns+"/"+name]
	if !ok {
		return nil, nil
	}
	p := &kube.Policy{}
	p.Metadata.Namespace, p.Metadata.Name, p.Spec.Policy = ns, name, t
	return p, nil
}

func newServer(t *testing.T, warden string) *server {
	if warden == "" {
		warden = filepath.Join(t.TempDir(), "warden")
		if err := os.WriteFile(warden, []byte(fakeWarden), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &server{warden: warden, cache: map[string]checked{}, api: fakeAPI{
		"team-a/agent":  "allow path /tmp/\n",
		"team-a/launch": "require warden 1.29\nallow path /tmp/\nallow exec /bin/true\n",
		"team-a/broken": "allow path /tmp/\nbad\n",
	}}
}

// post one AdmissionReview to path; allowed, and the message
func post(t *testing.T, s *server, path, ns string, obj interface{}) (bool, string) {
	b, _ := json.Marshal(obj)
	in, _ := json.Marshal(review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
		Request: &request{UID: "u-1", Namespace: ns, Operation: "CREATE", Object: b}})
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
	s := newServer(t, "")
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
	p.Spec.Containers = []container{{Name: "agent", Command: []string{"/usr/bin/agent"},
		SecurityContext: &secCtx{AllowPrivilegeEscalation: f(false), RunAsNonRoot: f(true), ReadOnlyRootFilesystem: f(true)}}}
	if edit != nil {
		edit(&p)
	}
	return p
}

func TestPod(t *testing.T) {
	s := newServer(t, "")
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
			p.Spec.SecurityContext = &secCtx{RunAsUser: n(1000)}
		}, ""},
		{"group root", "/pod", "agent", func(p *pod) { sc(p).RunAsGroup = n(0) }, "its group is root"},
		{"a command by a relative path", "/pod", "agent", func(p *pod) { p.Spec.Containers[0].Command = []string{"python"} }, "absolute path"},
		{"decided launches with a writable root", "/pod", "launch", func(p *pod) { sc(p).ReadOnlyRootFilesystem = f(false) }, "must be read-only"},
		{"the node's network", "/pod", "agent", func(p *pod) { p.Spec.HostNetwork = true }, "hostNetwork"},
		{"an init container checked too", "/pod", "agent", func(p *pod) {
			p.Spec.InitContainers = []container{{Name: "init", SecurityContext: &secCtx{RunAsNonRoot: f(true)}}}
		}, "container init: allowPrivilegeEscalation"},
	} {
		ok, msg := post(t, s, c.path, "team-a", agentPod(c.policy, c.edit))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}

func TestDecidesLaunches(t *testing.T) {
	for text, want := range map[string]bool{"allow path /tmp/\n": false, "require warden 1.26\n": false,
		"require warden 1.27\n": true, "  require warden 1.31\n": true, "require warden 2.0\n": true, "# require warden 1.29\n": false} {
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
	s := newServer(t, w)
	for _, c := range []struct {
		what, text, why string
	}{
		{"a policy it loads", "require warden 1.29\nallow path /tmp/\n", ""},
		{"one it does not parse", "allow pathh /tmp/\n", "refuses this policy"},
		{"credentials, which the node agent does not carry yet", "require warden 1.28\nproxy on\ncredential k from file:/etc/varek/creds/k\nallow host api.example.com:443\n", "does not carry credentials"},
	} {
		ok, msg := post(t, s, "/varekpolicy", "team-a", vp("agent", c.text))
		if ok != (c.why == "") || !strings.Contains(msg, c.why) {
			t.Errorf("%s: allowed %v, %q", c.what, ok, msg)
		}
	}
}
