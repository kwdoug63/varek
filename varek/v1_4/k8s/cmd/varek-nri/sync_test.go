// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

func item(ns, name, rv, text string) string {
	return fmt.Sprintf(`{"metadata":{"namespace":%q,"name":%q,"resourceVersion":%q},"spec":{"policy":%q}}`, ns, name, rv, text)
}

// a stand-in API server: one list in two pages, then a watch with three events, then one
// that ends 410 (a list again), then a watch that waits
func fakeAPI(t *testing.T) (*httptest.Server, *int) {
	var mu sync.Mutex
	lists, watches := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/varek.dev/v1alpha1/varekpolicies" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Query().Get("watch") == "" {
			if r.URL.Query().Get("limit") != fmt.Sprint(kube.PageSize) {
				t.Errorf("a list without a page size: %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("continue") == "page-2" {
				fmt.Fprintf(w, `{"metadata":{"resourceVersion":"5"},"items":[%s]}`, item("Team_B", "agent", "4", "allow path /x/\n"))
				return
			}
			lists++
			if lists == 1 {
				fmt.Fprintf(w, `{"metadata":{"resourceVersion":"5","continue":"page-2"},"items":[%s,%s]}`,
					item("team-a", "agent", "3", "allow path /tmp/\n"), item("team-a", "old", "4", "allow path /old/\n"))
			} else {
				fmt.Fprintf(w, `{"metadata":{"resourceVersion":"9"},"items":[%s]}`, item("team-a", "agent", "6", "allow path /tmp/\nallow path /var/\n"))
			}
			return
		}
		watches++
		switch watches {
		case 1:
			if r.URL.Query().Get("resourceVersion") != "5" {
				t.Errorf("the watch from %q, not the list's version", r.URL.Query().Get("resourceVersion"))
			}
			fmt.Fprintln(w, `{"type":"MODIFIED","object":`+item("team-a", "agent", "6", "allow path /tmp/\nallow path /var/\n")+`}`)
			fmt.Fprintln(w, `{"type":"ADDED","object":`+item("team-c", "new", "7", "allow path /new/\n")+`}`)
			fmt.Fprintln(w, `{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"8"}}}`)
		case 2:
			if r.URL.Query().Get("resourceVersion") != "8" {
				t.Errorf("the second watch from %q, not the bookmark's", r.URL.Query().Get("resourceVersion"))
			}
			fmt.Fprintln(w, `{"type":"ERROR","object":{"kind":"Status","code":410,"message":"too old"}}`)
		default:
			mu.Unlock()
			<-r.Context().Done()
			mu.Lock()
		}
	}))
	return srv, &lists
}

func TestSync(t *testing.T) {
	srv, lists := fakeAPI(t)
	defer srv.Close()
	d := t.TempDir()
	tok := filepath.Join(d, "token")
	os.WriteFile(tok, []byte("tok\n"), 0o600)
	pol := filepath.Join(d, "policies")
	c := &kube.Client{Base: srv.URL, TokenFile: tok, HTTP: srv.Client()}
	s := &syncer{c: c, dir: pol, logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(pol, p)); return string(b) }
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && *lists < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if got := read("team-a/agent.policy"); got != "allow path /tmp/\nallow path /var/\n" {
		t.Errorf("a modified policy: %q", got)
	}
	if _, err := os.Stat(filepath.Join(pol, "team-a/old.policy")); !os.IsNotExist(err) {
		t.Errorf("a policy gone from the second list is removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pol, "team-c/new.policy")); !os.IsNotExist(err) {
		t.Errorf("a policy added, then gone from the list after the 410, is removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pol, "Team_B")); !os.IsNotExist(err) {
		t.Errorf("a namespace the node agent does not take is not written: %v", err)
	}
	st, err := os.Stat(filepath.Join(pol, "team-a/agent.policy"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("the policy file's mode: %v %v", st, err)
	}
	if e, _ := os.ReadDir(filepath.Join(pol, "team-a")); len(e) != 1 {
		t.Errorf("only the policy is left in its namespace's directory (no temporary file): %v", e)
	}
}

// v1.35 step 4c (D11): the VarekPlan resources, as <namespace>/<name>.plan,
// beside the policies and apart from them
func TestSyncPlans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/varek.dev/v1alpha1/varekplans" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("watch") == "" {
			fmt.Fprint(w, `{"metadata":{"resourceVersion":"3"},"items":[{"metadata":{"namespace":"team-a","name":"p1","resourceVersion":"2"},"spec":{"plan":"plan 1.35\naction a file_open /tmp/x\n"}}]}`)
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	pol := t.TempDir()
	os.MkdirAll(filepath.Join(pol, "team-a"), 0o755)
	os.WriteFile(filepath.Join(pol, "team-a", "agent.policy"), []byte("allow path /tmp/\n"), 0o644)
	os.WriteFile(filepath.Join(pol, "team-a", "gone.plan"), []byte("plan 1.35\n"), 0o644)
	s := &syncer{c: &kube.Client{Base: srv.URL, HTTP: srv.Client()}, dir: pol, logf: t.Logf, resource: kube.Plans}
	if _, err := s.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(pol, "team-a", "p1.plan")); string(b) != "plan 1.35\naction a file_open /tmp/x\n" {
		t.Errorf("the plan written: %q", b)
	}
	if _, err := os.Stat(filepath.Join(pol, "team-a", "gone.plan")); !os.IsNotExist(err) {
		t.Errorf("a plan gone from the list is removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pol, "team-a", "agent.policy")); err != nil {
		t.Errorf("the plans' prune leaves the policies: %v", err)
	}
}

// v1.36 step 4 (D2): the VarekCredential resources, as one list beside the
// policies (POLICY_DIR/.credentials), the ones the node agent does not take
// left out, rewritten as they change
func TestSyncCredentials(t *testing.T) {
	cr := func(name, cred, src, ns string) string {
		return fmt.Sprintf(`{"metadata":{"name":%q,"resourceVersion":"1"},"spec":{"credential":%q,"source":%q,"namespaces":[%s]}}`,
			name, cred, src, ns)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/varek.dev/v1alpha1/varekcredentials" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"metadata":{"resourceVersion":"3"},"items":[%s,%s,%s]}`,
			cr("gh-token", "gh", "file:/var/lib/varek/credentials/gh/token", `"team-a","team-b"`),
			cr("db", "db", "vault:database/creds/ro#password", `"team-a"`),
			cr("bad", "Bad-Name", "file:/x", `"team-a"`))
	}))
	defer srv.Close()
	pol := t.TempDir()
	s := &credSyncer{c: &kube.Client{Base: srv.URL, HTTP: srv.Client()}, dir: pol, logf: t.Logf}
	if _, err := s.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "# VAREK: the cluster's VarekCredential resources (v1.36): credential, namespaces, source, resource\n" +
		"db\tteam-a\tvault:database/creds/ro#password\tdb\n" +
		"gh\tteam-a,team-b\tfile:/var/lib/varek/credentials/gh/token\tgh-token\n"
	path := filepath.Join(pol, kube.CredentialListFile)
	if b, _ := os.ReadFile(path); string(b) != want {
		t.Errorf("the list: %q", b)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("the list's mode: %v %v", st, err)
	}
	if err := s.event(kube.Event{Type: "DELETED", Object: []byte(cr("db", "db", "vault:database/creds/ro#password", `"team-a"`))}); err != nil {
		t.Fatal(err)
	}
	if err := s.event(kube.Event{Type: "MODIFIED", Object: []byte(cr("gh-token", "gh", "file:/var/lib/varek/credentials/gh/token", `"team-c"`))}); err != nil {
		t.Fatal(err)
	}
	want = "# VAREK: the cluster's VarekCredential resources (v1.36): credential, namespaces, source, resource\n" +
		"gh\tteam-c\tfile:/var/lib/varek/credentials/gh/token\tgh-token\n"
	if b, _ := os.ReadFile(path); string(b) != want {
		t.Errorf("the list after a deletion and a change: %q", b)
	}
	if e, _ := os.ReadDir(pol); len(e) != 1 {
		t.Errorf("only the list is left (no temporary file): %v", e)
	}
}

// v1.36 step 7 (D6, D7, D7b): a VarekPolicy's flow policy and options beside
// its policy, kept while it says them and removed with it
func TestSyncFlowAndOptions(t *testing.T) {
	d := t.TempDir()
	s := &syncer{dir: d, logf: func(string, ...interface{}) {}}
	p := &kube.Policy{}
	p.Metadata.Namespace, p.Metadata.Name = "team-a", "agent"
	p.Spec.Policy, p.Spec.FlowPolicy, p.Spec.DryRun, p.Spec.TrustBundle = "allow path /tmp/\n", "varek_policy 1\n", true, "corp.pem"
	if err := s.write(p); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(d, "team-a", "agent")
	read := func(ext string) string { b, _ := os.ReadFile(base + ext); return string(b) }
	if read(".policy") != "allow path /tmp/\n" || read(".flow") != "varek_policy 1\n" ||
		read(".run") != `{"dryRun":true,"trustBundle":"corp.pem"}`+"\n" {
		t.Fatalf("the files: %q %q %q", read(".policy"), read(".flow"), read(".run"))
	}
	if st, err := os.Stat(base + ".flow"); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("the flow policy readable by all, written by root alone: %v", err)
	}
	p.Spec.FlowPolicy, p.Spec.DryRun, p.Spec.TrustBundle = "", false, ""
	if err := s.write(p); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".flow", ".run"} {
		if _, err := os.Stat(base + ext); !os.IsNotExist(err) {
			t.Errorf("%s kept for a policy that no longer says it: %v", ext, err)
		}
	}
	p.Spec.FlowPolicy = "varek_policy 1\n"
	s.write(p)
	if err := s.prune(map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".policy", ".flow"} {
		if _, err := os.Stat(base + ext); !os.IsNotExist(err) {
			t.Errorf("%s kept after its resource is gone: %v", ext, err)
		}
	}
	// plans have their own file alone
	ps := &syncer{dir: d, logf: s.logf, resource: kube.Plans}
	pl := &kube.Policy{}
	pl.Metadata.Namespace, pl.Metadata.Name, pl.Spec.Plan = "team-a", "p1", "plan 1.35\n"
	if err := ps.write(pl); err != nil || read(".flow") != "" {
		t.Fatalf("a plan: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "team-a", "p1.plan")); string(b) != "plan 1.35\n" {
		t.Errorf("the plan's file: %q", b)
	}
}
