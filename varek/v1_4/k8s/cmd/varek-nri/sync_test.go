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
