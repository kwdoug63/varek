// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

// a stand-in API server holding VarekNodeKey resources by name
type keyAPI struct {
	mu    sync.Mutex
	keys  map[string]kube.NodeKey
	posts int
}

func (a *keyAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	const base = "/apis/varek.dev/v1alpha1/vareknodekeys"
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == base:
		a.posts++
		var k kube.NodeKey
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &k) != nil || k.Kind != "VarekNodeKey" || k.APIVersion != "varek.dev/v1alpha1" {
			http.Error(w, "not a VarekNodeKey", http.StatusBadRequest)
			return
		}
		if _, ok := a.keys[k.Metadata.Name]; ok {
			http.Error(w, `{"reason":"AlreadyExists"}`, http.StatusConflict)
			return
		}
		a.keys[k.Metadata.Name] = k
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, string(b))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/"):
		k, ok := a.keys[strings.TrimPrefix(r.URL.Path, base+"/")]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(k)
	default:
		http.Error(w, "no", http.StatusMethodNotAllowed)
	}
}

func TestKeyPublisher(t *testing.T) {
	api := &keyAPI{keys: map[string]kube.NodeKey{}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	d := t.TempDir()
	tok := filepath.Join(d, "token")
	os.WriteFile(tok, []byte("tok\n"), 0o600)
	c, err := kube.InCluster(srv.URL, tok, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(d, "node.key.pub")
	key := strings.Repeat("0f", 32)
	var logs []string
	var lm sync.Mutex
	logf := func(f string, a ...interface{}) { lm.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); lm.Unlock() }
	// the node agent writes its key a little after the plugin starts
	go func() { time.Sleep(50 * time.Millisecond); os.WriteFile(pub, []byte(key+"\n"), 0o444) }()
	// held reads the stand-in API server's resource of that name
	held := func(name string) (kube.NodeKey, bool) {
		api.mu.Lock()
		defer api.mu.Unlock()
		k, ok := api.keys[name]
		return k, ok
	}
	waitFor := func(name string) kube.NodeKey {
		for i := 0; i < 1000; i++ {
			if k, ok := held(name); ok {
				return k
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s was not published", name)
		return kube.NodeKey{}
	}
	ctx1, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&keyPublisher{c: c, node: "node-1", pub: pub, logf: logf, wait: 10 * time.Millisecond, watch: 10 * time.Millisecond}).run(ctx1)
		close(done)
	}()
	k := waitFor("node-1-0f0f0f0f0f0f0f0f")
	if k.Spec.Node != "node-1" || k.Spec.PublicKey != key {
		t.Fatalf("published %+v", k)
	}
	// the node agent lost its key and made a new one after the plugin read
	// the old file: the new key published too, the old one kept
	key2 := strings.Repeat("1e", 32)
	os.WriteFile(pub+".new", []byte(key2+"\n"), 0o444)
	os.Rename(pub+".new", pub)
	k2 := waitFor("node-1-1e1e1e1e1e1e1e1e")
	if k2.Spec.Node != "node-1" || k2.Spec.PublicKey != key2 {
		t.Fatalf("published %+v", k2)
	}
	if _, ok := held("node-1-0f0f0f0f0f0f0f0f"); !ok {
		t.Error("the old key's VarekNodeKey is gone")
	}
	stop()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the publisher did not stop with its context")
	}
	lm.Lock()
	all := strings.Join(logs, "\n")
	if !strings.Contains(all, "not published yet") || !strings.Contains(all, "VarekNodeKey node-1-0f0f0f0f0f0f0f0f") ||
		!strings.Contains(logs[len(logs)-1], "VarekNodeKey node-1-1e1e1e1e1e1e1e1e") {
		t.Errorf("logs: %q", logs)
	}
	lm.Unlock()
	api.mu.Lock()
	posts := api.posts
	api.mu.Unlock()
	if posts != 2 {
		t.Errorf("%d posts: each key once, the file read again without posting", posts)
	}
	// the plugin started again: the key is there already, the same one
	if err := c.PublishNodeKey(context.Background(), "node-1", key); err != nil {
		t.Errorf("publishing the same key again: %v", err)
	}
	// a resource of that name holding another key: not taken for this one
	k.Spec.PublicKey = strings.Repeat("0f", 31) + "00"
	api.keys["node-1-0f0f0f0f0f0f0f0f"] = k
	if err := c.PublishNodeKey(context.Background(), "node-1", key); err == nil || !strings.Contains(err.Error(), "not for this node's key") {
		t.Errorf("another key under the name: %v", err)
	}
	// a file that is not a key: said, and not published
	os.WriteFile(filepath.Join(d, "bad.pub"), []byte("nope\n"), 0o444)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	n := api.posts
	logs = nil
	(&keyPublisher{c: c, node: "node-2", pub: filepath.Join(d, "bad.pub"), logf: logf, wait: 10 * time.Millisecond}).run(ctx)
	if api.posts != n || len(logs) != 1 || !strings.Contains(logs[0], "is not a public key") {
		t.Errorf("a bad file: %d posts, logs %q", api.posts-n, logs)
	}
}
