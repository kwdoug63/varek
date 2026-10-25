// SPDX-License-Identifier: MIT
//
// v1.34 step 5 (D7): the cluster's VarekPolicy resources, written to the
// node's policy directory as POLICY_DIR/<namespace>/<name>.policy, where the
// node agent and this plugin take a pod's policy by the name its pod gives.
// Listed a page at a time, then watched; listed again when the watch ends
// with its version too old. A file is written whole and renamed into place, root's, readable
// by all (the node agent refuses a directory others can write); one whose
// resource is gone is removed. A resource whose namespace or name the node
// agent would not take (1 to 63 of a-z, 0-9 and -), or whose text is larger
// than it reads, is not written (the admission webhook refuses it first).
//
// v1.35 step 4c (D11): the cluster's VarekPlan resources the same way, as
// POLICY_DIR/<namespace>/<name>.plan, by a second syncer.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

type syncer struct {
	c        *kube.Client
	dir      string
	logf     func(string, ...interface{})
	resource string // kube.Resource (the default) or kube.Plans (v1.35)
}

// what is synced: its word, and its files' extension
func (s *syncer) kind() (string, string) {
	if s.resource == kube.Plans {
		return "plan", ".plan"
	}
	return "policy", ".policy"
}

func (s *syncer) path(ns, name string) (string, bool) {
	if !kube.Name.MatchString(ns) || !kube.Name.MatchString(name) {
		return "", false
	}
	_, ext := s.kind()
	return filepath.Join(s.dir, ns, name+ext), true
}

func (s *syncer) write(p *kube.Policy) {
	what, ext := s.kind()
	text := p.Text(s.resource)
	path, ok := s.path(p.Metadata.Namespace, p.Metadata.Name)
	if !ok {
		s.logf("varek-nri: %s %s/%s: not a name the node agent takes; not written", what, p.Metadata.Namespace, p.Metadata.Name)
		return
	}
	if len(text) > kube.MaxPolicy {
		s.logf("varek-nri: %s %s/%s: larger than %d bytes; not written", what, p.Metadata.Namespace, p.Metadata.Name, kube.MaxPolicy)
		return
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.logf("varek-nri: %s %s/%s: %v", what, p.Metadata.Namespace, p.Metadata.Name, err)
		return
	}
	f, err := os.CreateTemp(dir, "."+p.Metadata.Name+ext+".tmp-")
	if err == nil {
		_, err = f.WriteString(text)
		if err == nil {
			err = f.Chmod(0o644)
		}
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(f.Name(), path)
		}
		if err != nil {
			os.Remove(f.Name())
		}
	}
	if err != nil {
		s.logf("varek-nri: %s %s/%s: %v", what, p.Metadata.Namespace, p.Metadata.Name, err)
		return
	}
	s.logf("varek-nri: %s %s/%s written (version %s)", what, p.Metadata.Namespace, p.Metadata.Name, p.Metadata.ResourceVersion)
}

func (s *syncer) remove(ns, name string) {
	what, _ := s.kind()
	if path, ok := s.path(ns, name); ok {
		if err := os.Remove(path); err == nil {
			s.logf("varek-nri: %s %s/%s removed", what, ns, name)
		}
	}
}

// After a list: the files of resources not in it removed
func (s *syncer) prune(have map[string]bool) {
	nss, _ := os.ReadDir(s.dir)
	for _, n := range nss {
		if !n.IsDir() || !kube.Name.MatchString(n.Name()) {
			continue
		}
		fs, _ := os.ReadDir(filepath.Join(s.dir, n.Name()))
		_, ext := s.kind()
		for _, f := range fs {
			name := strings.TrimSuffix(f.Name(), ext)
			if f.Type().IsRegular() && name != f.Name() && kube.Name.MatchString(name) && !have[n.Name()+"/"+name] {
				s.remove(n.Name(), name)
			}
		}
	}
}

func (s *syncer) list(ctx context.Context) (string, error) {
	have := map[string]bool{}
	rv, err := s.c.List(ctx, s.res(), func(p *kube.Policy) {
		have[p.Metadata.Namespace+"/"+p.Metadata.Name] = true
		s.write(p)
	})
	if err != nil {
		return "", err
	}
	s.prune(have)
	return rv, nil
}

func (s *syncer) event(ev kube.Event) error {
	var p kube.Policy
	if err := json.Unmarshal(ev.Object, &p); err != nil {
		what, _ := s.kind()
		return fmt.Errorf("a %s does not read: %v", what, err)
	}
	switch ev.Type {
	case "ADDED", "MODIFIED":
		s.write(&p)
	case "DELETED":
		s.remove(p.Metadata.Namespace, p.Metadata.Name)
	}
	return nil
}

// run lists and watches until ctx ends, listing again after a watch whose
// version is too old, and waiting a little after a failure
func (s *syncer) res() string {
	if s.resource == "" {
		return kube.Resource
	}
	return s.resource
}

func (s *syncer) run(ctx context.Context) {
	rv := ""
	for ctx.Err() == nil {
		var err error
		if rv == "" {
			if rv, err = s.list(ctx); err != nil {
				s.logf("varek-nri: listing the %s: %v", s.res(), err)
				rv = ""
			}
		}
		if rv != "" {
			rv, err = s.c.Watch(ctx, s.res(), rv, s.event)
			if kube.Gone(err) {
				rv = ""
				continue
			}
			if err != nil && ctx.Err() == nil {
				s.logf("varek-nri: watching the %s: %v", s.res(), err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}
