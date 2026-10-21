// SPDX-License-Identifier: MIT
//
// v1.34 step 5 (D7): the cluster's VarekPolicy resources, written to the
// node's policy directory as POLICY_DIR/<namespace>/<name>.policy, where the
// node agent and this plugin take a pod's policy by the name its pod gives.
// Listed, then watched; listed again when the watch ends with its version
// too old. A file is written whole and renamed into place, root's, readable
// by all (the node agent refuses a directory others can write); one whose
// resource is gone is removed. A resource whose namespace or name the node
// agent would not take (1 to 63 of a-z, 0-9 and -), or whose text is larger
// than it reads, is not written (the admission webhook refuses it first).
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
	c    *kube.Client
	dir  string
	logf func(string, ...interface{})
}

func (s *syncer) path(ns, name string) (string, bool) {
	if !kube.Name.MatchString(ns) || !kube.Name.MatchString(name) {
		return "", false
	}
	return filepath.Join(s.dir, ns, name+".policy"), true
}

func (s *syncer) write(p *kube.Policy) {
	path, ok := s.path(p.Metadata.Namespace, p.Metadata.Name)
	if !ok {
		s.logf("varek-nri: policy %s/%s: not a name the node agent takes; not written", p.Metadata.Namespace, p.Metadata.Name)
		return
	}
	if len(p.Spec.Policy) > kube.MaxPolicy {
		s.logf("varek-nri: policy %s/%s: larger than %d bytes; not written", p.Metadata.Namespace, p.Metadata.Name, kube.MaxPolicy)
		return
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == p.Spec.Policy {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.logf("varek-nri: policy %s/%s: %v", p.Metadata.Namespace, p.Metadata.Name, err)
		return
	}
	f, err := os.CreateTemp(dir, "."+p.Metadata.Name+".policy.tmp-")
	if err == nil {
		_, err = f.WriteString(p.Spec.Policy)
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
		s.logf("varek-nri: policy %s/%s: %v", p.Metadata.Namespace, p.Metadata.Name, err)
		return
	}
	s.logf("varek-nri: policy %s/%s written (version %s)", p.Metadata.Namespace, p.Metadata.Name, p.Metadata.ResourceVersion)
}

func (s *syncer) remove(ns, name string) {
	if path, ok := s.path(ns, name); ok {
		if err := os.Remove(path); err == nil {
			s.logf("varek-nri: policy %s/%s removed", ns, name)
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
		for _, f := range fs {
			name := strings.TrimSuffix(f.Name(), ".policy")
			if f.Type().IsRegular() && name != f.Name() && kube.Name.MatchString(name) && !have[n.Name()+"/"+name] {
				s.remove(n.Name(), name)
			}
		}
	}
}

func (s *syncer) list(ctx context.Context) (string, error) {
	l, err := s.c.ListPolicies(ctx)
	if err != nil {
		return "", err
	}
	have := map[string]bool{}
	for i := range l.Items {
		have[l.Items[i].Metadata.Namespace+"/"+l.Items[i].Metadata.Name] = true
		s.write(&l.Items[i])
	}
	s.prune(have)
	return l.Metadata.ResourceVersion, nil
}

func (s *syncer) event(ev kube.Event) error {
	var p kube.Policy
	if err := json.Unmarshal(ev.Object, &p); err != nil {
		return fmt.Errorf("a policy does not read: %v", err)
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
func (s *syncer) run(ctx context.Context) {
	rv := ""
	for ctx.Err() == nil {
		var err error
		if rv == "" {
			if rv, err = s.list(ctx); err != nil {
				s.logf("varek-nri: listing the policies: %v", err)
				rv = ""
			}
		}
		if rv != "" {
			rv, err = s.c.WatchPolicies(ctx, rv, s.event)
			if kube.Gone(err) {
				rv = ""
				continue
			}
			if err != nil && ctx.Err() == nil {
				s.logf("varek-nri: watching the policies: %v", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}
