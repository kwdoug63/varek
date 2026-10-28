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
//
// v1.36 step 7 (D6, D7, D7b): beside each policy, its flow policy
// (<name>.flow) and its dry run and trust bundle (<name>.run), when it has them.
//
// v1.36 step 4 (D2): the cluster's VarekCredential resources (cluster-scoped)
// as one list, POLICY_DIR/.credentials (kube.CredentialList), written whole
// after each list and each event, by a third (credSyncer). A resource the
// node agent would not take is left out of it, and said.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

// v1.36 step 7 (D6, D7, D7b): beside a VarekPolicy's policy, its flow policy
// (NAME.flow, the --flow-policy file) and what the plugin takes for it
// (NAME.run: its dry run and its trust bundle's name, as JSON); neither is
// kept for a policy that says none
type runOptions struct {
	DryRun      bool   `json:"dryRun,omitempty"`
	TrustBundle string `json:"trustBundle,omitempty"`
}

// a file of a resource: its extension and text ("" for one not kept)
type rfile struct{ ext, text string }

// a resource's files, its own last (the plugin reads a policy's others after
// the policy, and a change is taken whole at the next container)
func (s *syncer) files(p *kube.Policy) []rfile {
	_, ext := s.kind()
	if s.resource == kube.Plans {
		return []rfile{{ext, p.Text(s.resource)}}
	}
	run := ""
	if p.Spec.DryRun || p.Spec.TrustBundle != "" {
		b, _ := json.Marshal(runOptions{DryRun: p.Spec.DryRun, TrustBundle: p.Spec.TrustBundle})
		run = string(b) + "\n"
	}
	return []rfile{{".flow", p.Spec.FlowPolicy}, {".run", run}, {ext, p.Spec.Policy}}
}

// every extension a resource's files have
func (s *syncer) exts() []string {
	_, ext := s.kind()
	if s.resource == kube.Plans {
		return []string{ext}
	}
	return []string{".flow", ".run", ext}
}

func (s *syncer) path(ns, name string) (string, bool) {
	if !kube.Name.MatchString(ns) || !kube.Name.MatchString(name) {
		return "", false
	}
	_, ext := s.kind()
	return filepath.Join(s.dir, ns, name+ext), true
}

// write a resource's files; an error when one could not be written (v1.35
// step 9, review: a failure is retried, not only logged), none for a
// resource the node agent would not take (not written, said)
func (s *syncer) write(p *kube.Policy) error {
	what, _ := s.kind()
	path, ok := s.path(p.Metadata.Namespace, p.Metadata.Name)
	if !ok {
		s.logf("varek-nri: %s %s/%s: not a name the node agent takes; not written", what, p.Metadata.Namespace, p.Metadata.Name)
		return nil
	}
	rfs := s.files(p)
	for _, f := range rfs {
		if len(f.text) > kube.MaxPolicy {
			s.logf("varek-nri: %s %s/%s: larger than %d bytes; not written", what, p.Metadata.Namespace, p.Metadata.Name, kube.MaxPolicy)
			return s.remove(p.Metadata.Namespace, p.Metadata.Name) // step 9: an older version is not kept
		}
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	wrote := false
	for _, f := range rfs {
		w, err := s.writeFile(base+f.ext, f.text)
		if err != nil {
			return fmt.Errorf("%s %s/%s: %v", what, p.Metadata.Namespace, p.Metadata.Name, err)
		}
		wrote = wrote || w
	}
	if wrote {
		s.logf("varek-nri: %s %s/%s written (version %s)", what, p.Metadata.Namespace, p.Metadata.Name, p.Metadata.ResourceVersion)
	}
	return nil
}

// writeFile writes text whole and renames it into place (root's, readable by
// all), or removes the file for "": whether it changed
func (s *syncer) writeFile(path, text string) (bool, error) {
	if text == "" {
		err := os.Remove(path)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return false, err
	}
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
		return false, err
	}
	return true, nil
}

// remove a resource's files; an error when one is there and could not be removed
func (s *syncer) remove(ns, name string) error {
	what, _ := s.kind()
	path, ok := s.path(ns, name)
	if !ok {
		return nil
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	removed := false
	for _, ext := range s.exts() {
		err := os.Remove(base + ext)
		if err == nil {
			removed = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s %s/%s: not removed: %v", what, ns, name, err)
		}
	}
	if removed {
		s.logf("varek-nri: %s %s/%s removed", what, ns, name)
	}
	return nil
}

// After a list: the files of resources not in it removed (step 9, review: a
// directory that cannot be read, or a file that cannot be removed, fails the
// list, which is tried again)
func (s *syncer) prune(have map[string]bool) error {
	nss, err := os.ReadDir(s.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var first error
	for _, n := range nss {
		if !n.IsDir() || !kube.Name.MatchString(n.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, n.Name()))
		if err != nil {
			return err
		}
		for _, f := range files {
			for _, ext := range s.exts() {
				name := strings.TrimSuffix(f.Name(), ext)
				if f.Type().IsRegular() && name != f.Name() && kube.Name.MatchString(name) && !have[n.Name()+"/"+name] {
					if err := s.remove(n.Name(), name); err != nil && first == nil {
						first = err
					}
				}
			}
		}
	}
	return first
}

func (s *syncer) list(ctx context.Context) (string, error) {
	have := map[string]bool{}
	var werr error
	rv, err := s.c.List(ctx, s.res(), func(p *kube.Policy) {
		have[p.Metadata.Namespace+"/"+p.Metadata.Name] = true
		if err := s.write(p); err != nil && werr == nil {
			werr = err
		}
	})
	if err != nil {
		return "", err
	}
	if err := s.prune(have); err != nil && werr == nil {
		werr = err
	}
	if werr != nil {
		return "", werr
	}
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
		return s.write(&p)
	case "DELETED":
		return s.remove(p.Metadata.Namespace, p.Metadata.Name)
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

func (s *syncer) run(ctx context.Context) { runSync(ctx, s.c, s.res(), s.logf, s.list, s.event) }

// runSync lists and watches a resource until ctx ends (each syncer's run)
func runSync(ctx context.Context, c *kube.Client, res string, logf func(string, ...interface{}),
	list func(context.Context) (string, error), event func(kube.Event) error) {
	rv := ""
	for ctx.Err() == nil {
		var err error
		if rv == "" {
			if rv, err = list(ctx); err != nil {
				logf("varek-nri: listing the %s: %v", res, err)
				rv = ""
			}
		}
		if rv != "" {
			rv, err = c.Watch(ctx, res, rv, event)
			if kube.Gone(err) {
				rv = ""
				continue
			}
			if err != nil && ctx.Err() == nil {
				logf("varek-nri: watching the %s: %v", res, err)
				rv = "" // step 9 (review): listed again, so what failed is written again
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// v1.36 step 4 (D2): the cluster's VarekCredential resources, one list
type credSyncer struct {
	c    *kube.Client
	dir  string
	logf func(string, ...interface{})
	have map[string]*kube.Policy // by resource name
}

// the list written whole and renamed into place, root's, readable by all (the
// node agent refuses one others can write); unchanged, not written
func (s *credSyncer) write() error {
	items := make([]*kube.Policy, 0, len(s.have))
	for _, c := range s.have {
		items = append(items, c)
	}
	text := kube.CredentialList(items)
	path := filepath.Join(s.dir, kube.CredentialListFile)
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("the credential list: %v", err)
	}
	f, err := os.CreateTemp(s.dir, kube.CredentialListFile+".tmp-")
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
		return fmt.Errorf("the credential list: %v", err)
	}
	s.logf("varek-nri: the credential list written (%d VarekCredential resources)", strings.Count(text, "\n")-1)
	return nil
}

func (s *credSyncer) keep(p *kube.Policy) {
	if why := kube.CredentialProblem(p); why != "" {
		s.logf("varek-nri: VarekCredential %s: %s; not listed", p.Metadata.Name, why)
	}
	q := *p
	s.have[p.Metadata.Name] = &q
}

func (s *credSyncer) list(ctx context.Context) (string, error) {
	s.have = map[string]*kube.Policy{}
	rv, err := s.c.List(ctx, kube.Credentials, s.keep)
	if err != nil {
		return "", err
	}
	if err := s.write(); err != nil {
		return "", err
	}
	return rv, nil
}

func (s *credSyncer) event(ev kube.Event) error {
	var p kube.Policy
	if err := json.Unmarshal(ev.Object, &p); err != nil {
		return fmt.Errorf("a VarekCredential does not read: %v", err)
	}
	switch ev.Type {
	case "ADDED", "MODIFIED":
		s.keep(&p)
	case "DELETED":
		delete(s.have, p.Metadata.Name)
	default:
		return nil
	}
	return s.write()
}

func (s *credSyncer) run(ctx context.Context) {
	runSync(ctx, s.c, kube.Credentials, s.logf, s.list, s.event)
}
