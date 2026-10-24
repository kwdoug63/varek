// SPDX-License-Identifier: MIT
//
// varek-admission — v1.34 step 5 (docs/security/v1.34-kubernetes.md, D7):
// VAREK's admission webhook. It fails at deploy what the node agent would
// refuse at the container's start:
//
//	/varekpolicy   a VarekPolicy created or changed: its name is one the node
//	               agent takes, and the Warden loads its text and carries it in
//	               a pod (warden POLICY --oci-filter: both parsers, and nothing
//	               the node agent does not carry yet, credentials, sub-agents,
//	               the on-behalf-of chain);
//	/pod           a pod annotated varek.dev/policy: NAME names a VarekPolicy
//	               of its namespace that the Warden loads, and each of its
//	               containers runs as the node agent requires: no privilege
//	               escalation, not privileged, every capability dropped and
//	               none added, not as root (runAsNonRoot or a runAsUser above
//	               0, and no group 0), a command named by an absolute path
//	               where the pod gives one, a read-only root when the policy
//	               decides launches (D4), none of the node's namespaces
//	               (hostNetwork, hostPID, hostIPC: D5) and no PID namespace
//	               shared between its containers, the cluster's DNS (no
//	               dnsPolicy None, no nameservers of its own: the Warden
//	               resolves the policy's names through the pod's), a runtime
//	               class that runs the Warden's filter, and VAREK's
//	               unsupervised seccomp profile (Localhost
//	               varek/unsupervised.json), which the NRI plugin replaces
//	               with the Warden's filter: a container it does not adjust
//	               does not run (step 8 review, G-1). On an update, the
//	               annotation is not added, changed or removed;
//	/pod-required  a pod without the annotation, refused: the webhook
//	               configuration sends here the pods of the namespaces that
//	               require a policy (a namespaceSelector).
//
// Each answer that refuses says why; the API server shows it to whoever
// applied the object.
//
// The certificate is read again when its files change (a Secret rotated by
// cert-manager); the Warden's checks are bounded in number at once and kept
// by the policy's SHA-256.
//
//	varek-admission -warden FILE -tls-cert FILE -tls-key FILE [-listen :8443]
//	                [-runtime-classes NAME,...]
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

const (
	annotation = "varek.dev/policy"
	// the seccomp profile every container of an annotated pod names (G-1)
	unsupervised = "varek/unsupervised.json"
	// the largest AdmissionReview read: an object and its old one, each at
	// most etcd's 1.5 MiB
	maxReview = 4 << 20
	// the Warden's checks at once, and the verdicts kept
	maxChecks = 4
	maxCached = 4096
)

// The AdmissionReview parts used (admission.k8s.io/v1)
type review struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *request  `json:"request,omitempty"`
	Response   *response `json:"response,omitempty"`
}

type request struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Operation string          `json:"operation"`
	Object    json.RawMessage `json:"object"`
	OldObject json.RawMessage `json:"oldObject"`
}

type response struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}

type status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// The pod's parts the node agent's checks are about
type secCtx struct {
	RunAsUser                *int64      `json:"runAsUser"`
	RunAsGroup               *int64      `json:"runAsGroup"`
	RunAsNonRoot             *bool       `json:"runAsNonRoot"`
	AllowPrivilegeEscalation *bool       `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool       `json:"readOnlyRootFilesystem"`
	Privileged               *bool       `json:"privileged"`
	Capabilities             *caps       `json:"capabilities"`
	SeccompProfile           *seccompRef `json:"seccompProfile"`
	// the pod's only
	SupplementalGroups []int64 `json:"supplementalGroups"`
	FSGroup            *int64  `json:"fsGroup"`
}

type seccompRef struct {
	Type             string `json:"type"`
	LocalhostProfile string `json:"localhostProfile"`
}

type caps struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type container struct {
	Name            string   `json:"name"`
	Command         []string `json:"command"`
	SecurityContext *secCtx  `json:"securityContext"`
}

type pod struct {
	Metadata struct {
		Name         string            `json:"name"`
		GenerateName string            `json:"generateName"`
		Namespace    string            `json:"namespace"`
		Annotations  map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		HostNetwork           bool   `json:"hostNetwork"`
		HostPID               bool   `json:"hostPID"`
		HostIPC               bool   `json:"hostIPC"`
		ShareProcessNamespace *bool  `json:"shareProcessNamespace"`
		DNSPolicy             string `json:"dnsPolicy"`
		DNSConfig             *struct {
			Nameservers []string `json:"nameservers"`
		} `json:"dnsConfig"`
		RuntimeClassName *string     `json:"runtimeClassName"`
		SecurityContext  *secCtx     `json:"securityContext"`
		InitContainers   []container `json:"initContainers"`
		Containers       []container `json:"containers"`
	} `json:"spec"`
}

type checked struct {
	why      string // "" when the Warden carries it
	launches bool
}

type server struct {
	warden string
	api    interface {
		GetPolicy(ctx context.Context, ns, name string) (*kube.Policy, error)
	}
	classes map[string]bool // runtime classes whose handler runs the Warden's filter (G-4)
	mu      sync.Mutex
	cache   map[[32]byte]checked // by the policy's SHA-256 (W2)
	slots   chan struct{}        // the Warden's checks at once (W2)
}

// `require warden X.Y` from 1.27 on turns decided launches on (v1.27); the
// Warden splits a line on the same white space (review, G-6)
var requireLine = regexp.MustCompile(`(?m)^[ \t\r\v\f]*require[ \t\r\v\f]+warden[ \t\r\v\f]+(\d+)\.(\d+)`)

func decidesLaunches(text string) bool {
	for _, m := range requireLine.FindAllStringSubmatch(text, -1) {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		if a > 1 || (a == 1 && b >= 27) {
			return true
		}
	}
	return false
}

// Whether the Warden loads text and carries it in a pod: why not, or "".
// Its verdict is kept; a check that did not finish (the request's time, a
// failure of the webhook's own) is not.
func (s *server) check(ctx context.Context, text string) checked {
	sum := sha256.Sum256([]byte(text))
	s.mu.Lock()
	c, ok := s.cache[sum]
	s.mu.Unlock()
	if ok {
		return c
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return checked{why: "the webhook is busy (the request's time ran out waiting for the Warden)"}
	}
	c = checked{launches: decidesLaunches(text)}
	dir, err := os.MkdirTemp("", "varek-admission-")
	if err != nil {
		return checked{why: err.Error()}
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "policy")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return checked{why: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.warden, path, "--oci-filter")
	var errb strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &ee) || !ee.Exited() {
			return checked{why: fmt.Sprintf("the Warden did not finish checking it (%v)", err)}
		}
		c.why = warden(errb.String(), path)
		if c.why == "" {
			c.why = err.Error()
		}
	}
	s.mu.Lock()
	if len(s.cache) >= maxCached {
		s.cache = map[[32]byte]checked{}
	}
	s.cache[sum] = c
	s.mu.Unlock()
	return c
}

// the Warden's reason: its last line, the temporary file's name taken out
func warden(stderr, path string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	l = strings.ReplaceAll(l, path+":", "line ")
	l = strings.ReplaceAll(l, path, "the policy")
	return strings.TrimPrefix(l, "[warden] ")
}

func (s *server) varekPolicy(ctx context.Context, req *request) string {
	if req.Operation == "DELETE" {
		return ""
	}
	var p kube.Policy
	if err := json.Unmarshal(req.Object, &p); err != nil {
		return "the VarekPolicy does not read: " + err.Error()
	}
	if !kube.Name.MatchString(p.Metadata.Name) {
		return fmt.Sprintf("the VarekPolicy's name %q is not 1 to 63 of a-z, 0-9 and - (the node agent takes no other)", p.Metadata.Name)
	}
	ns := p.Metadata.Namespace
	if ns == "" {
		ns = req.Namespace
	}
	if !kube.Name.MatchString(ns) {
		return fmt.Sprintf("the namespace %q is not 1 to 63 of a-z, 0-9 and - (the node agent takes no other)", ns)
	}
	if len(p.Spec.Policy) > kube.MaxPolicy {
		return fmt.Sprintf("the policy is larger than %d bytes", kube.MaxPolicy)
	}
	if strings.TrimSpace(p.Spec.Policy) == "" {
		return "the policy is empty"
	}
	if c := s.check(ctx, p.Spec.Policy); c.why != "" {
		return "the Warden refuses this policy: " + c.why
	}
	return ""
}

func (s *server) pod(ctx context.Context, req *request) string {
	var p pod
	if err := json.Unmarshal(req.Object, &p); err != nil {
		return "the pod does not read: " + err.Error()
	}
	name, ok := p.Metadata.Annotations[annotation]
	// G-3: what a pod was admitted as it stays; its spec is otherwise
	// fixed, and an update is not checked again (a policy deleted since
	// does not keep its pod from being changed and deleted)
	if req.Operation == "UPDATE" {
		var old pod
		if err := json.Unmarshal(req.OldObject, &old); err != nil {
			return "the pod's old object does not read: " + err.Error()
		}
		was, wasOK := old.Metadata.Annotations[annotation]
		if was != name || wasOK != ok {
			return fmt.Sprintf("its %s annotation is set when the pod is created, and not added, changed or removed after", annotation)
		}
		return ""
	}
	if !ok {
		return ""
	}
	ns := p.Metadata.Namespace
	if ns == "" {
		ns = req.Namespace
	}
	if !kube.Name.MatchString(name) {
		return fmt.Sprintf("its policy name %q (%s) is not 1 to 63 of a-z, 0-9 and -", name, annotation)
	}
	if !kube.Name.MatchString(ns) {
		return fmt.Sprintf("its namespace %q is not a name a policy can be under", ns)
	}
	vp, err := s.api.GetPolicy(ctx, ns, name)
	if err != nil {
		return "its policy cannot be read from the API server: " + err.Error()
	}
	if vp == nil {
		return fmt.Sprintf("there is no VarekPolicy %s in namespace %s", name, ns)
	}
	c := s.check(ctx, vp.Spec.Policy)
	if c.why != "" {
		return fmt.Sprintf("the Warden refuses its policy %s: %s", name, c.why)
	}
	var whys []string
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
		whys = append(whys, "it shares the node's network, PID or IPC namespace (hostNetwork, hostPID, hostIPC)")
	}
	if p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace {
		whys = append(whys, "its containers share a PID namespace (shareProcessNamespace; the node agent takes a container whose own it is)")
	}
	// R7: the Warden resolves the policy's host names through the pod's DNS
	// server, which is then the cluster's (or the node's), not the pod's
	if p.Spec.DNSPolicy == "None" || (p.Spec.DNSConfig != nil && len(p.Spec.DNSConfig.Nameservers) > 0) {
		whys = append(whys, "it names DNS servers of its own (dnsPolicy None, dnsConfig.nameservers): the Warden resolves "+
			"its policy's names through the pod's, which are to be the cluster's")
	}
	if rc := p.Spec.RuntimeClassName; rc != nil && *rc != "" && !s.classes[*rc] {
		whys = append(whys, fmt.Sprintf("its runtime class %q is not one whose handler runs the Warden's filter (-runtime-classes)", *rc))
	}
	if pc := p.Spec.SecurityContext; pc != nil {
		for _, g := range pc.SupplementalGroups {
			if g == 0 {
				whys = append(whys, "its supplementalGroups hold group 0 (root)")
				break
			}
		}
		if pc.FSGroup != nil && *pc.FSGroup == 0 {
			whys = append(whys, "its fsGroup is 0 (root)")
		}
	}
	all := append(append([]container{}, p.Spec.InitContainers...), p.Spec.Containers...)
	for _, k := range all {
		pc, cc := p.Spec.SecurityContext, k.SecurityContext
		user := pick(cc, pc, func(x *secCtx) *int64 { return x.RunAsUser })
		group := pick(cc, pc, func(x *secCtx) *int64 { return x.RunAsGroup })
		nonRoot := pickb(cc, pc, func(x *secCtx) *bool { return x.RunAsNonRoot })
		w := func(f string, a ...interface{}) {
			whys = append(whys, fmt.Sprintf("container %s: ", k.Name)+fmt.Sprintf(f, a...))
		}
		if cc == nil || cc.AllowPrivilegeEscalation == nil || *cc.AllowPrivilegeEscalation {
			w("allowPrivilegeEscalation must be false (the node agent requires no new privileges)")
		}
		if cc != nil && cc.Privileged != nil && *cc.Privileged {
			w("it is privileged")
		}
		// v1.34 step 7: the node agent refuses a container holding a
		// capability (the Warden's agent holds none), which the runtime gives
		// a user other than root unless they are dropped
		if cc == nil || cc.Capabilities == nil || !dropsAll(cc.Capabilities.Drop) {
			w("capabilities must drop ALL (capabilities: drop: [ALL]; the agent holds none)")
		} else if len(cc.Capabilities.Add) > 0 {
			w("it adds capabilities %v (the agent holds none)", cc.Capabilities.Add)
		}
		if user != nil && *user == 0 {
			w("it runs as root (runAsUser 0)")
		} else if user == nil && (nonRoot == nil || !*nonRoot) {
			w("give runAsNonRoot: true or a runAsUser above 0 (the node agent refuses a container running as root)")
		}
		if group != nil && *group == 0 {
			w("its group is root (runAsGroup 0)")
		}
		if len(k.Command) > 0 && !strings.HasPrefix(k.Command[0], "/") {
			w("its command must be named by an absolute path (it is %q)", k.Command[0])
		}
		if c.launches && (cc == nil || cc.ReadOnlyRootFilesystem == nil || !*cc.ReadOnlyRootFilesystem) {
			w("its policy decides launches, so its root file system must be read-only (readOnlyRootFilesystem: true; D4)")
		}
		sp := (*seccompRef)(nil)
		if cc != nil && cc.SeccompProfile != nil {
			sp = cc.SeccompProfile
		} else if pc != nil {
			sp = pc.SeccompProfile
		}
		if sp == nil || sp.Type != "Localhost" || sp.LocalhostProfile != unsupervised {
			w("its seccompProfile must be {type: Localhost, localhostProfile: %s} (VAREK's unsupervised profile, which "+
				"the NRI plugin replaces with the Warden's filter: a container it does not adjust does not run)", unsupervised)
		}
	}
	return strings.Join(whys, "; ")
}

func newServer(warden string, api interface {
	GetPolicy(ctx context.Context, ns, name string) (*kube.Policy, error)
}, classes string) *server {
	s := &server{warden: warden, api: api, classes: map[string]bool{}, cache: map[[32]byte]checked{},
		slots: make(chan struct{}, maxChecks)}
	for _, c := range strings.Split(classes, ",") {
		if c = strings.TrimSpace(c); c != "" {
			s.classes[c] = true
		}
	}
	return s
}

func dropsAll(d []string) bool {
	for _, x := range d {
		if strings.EqualFold(x, "ALL") {
			return true
		}
	}
	return false
}

func pick(c, p *secCtx, f func(*secCtx) *int64) *int64 {
	if c != nil && f(c) != nil {
		return f(c)
	}
	if p != nil {
		return f(p)
	}
	return nil
}

func pickb(c, p *secCtx, f func(*secCtx) *bool) *bool {
	if c != nil && f(c) != nil {
		return f(c)
	}
	if p != nil {
		return f(p)
	}
	return nil
}

func (s *server) handle(decide func(context.Context, *request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rv review
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReview)).Decode(&rv) != nil || rv.Request == nil {
			http.Error(w, "an AdmissionReview is expected", http.StatusBadRequest)
			return
		}
		why := decide(r.Context(), rv.Request)
		out := review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
			Response: &response{UID: rv.Request.UID, Allowed: why == ""}}
		if why != "" {
			out.Response.Status = &status{Code: http.StatusForbidden, Message: "VAREK: " + why}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (s *server) mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/varekpolicy", s.handle(s.varekPolicy))
	m.HandleFunc("/pod", s.handle(s.pod))
	m.HandleFunc("/pod-required", s.handle(func(ctx context.Context, r *request) string {
		var p pod
		if err := json.Unmarshal(r.Object, &p); err != nil {
			return "the pod does not read: " + err.Error()
		}
		if _, ok := p.Metadata.Annotations[annotation]; !ok && r.Operation != "UPDATE" {
			return "this namespace requires every pod to name its policy (" + annotation + ")"
		}
		return s.pod(ctx, r)
	}))
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	return m
}

// W1: the certificate, read again when its files change (a Secret's
// volume is updated in place when cert-manager or the operator rotates it)
type certFiles struct {
	cert, key string
	mu        sync.Mutex
	at        time.Time // when last looked at
	mod       [2]time.Time
	c         *tls.Certificate
}

func (f *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.c != nil && time.Since(f.at) < 10*time.Second {
		return f.c, nil
	}
	f.at = time.Now()
	a, err1 := os.Stat(f.cert)
	b, err2 := os.Stat(f.key)
	if f.c != nil && err1 == nil && err2 == nil && a.ModTime().Equal(f.mod[0]) && b.ModTime().Equal(f.mod[1]) {
		return f.c, nil
	}
	c, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		if f.c != nil {
			fmt.Fprintln(os.Stderr, "varek-admission: the certificate does not read again (the one read before is kept):", err)
			return f.c, nil
		}
		return nil, err
	}
	if f.c != nil {
		fmt.Fprintln(os.Stderr, "varek-admission: the certificate read again")
	}
	f.c = &c
	if err1 == nil && err2 == nil {
		f.mod = [2]time.Time{a.ModTime(), b.ModTime()}
	}
	return f.c, nil
}

func main() {
	wardenPath := flag.String("warden", "", "the warden binary")
	listen := flag.String("listen", ":8443", "where to listen")
	cert := flag.String("tls-cert", "", "the webhook's certificate (the API server checks it against the configuration's caBundle)")
	key := flag.String("tls-key", "", "its key")
	api := flag.String("api", "", "the API server (default: the cluster's, from the service account)")
	apiToken := flag.String("api-token", "", "the service account's token file")
	apiCA := flag.String("api-ca", "", "the cluster's CA")
	classes := flag.String("runtime-classes", "", "the RuntimeClass names whose handler runs the Warden's filter (runc, crun); "+
		"a pod naming another is refused")
	flag.Parse()
	if !strings.HasPrefix(*wardenPath, "/") || *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "varek-admission: give -warden (an absolute path), -tls-cert and -tls-key")
		os.Exit(2)
	}
	c, err := kube.InCluster(*api, *apiToken, *apiCA)
	if err != nil {
		fmt.Fprintln(os.Stderr, "varek-admission:", err)
		os.Exit(2)
	}
	s := newServer(*wardenPath, c, *classes)
	cf := &certFiles{cert: *cert, key: *key}
	if _, err := cf.get(nil); err != nil {
		fmt.Fprintln(os.Stderr, "varek-admission: the certificate:", err)
		os.Exit(2)
	}
	hs := &http.Server{Addr: *listen, Handler: s.mux(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cf.get}}
	fmt.Fprintf(os.Stderr, "varek-admission: listening on %s\n", *listen)
	if err := hs.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintln(os.Stderr, "varek-admission:", err)
		os.Exit(1)
	}
}
