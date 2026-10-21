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
//	               escalation, not as root (runAsNonRoot or a runAsUser above
//	               0, and no group 0), a command named by an absolute path
//	               where the pod gives one, a read-only root when the policy
//	               decides launches (D4), and none of the node's namespaces
//	               (hostNetwork, hostPID, hostIPC: D5);
//	/pod-required  a pod without the annotation, refused: the webhook
//	               configuration sends here the pods of the namespaces that
//	               require a policy (a namespaceSelector).
//
// Each answer that refuses says why; the API server shows it to whoever
// applied the object.
//
//	varek-admission -warden FILE -tls-cert FILE -tls-key FILE [-listen :8443]
package main

import (
	"context"
	"encoding/json"
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

const annotation = "varek.dev/policy"

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
	RunAsUser                *int64 `json:"runAsUser"`
	RunAsGroup               *int64 `json:"runAsGroup"`
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
	Privileged               *bool  `json:"privileged"`
	Capabilities             *caps  `json:"capabilities"`
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
		HostNetwork     bool        `json:"hostNetwork"`
		HostPID         bool        `json:"hostPID"`
		HostIPC         bool        `json:"hostIPC"`
		SecurityContext *secCtx     `json:"securityContext"`
		InitContainers  []container `json:"initContainers"`
		Containers      []container `json:"containers"`
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
	mu    sync.Mutex
	cache map[string]checked // by policy text
}

// `require warden X.Y` from 1.27 on turns decided launches on (v1.27)
var requireLine = regexp.MustCompile(`(?m)^[ \t]*require[ \t]+warden[ \t]+(\d+)\.(\d+)`)

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

// Whether the Warden loads text and carries it in a pod: why not, or ""
func (s *server) check(text string) checked {
	s.mu.Lock()
	c, ok := s.cache[text]
	s.mu.Unlock()
	if ok {
		return c
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.warden, path, "--oci-filter")
	var errb strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		c.why = warden(errb.String(), path)
		if c.why == "" {
			c.why = err.Error()
		}
	}
	s.mu.Lock()
	if len(s.cache) >= 256 {
		s.cache = map[string]checked{}
	}
	s.cache[text] = c
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

func (s *server) varekPolicy(req *request) string {
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
	if c := s.check(p.Spec.Policy); c.why != "" {
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
	c := s.check(vp.Spec.Policy)
	if c.why != "" {
		return fmt.Sprintf("the Warden refuses its policy %s: %s", name, c.why)
	}
	var whys []string
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
		whys = append(whys, "it shares the node's network, PID or IPC namespace (hostNetwork, hostPID, hostIPC)")
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
	}
	return strings.Join(whys, "; ")
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
		if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&rv) != nil || rv.Request == nil {
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
	m.HandleFunc("/varekpolicy", s.handle(func(_ context.Context, r *request) string { return s.varekPolicy(r) }))
	m.HandleFunc("/pod", s.handle(s.pod))
	m.HandleFunc("/pod-required", s.handle(func(ctx context.Context, r *request) string {
		var p pod
		if err := json.Unmarshal(r.Object, &p); err != nil {
			return "the pod does not read: " + err.Error()
		}
		if _, ok := p.Metadata.Annotations[annotation]; !ok {
			return "this namespace requires every pod to name its policy (" + annotation + ")"
		}
		return s.pod(ctx, r)
	}))
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	return m
}

func main() {
	wardenPath := flag.String("warden", "", "the warden binary")
	listen := flag.String("listen", ":8443", "where to listen")
	cert := flag.String("tls-cert", "", "the webhook's certificate (the API server checks it against the configuration's caBundle)")
	key := flag.String("tls-key", "", "its key")
	api := flag.String("api", "", "the API server (default: the cluster's, from the service account)")
	apiToken := flag.String("api-token", "", "the service account's token file")
	apiCA := flag.String("api-ca", "", "the cluster's CA")
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
	s := &server{warden: *wardenPath, api: c, cache: map[string]checked{}}
	hs := &http.Server{Addr: *listen, Handler: s.mux(), ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "varek-admission: listening on %s\n", *listen)
	if err := hs.ListenAndServeTLS(*cert, *key); err != nil {
		fmt.Fprintln(os.Stderr, "varek-admission:", err)
		os.Exit(1)
	}
}
