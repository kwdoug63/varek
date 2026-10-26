// SPDX-License-Identifier: MIT
//
// Package kube is the little of the Kubernetes API that VAREK's node plugin
// and admission webhook use (v1.34 step 5, docs/security/v1.34-kubernetes.md,
// D7): the VarekPolicy resource, read and watched through the API server with
// the pod's service account, over HTTPS checked against the cluster's CA. No
// client library: a list, a get and a watch are a few requests. v1.35 step
// 4c (D11): and the VarekPlan resource, a pod's plan, the same way.
package kube

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Group, version and resource of VAREK's policies (packaging/helm/varek/crds/varekpolicy.yaml),
// and of its plans (crds/varekplan.yaml, v1.35)
const (
	Group    = "varek.dev"
	Version  = "v1alpha1"
	Resource = "varekpolicies"
	Plans    = "varekplans"
)

// A policy's name, and a namespace's as the node agent takes it: 1 to 63 of
// a-z, 0-9 and - (the node agent's node_label)
var Name = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// MaxPolicy is the largest policy text taken (the node agent's limit)
const MaxPolicy = 8 << 20

// Meta is the part of an object's metadata used here
type Meta struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion"`
}

// Policy is a VarekPolicy: its text is the policy as written for the Warden;
// or a VarekPlan (v1.35): its text is the plan, as written for the Warden
type Policy struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Policy string `json:"policy"`
		Plan   string `json:"plan"`
	} `json:"spec"`
}

// Text is a VarekPolicy's policy, or a VarekPlan's plan
func (p *Policy) Text(resource string) string {
	if resource == Plans {
		return p.Spec.Plan
	}
	return p.Spec.Policy
}

// List is a page of them
type List struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []Policy `json:"items"`
}

// PageSize is how many policies a page of a list holds (review, G-2: a
// cluster's every policy is not held at once on every node)
const PageSize = 16

// Event is one of a watch's
type Event struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// StatusError is an answer of the API server that is not 2xx
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the API server answered %d: %s", e.Code, e.Body)
}

// Gone reports a watch's resourceVersion too old (410): list again
func Gone(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusGone
}

// Client is the API server, as the pod's service account
type Client struct {
	Base      string // https://host:port
	TokenFile string // read at each request: projected tokens rotate
	HTTP      *http.Client
}

// InCluster is the client for the cluster the pod runs in; base, token and
// ca override what the service account gives (tests, or a node's own setup)
func InCluster(base, token, ca string) (*Client, error) {
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	if base == "" {
		h, p := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if h == "" || p == "" {
			return nil, errors.New("not in a cluster (no KUBERNETES_SERVICE_HOST): give the API server's address")
		}
		base = "https://" + net.JoinHostPort(h, p)
	}
	if token == "" {
		token = sa + "token"
	}
	if ca == "" {
		ca = sa + "ca.crt"
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: nil}
	if strings.HasPrefix(base, "https://") {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("the cluster's CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the cluster's CA (%s) holds no certificate", ca)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &Client{Base: strings.TrimRight(base, "/"), TokenFile: token, HTTP: &http.Client{Transport: tr}}, nil
}

func (c *Client) request(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.TokenFile != "" {
		if t, err := os.ReadFile(c.TokenFile); err == nil {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(t)))
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("the service account's token: %v", err)
		}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	return resp, nil
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.request(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(out)
}

func collection(resource, ns string) string {
	if ns == "" {
		return fmt.Sprintf("/apis/%s/%s/%s", Group, Version, resource)
	}
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", Group, Version, url.PathEscape(ns), resource)
}

// ListPolicies calls each for every namespace's policies, a page at a time,
// and returns the list's version (a watch's start); a list whose
// continuation expired (410) fails Gone, and is listed again
func (c *Client) ListPolicies(ctx context.Context, each func(*Policy)) (string, error) {
	return c.List(ctx, Resource, each)
}

// List is ListPolicies for either resource (Resource, Plans)
func (c *Client) List(ctx context.Context, resource string, each func(*Policy)) (string, error) {
	cont := ""
	for {
		q := "?limit=" + fmt.Sprint(PageSize)
		if cont != "" {
			q += "&continue=" + url.QueryEscape(cont)
		}
		l := &List{}
		if err := c.get(ctx, collection(resource, "")+q, l); err != nil {
			return "", err
		}
		for i := range l.Items {
			each(&l.Items[i])
		}
		if l.Metadata.Continue == "" {
			return l.Metadata.ResourceVersion, nil
		}
		cont = l.Metadata.Continue
	}
}

// GetPolicy is a namespace's policy by its name; nil, nil when there is none
func (c *Client) GetPolicy(ctx context.Context, ns, name string) (*Policy, error) {
	return c.Get(ctx, Resource, ns, name)
}

// GetPlan is a namespace's plan by its name (v1.35); nil, nil when there is none
func (c *Client) GetPlan(ctx context.Context, ns, name string) (*Policy, error) {
	return c.Get(ctx, Plans, ns, name)
}

// Get is GetPolicy for either resource
func (c *Client) Get(ctx context.Context, resource, ns, name string) (*Policy, error) {
	p := &Policy{}
	err := c.get(ctx, collection(resource, ns)+"/"+url.PathEscape(name), p)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// WatchPolicies calls each for every event after resourceVersion rv, until
// the watch ends (nil: watch again from the last version seen, which it
// returns) or fails (Gone: list again)
func (c *Client) WatchPolicies(ctx context.Context, rv string, each func(Event) error) (string, error) {
	return c.Watch(ctx, Resource, rv, each)
}

// Watch is WatchPolicies for either resource
func (c *Client) Watch(ctx context.Context, resource, rv string, each func(Event) error) (string, error) {
	resp, err := c.request(ctx, collection(resource, "")+"?watch=1&allowWatchBookmarks=true&resourceVersion="+url.QueryEscape(rv))
	if err != nil {
		return rv, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 2*MaxPolicy)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return rv, fmt.Errorf("a watch event does not read: %v", err)
		}
		if ev.Type == "ERROR" {
			var st struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			return rv, &StatusError{Code: st.Code, Body: st.Message}
		}
		var m struct {
			Metadata Meta `json:"metadata"`
		}
		next := rv
		if json.Unmarshal(ev.Object, &m) == nil && m.Metadata.ResourceVersion != "" {
			next = m.Metadata.ResourceVersion
		}
		// v1.35 step 9 (review): past an event only once it is applied, so a
		// failed one is not skipped when the watch resumes
		if ev.Type != "BOOKMARK" {
			if err := each(ev); err != nil {
				return rv, err
			}
		}
		rv = next
	}
	return rv, sc.Err()
}
