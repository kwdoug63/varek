// SPDX-License-Identifier: MIT
//
// Package kube is the little of the Kubernetes API that VAREK's node plugin
// and admission webhook use (v1.34 step 5, docs/security/v1.34-kubernetes.md,
// D7): the VarekPolicy resource, read and watched through the API server with
// the pod's service account, over HTTPS checked against the cluster's CA. No
// client library: a list, a get and a watch are a few requests.
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

// Group, version and resource of VAREK's policies (packaging/kubernetes/varekpolicy-crd.yaml)
const (
	Group    = "varek.dev"
	Version  = "v1alpha1"
	Resource = "varekpolicies"
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

// Policy is a VarekPolicy: its text is the policy as written for the Warden
type Policy struct {
	Metadata Meta `json:"metadata"`
	Spec     struct {
		Policy string `json:"policy"`
	} `json:"spec"`
}

// List is a list of them
type List struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []Policy `json:"items"`
}

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

func collection(ns string) string {
	if ns == "" {
		return fmt.Sprintf("/apis/%s/%s/%s", Group, Version, Resource)
	}
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", Group, Version, url.PathEscape(ns), Resource)
}

// ListPolicies lists every namespace's policies
func (c *Client) ListPolicies(ctx context.Context) (*List, error) {
	l := &List{}
	return l, c.get(ctx, collection(""), l)
}

// GetPolicy is a namespace's policy by its name; nil, nil when there is none
func (c *Client) GetPolicy(ctx context.Context, ns, name string) (*Policy, error) {
	p := &Policy{}
	err := c.get(ctx, collection(ns)+"/"+url.PathEscape(name), p)
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
	resp, err := c.request(ctx, collection("")+"?watch=1&allowWatchBookmarks=true&resourceVersion="+url.QueryEscape(rv))
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
		if json.Unmarshal(ev.Object, &m) == nil && m.Metadata.ResourceVersion != "" {
			rv = m.Metadata.ResourceVersion
		}
		if ev.Type == "BOOKMARK" {
			continue
		}
		if err := each(ev); err != nil {
			return rv, err
		}
	}
	return rv, sc.Err()
}
