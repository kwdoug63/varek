// SPDX-License-Identifier: MIT
//
// v1.36 step 9 (docs/security/v1.36-kubernetes-parity.md, D10): the
// VarekNodeKey resource, cluster-scoped. Each node agent makes its own
// signing key at its first start and keeps it on the node; the NRI plugin on
// that node publishes its public key as a VarekNodeKey named for the node
// and the key (NodeKeyName), which the admission webhook admits only from
// the plugin on that node (by the node's name in its service account
// token). A key is never changed: a rebuilt node's new key is a new
// VarekNodeKey, and the one before it is retired at the new one's
// creationTimestamp (the cluster's time). The audit takes the cluster's
// list (kubectl get vareknodekeys -o json, varek_audit.py --node-keys).
package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// NodeKeys is the VarekNodeKey resource (packaging/helm/varek/crds/vareknodekey.yaml)
const NodeKeys = "vareknodekeys"

// NodeKey is a VarekNodeKey
type NodeKey struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Metadata   struct {
		Name              string `json:"name"`
		CreationTimestamp string `json:"creationTimestamp,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Node      string `json:"node"`
		PublicKey string `json:"publicKey"`
	} `json:"spec"`
}

// a node's name as Kubernetes has it (a DNS subdomain), and a key as the
// Warden writes it (tools/varek_keygen's .pub)
var (
	nodeName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	publicKey = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NodeKeyName is the VarekNodeKey of a node's key: the node's name and the
// key's first 16 hex characters
func NodeKeyName(node, key string) string {
	if len(key) > 16 {
		key = key[:16]
	}
	return node + "-" + key
}

// NewNodeKey is the VarekNodeKey of a node's key
func NewNodeKey(node, key string) *NodeKey {
	k := &NodeKey{APIVersion: Group + "/" + Version, Kind: "VarekNodeKey"}
	k.Metadata.Name = NodeKeyName(node, key)
	k.Spec.Node, k.Spec.PublicKey = node, key
	return k
}

// NodeKeyProblem is why a VarekNodeKey is not one a node agent publishes, or ""
func NodeKeyProblem(k *NodeKey) string {
	if !nodeName.MatchString(k.Spec.Node) {
		return fmt.Sprintf("spec.node %q is not a node's name (1 to 253 of a-z, 0-9, . and -)", k.Spec.Node)
	}
	if !publicKey.MatchString(k.Spec.PublicKey) {
		return "spec.publicKey is not a key as the Warden writes it (64 lowercase hex characters)"
	}
	if want := NodeKeyName(k.Spec.Node, k.Spec.PublicKey); k.Metadata.Name != want {
		return fmt.Sprintf("a VarekNodeKey is named for its node and key: %s, not %q", want, k.Metadata.Name)
	}
	if len(k.Metadata.Name) > 253 {
		return fmt.Sprintf("the node's name is too long for its key's name (%s: at most 253 characters)", k.Metadata.Name)
	}
	return ""
}

// ReadPublicKey is the key a node agent wrote (its --node-key FILE.pub)
func ReadPublicKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k := strings.TrimSuffix(string(b), "\n")
	if !publicKey.MatchString(k) {
		return "", fmt.Errorf("%s is not a public key as the Warden writes it (64 lowercase hex characters)", path)
	}
	return k, nil
}

// GetNodeKey is a VarekNodeKey by its name; nil, nil when there is none
func (c *Client) GetNodeKey(ctx context.Context, name string) (*NodeKey, error) {
	k := &NodeKey{}
	err := c.get(ctx, collection(NodeKeys, "")+"/"+url.PathEscape(name), k)
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// CreateNodeKey makes a VarekNodeKey; one there already fails with a
// StatusError of 409
func (c *Client) CreateNodeKey(ctx context.Context, k *NodeKey) error {
	body, err := json.Marshal(k)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+collection(NodeKeys, ""), bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.TokenFile != "" {
		if t, err := os.ReadFile(c.TokenFile); err == nil {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(t)))
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("the service account's token: %v", err)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	return nil
}

// PublishNodeKey makes the node's VarekNodeKey, or finds it made: nil once
// the cluster holds this key for this node
func (c *Client) PublishNodeKey(ctx context.Context, node, key string) error {
	k := NewNodeKey(node, key)
	if why := NodeKeyProblem(k); why != "" {
		return errors.New(why)
	}
	err := c.CreateNodeKey(ctx, k)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusConflict {
		return err
	}
	have, err := c.GetNodeKey(ctx, k.Metadata.Name)
	if err != nil {
		return err
	}
	if have == nil || have.Spec.Node != node || have.Spec.PublicKey != key {
		return fmt.Errorf("VarekNodeKey %s is there, and not for this node's key", k.Metadata.Name)
	}
	return nil
}
