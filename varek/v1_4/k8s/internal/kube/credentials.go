// SPDX-License-Identifier: MIT
//
// v1.36 step 4 (docs/security/v1.36-kubernetes-parity.md, D2): the
// VarekCredential resource, cluster-scoped. A cluster administrator gives a
// credential, by the name a policy names it (spec.credential) and from one
// source (spec.source, as the policy writes it: file:PATH, vault:PATH#FIELD,
// aws-sm:ARN), to the namespaces whose policies may name it
// (spec.namespaces). The node agent and the Warden's --oci-filter take the
// cluster's as a list (CredentialList), one a line:
//
//	CREDENTIAL <tab> NAMESPACE[,NAMESPACE...] <tab> SOURCE <tab> RESOURCE
//
// which the NRI plugin's sync writes as POLICY_DIR/.credentials and the
// admission webhook builds from the API server for each check.
package kube

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Credentials is the VarekCredential resource (packaging/helm/varek/crds/varekcredential.yaml)
const Credentials = "varekcredentials"

// CredentialListFile is the list's name in the node's policy directory (a
// name no namespace has)
const CredentialListFile = ".credentials"

// CredentialName is a credential's name as a policy writes it (the Warden's
// grammar: a lowercase letter, then up to 31 of a-z, 0-9 and _)
var CredentialName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// a source as a policy writes it: a store, then a reference of 1 to 1024
// printable ASCII bytes with no space (a policy's line is split on spaces)
var credentialSource = regexp.MustCompile(`^(file|vault|aws-sm):[\x21-\x7e]+$`)

// CredentialProblem is why a VarekCredential is not one the node agent takes,
// or "" (the webhook refuses it; the sync leaves it out of the list)
func CredentialProblem(c *Policy) string {
	if c.Metadata.Name == "" || len(c.Metadata.Name) > 253 || strings.ContainsAny(c.Metadata.Name, "\t\n\r") {
		return fmt.Sprintf("the VarekCredential's name %q is not one", c.Metadata.Name)
	}
	if !CredentialName.MatchString(c.Spec.Credential) {
		return fmt.Sprintf("spec.credential %q is not a credential's name as a policy writes it (a lowercase letter, "+
			"then up to 31 of a-z, 0-9 and _)", c.Spec.Credential)
	}
	store, ref, _ := strings.Cut(c.Spec.Source, ":")
	if !credentialSource.MatchString(c.Spec.Source) || len(ref) > 1024 || store == "" {
		return fmt.Sprintf("spec.source %q is not file:PATH, vault:PATH#FIELD or aws-sm:ARN (printable, no space, at most "+
			"1024 bytes after the store)", c.Spec.Source)
	}
	if strings.HasPrefix(c.Spec.Source, "file:") && !strings.HasPrefix(c.Spec.Source, "file:/") {
		return "a file: source is an absolute path"
	}
	if strings.HasPrefix(c.Spec.Source, "vault:") && !strings.Contains(c.Spec.Source, "#") {
		return "a vault: source names its field (vault:PATH#FIELD)"
	}
	if len(c.Spec.Namespaces) == 0 {
		return "spec.namespaces names no namespace"
	}
	for _, ns := range c.Spec.Namespaces {
		if !Name.MatchString(ns) {
			return fmt.Sprintf("spec.namespaces: %q is not 1 to 63 of a-z, 0-9 and -", ns)
		}
	}
	return ""
}

// CredentialList is the list the node agent reads, from the cluster's
// VarekCredential resources: the ones it takes, one a line, by resource name
func CredentialList(items []*Policy) string {
	keep := []*Policy{}
	for _, c := range items {
		if CredentialProblem(c) == "" {
			keep = append(keep, c)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Metadata.Name < keep[j].Metadata.Name })
	var b strings.Builder
	b.WriteString("# VAREK: the cluster's VarekCredential resources (v1.36): credential, namespaces, source, resource\n")
	for _, c := range keep {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", c.Spec.Credential, strings.Join(c.Spec.Namespaces, ","), c.Spec.Source,
			c.Metadata.Name)
	}
	return b.String()
}

// ListCredentials is every VarekCredential, a page at a time
func (c *Client) ListCredentials(ctx context.Context) ([]*Policy, error) {
	var out []*Policy
	_, err := c.List(ctx, Credentials, func(p *Policy) {
		q := *p
		out = append(out, &q)
	})
	return out, err
}
