// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	delegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
)

// a stand-in for the SPIRE agent's Delegated Identity API: it answers a
// process id with the SVIDs ids, and records the process ids asked for
type standIn struct {
	delegated.UnimplementedDelegatedIdentityServer
	ids  []string
	asks []int32
}

// the stand-in's authority: every SVID is signed by it, as SPIRE's server's
var (
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caDER  []byte
)

func authority(t *testing.T) {
	t.Helper()
	if caCert != nil {
		return
	}
	var err error
	if caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://example.test")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, URIs: []*url.URL{u},
		Subject:  pkix.Name{Organization: []string{"SPIRE"}, CommonName: "example.test"},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if caDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey); err != nil {
		t.Fatal(err)
	}
	if caCert, err = x509.ParseCertificate(caDER); err != nil {
		t.Fatal(err)
	}
}

func svid(t *testing.T, id string) *delegated.X509SVIDWithKey {
	t.Helper()
	authority(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return &delegated.X509SVIDWithKey{
		X509Svid:    &types.X509SVID{Id: &types.SPIFFEID{TrustDomain: u.Host, Path: u.Path}, CertChain: [][]byte{der}},
		X509SvidKey: kd,
	}
}

func (s *standIn) SubscribeToX509SVIDs(req *delegated.SubscribeToX509SVIDsRequest,
	st delegated.DelegatedIdentity_SubscribeToX509SVIDsServer) error {
	s.asks = append(s.asks, req.GetPid())
	r := &delegated.SubscribeToX509SVIDsResponse{}
	for _, id := range s.ids {
		r.X509Svids = append(r.X509Svids, svid(testT, id))
	}
	return st.Send(r)
}

var testT *testing.T

func serve(t *testing.T, ids ...string) (string, *standIn) {
	t.Helper()
	testT = t
	sock := filepath.Join(t.TempDir(), "admin.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{ids: ids}
	g := grpc.NewServer()
	delegated.RegisterDelegatedIdentityServer(g, s)
	go g.Serve(l)
	t.Cleanup(g.Stop)
	return sock, s
}

const self = "spiffe://example.test/ns/varek-system/sa/varek-node"

func TestFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// the pod's SVID, beside the node agent's own (an entry selected by uid)
	sock, s := serve(t, self, "spiffe://example.test/ns/agents/sa/coder")
	id, out, err := fetch(ctx, sock, 4242, []string{self})
	if err != nil || id != "spiffe://example.test/ns/agents/sa/coder" {
		t.Fatalf("the pod's SVID: %q, %v", id, err)
	}
	if len(s.asks) != 1 || s.asks[0] != 4242 {
		t.Errorf("asked by process id: %v", s.asks)
	}
	b1, rest := pem.Decode(out)
	b2, rest := pem.Decode(rest)
	if b1 == nil || b1.Type != "CERTIFICATE" || b2 == nil || b2.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("its chain and key in PEM: %q", out)
	}
	if c, err := x509.ParseCertificate(b1.Bytes); err != nil || len(c.URIs) != 1 || c.URIs[0].String() != id {
		t.Errorf("the certificate is the SVID's: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(b2.Bytes); err != nil {
		t.Errorf("the key: %v", err)
	}
	for _, c := range []struct {
		what string
		ids  []string
		why  string
	}{
		{"no SVID for the process", nil, "no SVID of its pod"},
		{"only the node agent's own", []string{self}, "no SVID of its pod"},
		{"two for the pod", []string{"spiffe://example.test/a", "spiffe://example.test/b"}, "2 SVIDs"},
	} {
		sock, _ := serve(t, c.ids...)
		if _, _, err := fetch(ctx, sock, 7, []string{self}); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v", c.what, err)
		}
	}
	if _, _, err := fetch(ctx, filepath.Join(t.TempDir(), "none.sock"), 7, nil); err == nil {
		t.Error("no SPIRE agent: no error")
	}
}

// the binary: the file it writes is made new, 0600, and a refusal writes none
func TestMain_File(t *testing.T) {
	if os.Getenv("VAREK_SVID_BIN") == "" {
		t.Skip("VAREK_SVID_BIN is not set")
	}
	sock, _ := serve(t, "spiffe://example.test/ns/agents/sa/coder")
	out := filepath.Join(t.TempDir(), "x.svid")
	if b, err := exec.Command(os.Getenv("VAREK_SVID_BIN"), "-socket", sock, "-pid", "9", "-out", out).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v", err)
	}
	if exec.Command(os.Getenv("VAREK_SVID_BIN"), "-socket", sock, "-pid", "9", "-out", out).Run() == nil {
		t.Error("an existing file: written over")
	}
	// what it writes is what the Warden's --agent-svid takes: warden-secrets
	// verifies it against the authority (as root, the Warden's own test)
	w := os.Getenv("VAREK_WARDEN")
	if w == "" || os.Geteuid() != 0 {
		t.Log("the Warden's check skipped (VAREK_WARDEN unset, or not root)")
		return
	}
	d, err := os.MkdirTemp("/tmp", "varek_svid.")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	bundle, pol, f := filepath.Join(d, "bundle.pem"), filepath.Join(d, "p.txt"), filepath.Join(d, "agent.svid")
	os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)
	os.WriteFile(pol, []byte("require warden 1.28\ntrust spiffe example.test bundle "+bundle+"\nallow path /usr/ readonly\n"), 0o644)
	if b, err := exec.Command(os.Getenv("VAREK_SVID_BIN"), "-socket", sock, "-pid", "9", "-out", f).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	b, err := exec.Command(w, pol, "--agent-svid", f, "--check-credentials").CombinedOutput()
	if err != nil || !strings.Contains(string(b), "agent spiffe://example.test/ns/agents/sa/coder: SVID verified") {
		t.Errorf("the Warden's --agent-svid: %v: %s", err, b)
	}
}
