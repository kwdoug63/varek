// SPDX-License-Identifier: MIT
//
// varek-svid — v1.36 step 6 (docs/security/v1.36-kubernetes-parity.md, D5,
// M3): the pod's X.509-SVID for the node agent. It asks the node's SPIRE
// agent through its admin socket (the Delegated Identity API, the node
// agent an authorized delegate) for the SVIDs of a process, by its process
// id, as the Kubernetes workload attestor attests it (its pod), and writes
// the one SVID that is the pod's, its certificate chain and its private key
// in PEM, to a file of root's alone (-out, made new), which the Warden
// hands to warden-secrets as --agent-svid on a host.
//
//	varek-svid -socket ADMIN_SOCKET -pid PID -out FILE [-not SPIFFE_ID]... [-timeout 30s]
//
// -not leaves an SVID out by its SPIFFE ID: the node agent's own (M3: an
// entry that selects the delegate, by uid alone, matches every process run
// as that uid, the pod's too). No SVID left, or more than one, is a
// refusal: the pod's registration entries name one SVID. Exit status 0, or
// 1 with why on standard error.
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	delegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type notList []string

func (n *notList) String() string     { return strings.Join(*n, ",") }
func (n *notList) Set(v string) error { *n = append(*n, v); return nil }

// fetch asks the SPIRE agent at socket for pid's SVIDs and returns the one
// that is not left out: its SPIFFE ID and its chain and key in PEM.
func fetch(ctx context.Context, socket string, pid int32, not []string) (string, []byte, error) {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", nil, fmt.Errorf("cannot reach the SPIRE agent's admin socket %s: %w", socket, err)
	}
	defer conn.Close()
	st, err := delegated.NewDelegatedIdentityClient(conn).SubscribeToX509SVIDs(ctx,
		&delegated.SubscribeToX509SVIDsRequest{Pid: pid})
	if err != nil {
		return "", nil, fmt.Errorf("the SPIRE agent refuses the request: %w", err)
	}
	r, err := st.Recv()
	if err != nil {
		return "", nil, fmt.Errorf("the SPIRE agent gives no answer for process %d: %w", pid, err)
	}
	type got struct {
		id    string
		chain [][]byte
		key   []byte
	}
	var keep []got
	var seen []string
	for _, s := range r.GetX509Svids() {
		x := s.GetX509Svid()
		if x == nil || x.GetId() == nil {
			continue
		}
		id := "spiffe://" + x.GetId().GetTrustDomain() + x.GetId().GetPath()
		seen = append(seen, id)
		left := false
		for _, n := range not {
			left = left || n == id
		}
		if !left {
			keep = append(keep, got{id, x.GetCertChain(), s.GetX509SvidKey()})
		}
	}
	switch {
	case len(keep) == 0:
		return "", nil, fmt.Errorf("the SPIRE agent gives process %d no SVID of its pod (%s): no registration entry "+
			"names its pod", pid, strings.Join(append([]string{"given:"}, seen...), " "))
	case len(keep) > 1:
		ids := make([]string, len(keep))
		for i, k := range keep {
			ids[i] = k.id
		}
		return "", nil, fmt.Errorf("the SPIRE agent gives process %d %d SVIDs (%s): its pod's registration "+
			"entries are to name one", pid, len(keep), strings.Join(ids, ", "))
	}
	k := keep[0]
	if len(k.chain) == 0 || len(k.key) == 0 {
		return "", nil, errors.New("the SPIRE agent's SVID has no certificate or no key")
	}
	var out []byte
	for _, c := range k.chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k.key})...)
	return k.id, out, nil
}

func main() {
	socket := flag.String("socket", "", "the SPIRE agent's admin socket")
	pid := flag.Int("pid", 0, "the process whose SVID is asked for")
	out := flag.String("out", "", "the file to write (made new, 0600)")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to wait for the SPIRE agent")
	var not notList
	flag.Var(&not, "not", "a SPIFFE ID to leave out (the node agent's own); may be given again")
	flag.Parse()
	if *socket == "" || *pid <= 0 || *pid > 1<<31-1 || *out == "" || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: varek-svid -socket ADMIN_SOCKET -pid PID -out FILE [-not SPIFFE_ID]... [-timeout 30s]")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	id, pemb, err := fetch(ctx, *socket, int32(*pid), not)
	if err != nil {
		fmt.Fprintln(os.Stderr, "varek-svid:", err)
		os.Exit(1)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_, err = f.Write(pemb)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	for i := range pemb {
		pemb[i] = 0
	}
	if err != nil {
		os.Remove(*out)
		fmt.Fprintln(os.Stderr, "varek-svid: cannot write", *out+":", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "varek-svid: %s for process %d, from the SPIRE agent\n", id, *pid)
}
