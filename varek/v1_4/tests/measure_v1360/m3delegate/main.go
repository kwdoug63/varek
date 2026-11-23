package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	delegated "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[2])
	conn, err := grpc.NewClient("unix://"+os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := delegated.NewDelegatedIdentityClient(conn).SubscribeToX509SVIDs(ctx,
		&delegated.SubscribeToX509SVIDsRequest{Pid: int32(pid)})
	if err == nil {
		var r *delegated.SubscribeToX509SVIDsResponse
		if r, err = st.Recv(); err == nil {
			if len(r.X509Svids) == 0 {
				fmt.Println("none")
			}
			for _, s := range r.X509Svids {
				fmt.Printf("spiffe://%s%s\n", s.X509Svid.Id.TrustDomain, s.X509Svid.Id.Path)
			}
			return
		}
	}
	fmt.Println("error:", err)
}
