// SPDX-License-Identifier: MIT
// v1250_client.go — run as the agent by test_v1250.sh (Go's own resolver,
// built with CGO_ENABLED=0: it reads /etc/nsswitch.conf and /etc/resolv.conf
// and sends its own questions, here to the Warden's stub).
//   v1250_client_go <port> <wildcard-name> <outside-name>
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	port, name, outside := os.Args[1], os.Args[2], os.Args[3]
	t0 := time.Now()
	a, err := net.LookupHost(name)
	if err != nil {
		fmt.Println("ERR resolve", time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK resolve", a[0], time.Since(t0).Milliseconds())
	}
	t0 = time.Now()
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://" + name + ":" + port + "/")
	if err != nil {
		fmt.Println("ERR http", time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK http", r.StatusCode, time.Since(t0).Milliseconds())
		r.Body.Close()
	}
	t0 = time.Now()
	if _, err := net.LookupHost(outside); err != nil {
		fmt.Println("ERR unlisted", time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK unlisted", time.Since(t0).Milliseconds())
	}
}
