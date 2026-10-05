// SPDX-License-Identifier: MIT
// v1240_client.go — run as the agent by test_v1240.sh (Go's own resolver,
// built with CGO_ENABLED=0: it reads /etc/nsswitch.conf and /etc/hosts itself).
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Args[1]
	t0 := time.Now()
	a, err := net.LookupHost("api.example.com")
	if err != nil {
		fmt.Println("ERR resolve", err, time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK resolve", a[0], time.Since(t0).Milliseconds())
	}
	t0 = time.Now()
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://api.example.com:" + port + "/")
	if err != nil {
		fmt.Println("ERR http", time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK http", r.StatusCode, time.Since(t0).Milliseconds())
		r.Body.Close()
	}
	t0 = time.Now()
	if _, err := net.LookupHost("other.example.com"); err != nil {
		fmt.Println("ERR unlisted", time.Since(t0).Milliseconds())
	} else {
		fmt.Println("OK unlisted", time.Since(t0).Milliseconds())
	}
}
