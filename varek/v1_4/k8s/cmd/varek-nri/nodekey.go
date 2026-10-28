// SPDX-License-Identifier: MIT
//
// v1.36 step 9 (docs/security/v1.36-kubernetes-parity.md, D10): the node's
// key published. The node agent makes its key at its first start and writes
// its public key beside it (--node-key FILE, FILE.pub); this plugin, on the
// same node, publishes that as the node's VarekNodeKey (kube.PublishNodeKey),
// waiting for the file when the node agent has not written it yet, and
// trying again while the API server refuses or cannot be reached. The
// admission webhook admits the VarekNodeKey only from the plugin on the node
// it names.
package main

import (
	"context"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

type keyPublisher struct {
	c    *kube.Client
	node string // the node's name (the pod's spec.nodeName)
	pub  string // the node agent's FILE.pub
	logf func(string, ...interface{})
	wait time.Duration // the first wait between tries (doubled to a minute)
}

// run publishes the key the file holds, and returns once the cluster holds it
func (p *keyPublisher) run(ctx context.Context) {
	wait := p.wait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	said := ""
	for {
		key, err := kube.ReadPublicKey(p.pub)
		if err == nil {
			if err = p.c.PublishNodeKey(ctx, p.node, key); err == nil {
				p.logf("varek-nri: the node's key is VarekNodeKey %s", kube.NodeKeyName(p.node, key))
				return
			}
		}
		if msg := err.Error(); msg != said { // said once, until it changes
			p.logf("varek-nri: the node's key is not published yet: %s", msg)
			said = msg
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if wait *= 2; wait > time.Minute {
			wait = time.Minute
		}
	}
}
