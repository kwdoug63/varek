// SPDX-License-Identifier: MIT
//
// v1.36 step 9 (docs/security/v1.36-kubernetes-parity.md, D10): the node's
// key published. The node agent makes its key at its first start and writes
// its public key beside it (--node-key FILE, FILE.pub); this plugin, on the
// same node, publishes that as the node's VarekNodeKey (kube.PublishNodeKey),
// waiting for the file when the node agent has not written it yet, and
// trying again while the API server refuses or cannot be reached. It keeps
// reading the file after that, and publishes again when the key in it
// changes: a node agent that lost its key makes a new one at its start, and
// the plugin may read the file before the new key is written (it then
// publishes the old one, which the cluster holds already). The admission
// webhook admits the VarekNodeKey only from the plugin on the node it names.
package main

import (
	"context"
	"time"

	"varek.dev/varek-k8s/internal/kube"
)

type keyPublisher struct {
	c     *kube.Client
	node  string // the node's name (the pod's spec.nodeName)
	pub   string // the node agent's FILE.pub
	logf  func(string, ...interface{})
	wait  time.Duration // the first wait between tries (doubled to a minute)
	watch time.Duration // between reads of the file once its key is published
}

// run publishes the key the file holds, and again whenever it changes, until
// ctx is done
func (p *keyPublisher) run(ctx context.Context) {
	first := p.wait
	if first <= 0 {
		first = 2 * time.Second
	}
	watch := p.watch
	if watch <= 0 {
		watch = 5 * time.Second
	}
	wait, said, published := first, "", ""
	for {
		next := watch
		key, err := kube.ReadPublicKey(p.pub)
		if err == nil && key != published {
			if err = p.c.PublishNodeKey(ctx, p.node, key); err == nil {
				p.logf("varek-nri: the node's key is VarekNodeKey %s", kube.NodeKeyName(p.node, key))
				published, said, wait = key, "", first
			}
		}
		if err != nil {
			if msg := err.Error(); msg != said { // said once, until it changes
				p.logf("varek-nri: the node's key is not published yet: %s", msg)
				said = msg
			}
			next = wait
			if wait *= 2; wait > time.Minute {
				wait = time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}
