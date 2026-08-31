// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import "sync"

// coverage tracks which hub replicas this spoke currently holds a tunnel to,
// for one configured endpoint.
//
// It exists because a tunnel terminates on exactly one hub replica and the hub
// deliberately does not forward between replicas, so a spoke that holds a
// tunnel to two of three replicas has a third of its tool calls answered with
// "cluster not connected". Behind a single Ingress hostname the spoke cannot
// choose a replica: the load balancer does. So it dials repeatedly and records
// which replica answered, until it has one tunnel per replica.
//
// The alternative was a distinct external hostname per replica, configured into
// every spoke. That works, and is what this replaces: it is real ingress work
// per replica, and getting it wrong fails intermittently rather than loudly.
//
// All methods are safe for concurrent use.
type coverage struct {
	mu sync.Mutex
	// live counts tunnels per hub ServerID. A count rather than a set because
	// two dialers can briefly hold tunnels to the same replica -- during a
	// reconnect race, or before a duplicate notices itself -- and the replica
	// is still covered until the last one drops.
	live map[string]int
	// want is the replica count the hub last advertised. Zero means the hub
	// could not tell us, in which case one tunnel is all this endpoint needs.
	want int
}

func newCoverage() *coverage { return &coverage{live: make(map[string]int)} }

// join records a tunnel to serverID and reports whether this dialer is a
// duplicate that should step aside.
//
// A duplicate is only asked to step aside while coverage is incomplete. Once
// every replica is covered, a redundant tunnel is harmless and closing it would
// just start another dial.
func (c *coverage) join(serverID string, replicas int) (duplicate bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if replicas > 0 {
		c.want = replicas
	}
	already := c.live[serverID] > 0
	c.live[serverID]++
	return already && len(c.live) < c.want
}

// leave records that a tunnel to serverID has ended.
func (c *coverage) leave(serverID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live[serverID] <= 1 {
		delete(c.live, serverID)
		return
	}
	c.live[serverID]--
}

// state reports how many distinct replicas are covered and how many are wanted.
func (c *coverage) state() (covered, want int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.live), c.want
}

// dialers is how many concurrent dial loops this endpoint should run.
//
// One per wanted replica: fewer cannot reach full coverage, and more would add
// connections that are guaranteed redundant. Always at least one, because a
// hub that advertises nothing still needs a tunnel.
func (c *coverage) dialers() int {
	_, want := c.state()
	if want < 1 {
		return 1
	}
	return want
}
