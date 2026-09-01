// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import "sync"

// maxAdvertisedReplicas caps the replica count a hub's self-reported hello
// may set, and thereby the dial-loop pool (which runs one probe above it, so
// the pool ceiling is this plus one). The count arrives in the handshake before anything about
// the hub is proven, and it directly sizes a goroutine pool: without a ceiling
// a single malicious or misconfigured answer of two billion would have every
// spoke that hears it dial itself to death, and re-learn the value on every
// restart. Sixteen covers any sane hub deployment -- the chart defaults to
// three -- while keeping the worst case a nuisance rather than an outage.
const maxAdvertisedReplicas = 16

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
	// discover is true in single-endpoint mode, where one hostname load-
	// balances across every hub replica and coverage is reached by searching.
	// With several configured endpoints the operator has addressed replicas
	// EXPLICITLY -- each endpoint is expected to pin to one replica -- so the
	// advertised count is ignored, each endpoint keeps exactly one tunnel,
	// and no probe runs: a pinned hostname can never reach a new replica, so
	// probing it can only produce churn, and a scale-up in that mode is the
	// operator adding an endpoint to the values file.
	discover bool

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

func newCoverage(discover bool) *coverage {
	c := &coverage{discover: discover, live: make(map[string]int)}
	if !discover {
		c.want = 1
	}
	return c
}

// join records a tunnel to serverID and reports whether this dialer is a
// duplicate that should step aside.
//
// Every duplicate steps aside; what differs is why, and dialLoop's pacing.
// While coverage is incomplete a duplicate is a wrong guess in the search --
// coverage is reached by redialing until the load balancer hands out an
// uncovered replica -- and the redial comes quickly. Once coverage is
// complete a duplicate is the probe dialer coming back around: the pool
// deliberately runs one dialer more than the replica count, and its slow
// cycle of connect, hear the hub's current count in the hello, step aside is
// the only way a settled spoke ever learns the hub scaled up. Without it a
// new replica receives MCP traffic immediately and answers "cluster not
// connected" until some unrelated reconnect happens to land there.
func (c *coverage) join(serverID string, replicas int) (duplicate bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.discover {
		if replicas > maxAdvertisedReplicas {
			replicas = maxAdvertisedReplicas
		}
		if replicas > 0 {
			c.want = replicas
		}
	}
	already := c.live[serverID] > 0
	c.live[serverID]++
	return already
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
// One per wanted replica, plus one: fewer than the count cannot reach full
// coverage, and the one extra is the probe -- the dialer that keeps cycling
// after coverage completes so the spoke still hears the hub's current replica
// count now and then. Its cost is bounded by the probe backoff in dialLoop,
// not by this number. Before any hello has arrived the count is unknown, and
// one dialer is all an endpoint needs to learn it.
func (c *coverage) dialers() int {
	if !c.probing() {
		return 1
	}
	_, want := c.state()
	if want < 1 {
		// The count is UNKNOWN, not one: a discovery-mode hub advertises
		// zero exactly while its own peer cache is cold or broken. The probe
		// must already be running then -- the established tunnel never
		// handshakes again, so without a probe the first spoke to dial a
		// freshly started hub would keep a single tunnel against a
		// three-replica fleet forever, with both coverage alerts blind to it
		// (they gate on a count the spoke never learned).
		return 2
	}
	return want + 1
}

// probing reports whether this endpoint runs the probe dialer. Only the
// discovery mode does; an explicitly addressed endpoint holds exactly one
// tunnel and hears nothing new from redialing a pinned hostname.
func (c *coverage) probing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.discover
}
