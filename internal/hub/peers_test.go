// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// peerCounter
// ---------------------------------------------------------------------------

// gatedResolve is a resolve func a test can drive by hand: each call blocks on
// release until the test lets it through, and every call is counted so a test
// can assert exactly how many DNS lookups happened.
type gatedResolve struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
	addrs   []string
	err     error
}

func newGatedResolve() *gatedResolve {
	return &gatedResolve{release: make(chan struct{})}
}

// resolve is the peerCounter.resolve field.
func (g *gatedResolve) resolve(ctx context.Context, _ string) ([]string, error) {
	g.mu.Lock()
	g.calls++
	g.mu.Unlock()

	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	return g.addrs, g.err
}

func (g *gatedResolve) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// set changes what the next (and every subsequent) call returns.
func (g *gatedResolve) set(addrs []string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.addrs, g.err = addrs, err
}

// letThrough releases every call currently blocked, and every call after it,
// by closing the release channel once.
func (g *gatedResolve) letThrough() {
	close(g.release)
}

// immediateResolve is a resolve func that never blocks, for tests that only
// care about the eventual count.
func immediateResolve(addrs []string, err error) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		return addrs, err
	}
}

// panicResolve fails the test immediately if DNS is ever consulted. It backs
// the "must not resolve" assertions.
func panicResolve(t *testing.T) func(context.Context, string) ([]string, error) {
	t.Helper()
	return func(context.Context, string) ([]string, error) {
		t.Fatal("resolve was called when it must not have been")
		return nil, nil
	}
}

// waitForCalls polls until a gatedResolve has been called n times.
func waitForCalls(t *testing.T, g *gatedResolve, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g.callCount() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d resolve call(s), got %d", n, g.callCount())
}

// TestPeerCounterEmptyDomainNeverResolves is what makes a peerCounter safe to
// build unconditionally: an operator who never configured peer discovery gets
// a counter that costs nothing and advertises nothing.
func TestPeerCounterEmptyDomainNeverResolves(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	p := newPeerCounter("", logger, nil)
	p.resolve = panicResolve(t)

	for i := range 3 {
		if got := p.Count(); got != 0 {
			t.Fatalf("Count() call %d = %d, want 0 for an empty domain", i, got)
		}
	}
}

// TestPeerCounterNilReceiverReturnsZero. newTunnelServer always builds one, but
// a nil-safe Count keeps the field usable the same way a nil *slog.Logger
// method call would be dangerous but a nil map read is not: callers should not
// need a guard before every use.
func TestPeerCounterNilReceiverReturnsZero(t *testing.T) {
	t.Parallel()

	var p *peerCounter
	if got := p.Count(); got != 0 {
		t.Fatalf("Count() on a nil *peerCounter = %d, want 0", got)
	}
}

// TestPeerCounterFirstCallTriggersABackgroundRefresh. The very first call has
// nothing cached, so it must answer 0 immediately (never block) and kick off a
// refresh that eventually populates the cache.
func TestPeerCounterFirstCallTriggersABackgroundRefresh(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	g := newGatedResolve()
	g.set([]string{"10.0.0.1", "10.0.0.2"}, nil)

	var observed []int
	var observedMu sync.Mutex
	p := newPeerCounter("hub-headless.monitoring.svc", logger, func(n int) {
		observedMu.Lock()
		observed = append(observed, n)
		observedMu.Unlock()
	})
	p.resolve = g.resolve

	if got := p.Count(); got != 0 {
		t.Fatalf("first Count() = %d, want 0 before any resolution has completed", got)
	}
	g.letThrough()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.Count() == 2 {
			// The observer is the discovered-peers gauge: it must have been
			// told the same count the spokes will be, or the one alert for a
			// broken discovery watches a number nothing updates.
			observedMu.Lock()
			got := append([]int(nil), observed...)
			observedMu.Unlock()
			if len(got) == 0 || got[len(got)-1] != 2 {
				t.Fatalf("observer saw %v, want a final 2", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Count() never reached 2 after the background refresh completed; got %d", p.Count())
}

// TestPeerCounterServesACachedValueWhileFresh. A second call inside the TTL
// must not resolve again: that is what keeps a hundred spokes reconnecting at
// once from turning into a DNS query per handshake.
func TestPeerCounterServesACachedValueWhileFresh(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	now := time.Now()
	clock := func() time.Time { return now }

	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.now = clock
	p.ttl = time.Minute
	p.count = 3
	p.fetched = now
	p.resolve = panicResolve(t)

	if got := p.Count(); got != 3 {
		t.Fatalf("Count() = %d, want the cached 3", got)
	}
}

// TestPeerCounterFreshnessBoundaryIsInclusive pins the exact instant the
// cache flips from fresh to stale: one tick before the TTL has elapsed the
// cached value must be served with no DNS lookup, and AT the TTL a refresh
// must already be started. TestPeerCounterServesACachedValueWhileFresh (zero
// elapsed) and the stale-cache test (two TTLs elapsed) both sit far enough
// from this line that a CONDITIONALS_BOUNDARY mutant turning "<" into "<="
// would pass either unnoticed.
func TestPeerCounterFreshnessBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	now := time.Now()

	// One tick before the TTL has elapsed: still fresh, so resolve must
	// never be consulted.
	before := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	before.now = func() time.Time { return now }
	before.ttl = time.Minute
	before.count = 3
	before.fetched = now.Add(-(time.Minute - time.Nanosecond))
	before.resolve = panicResolve(t)
	if got := before.Count(); got != 3 {
		t.Fatalf("Count() = %d, want the cached 3 one tick before the TTL", got)
	}

	// Exactly at the TTL: stale, so a background refresh must start.
	g := newGatedResolve()
	g.set([]string{"10.0.0.1"}, nil)
	at := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	at.now = func() time.Time { return now }
	at.ttl = time.Minute
	at.count = 3
	at.fetched = now.Add(-time.Minute)
	at.resolve = g.resolve
	if got := at.Count(); got != 3 {
		t.Fatalf("Count() = %d, want the still-cached 3 while the refresh runs", got)
	}
	waitForCalls(t, g, 1)
	g.letThrough()
}

// TestPeerCounterStaleCacheTriggersExactlyOneRefreshUnderConcurrency is the
// inFlight property: many goroutines racing Count() against a stale cache must
// start a single background refresh, not one per caller.
func TestPeerCounterStaleCacheTriggersExactlyOneRefreshUnderConcurrency(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	now := time.Now()
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	g := newGatedResolve()
	g.set([]string{"10.0.0.1"}, nil)

	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.now = clock
	p.ttl = time.Minute
	p.resolve = g.resolve
	// Stale: fetched a TTL and a bit ago.
	p.fetched = now.Add(-2 * time.Minute)

	var wg sync.WaitGroup
	var calls int32
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddInt32(&calls, 1)
			p.Count()
		}()
	}
	wg.Wait()

	// Give the single goroutine's refresh a moment to actually call resolve
	// before asserting there is only one in flight.
	waitForCalls(t, g, 1)
	time.Sleep(20 * time.Millisecond)
	if got := g.callCount(); got != 1 {
		t.Fatalf("resolve was called %d times for %d concurrent Count() calls against a "+
			"stale cache, want exactly 1", got, calls)
	}
	g.letThrough()
}

// TestPeerCounterCountNeverBlocksOnDNS pins the contract line by line: this
// runs inside a tunnel handshake, so a slow resolver must cost a stale read,
// never a stalled caller.
func TestPeerCounterCountNeverBlocksOnDNS(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	g := newGatedResolve() // never released during this test

	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.resolve = g.resolve

	done := make(chan int, 1)
	go func() { done <- p.Count() }()

	select {
	case got := <-done:
		if got != 0 {
			t.Errorf("Count() = %d, want 0 while resolution is still pending", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Count() blocked on a resolve call that had not returned")
	}
}

// TestPeerCounterRefreshBudgetsAFiveSecondTimeout pins that the context
// refresh hands to resolve carries the full 5-second budget the code
// comments its way to, not merely "a" budget. An ARITHMETIC_BASE mutant
// turning "5*time.Second" into "5/time.Second" collapses it to zero, so the
// context would already be expired the instant resolve receives it.
func TestPeerCounterRefreshBudgetsAFiveSecondTimeout(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	entered := make(chan struct{})
	p.resolve = func(ctx context.Context, _ string) ([]string, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		p.refresh()
	}()

	<-entered
	select {
	case <-finished:
		t.Fatal("refresh returned almost immediately; its context was already expired")
	case <-time.After(200 * time.Millisecond):
		// Still running with roughly 4.8s of budget left, as it must be.
	}
}

// TestPeerCounterResolveErrorKeepsThePreviousCount is deliberate: zero means
// "no idea", which would tell every spoke to stop dialing for full coverage,
// so a momentary NXDOMAIN during a rolling update must not collapse the fleet
// onto one replica.
func TestPeerCounterResolveErrorKeepsThePreviousCount(t *testing.T) {
	t.Parallel()

	logger, sink := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.count = 3
	p.resolve = immediateResolve(nil, errors.New("lookup hub-headless.monitoring.svc: no such host"))

	p.refresh()

	if got := p.count; got != 3 {
		t.Fatalf("count after a failed refresh = %d, want the previous 3 kept", got)
	}
	if sink.find("peer discovery failed; keeping the previous replica count") == nil {
		t.Errorf("no log line reported the failed refresh; log was:\n%s", sink.String())
	}
}

// TestPeerCounterDeduplicatesAddresses. A headless Service can answer with the
// same address more than once during propagation; the count is of replicas,
// not of A records.
func TestPeerCounterDeduplicatesAddresses(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.resolve = immediateResolve([]string{"10.0.0.1", "10.0.0.1", "10.0.0.2"}, nil)

	p.refresh()

	if got := p.count; got != 2 {
		t.Fatalf("count after refresh = %d, want 2 distinct addresses", got)
	}
}

// TestPeerCounterLogsAChangedCount. This is the one line an operator watching a
// scale-up or scale-down would look for.
func TestPeerCounterLogsAChangedCount(t *testing.T) {
	t.Parallel()

	logger, sink := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.count = 1
	p.resolve = immediateResolve([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)

	p.refresh()

	rec := sink.find("hub replica count changed")
	if rec == nil {
		t.Fatalf("no log line reported the changed count; log was:\n%s", sink.String())
	}
	if rec["from"] != float64(1) || rec["to"] != float64(3) {
		t.Errorf("changed-count log = %+v, want from=1 to=3", rec)
	}
	if got := p.count; got != 3 {
		t.Fatalf("count after refresh = %d, want 3", got)
	}
}

// TestPeerCounterDoesNotLogAnUnchangedCount keeps the log from becoming noise
// on every refresh of a fleet that has not changed size.
func TestPeerCounterDoesNotLogAnUnchangedCount(t *testing.T) {
	t.Parallel()

	logger, sink := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)
	p.count = 2
	p.resolve = immediateResolve([]string{"10.0.0.1", "10.0.0.2"}, nil)

	p.refresh()

	if rec := sink.find("hub replica count changed"); rec != nil {
		t.Errorf("an unchanged count was logged anyway: %+v", rec)
	}
}

// TestNewPeerCounterWiresRealDefaults pins that a counter built the production
// way resolves with net.DefaultResolver.LookupHost, uses time.Now and carries
// the package TTL -- the seams the tests above override, proven wired here so
// that overriding them in a test is proven to be overriding something real.
func TestNewPeerCounterWiresRealDefaults(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()
	p := newPeerCounter("hub-headless.monitoring.svc", logger, nil)

	if p.domain != "hub-headless.monitoring.svc" {
		t.Errorf("domain = %q, want the configured value", p.domain)
	}
	if p.resolve == nil {
		t.Error("resolve was not wired")
	}
	if p.now == nil {
		t.Error("now was not wired")
	}
	if p.ttl != peerCacheTTL {
		t.Errorf("ttl = %s, want %s", p.ttl, peerCacheTTL)
	}
}

// TestAdvertisedReplicas pins the meaning of the hello's replica count. Zero
// is reserved for "unknown, keep probing" -- so a hub with NO discovery
// domain, whose only reachable replica is itself, must advertise exactly 1,
// or every spoke would probe forever for a count that is never coming. With
// discovery configured, the count comes from the resolver, cold cache and
// all: that zero is the one that closes the bootstrap hole.
func TestAdvertisedReplicas(t *testing.T) {
	t.Parallel()

	logger, _ := newLogSink()

	h := &hub{cfg: &config.Hub{}}
	if got := h.advertisedReplicas(newPeerCounter("", logger, nil))(); got != 1 {
		t.Errorf("no discovery domain: advertised = %d, want 1", got)
	}

	h2 := &hub{cfg: &config.Hub{PeerDiscoveryDomain: "hub-peers.ns.svc"}}
	p := newPeerCounter("hub-peers.ns.svc", logger, nil)
	if got := h2.advertisedReplicas(p)(); got != 0 {
		t.Errorf("cold discovery cache: advertised = %d, want 0 (unknown)", got)
	}
}
