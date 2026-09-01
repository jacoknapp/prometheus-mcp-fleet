// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sync/atomic"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// ---------------------------------------------------------------------------
// spokeInstanceID
// ---------------------------------------------------------------------------

// withStubHostname replaces osHostname for the duration of the test.
func withStubHostname(t *testing.T, host string, err error) {
	t.Helper()
	orig := osHostname
	osHostname = func() (string, error) { return host, err }
	t.Cleanup(func() { osHostname = orig })
}

// TestSpokeInstanceIDPrefersTheHostname is the ordinary pod: a stable,
// distinct, log-meaningful name comes for free from the platform.
//
// Not parallel: it swaps the package-level osHostname indirection, which
// spokeInstanceID reads from any goroutine, including ones started by other
// tests in this package (Run and s.run both call it).
func TestSpokeInstanceIDPrefersTheHostname(t *testing.T) {
	withStubHostname(t, "spoke-7f9c8d-abcde", nil)
	if got := spokeInstanceID(); got != "spoke-7f9c8d-abcde" {
		t.Errorf("spokeInstanceID() = %q, want the hostname", got)
	}
}

// TestSpokeInstanceIDFallsBackToARandomValue covers both shapes of "this host
// cannot name itself": an error from the syscall, and an empty string with no
// error. An empty value would make every anonymous pod collide into one slot
// and evict each other, which is exactly what the fallback exists to prevent.
//
// Not parallel, including its subtests: see
// [TestSpokeInstanceIDPrefersTheHostname].
func TestSpokeInstanceIDFallsBackToARandomValue(t *testing.T) {
	tests := []struct {
		name string
		host string
		err  error
	}{
		{name: "the syscall failed", host: "", err: errors.New("host name lookup failed")},
		{name: "no error but nothing was returned", host: "", err: nil},
		// A host reported alongside an error must not be trusted: the failure
		// is what the caller is told to act on.
		{name: "a host reported alongside an error is not trusted", host: "should-be-ignored", err: errors.New("boom")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withStubHostname(t, tc.host, tc.err)

			got := spokeInstanceID()
			if !strings.HasPrefix(got, "spoke-") {
				t.Fatalf("spokeInstanceID() = %q, want the spoke-<hex> fallback", got)
			}
			if strings.Contains(got, "should-be-ignored") {
				t.Errorf("spokeInstanceID() = %q, used the host reported alongside an error", got)
			}
			if len(got) != len("spoke-")+16 {
				t.Errorf("spokeInstanceID() = %q, want 8 random bytes hex-encoded after the prefix", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// superviseEndpoint
// ---------------------------------------------------------------------------

// countLogLines counts records whose message contains want. logCapture only
// exposes has/find (a single hit), and proving growth here means counting
// every "tunnel connected" line the pool has produced so far.
func countLogLines(logs *spokeProbe, want string) int {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	n := 0
	for _, r := range logs.records {
		if strings.Contains(r.Message, want) {
			n++
		}
	}
	return n
}

// logLineTimes returns the time of every record whose message contains want,
// in the order they were logged.
func logLineTimes(logs *spokeProbe, want string) []time.Time {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var out []time.Time
	for _, r := range logs.records {
		if strings.Contains(r.Message, want) {
			out = append(out, r.Time)
		}
	}
	return out
}

// TestSuperviseEndpointGrowsThePoolToMatchAdvertisedReplicas drives
// superviseEndpoint directly against a real hub that advertises 3 replicas,
// and proves the dialer pool actually grows from its starting size of one:
// the first connection's handshake reports the replica count, and the next
// coverageInterval tick must spin up two more dialLoop goroutines rather than
// leaving the endpoint permanently under-covered.
//
// The reconnect backoff is pinned to a full minute so that once the two
// redundant dialers are cancelled (this one hub can only ever answer as a
// single ServerID, so every connection past the first is a duplicate while
// coverage is incomplete) they do not retry inside the test's window: exactly
// three "tunnel connected" lines is the signature of the pool having grown to
// three, not of one dialer retrying quickly.
func TestSuperviseEndpointGrowsThePoolToMatchAdvertisedReplicas(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 3)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: time.Minute,
		ReconnectMaxBackoff: time.Minute,
	})
	s.timing.dialStagger = time.Millisecond
	s.timing.coverageInterval = 5 * time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.superviseEndpoint(ctx, hub.url) }()

	eventually(t, "the dialer pool to grow to 3 concurrent connections", func() bool {
		return countLogLines(logs, "tunnel connected") >= 3
	})

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("superviseEndpoint did not stop after its context was cancelled")
	}
}

// TestSuperviseEndpointOneConfiguredEndpointStillDiscovers pins the boundary
// of superviseEndpoint's own "len(s.cfg.HubEndpoints) <= 1" check: the
// ordinary single-hostname deployment -- exactly one configured endpoint,
// not zero -- must still run in discovery mode and grow its pool to match
// the hub's advertised replica count. TestSuperviseEndpointGrowsThePool... in
// this file never sets HubEndpoints at all (length zero), so it cannot tell
// "<= 1" apart from "< 1"; only length exactly 1 does. Getting this wrong
// would leave the single most common deployment shape pinned at one tunnel
// forever, silently starving two of every three replicas behind a
// three-replica hub.
func TestSuperviseEndpointOneConfiguredEndpointStillDiscovers(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 3)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: time.Minute,
		ReconnectMaxBackoff: time.Minute,
		HubEndpoints:        []string{hub.url},
	})
	s.timing.dialStagger = time.Millisecond
	s.timing.coverageInterval = 5 * time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.superviseEndpoint(ctx, hub.url) }()

	eventually(t, "the dialer pool to grow to 3 concurrent connections with exactly one configured endpoint", func() bool {
		return countLogLines(logs, "tunnel connected") >= 3
	})

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("superviseEndpoint did not stop after its context was cancelled")
	}
}

// TestSuperviseEndpointPinnedModePoolNeverGrowsPastOne pins the boundary from
// the other side: with several configured endpoints (explicit-addressing
// mode), coverage.dialers() is fixed at exactly 1 forever regardless of what
// the hub advertises, so the pool-growth loop's own boundary --
// "int(active.Load()) < want" -- must stop growing at exactly one dial loop.
// An off-by-one there ("<=") would spin up a second dialer that immediately
// lands on the same physical hub as a duplicate, since this test's hub only
// ever answers as one server ID: a "redundant tunnel" log line is the
// unambiguous signature of that second, unwanted dialer, since a correctly
// sized pool of one never has anything to be redundant against.
func TestSuperviseEndpointPinnedModePoolNeverGrowsPastOne(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 3)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: time.Minute,
		ReconnectMaxBackoff: time.Minute,
		// Two configured endpoints puts coverage into explicit-addressing
		// mode for BOTH -- including hub.url, the only one actually dialed
		// here. The second entry is never dialed; it exists only to make
		// len(HubEndpoints) == 2.
		HubEndpoints: []string{hub.url, "ws://unused.invalid/tunnel"},
	})
	s.timing.dialStagger = time.Millisecond
	s.timing.coverageInterval = 5 * time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.superviseEndpoint(ctx, hub.url) }()

	eventually(t, "the one tunnel this pinned endpoint wants", func() bool {
		return countLogLines(logs, "tunnel connected") >= 1
	})
	// Several more coverageInterval ticks: a pool that over-grew would have
	// spun up its second, redundant dialer well within this window.
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("superviseEndpoint did not stop after its context was cancelled")
	}
	if logs.has("redundant tunnel to an already-covered hub replica") {
		t.Error("a pinned endpoint's pool grew past one dial loop: " + logs.messages())
	}
}

// TestSuperviseEndpointShrinksThenKeepsProbingAfterScaleDown pins the SIGN of
// the pool counter's decrement (see the "defer active.Add(-1)" in
// superviseEndpoint's growth loop). That counter is shared and read by every
// dial loop's own retirement check, so a decrement that went the wrong way
// would not just mis-size the pool once -- it would make every surplus loop's
// exit push the counter FURTHER from correct, and every dialer still running
// would see an ever-growing "surplus" and retire too. The whole endpoint
// would collapse to its one genuine tunnel and go silent: no more probing,
// ever, since nothing is left to run it.
//
// This drives that scenario for real: scale a hub down from five replicas to
// one and confirm the endpoint keeps producing fresh probe activity well
// after the retirements from the scale-down have had time to finish, rather
// than that activity permanently stopping the moment the last surplus dialer
// (wrongly) retires itself into oblivion.
func TestSuperviseEndpointShrinksThenKeepsProbingAfterScaleDown(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub, replicas := newHAHubDynamic(t, ca, 5)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: 5 * time.Millisecond,
		ReconnectMaxBackoff: 50 * time.Millisecond,
	})
	s.timing.coverageProbe = 20 * time.Millisecond
	s.timing.coverageInterval = 5 * time.Millisecond
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.superviseEndpoint(ctx, hub.url) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("superviseEndpoint did not stop after its context was cancelled")
		}
	})

	// Let the pool grow to match five advertised replicas (six dial loops:
	// one real tunnel plus five redundant, since this one physical process
	// only ever answers as a single server ID).
	eventually(t, "the pool to grow for five advertised replicas", func() bool {
		return countLogLines(logs, "redundant tunnel to an already-covered hub replica") >= 5
	})

	// Scale down hard, then let the dust settle: every surplus loop gets a
	// chance to see the new, smaller dialers() and retire.
	replicas.Store(1)
	time.Sleep(300 * time.Millisecond)
	settledCount := countLogLines(logs, "redundant tunnel to an already-covered hub replica")

	// If a probe survived the scale-down (the correct outcome), it keeps
	// cycling at the probe pace and this count keeps climbing. If every
	// non-holder loop cascaded into retiring (the broken decrement), nothing
	// is left to produce this log line ever again.
	eventually(t, "probe activity to continue well after the scale-down settled", func() bool {
		return countLogLines(logs, "redundant tunnel to an already-covered hub replica") > settledCount
	})
}

// ---------------------------------------------------------------------------
// dialOnce's OnConnected callback
// ---------------------------------------------------------------------------

// haHub is a real wstun hub that advertises a configurable, fixed replica
// count. newTunnelHub (helpers_test.go) never sets Replicas, so it cannot
// drive the coverage-tracking branches inside dialOnce's OnConnected callback:
// those need a hub that claims more replicas than the one physical process
// backing this test can actually be.
type haHub struct {
	url      string
	sessions chan tunnel.Session
}

// newHAHub stands one up and serves until the test ends.
func newHAHub(t *testing.T, ca *testCA, replicas int) *haHub {
	t.Helper()
	return newHAHubReplicasFunc(t, ca, func() int { return replicas })
}

// newHAHubDynamic is newHAHub with a replica count the test can change after
// the hub is already serving, so a test can drive a scale-up or scale-down
// through a live spoke rather than only ever dialing a fixed-size hub.
func newHAHubDynamic(t *testing.T, ca *testCA, initialReplicas int) (*haHub, *atomic.Int32) {
	t.Helper()
	replicas := &atomic.Int32{}
	replicas.Store(int32(initialReplicas))
	return newHAHubReplicasFunc(t, ca, func() int { return int(replicas.Load()) }), replicas
}

func newHAHubReplicasFunc(t *testing.T, ca *testCA, replicas func() int) *haHub {
	t.Helper()

	srv, err := wstun.NewServer(wstun.ServerConfig{
		Verify:   ca.verify,
		Logger:   quiet(),
		ServerID: "hub-test-0",
		Replicas: replicas,
		Keepalive: grpctun.KeepaliveParams{
			Time: time.Minute, Timeout: 30 * time.Second, PermitWithoutStream: true,
		},
	})
	if err != nil {
		t.Fatalf("wstun.NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(wstun.DefaultPath, srv.Handler())
	ts := httptest.NewServer(mux)

	h := &haHub{
		url:      "ws" + strings.TrimPrefix(ts.URL, "http") + wstun.DefaultPath,
		sessions: make(chan tunnel.Session, 8),
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- srv.Listener().Serve(ctx, tunnel.SessionHandlerFunc(
			func(_ context.Context, s tunnel.Session) (func(), error) {
				h.sessions <- s
				return nil, nil
			}))
	}()
	t.Cleanup(func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = srv.Listener().Shutdown(shutCtx)
		<-served
		ts.Close()
	})
	return h
}

func (h *haHub) awaitSession(t *testing.T) tunnel.Session {
	t.Helper()
	select {
	case s := <-h.sessions:
		return s
	case <-time.After(20 * time.Second):
		t.Fatal("no spoke connected to the hub")
		return nil
	}
}

// TestDialOnceOnConnectedWithNilCoverage covers the endpoint no test above
// exercises: dialOnce called with a nil *coverage, which superviseEndpoint
// never does but the parameter's own nil-safety is a stated contract. The
// hub-replicas gauge must still be set; nothing coverage-shaped may run.
func TestDialOnceOnConnectedWithNilCoverage(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 3)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reason := make(chan string, 1)
	go func() { reason <- s.dialOnce(ctx, hub.url, quiet(), nil) }()

	hub.awaitSession(t)
	eventually(t, "the hub replicas gauge to be set", func() bool {
		return logs.metric(t, "promfleet_spoke_hub_replicas", "endpoint="+hub.url) == 3
	})
	if got := logs.metric(t, "promfleet_spoke_tunnels_covered", "endpoint="+hub.url); got != 0 {
		t.Errorf("tunnels_covered = %v with a nil coverage tracker, want untouched at 0", got)
	}

	cancel()
	select {
	case got := <-reason:
		if got != "context-cancelled" {
			t.Errorf("dialOnce reported %q, want context-cancelled", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dialOnce did not return after its context was cancelled")
	}
}

// TestDialOnceOnConnectedDropsARedundantTunnel drives the one state the HA
// design must not settle into: two connections landing on the same hub
// replica while the hub says more replicas exist. The second must be told it
// is a duplicate and have its connection cancelled so the retry can land
// elsewhere; the first must be left alone.
func TestDialOnceOnConnectedDropsARedundantTunnel(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	// This one physical hub process answers every dial with the same
	// ServerID, but claims 2 replicas exist -- exactly what a spoke sees
	// mid-rollout, before it has dialed enough times to land on the other one.
	hub := newHAHub(t, ca, 2)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	cov := newCoverage(true)

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	first := make(chan string, 1)
	go func() { first <- s.dialOnce(ctx1, hub.url, s.logger, cov) }()
	hub.awaitSession(t)

	eventually(t, "the first tunnel to be recorded as covering a replica", func() bool {
		covered, _ := cov.state()
		return covered == 1
	})

	// The redundant connection is cancelled by its own OnConnected callback
	// before grpctun finishes establishing a session on top of it, so unlike
	// the first connection there is never a tunnel.Session to await here: the
	// hub-side handler is never invoked for it. What is observable is
	// dialOnce's own return value and the log line below.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	second := make(chan string, 1)
	go func() { second <- s.dialOnce(ctx2, hub.url, s.logger, cov) }()

	select {
	case got := <-second:
		// Reported distinctly, not as a generic cancellation. The dial loop
		// exempts this reason from the failure backoff: landing on a covered
		// replica is a step in the coverage search, not a fault, and charging
		// it to the backoff made every wrong guess slow the next one
		// exponentially -- worst exactly when the fleet was nearly covered.
		if got != reasonRedundantTunnel {
			t.Errorf("the redundant dialOnce reported %q, want %q", got, reasonRedundantTunnel)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the redundant tunnel was never dropped")
	}
	if !logs.has("redundant tunnel to an already-covered hub replica") {
		t.Errorf("the duplicate was not logged; got %s", logs.messages())
	}

	// The first tunnel must not have been touched by the second's duplicate
	// handling.
	select {
	case got := <-first:
		t.Fatalf("the first, non-duplicate tunnel returned (%q) instead of staying up", got)
	case <-time.After(200 * time.Millisecond):
	}
	cancel1()
	select {
	case got := <-first:
		if got != "context-cancelled" {
			t.Errorf("the first tunnel reported %q after its own cancellation, want context-cancelled", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the first tunnel did not stop after being cancelled")
	}
}

// TestDialLoopProbePacesRedundantDialsAfterCoverage drives dialLoop itself
// through the probe regime: coverage is complete, so its redundant dials are
// paced by the probe interval rather than the fast search backoff, and each
// cycle is what re-learns the hub's replica count. The intervals are shrunk
// so the test observes more than one cycle without waiting a minute.
func TestDialLoopProbePacesRedundantDialsAfterCoverage(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 1)
	clock := newStubClock()
	s, logs2 := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: 10 * time.Millisecond,
		ReconnectMaxBackoff: 100 * time.Millisecond,
	})
	logs := logs2.logCapture
	s.timing.coverageProbe = 30 * time.Millisecond
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	cov := newCoverage(true)

	// The first tunnel covers the hub's only replica.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go s.dialOnce(ctx1, hub.url, s.logger, cov)
	hub.awaitSession(t)
	eventually(t, "coverage to complete", func() bool {
		covered, want := cov.state()
		return covered == 1 && want == 1
	})

	// The probe: every dial it makes is redundant, and dialLoop must keep
	// cycling it at the probe pace rather than stopping or hammering.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx2, hub.url, cov, nil) }()

	eventually(t, "at least two probe cycles", func() bool {
		return logs.count("redundant tunnel to an already-covered hub replica") >= 2
	})

	// THE regression this design shipped once: the probe's routine step-aside
	// must not clear the signals the live tunnel earned. Every probe cycle
	// has now ended at least twice; the endpoint still holds a real tunnel,
	// so readiness and the gauge must both say up.
	if ready, reasons := s.health.Ready(); !ready {
		t.Errorf("spoke NotReady while a live tunnel is up: %v", reasons)
	}
	if got := logs2.metric(t, "promfleet_spoke_tunnel_up", "endpoint="+hub.url); got != 1 {
		t.Errorf("promfleet_spoke_tunnel_up = %v while a live tunnel is up, want 1", got)
	}
	cancel2()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop did not stop after cancellation")
	}
}

// TestDialLoopRedundantStreakReachesTheSearchLimitAndSlowsDown drives dialLoop
// through the SEARCHING regime -- coverage never completes, because this one
// physical hub process always answers with the same replica ID while claiming
// two exist -- for long enough that the CONSECUTIVE redundant streak must
// cross redundantSearchLimit for the pace to ever slow down (coverage staying
// incomplete forever means the OTHER half of [redundantCeiling]'s condition
// never fires). If the streak counter did not actually increment each
// attempt -- stuck at zero, or decremented into negative territory, where
// Go's integer range clause also runs zero iterations -- it would never reach
// the limit, and every cycle would stay at the fast pace forever.
//
// The two ceilings are separated by more than 10x so that ordinary dial
// handshake latency (a real, if fast, TLS-over-loopback connection) cannot be
// mistaken for the slow pace, and enough post-limit cycles are collected that
// every one of them drawing below the fast ceiling by chance -- despite a
// window many times wider -- is not a realistic outcome.
func TestDialLoopRedundantStreakReachesTheSearchLimitAndSlowsDown(t *testing.T) {
	t.Parallel()

	const (
		base = 5 * time.Millisecond
		// fastCeilingMax is the largest delay the fast pace could ever produce:
		// redundantSearchMultiple (8) times base, plus fullJitter's base/4 floor.
		fastCeilingMax = redundantSearchMultiple*base + base/4
		slow           = 500 * time.Millisecond
		// postLimitCycles is how many cycles to collect once the streak is past
		// the limit. Each independently has only a fastCeilingMax/slow (~9%)
		// chance of drawing below fastCeilingMax from the fully-saturated slow
		// window; the odds all of them do are negligible.
		postLimitCycles = 7
	)

	ca := newTestCA(t)
	// Two advertised replicas from one physical process: every connection
	// after the first lands on the same server ID, so coverage sticks at
	// covered=1, want=2 -- searching, never the probe -- for the whole test.
	hub := newHAHub(t, ca, 2)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: base,
		ReconnectMaxBackoff: time.Second,
	})
	s.timing.coverageProbe = slow
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	cov := newCoverage(true)

	// The first tunnel covers one of the two claimed replicas; every dial
	// after it, including dialLoop's own, lands on the same one.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go s.dialOnce(ctx1, hub.url, s.logger, cov)
	hub.awaitSession(t)
	eventually(t, "the first tunnel to be recorded", func() bool {
		covered, want := cov.state()
		return covered == 1 && want == 2
	})

	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx2, hub.url, cov, nil) }()

	// redundantSearchLimit consecutive fast cycles, plus enough more that the
	// pace can only have slowed down by then if the streak truly reached the
	// limit.
	const want = redundantSearchLimit + postLimitCycles
	eventually(t, "the streak to pass the search limit", func() bool {
		return countLogLines(logs, "redundant tunnel to an already-covered hub replica") >= want
	})

	// times[i+1]-times[i] is the delay chosen while redundant == i (the value
	// dialLoop read BEFORE incrementing past that cycle), so the earliest gap
	// that can reflect redundant >= redundantSearchLimit is the one landing
	// AFTER index redundantSearchLimit.
	times := logLineTimes(logs, "redundant tunnel to an already-covered hub replica")
	slowSeen := false
	for i := redundantSearchLimit + 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap > fastCeilingMax {
			slowSeen = true
			break
		}
	}
	if !slowSeen {
		t.Errorf("none of the %d cycles after the search limit paced slower than the fast ceiling %s; "+
			"the redundant streak never reached redundantSearchLimit (%d), so it is not actually incrementing",
			postLimitCycles, fastCeilingMax, redundantSearchLimit)
	}

	cancel2()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop did not stop after cancellation")
	}
}

// TestDialLoopRetiresSurplusDialers covers the shrink half of the pool
// contract: after a hub scale-down every historical dialer would otherwise
// live on as another probe, multiplying the steady-state handshake load by
// the old replica count until the pod restarts.
func TestDialLoopRetiresSurplusDialers(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 1)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: 10 * time.Millisecond,
		ReconnectMaxBackoff: 100 * time.Millisecond,
	})
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	cov := newCoverage(true)

	// The hub's one replica is already covered by another dialer.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go s.dialOnce(ctx1, hub.url, s.logger, cov)
	hub.awaitSession(t)
	eventually(t, "coverage to complete", func() bool {
		covered, want := cov.state()
		return covered == 1 && want == 1
	})

	// A pool inflated far beyond dialers() = want+1, as a scale-down leaves.
	var active atomic.Int64
	active.Store(5)
	done := make(chan struct{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { defer close(done); s.dialLoop(ctx2, hub.url, cov, &active) }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the surplus dialer never retired itself")
	}
	if !logs.has("retiring a surplus dialer") {
		t.Error("the retirement was not logged")
	}
}

// TestDialLoopDoesNotRetireAtExactlyDialersCount pins the other edge of the
// retirement boundary: a pool sized EXACTLY to what coverage wants is not a
// surplus, and must not retire. TestDialLoopRetiresSurplusDialers above only
// exercises a pool far past the boundary (5 against a want of 2); a
// "pool > dialers()" turned into "pool >= dialers()" would still pass that
// one, since 5 is greater than 2 either way, but would wrongly retire a
// correctly-sized pool here, where active.Load() == cov.dialers() exactly --
// collapsing every settled endpoint's probe dialer the moment it first comes
// back around.
func TestDialLoopDoesNotRetireAtExactlyDialersCount(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 1)
	clock := newStubClock()
	s, logs2 := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: 10 * time.Millisecond,
		ReconnectMaxBackoff: 100 * time.Millisecond,
	})
	logs := logs2.logCapture
	s.timing.coverageProbe = 30 * time.Millisecond
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	cov := newCoverage(true)

	// The hub's one replica is already covered by another dialer.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go s.dialOnce(ctx1, hub.url, s.logger, cov)
	hub.awaitSession(t)
	eventually(t, "coverage to complete", func() bool {
		covered, want := cov.state()
		return covered == 1 && want == 1
	})

	// A pool sized to exactly what one covered replica wants: dialers() = 1
	// replica + 1 probe = 2, and this loop itself is that second, so the pool
	// this loop sees itself as part of is exactly 2 -- not a surplus.
	var active atomic.Int64
	active.Store(int64(cov.dialers()))
	done := make(chan struct{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { defer close(done); s.dialLoop(ctx2, hub.url, cov, &active) }()

	// Several probe cycles: a boundary bug retires on the very first one.
	eventually(t, "at least two probe cycles", func() bool {
		return logs.count("redundant tunnel to an already-covered hub replica") >= 2
	})
	if logs.has("retiring a surplus dialer") {
		t.Error("a pool sized exactly to dialers() retired itself; it is not a surplus")
	}

	cancel2()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("dialLoop did not stop after cancellation")
	}
}
