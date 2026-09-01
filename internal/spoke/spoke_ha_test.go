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

	srv, err := wstun.NewServer(wstun.ServerConfig{
		Verify:   ca.verify,
		Logger:   quiet(),
		ServerID: "hub-test-0",
		Replicas: func() int { return replicas },
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

	cov := newCoverage()

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
