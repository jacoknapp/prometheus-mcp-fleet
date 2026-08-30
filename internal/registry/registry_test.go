// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// waitFor polls cond until it holds or the test's patience runs out. It exists
// so the facts-poller assertions do not race the poller goroutine; sleeping a
// fixed interval instead would be either flaky or slow.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// entryCount reports the size of the internal map, which is what distinguishes
// "filtered from every read path" from "actually evicted".
func entryCount(r *Registry) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

func TestNewDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
		check   func(t *testing.T, r *Registry)
	}{
		{
			name: "zero value is usable",
			opts: Options{},
			check: func(t *testing.T, r *Registry) {
				if r.pollInterval != DefaultFactsPollInterval {
					t.Errorf("pollInterval = %s, want %s", r.pollInterval, DefaultFactsPollInterval)
				}
				if r.pollTimeout != DefaultFactsPollTimeout {
					t.Errorf("pollTimeout = %s, want %s", r.pollTimeout, DefaultFactsPollTimeout)
				}
				if r.grace != DefaultDisconnectGrace {
					t.Errorf("grace = %s, want %s", r.grace, DefaultDisconnectGrace)
				}
				if r.sweepInterval != time.Minute {
					t.Errorf("sweepInterval = %s, want 1m", r.sweepInterval)
				}
				if r.log == nil || r.metrics == nil || r.now == nil {
					t.Error("New left a nil logger, metrics or clock")
				}
			},
		},
		{
			name: "negative grace disables the window",
			opts: Options{DisconnectGrace: -1},
			check: func(t *testing.T, r *Registry) {
				if r.grace != 0 {
					t.Errorf("grace = %s, want 0", r.grace)
				}
				if r.sweepInterval != time.Second {
					t.Errorf("sweepInterval = %s, want 1s", r.sweepInterval)
				}
			},
		},
		{
			name: "explicit sweep interval is honoured",
			opts: Options{SweepInterval: 3 * time.Second},
			check: func(t *testing.T, r *Registry) {
				if r.sweepInterval != 3*time.Second {
					t.Errorf("sweepInterval = %s, want 3s", r.sweepInterval)
				}
			},
		},
		{name: "negative poll interval", opts: Options{FactsPollInterval: -1}, wantErr: true},
		{name: "negative poll timeout", opts: Options{FactsPollTimeout: -1}, wantErr: true},
		{name: "negative sweep interval", opts: Options{SweepInterval: -1}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := New(tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("New: want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tc.check(t, r)
		})
	}
}

// TestOnSessionDescribesBeforeDeciding pins the ordering the security model
// depends on: the registry identifies a spoke before it admits it, and a spoke
// that cannot be identified is refused rather than published with no facts.
func TestOnSessionDescribesBeforeDeciding(t *testing.T) {
	t.Parallel()

	t.Run("describe precedes admission", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{FactsPollInterval: time.Hour, Clock: clock.Now})
		s := newFakeSession("prod-eu", 100)

		var seenDuringDescribe int
		s.describeFn = func(n int, known string) (tunnel.Facts, error) {
			seenDuringDescribe = len(r.List())
			return s.facts, nil
		}

		attach(t, r, s)

		if seenDuringDescribe != 0 {
			t.Errorf("registry held %d clusters during Describe, want 0: the entry was published before identification",
				seenDuringDescribe)
		}
		if got := s.describes(); !cmp.Equal(got, []string{""}) {
			t.Errorf("Describe fingerprints = %v, want one call with an empty fingerprint", got)
		}
		if got := r.ConnectedCount(); got != 1 {
			t.Errorf("ConnectedCount = %d, want 1", got)
		}
	})

	t.Run("describe failure rejects the session", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		s := newFakeSession("prod-eu", 100)
		boom := errors.New("spoke exploded")
		s.describeFn = func(int, string) (tunnel.Facts, error) { return tunnel.Facts{}, boom }

		rel, err := r.OnSession(context.Background(), s)
		if !errors.Is(err, ErrRejectedSession) {
			t.Fatalf("OnSession error = %v, want ErrRejectedSession", err)
		}
		if !errors.Is(err, boom) {
			t.Errorf("OnSession error = %v, want it to wrap the Describe failure", err)
		}
		if rel != nil {
			t.Error("OnSession returned a release func for a rejected session")
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("List = %v, want empty: an unidentified spoke must not be admitted", got)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})

		if _, err := r.OnSession(context.Background(), nil); !errors.Is(err, ErrRejectedSession) {
			t.Errorf("OnSession(nil) error = %v, want ErrRejectedSession", err)
		}
		anon := newFakeSession("", 1)
		if _, err := r.OnSession(context.Background(), anon); !errors.Is(err, ErrRejectedSession) {
			t.Errorf("OnSession(no cert identity) error = %v, want ErrRejectedSession", err)
		}
		if got := len(anon.describes()); got != 0 {
			t.Errorf("Describe called %d times for a session with no identity, want 0", got)
		}
	})

	t.Run("generation falls back to the describe payload", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		s := newFakeSession("prod-eu", 0)
		s.facts.Generation = 777

		attach(t, r, s)

		r.mu.RLock()
		gen := r.entries["prod-eu"].generation
		r.mu.RUnlock()
		if gen != 777 {
			t.Errorf("generation = %d, want 777 from the Describe payload", gen)
		}
	})
}

func TestGenerationCAS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		incumbentGen  int64
		newcomerGen   int64
		wantAdmitted  bool
		wantLiveGen   int64
		wantOldClosed bool
	}{
		{
			name: "newer replaces older", incumbentGen: 100, newcomerGen: 200,
			wantAdmitted: true, wantLiveGen: 200, wantOldClosed: true,
		},
		{
			name: "equal generations replace", incumbentGen: 100, newcomerGen: 100,
			wantAdmitted: true, wantLiveGen: 100, wantOldClosed: true,
		},
		{
			name: "older loses", incumbentGen: 200, newcomerGen: 100,
			wantAdmitted: false, wantLiveGen: 200, wantOldClosed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			metrics := newCountingMetrics()
			r := mustNew(t, Options{FactsPollInterval: time.Hour, Metrics: metrics})

			old := newFakeSession("prod-eu", tc.incumbentGen)
			attach(t, r, old)
			newer := newFakeSession("prod-eu", tc.newcomerGen)

			_, err := r.OnSession(context.Background(), newer)
			if tc.wantAdmitted {
				if err != nil {
					t.Fatalf("OnSession: %v", err)
				}
			} else {
				if !errors.Is(err, ErrStaleGeneration) {
					t.Fatalf("OnSession error = %v, want ErrStaleGeneration", err)
				}
				if !errors.Is(err, ErrRejectedSession) {
					t.Errorf("ErrStaleGeneration does not wrap ErrRejectedSession: %v", err)
				}
			}

			r.mu.RLock()
			gen := r.entries["prod-eu"].generation
			r.mu.RUnlock()
			if gen != tc.wantLiveGen {
				t.Errorf("live generation = %d, want %d", gen, tc.wantLiveGen)
			}

			if tc.wantOldClosed {
				waitFor(t, "the displaced session to be closed", func() bool {
					return len(old.closes()) == 1
				})
				if got := old.closes(); !cmp.Equal(got, []string{ReplacedReason}) {
					t.Errorf("close reasons = %v, want [%s]", got, ReplacedReason)
				}
			} else if got := old.closes(); len(got) != 0 {
				t.Errorf("incumbent was closed %v; the loser of the race must be", got)
			}

			if got := r.ConnectedCount(); got != 1 {
				t.Errorf("ConnectedCount = %d, want exactly one live session", got)
			}
			if !metrics.isConnected("prod-eu") {
				t.Error("spoke_connected gauge is false while a session is live")
			}
		})
	}
}

// TestGenerationCASRace drives the reconnect race with real goroutines. The
// invariant is not "whoever wins" but "the newer generation is always the one
// left standing", regardless of which goroutine reaches the lock first.
func TestGenerationCASRace(t *testing.T) {
	t.Parallel()

	for i := range 50 {
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		older := newFakeSession("prod-eu", 100)
		newer := newFakeSession("prod-eu", 200)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for j, s := range []*fakeSession{older, newer} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[j] = r.OnSession(context.Background(), s)
			}()
		}
		close(start)
		wg.Wait()

		r.mu.RLock()
		e := r.entries["prod-eu"]
		gen := e.generation
		live := e.session
		r.mu.RUnlock()

		if gen != 200 {
			t.Fatalf("iteration %d: live generation = %d, want the newer 200", i, gen)
		}
		if live != tunnel.Session(newer) {
			t.Fatalf("iteration %d: live session is not the newer one", i)
		}
		if errs[1] != nil {
			t.Fatalf("iteration %d: the newer session was rejected: %v", i, errs[1])
		}
		// The older session either lost the CAS outright or was admitted first
		// and then displaced; exactly one of those two must have happened.
		lostCAS := errors.Is(errs[0], ErrStaleGeneration)
		if lostCAS {
			if got := older.closes(); len(got) != 0 {
				t.Fatalf("iteration %d: a rejected session was also closed: %v", i, got)
			}
			continue
		}
		if errs[0] != nil {
			t.Fatalf("iteration %d: unexpected error for the older session: %v", i, errs[0])
		}
		waitFor(t, "the displaced session to be closed", func() bool {
			return len(older.closes()) == 1
		})
		if got := older.closes(); !cmp.Equal(got, []string{ReplacedReason}) {
			t.Fatalf("iteration %d: close reasons = %v, want [%s]", i, got, ReplacedReason)
		}
	}
}

// TestCertificateIdentityWins is the registry's half of security invariant 9:
// nothing self-reported may override the certificate.
func TestCertificateIdentityWins(t *testing.T) {
	t.Parallel()

	t.Run("on admission", func(t *testing.T) {
		t.Parallel()
		metrics := newCountingMetrics()
		r := mustNew(t, Options{FactsPollInterval: time.Hour, Metrics: metrics})
		s := newFakeSession("prod-eu", 100)
		s.facts.Cluster.ID = "prod-us" // a spoke claiming somebody else's name

		attach(t, r, s)

		c, ok := r.Cluster("prod-eu")
		if !ok {
			t.Fatal("Cluster(prod-eu) not found; the certificate identity was not used as the key")
		}
		if c.ID != "prod-eu" {
			t.Errorf("Cluster.ID = %q, want the certificate's prod-eu", c.ID)
		}
		if _, ok := r.Cluster("prod-us"); ok {
			t.Error("the self-reported cluster id was admitted as an entry")
		}
		if got := metrics.mismatches("prod-eu"); got != 1 {
			t.Errorf("IdentityMismatch(prod-eu) = %d, want 1", got)
		}
		if got := metrics.mismatches("prod-us"); got != 0 {
			t.Errorf("IdentityMismatch(prod-us) = %d; the metric label must never carry the reported id", got)
		}
		if exp, ok := metrics.expiry("prod-eu"); !ok || !exp.Equal(s.ident.CertNotAfter) {
			t.Errorf("SpokeCertExpiry = %v/%v, want %v", exp, ok, s.ident.CertNotAfter)
		}
	})

	t.Run("on every facts refresh", func(t *testing.T) {
		t.Parallel()
		metrics := newCountingMetrics()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, Metrics: metrics})
		s := newFakeSession("prod-eu", 100)
		s.describeFn = func(n int, known string) (tunnel.Facts, error) {
			f := s.facts
			f.Fingerprint = fmt.Sprintf("fp-%d", n)
			f.Changed = true
			f.Cluster.ID = "prod-us"
			return f, nil
		}
		attach(t, r, s)
		t.Cleanup(func() { r.Close("test") })

		// A spoke that reports the right id once and a different one later is
		// exactly what the counter exists to surface, so it must keep counting.
		waitFor(t, "repeat identity mismatches", func() bool {
			return metrics.mismatches("prod-eu") >= 3
		})
		c, _ := r.Cluster("prod-eu")
		if c.ID != "prod-eu" {
			t.Errorf("Cluster.ID = %q after refresh, want prod-eu", c.ID)
		}
	})

	t.Run("a matching reported id is not a mismatch", func(t *testing.T) {
		t.Parallel()
		metrics := newCountingMetrics()
		r := mustNew(t, Options{FactsPollInterval: time.Hour, Metrics: metrics})
		attach(t, r, newFakeSession("prod-eu", 100))
		if got := metrics.mismatches("prod-eu"); got != 0 {
			t.Errorf("IdentityMismatch = %d, want 0", got)
		}
	})
}

func TestStateMachine(t *testing.T) {
	t.Parallel()

	t.Run("connected and degraded", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{FactsPollInterval: time.Hour, Clock: clock.Now})

		ok := newFakeSession("prod-eu", 100)
		bad := newFakeSession("prod-us", 100)
		bad.facts.Cluster.Prometheus = fleet.PrometheusInfo{
			Reachable:         false,
			UnreachableReason: "connection refused",
		}
		attach(t, r, ok)
		attach(t, r, bad)

		if c, _ := r.Cluster("prod-eu"); c.State != fleet.StateConnected {
			t.Errorf("state = %q, want connected", c.State)
		}
		c, _ := r.Cluster("prod-us")
		if c.State != fleet.StateDegraded {
			t.Errorf("state = %q, want degraded when the spoke cannot reach Prometheus", c.State)
		}
		if c.Prometheus.UnreachableReason != "connection refused" {
			t.Errorf("UnreachableReason = %q, want it preserved for the agent", c.Prometheus.UnreachableReason)
		}
		// A degraded cluster still holds a tunnel, so it is still routable.
		if _, err := r.Session("prod-us"); err != nil {
			t.Errorf("Session(degraded) = %v, want a live session", err)
		}
		if got := r.ConnectedCount(); got != 2 {
			t.Errorf("ConnectedCount = %d, want 2: degraded still holds a tunnel", got)
		}
	})

	t.Run("disconnected inside the grace window then absent", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		metrics := newCountingMetrics()
		r := mustNew(t, Options{
			FactsPollInterval: time.Hour,
			DisconnectGrace:   5 * time.Minute,
			Clock:             clock.Now,
			Metrics:           metrics,
		})
		s := newFakeSession("prod-eu", 100)
		release := attach(t, r, s)
		connectedAt := clock.Now()

		clock.Advance(30 * time.Second)
		release()
		release() // release is idempotent

		c, ok := r.Cluster("prod-eu")
		if !ok {
			t.Fatal("Cluster gone immediately after release; the grace window did not apply")
		}
		if c.State != fleet.StateDisconnected {
			t.Errorf("state = %q, want disconnected", c.State)
		}
		if want := connectedAt.Add(30 * time.Second); !c.LastSeen.Equal(want) {
			t.Errorf("LastSeen = %s, want %s", c.LastSeen, want)
		}
		if !c.ConnectedSince.IsZero() {
			t.Errorf("ConnectedSince = %s, want zero once the tunnel is gone", c.ConnectedSince)
		}
		if got := r.ConnectedCount(); got != 0 {
			t.Errorf("ConnectedCount = %d, want 0", got)
		}
		if metrics.isConnected("prod-eu") {
			t.Error("spoke_connected gauge is still true after release")
		}
		if n, _ := metrics.lastSpokesConnected(); n != 0 {
			t.Errorf("spokes_connected = %d, want 0", n)
		}

		// Inside the window a caller learns "not connected" but not "unknown":
		// the distinction is the whole point of keeping the entry.
		_, err := r.Session("prod-eu")
		if !errors.Is(err, tunnel.ErrNotConnected) {
			t.Errorf("Session error = %v, want tunnel.ErrNotConnected", err)
		}
		if errors.Is(err, ErrUnknownCluster) {
			t.Errorf("Session error = %v, must not report an in-grace cluster as unknown", err)
		}
		if got := r.List(); len(got) != 1 {
			t.Errorf("List = %v, want the disconnected cluster to still be listed", got)
		}

		// Exactly at the boundary the entry is still present.
		clock.Advance(5 * time.Minute)
		if _, ok := r.Cluster("prod-eu"); !ok {
			t.Error("entry evicted at exactly LastSeen+grace; the window is inclusive")
		}

		clock.Advance(time.Nanosecond)
		if _, ok := r.Cluster("prod-eu"); ok {
			t.Error("entry still present past the grace window")
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("List = %v, want empty past the grace window", got)
		}
		if got := r.Nearest("prod-eu", 5); len(got) != 0 {
			t.Errorf("Nearest = %v, want no suggestion for a forgotten cluster", got)
		}
		_, err = r.Session("prod-eu")
		if !errors.Is(err, ErrUnknownCluster) || !errors.Is(err, tunnel.ErrNotConnected) {
			t.Errorf("Session error = %v, want both ErrUnknownCluster and tunnel.ErrNotConnected", err)
		}

		// Read paths filter it, but only the sweep reclaims the memory.
		if got := entryCount(r); got != 1 {
			t.Errorf("entryCount = %d, want the expired entry still resident before a sweep", got)
		}
		if n := r.sweep(clock.Now()); n != 1 {
			t.Errorf("sweep = %d, want 1 eviction", n)
		}
		if got := entryCount(r); got != 0 {
			t.Errorf("entryCount = %d after sweep, want 0", got)
		}
	})

	t.Run("negative grace forgets immediately", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{
			FactsPollInterval: time.Hour,
			DisconnectGrace:   -1,
			Clock:             clock.Now,
		})
		release := attach(t, r, newFakeSession("prod-eu", 100))
		release()

		if _, ok := r.Cluster("prod-eu"); ok {
			t.Error("cluster retained after release with the grace window disabled")
		}
		if got := entryCount(r); got != 0 {
			t.Errorf("entryCount = %d, want 0", got)
		}
	})

	t.Run("reconnect inside the grace window re-derives everything", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{
			FactsPollInterval: time.Hour,
			DisconnectGrace:   time.Hour,
			Clock:             clock.Now,
		})
		first := newFakeSession("prod-eu", 100)
		first.facts.Cluster.DisplayName = "stale name"
		release := attach(t, r, first)
		clock.Advance(time.Minute)
		release()

		second := newFakeSession("prod-eu", 200)
		second.facts.Cluster.DisplayName = "fresh name"
		attach(t, r, second)

		c, _ := r.Cluster("prod-eu")
		if c.DisplayName != "fresh name" {
			t.Errorf("DisplayName = %q, want the fresh Describe to be authoritative", c.DisplayName)
		}
		if c.State != fleet.StateConnected {
			t.Errorf("state = %q, want connected", c.State)
		}
		if !c.ConnectedSince.Equal(clock.Now()) {
			t.Errorf("ConnectedSince = %s, want the reconnect time %s", c.ConnectedSince, clock.Now())
		}
	})

	t.Run("release after replacement does not evict the successor", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		old := newFakeSession("prod-eu", 100)
		releaseOld := attach(t, r, old)
		newer := newFakeSession("prod-eu", 200)
		attach(t, r, newer)

		releaseOld()

		if got := r.ConnectedCount(); got != 1 {
			t.Fatalf("ConnectedCount = %d, want 1: a slow release evicted its successor", got)
		}
		s, err := r.Session("prod-eu")
		if err != nil {
			t.Fatalf("Session: %v", err)
		}
		if s != tunnel.Session(newer) {
			t.Error("the successor session was replaced by a stale release")
		}
	})

	t.Run("unknown cluster", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		if _, ok := r.Cluster("nope"); ok {
			t.Error("Cluster reported a cluster that never connected")
		}
		_, err := r.Session("nope")
		if !errors.Is(err, ErrUnknownCluster) || !errors.Is(err, tunnel.ErrNotConnected) {
			t.Errorf("Session error = %v, want ErrUnknownCluster and tunnel.ErrNotConnected", err)
		}
	})
}

func TestVisible(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	r := mustNew(t, Options{FactsPollInterval: time.Hour, Clock: clock.Now})
	for id, labels := range map[string]map[string]string{
		"prod-eu":  {"env": "prod", "region": "eu"},
		"prod-us":  {"env": "prod", "region": "us"},
		"stage-eu": {"env": "stage", "region": "eu"},
	} {
		s := newFakeSession(id, 100)
		s.facts.Cluster.Labels = labels
		attach(t, r, s)
	}

	scoped := func(s *fleet.Scope) *fleet.Principal {
		return &fleet.Principal{KID: "k1", Class: fleet.ClassAgent, Role: fleet.RoleViewer, Scope: s}
	}

	tests := []struct {
		name string
		p    *fleet.Principal
		want []string
	}{
		{name: "nil principal sees nothing", p: nil},
		{name: "nil scope sees nothing", p: &fleet.Principal{KID: "k1"}},
		{name: "empty scope sees nothing", p: scoped(&fleet.Scope{})},
		{
			name: "wildcard allow",
			p:    scoped(&fleet.Scope{Clusters: fleet.ClusterScope{Allow: []string{"*"}}}),
			want: []string{"prod-eu", "prod-us", "stage-eu"},
		},
		{
			name: "explicit allow",
			p:    scoped(&fleet.Scope{Clusters: fleet.ClusterScope{Allow: []string{"prod-us", "absent"}}}),
			want: []string{"prod-us"},
		},
		{
			name: "label selector",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				MatchLabels: map[string]string{"env": "prod"},
			}}),
			want: []string{"prod-eu", "prod-us"},
		},
		{
			name: "label selectors are conjunctive",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				MatchLabels: map[string]string{"env": "prod", "region": "eu"},
			}}),
			want: []string{"prod-eu"},
		},
		{
			name: "deny beats wildcard allow",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				Allow: []string{"*"},
				Deny:  []string{"prod-us"},
			}}),
			want: []string{"prod-eu", "stage-eu"},
		},
		{
			name: "deny beats explicit allow",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				Allow: []string{"prod-eu", "prod-us"},
				Deny:  []string{"prod-eu"},
			}}),
			want: []string{"prod-us"},
		},
		{
			name: "deny beats a matching label selector",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				MatchLabels: map[string]string{"env": "prod"},
				Deny:        []string{"prod-eu", "prod-us"},
			}}),
		},
		{
			name: "allow and label selector must both hold",
			p: scoped(&fleet.Scope{Clusters: fleet.ClusterScope{
				Allow:       []string{"prod-eu", "stage-eu"},
				MatchLabels: map[string]string{"env": "prod"},
			}}),
			want: []string{"prod-eu"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ids(r.Visible(tc.p))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Visible (-want +got):\n%s", diff)
			}
		})
	}
}

// ids projects cluster IDs, returning nil for an empty result so that a
// cmp.Diff against a nil "want" reads naturally.
func ids(cs []fleet.Cluster) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func TestListIsSortedAndCopied(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	for _, id := range []string{"zulu", "alpha", "mike"} {
		attach(t, r, newFakeSession(id, 100))
	}

	got := r.List()
	if diff := cmp.Diff([]string{"alpha", "mike", "zulu"}, ids(got)); diff != "" {
		t.Errorf("List order (-want +got):\n%s", diff)
	}

	// Mutating what a caller was handed must not reach registry state.
	got[0].DisplayName = "tampered"
	got[0].Labels["env"] = "tampered"
	got[0].Labels["injected"] = "yes"

	fresh, _ := r.Cluster("alpha")
	if fresh.DisplayName == "tampered" {
		t.Error("Cluster.DisplayName was mutated through a returned copy")
	}
	if diff := cmp.Diff(map[string]string{"env": "prod"}, fresh.Labels); diff != "" {
		t.Errorf("Labels were mutated through a returned copy (-want +got):\n%s", diff)
	}
}

func TestCopyClusterDeepCopiesEverySliceAndMap(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	s := newFakeSession("prod-eu", 100)
	s.facts.Cluster.Prometheus = fleet.PrometheusInfo{
		Reachable:      true,
		ExternalLabels: map[string]string{"cluster": "prod-eu"},
		Jobs:           []string{"api", "node"},
		Namespaces:     []string{"monitoring"},
		MetricPrefixes: []string{"kube_"},
	}
	attach(t, r, s)

	c, _ := r.Cluster("prod-eu")
	c.Prometheus.ExternalLabels["cluster"] = "tampered"
	c.Prometheus.Jobs[0] = "tampered"
	c.Prometheus.Namespaces[0] = "tampered"
	c.Prometheus.MetricPrefixes[0] = "tampered"

	again, _ := r.Cluster("prod-eu")
	want := fleet.PrometheusInfo{
		Reachable:      true,
		ExternalLabels: map[string]string{"cluster": "prod-eu"},
		Jobs:           []string{"api", "node"},
		Namespaces:     []string{"monitoring"},
		MetricPrefixes: []string{"kube_"},
	}
	if diff := cmp.Diff(want, again.Prometheus); diff != "" {
		t.Errorf("registry state after mutating a copy (-want +got):\n%s", diff)
	}
}

func TestFactsPolling(t *testing.T) {
	t.Parallel()

	t.Run("unchanged fingerprint refreshes only LastSeen", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, Clock: clock.Now})
		t.Cleanup(func() { r.Close("test") })

		s := newFakeSession("prod-eu", 100)
		s.describeFn = func(n int, known string) (tunnel.Facts, error) {
			if n == 0 {
				return s.facts, nil
			}
			clock.Advance(time.Minute)
			return tunnel.Facts{Fingerprint: known, Changed: false}, nil
		}
		attach(t, r, s)
		before, _ := r.Cluster("prod-eu")

		waitFor(t, "LastSeen to advance", func() bool {
			c, _ := r.Cluster("prod-eu")
			return c.LastSeen.After(before.LastSeen)
		})

		after, _ := r.Cluster("prod-eu")
		want := before
		want.LastSeen = after.LastSeen
		if diff := cmp.Diff(want, after); diff != "" {
			t.Errorf("an unchanged fingerprint altered more than LastSeen (-want +got):\n%s", diff)
		}
		// Every poll must offer the fingerprint the registry already holds,
		// which is what lets an unchanged spoke answer with Changed=false.
		calls := s.describes()
		if len(calls) < 2 {
			t.Fatalf("Describe calls = %v, want at least two", calls)
		}
		if calls[0] != "" {
			t.Errorf("admission Describe fingerprint = %q, want empty", calls[0])
		}
		for _, got := range calls[1:] {
			if got != "fp-1" {
				t.Errorf("poll Describe fingerprint = %q, want fp-1", got)
			}
		}
	})

	t.Run("a changed fingerprint replaces the facts", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, Clock: clock.Now})
		t.Cleanup(func() { r.Close("test") })

		s := newFakeSession("prod-eu", 100)
		s.describeFn = func(n int, known string) (tunnel.Facts, error) {
			if n == 0 {
				return s.facts, nil
			}
			clock.Advance(time.Minute)
			return tunnel.Facts{
				Fingerprint: "fp-2",
				Changed:     true,
				Cluster: fleet.Cluster{
					ID:          "prod-eu",
					DisplayName: "renamed",
					Labels:      map[string]string{"env": "canary"},
					// The registry must recompute the state from the new facts.
					Prometheus: fleet.PrometheusInfo{
						Reachable:         false,
						UnreachableReason: "dial tcp: refused",
					},
					// A spoke cannot dictate these; the certificate and the
					// attach time own them.
					CertNotAfter:   time.Unix(1, 0).UTC(),
					ConnectedSince: time.Unix(2, 0).UTC(),
					LastSeen:       time.Unix(3, 0).UTC(),
				},
			}, nil
		}
		attach(t, r, s)
		admitted, _ := r.Cluster("prod-eu")

		waitFor(t, "the new facts to be applied", func() bool {
			c, _ := r.Cluster("prod-eu")
			return c.DisplayName == "renamed"
		})

		got, _ := r.Cluster("prod-eu")
		want := fleet.Cluster{
			ID:             "prod-eu",
			DisplayName:    "renamed",
			Labels:         map[string]string{"env": "canary"},
			State:          fleet.StateDegraded,
			LastSeen:       got.LastSeen,
			ConnectedSince: admitted.ConnectedSince,
			CertNotAfter:   s.ident.CertNotAfter,
			Prometheus: fleet.PrometheusInfo{
				Reachable:         false,
				UnreachableReason: "dial tcp: refused",
			},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("refreshed cluster (-want +got):\n%s", diff)
		}
		if !got.LastSeen.After(admitted.LastSeen) {
			t.Errorf("LastSeen = %s, want it to advance past %s", got.LastSeen, admitted.LastSeen)
		}
		waitFor(t, "the new fingerprint to be offered upstream", func() bool {
			calls := s.describes()
			return len(calls) > 0 && calls[len(calls)-1] == "fp-2"
		})
	})

	t.Run("a failed poll does not evict or alter the cluster", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, Clock: clock.Now})
		t.Cleanup(func() { r.Close("test") })

		s := newFakeSession("prod-eu", 100)
		var polls atomic.Int64
		s.describeFn = func(n int, known string) (tunnel.Facts, error) {
			if n == 0 {
				return s.facts, nil
			}
			polls.Add(1)
			clock.Advance(time.Minute)
			return tunnel.Facts{}, errors.New("spoke is wedged")
		}
		attach(t, r, s)
		before, _ := r.Cluster("prod-eu")

		waitFor(t, "several failed polls", func() bool { return polls.Load() >= 3 })

		got, ok := r.Cluster("prod-eu")
		if !ok {
			t.Fatal("a failing Describe evicted the cluster; liveness belongs to the keepalive")
		}
		if diff := cmp.Diff(before, got); diff != "" {
			t.Errorf("cluster changed after failed polls (-want +got):\n%s", diff)
		}
		if _, err := r.Session("prod-eu"); err != nil {
			t.Errorf("Session = %v, want the cluster to stay routable", err)
		}
	})

	t.Run("polling stops when the session ends", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond})
		s := newFakeSession("prod-eu", 100)
		attach(t, r, s)

		if err := s.Close("gone"); err != nil {
			t.Fatalf("Close: %v", err)
		}
		waitFor(t, "the poller to notice the closed session", func() bool {
			done := make(chan struct{})
			go func() { r.wg.Wait(); close(done) }()
			select {
			case <-done:
				return true
			case <-time.After(50 * time.Millisecond):
				return false
			}
		})
	})

	t.Run("facts for a replaced entry are discarded", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		old := newFakeSession("prod-eu", 100)
		attach(t, r, old)
		r.mu.RLock()
		stale := r.entries["prod-eu"]
		r.mu.RUnlock()

		attach(t, r, newFakeSession("prod-eu", 200))

		r.applyFacts("prod-eu", stale, tunnel.Facts{
			Fingerprint: "zombie",
			Changed:     true,
			Cluster:     fleet.Cluster{DisplayName: "resurrected"},
		})

		c, _ := r.Cluster("prod-eu")
		if c.DisplayName == "resurrected" {
			t.Error("a displaced session's facts were applied to its successor's entry")
		}
	})
}

func TestRunSweeps(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	r := mustNew(t, Options{
		FactsPollInterval: time.Hour,
		DisconnectGrace:   time.Minute,
		SweepInterval:     time.Millisecond,
		Clock:             clock.Now,
	})
	release := attach(t, r, newFakeSession("prod-eu", 100))
	release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	clock.Advance(2 * time.Minute)
	waitFor(t, "the sweeper to evict the expired entry", func() bool { return entryCount(r) == 0 })

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

func TestRunStopsOnClose(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{SweepInterval: time.Millisecond})
	done := make(chan struct{})
	go func() { defer close(done); r.Run(context.Background()) }()
	r.Close("shutdown")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after Close")
	}
}

func TestClose(t *testing.T) {
	t.Parallel()

	t.Run("closes every session and refuses new ones", func(t *testing.T) {
		t.Parallel()
		metrics := newCountingMetrics()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, Metrics: metrics})
		a := newFakeSession("prod-eu", 100)
		b := newFakeSession("prod-us", 100)
		b.closeErr = errors.New("already gone") // logged, never propagated
		attach(t, r, a)
		attach(t, r, b)

		r.Close("hub-shutdown")

		for _, s := range []*fakeSession{a, b} {
			if got := s.closes(); !cmp.Equal(got, []string{"hub-shutdown"}) {
				t.Errorf("%s close reasons = %v, want [hub-shutdown]", s.ident.ClusterID, got)
			}
		}
		if got := r.ConnectedCount(); got != 0 {
			t.Errorf("ConnectedCount = %d, want 0", got)
		}
		if got := r.List(); len(got) != 0 {
			t.Errorf("List = %v, want empty", got)
		}
		if n, _ := metrics.lastSpokesConnected(); n != 0 {
			t.Errorf("spokes_connected = %d, want 0", n)
		}
		if metrics.isConnected("prod-eu") || metrics.isConnected("prod-us") {
			t.Error("a spoke_connected gauge is still true after Close")
		}

		_, err := r.OnSession(context.Background(), newFakeSession("prod-eu", 300))
		if !errors.Is(err, ErrClosed) || !errors.Is(err, ErrRejectedSession) {
			t.Errorf("OnSession after Close = %v, want ErrClosed and ErrRejectedSession", err)
		}

		r.Close("again") // idempotent
		if got := len(a.closes()); got != 1 {
			t.Errorf("session closed %d times, want 1", got)
		}
	})

	t.Run("a session admitted concurrently with Close is rejected or closed", func(t *testing.T) {
		t.Parallel()
		for range 30 {
			r := mustNew(t, Options{FactsPollInterval: time.Hour})
			s := newFakeSession("prod-eu", 100)
			var wg sync.WaitGroup
			wg.Add(2)
			var attachErr error
			go func() { defer wg.Done(); _, attachErr = r.OnSession(context.Background(), s) }()
			go func() { defer wg.Done(); r.Close("hub-shutdown") }()
			wg.Wait()

			if attachErr == nil && len(s.closes()) == 0 && r.ConnectedCount() != 0 {
				t.Fatal("a session admitted during Close was left open and unregistered")
			}
			if got := r.ConnectedCount(); got != 0 {
				t.Fatalf("ConnectedCount = %d after Close, want 0", got)
			}
		}
	})
}

// TestConcurrentAccess hammers every read path while sessions attach and
// detach. Its job is to be run under -race; the assertions are secondary to
// that.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Millisecond, DisconnectGrace: time.Minute})
	t.Cleanup(func() { r.Close("test") })

	p := &fleet.Principal{
		KID:   "k1",
		Class: fleet.ClassAgent,
		Scope: &fleet.Scope{Clusters: fleet.ClusterScope{Allow: []string{"*"}, Deny: []string{"c3"}}},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("c%d", w)
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := newFakeSession(id, time.Now().UnixNano())
				rel, err := r.OnSession(context.Background(), s)
				if err != nil {
					continue
				}
				rel()
			}
		}()
	}

	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, c := range r.List() {
					// Writing through the copy must never be observable.
					c.Labels["scribble"] = "1"
					c.Prometheus.Jobs = append(c.Prometheus.Jobs, "scribble")
				}
				for _, c := range r.Visible(p) {
					if c.ID == "c3" {
						t.Errorf("Visible returned a denied cluster %q", c.ID)
						return
					}
				}
				_, _ = r.Session("c0")
				_, _ = r.Cluster("c1")
				_ = r.Nearest("c", 3)
				_ = r.ConnectedCount()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	for _, c := range r.List() {
		if _, ok := c.Labels["scribble"]; ok {
			t.Errorf("cluster %q: registry state was mutated through a returned copy", c.ID)
		}
		for _, j := range c.Prometheus.Jobs {
			if j == "scribble" {
				t.Errorf("cluster %q: Jobs was mutated through a returned copy", c.ID)
			}
		}
	}
}

// TestOnSessionClosedDuringDescribe covers the second closed check, the one
// taken under the write lock. The first check cannot be trusted on its own: a
// Describe takes real time, and a hub shutting down during it must not end up
// with a live session in an emptied registry.
func TestOnSessionClosedDuringDescribe(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	s := newFakeSession("prod-eu", 100)
	s.describeFn = func(int, string) (tunnel.Facts, error) {
		r.Close("hub-shutdown")
		return s.facts, nil
	}

	_, err := r.OnSession(context.Background(), s)
	if !errors.Is(err, ErrClosed) || !errors.Is(err, ErrRejectedSession) {
		t.Fatalf("OnSession error = %v, want ErrClosed and ErrRejectedSession", err)
	}
	if got := entryCount(r); got != 0 {
		t.Errorf("entryCount = %d, want 0", got)
	}
	if got := r.ConnectedCount(); got != 0 {
		t.Errorf("ConnectedCount = %d, want 0", got)
	}
}

// TestSweepKeepsPresentEntries makes sure the sweeper is a garbage collector
// and not a reaper: it must walk past everything that is still visible.
func TestSweepKeepsPresentEntries(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	r := mustNew(t, Options{
		FactsPollInterval: time.Hour,
		DisconnectGrace:   time.Minute,
		Clock:             clock.Now,
	})
	attach(t, r, newFakeSession("live", 100))
	releaseRecent := attach(t, r, newFakeSession("recent", 100))
	releaseOld := attach(t, r, newFakeSession("expired", 100))
	releaseOld()
	clock.Advance(90 * time.Second)
	releaseRecent()

	if n := r.sweep(clock.Now()); n != 1 {
		t.Fatalf("sweep = %d, want exactly the expired entry", n)
	}
	if diff := cmp.Diff([]string{"live", "recent"}, ids(r.List())); diff != "" {
		t.Errorf("List after sweep (-want +got):\n%s", diff)
	}
	if n := r.sweep(clock.Now()); n != 0 {
		t.Errorf("sweep = %d on a clean registry, want 0", n)
	}
}

// TestNopMetricsIsInert is the default Options.Metrics, so it has to be safe to
// call rather than merely present.
func TestNopMetricsIsInert(t *testing.T) {
	t.Parallel()

	var m Metrics = NopMetrics{}
	m.SpokeConnected("prod-eu", true)
	m.SpokesConnected(1)
	m.SpokeCertExpiry("prod-eu", time.Now())
	m.IdentityMismatch("prod-eu")

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	if _, ok := r.metrics.(NopMetrics); !ok {
		t.Errorf("default metrics = %T, want NopMetrics", r.metrics)
	}
}
