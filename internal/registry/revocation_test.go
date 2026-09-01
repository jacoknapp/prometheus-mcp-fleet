// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// TestCloseRevoked covers the whole point of the method: a certificate that
// has been revoked must stop serving the connection it is already on, not
// merely the next one it would make.
func TestCloseRevoked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup attaches sessions and returns the serials to revoke.
		setup func(t *testing.T, r *Registry) []string
		want  []string
		// check runs after the call, with the sessions the setup kept.
		check func(t *testing.T, r *Registry)
	}{
		{
			name: "closes the live session the serial admitted",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSession("prod-eu", 100))
				return []string{"serial-prod-eu"}
			},
			want: []string{"prod-eu"},
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 0 {
					t.Errorf("poolSize = %d, want 0: the slot must leave the pool", got)
				}
				_, err := r.Session("prod-eu")
				if !errors.Is(err, tunnel.ErrNotConnected) {
					t.Errorf("Session error = %v, want ErrNotConnected", err)
				}
			},
		},
		{
			name: "revoking one pod's certificate leaves its siblings serving",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSessionInstance("prod-eu", 100, "pod-a"))
				attach(t, r, newFakeSessionInstance("prod-eu", 100, "pod-b"))
				return []string{"serial-prod-eu-pod-a"}
			},
			want: []string{"prod-eu"},
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 1 {
					t.Fatalf("poolSize = %d, want 1: only the revoked pod may go", got)
				}
				// The cluster is still connected, and still routable, because
				// a sibling holds an unrevoked certificate.
				c, ok := r.Cluster("prod-eu")
				if !ok || c.State != fleet.StateConnected {
					t.Errorf("cluster state = %q (present=%v), want connected", c.State, ok)
				}
				s, err := r.Session("prod-eu")
				if err != nil {
					t.Fatalf("Session: %v", err)
				}
				if got := s.Identity().CertSerial; got != "serial-prod-eu-pod-b" {
					t.Errorf("routed to %q, want the unrevoked sibling", got)
				}
			},
		},
		{
			name: "revoking several serials at once closes each of them",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSession("prod-eu", 100))
				attach(t, r, newFakeSession("prod-us", 100))
				attach(t, r, newFakeSession("staging", 100))
				return []string{"serial-prod-us", "serial-prod-eu"}
			},
			want: []string{"prod-eu", "prod-us"},
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "staging"); got != 1 {
					t.Errorf("staging poolSize = %d, want 1: it was not revoked", got)
				}
			},
		},
		{
			name: "a serial with no live session closes nothing",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSession("prod-eu", 100))
				return []string{"serial-of-a-spoke-that-went-home"}
			},
			want: nil,
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 1 {
					t.Errorf("poolSize = %d, want 1: an unrelated revocation must not disturb it", got)
				}
			},
		},
		{
			name: "no serials closes nothing",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSession("prod-eu", 100))
				return nil
			},
			want: nil,
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 1 {
					t.Errorf("poolSize = %d, want 1", got)
				}
			},
		},
		{
			name: "an empty serial never matches a session that has none",
			setup: func(t *testing.T, r *Registry) []string {
				s := newFakeSession("prod-eu", 100)
				s.ident.CertSerial = ""
				attach(t, r, s)
				return []string{""}
			},
			want: nil,
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 1 {
					t.Errorf("poolSize = %d, want 1: an anonymous session is not revocable by an empty serial", got)
				}
			},
		},
		{
			name: "a slot already released is not closed a second time",
			setup: func(t *testing.T, r *Registry) []string {
				rel := attach(t, r, newFakeSession("prod-eu", 100))
				rel()
				return []string{"serial-prod-eu"}
			},
			want: nil,
			check: func(t *testing.T, r *Registry) {
				if got := poolSize(r, "prod-eu"); got != 0 {
					t.Errorf("poolSize = %d, want 0", got)
				}
			},
		},
		{
			name: "a closed registry has nothing left to close",
			setup: func(t *testing.T, r *Registry) []string {
				attach(t, r, newFakeSession("prod-eu", 100))
				r.Close("shutdown")
				return []string{"serial-prod-eu"}
			},
			want: nil,
			check: func(t *testing.T, r *Registry) {
				if got := entryCount(r); got != 0 {
					t.Errorf("entryCount = %d, want 0", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := mustNew(t, Options{FactsPollInterval: time.Hour, DisconnectGrace: time.Minute})
			t.Cleanup(func() { r.Close("test") })

			serials := tt.setup(t, r)
			got := r.CloseRevoked(serials...)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CloseRevoked() closed clusters (-want +got):\n%s", diff)
			}
			tt.check(t, r)
		})
	}
}

// TestCloseRevokedTearsDownTheSession asserts the parts a cluster-ID return
// value cannot show: the reason the spoke is told, the metrics an operator
// watches, and the disconnected-but-remembered entry the grace window leaves
// behind.
func TestCloseRevokedTearsDownTheSession(t *testing.T) {
	t.Parallel()

	metrics := newCountingMetrics()
	logs := &recordingHandler{}
	clock := newTestClock()
	r := mustNew(t, Options{
		FactsPollInterval: time.Hour,
		DisconnectGrace:   time.Minute,
		Metrics:           metrics,
		Logger:            slog.New(logs),
		Clock:             clock.Now,
	})
	t.Cleanup(func() { r.Close("test") })

	s := newFakeSession("prod-eu", 100)
	attach(t, r, s)

	if got := r.CloseRevoked("serial-prod-eu"); !cmp.Equal(got, []string{"prod-eu"}) {
		t.Fatalf("CloseRevoked = %v, want [prod-eu]", got)
	}

	if diff := cmp.Diff([]string{RevokedReason}, s.closes()); diff != "" {
		t.Errorf("close reasons (-want +got):\n%s", diff)
	}
	select {
	case <-s.Done():
	default:
		t.Error("the session is still live after its certificate was revoked")
	}
	if metrics.isConnected("prod-eu") {
		t.Error("SpokeConnected still reports the revoked cluster as connected")
	}
	if got := metrics.sessions("prod-eu"); got != 0 {
		t.Errorf("SessionsPerCluster = %d, want 0", got)
	}
	if n, ok := metrics.lastSpokesConnected(); !ok || n != 0 {
		t.Errorf("SpokesConnected = %d (reported=%v), want 0", n, ok)
	}
	if got := r.ConnectedCount(); got != 0 {
		t.Errorf("ConnectedCount = %d, want 0", got)
	}

	// Inside the grace window the cluster is still described, as disconnected,
	// so an agent is told what happened rather than "no such cluster".
	c, ok := r.Cluster("prod-eu")
	if !ok || c.State != fleet.StateDisconnected {
		t.Fatalf("Cluster = %+v (present=%v), want a disconnected entry", c, ok)
	}
	if !c.LastSeen.Equal(clock.Now()) {
		t.Errorf("LastSeen = %s, want %s", c.LastSeen, clock.Now())
	}

	const msg = "registry: closing session for a revoked certificate"
	if diff := cmp.Diff([]string{"serial-prod-eu"}, logs.stringAttrs(msg, "cert_serial")); diff != "" {
		t.Errorf("audit log cert_serial (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"prod-eu"}, logs.stringAttrs(msg, "cluster")); diff != "" {
		t.Errorf("audit log cluster (-want +got):\n%s", diff)
	}
}

// TestCloseRevokedByPredicate covers the form a hub replica uses to act on a
// revocation that happened somewhere else.
func TestCloseRevokedByPredicate(t *testing.T) {
	t.Parallel()

	t.Run("a nil predicate closes nothing", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		t.Cleanup(func() { r.Close("test") })
		attach(t, r, newFakeSession("prod-eu", 100))

		if got := r.CloseRevokedBy(nil); got != nil {
			t.Errorf("CloseRevokedBy(nil) = %v, want nil", got)
		}
		if got := poolSize(r, "prod-eu"); got != 1 {
			t.Errorf("poolSize = %d, want 1", got)
		}
	})

	t.Run("the predicate is asked once per distinct serial", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		t.Cleanup(func() { r.Close("test") })

		// Two pods of one cluster sharing one certificate: a legitimate
		// deployment where the leaf is mounted from a single Secret.
		a := newFakeSessionInstance("prod-eu", 100, "pod-a")
		b := newFakeSessionInstance("prod-eu", 100, "pod-b")
		a.ident.CertSerial = "shared"
		b.ident.CertSerial = "shared"
		attach(t, r, a)
		attach(t, r, b)

		var mu sync.Mutex
		asked := map[string]int{}
		got := r.CloseRevokedBy(func(serial string) bool {
			mu.Lock()
			asked[serial]++
			mu.Unlock()
			return serial == "shared"
		})

		if diff := cmp.Diff([]string{"prod-eu", "prod-eu"}, got); diff != "" {
			t.Errorf("closed clusters (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(map[string]int{"shared": 1}, asked); diff != "" {
			t.Errorf("predicate calls (-want +got):\n%s", diff)
		}
		if got := poolSize(r, "prod-eu"); got != 0 {
			t.Errorf("poolSize = %d, want 0: both pods held the revoked certificate", got)
		}
	})

	t.Run("the predicate runs with no registry lock held", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		t.Cleanup(func() { r.Close("test") })
		attach(t, r, newFakeSession("prod-eu", 100))

		// A real predicate reaches the credential store, so holding a lock
		// across it would stall every MCP request behind a store round trip --
		// and, worse, deadlock anything the store calls back into.
		locked := false
		r.CloseRevokedBy(func(string) bool {
			if r.mu.TryLock() {
				locked = true
				r.mu.Unlock()
			}
			return false
		})
		if !locked {
			t.Error("the write lock was held while the revocation predicate ran")
		}
	})
}

// TestCloseRevokedRacesTheSlotItTargets is the concurrency contract: the slot
// identity is re-checked under the write lock, so a session that arrived after
// the predicate ran is never the one closed.
func TestCloseRevokedRacesTheSlotItTargets(t *testing.T) {
	t.Parallel()

	t.Run("a reconnect during the sweep keeps its slot", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		t.Cleanup(func() { r.Close("test") })

		old := newFakeSessionInstance("prod-eu", 100, "pod-a")
		attach(t, r, old)
		fresh := newFakeSessionInstance("prod-eu", 200, "pod-a")

		// The reconnect lands between the snapshot and the write lock, which
		// is the window the identity check exists for.
		got := r.CloseRevokedBy(func(string) bool {
			attach(t, r, fresh)
			return true
		})

		if got != nil {
			t.Errorf("closed clusters = %v, want nil: the target slot was already gone", got)
		}
		if got := fresh.closes(); len(got) != 0 {
			t.Errorf("the reconnected session was closed with %v; only the revoked one may go", got)
		}
		waitFor(t, "the displaced session to be closed", func() bool { return len(old.closes()) == 1 })
		if diff := cmp.Diff([]string{ReplacedReason}, old.closes()); diff != "" {
			t.Errorf("displaced close reasons (-want +got):\n%s", diff)
		}
		if got := poolSize(r, "prod-eu"); got != 1 {
			t.Errorf("poolSize = %d, want 1", got)
		}
	})

	t.Run("a request in flight does not hold the revocation up", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Hour})
		t.Cleanup(func() { r.Close("test") })

		release := make(chan struct{})
		entered := make(chan struct{})
		s := newFakeSession("prod-eu", 100)
		s.describeFn = func(n int, _ string) (tunnel.Facts, error) {
			if n == 0 { // the admission Describe, which must not block
				return s.facts, nil
			}
			close(entered)
			<-release
			return s.facts, nil
		}
		attach(t, r, s)

		live, err := r.Session("prod-eu")
		if err != nil {
			t.Fatalf("Session: %v", err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = live.Describe(context.Background(), "")
		}()
		<-entered

		if got := r.CloseRevoked("serial-prod-eu"); !cmp.Equal(got, []string{"prod-eu"}) {
			t.Fatalf("CloseRevoked = %v, want [prod-eu]: an in-flight request must not delay it", got)
		}
		close(release)
		<-done
	})

	t.Run("revocation, reconnects, releases and Close together", func(t *testing.T) {
		t.Parallel()
		r := mustNew(t, Options{FactsPollInterval: time.Millisecond, DisconnectGrace: time.Minute})

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
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					// Revoke everything, by both routes, as fast as possible.
					_ = r.CloseRevokedBy(func(string) bool { return true })
					_ = r.CloseRevoked("serial-c0", "serial-c1", "serial-c2", "serial-c3")
					_, _ = r.Session("c0")
					_ = r.List()
				}
			}()
		}

		time.Sleep(150 * time.Millisecond)
		// Close while the revokers are still running: it must neither deadlock
		// against them nor leave a facts poller behind.
		r.Close("shutdown")
		close(stop)
		wg.Wait()

		if got := entryCount(r); got != 0 {
			t.Errorf("entryCount = %d, want 0 after Close", got)
		}
		if got := r.CloseRevokedBy(func(string) bool { return true }); got != nil {
			t.Errorf("CloseRevokedBy after Close = %v, want nil", got)
		}
	})
}
