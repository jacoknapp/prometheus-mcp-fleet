// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"sync/atomic"

	"github.com/google/go-cmp/cmp"
)

// fakeSessions is a [SessionCloser] under the test's control. It records what
// it was asked to close and answers with whatever the test staged, so the API's
// behaviour can be pinned without a tunnel, a registry or a spoke.
type fakeSessions struct {
	mu sync.Mutex
	// serials records the arguments of every CloseRevoked call.
	serials [][]string
	// predicates counts CloseRevokedBy calls.
	predicates int
	// revoked is the set CloseRevokedBy's predicate is tried against, standing
	// in for the live sessions a replica is holding.
	revoked map[string]string
	// closed is what CloseRevoked answers with.
	closed []string
	// onClose, when set, runs at the start of every call.
	onClose func()
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{revoked: map[string]string{}}
}

func (f *fakeSessions) CloseRevoked(serials ...string) []string {
	f.mu.Lock()
	f.serials = append(f.serials, append([]string(nil), serials...))
	hook, out := f.onClose, append([]string(nil), f.closed...)
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (f *fakeSessions) CloseRevokedBy(isRevoked func(string) bool) []string {
	f.mu.Lock()
	f.predicates++
	// Copy the live set so the predicate runs outside the lock, exactly as the
	// real registry promises.
	live := make(map[string]string, len(f.revoked))
	for serial, cluster := range f.revoked {
		live[serial] = cluster
	}
	hook := f.onClose
	f.mu.Unlock()
	if hook != nil {
		hook()
	}

	var out []string
	for serial, cluster := range live {
		if isRevoked(serial) {
			out = append(out, cluster)
			f.mu.Lock()
			delete(f.revoked, serial)
			f.mu.Unlock()
		}
	}
	return uniqueSorted(out)
}

// calls returns the serial lists CloseRevoked was asked for.
func (f *fakeSessions) calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.serials...)
}

// sweeps returns how many times CloseRevokedBy was called.
func (f *fakeSessions) sweeps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.predicates
}

// stage sets what the next CloseRevoked answers with.
func (f *fakeSessions) stage(clusters ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = clusters
}

// hold records a live session on the given serial for cluster.
func (f *fakeSessions) hold(serial, cluster string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[serial] = cluster
}

var _ SessionCloser = (*fakeSessions)(nil)

// TestRevokeCertClosesLiveSessions is the enforcement half of revocation:
// adding a serial to a list that is only read at handshake time leaves the
// connection it was revoking up, which is the case the admin route must not
// leave behind.
func TestRevokeCertClosesLiveSessions(t *testing.T) {
	t.Parallel()

	serial := hex.EncodeToString([]byte{0x0a, 0x1b, 0x2c})

	tests := []struct {
		name string
		// wire builds the harness. Nil means no session closer at all.
		wire func(t *testing.T) (*harness, *fakeSessions)
		// wantStatus is the response to the revoke call.
		wantStatus int
		// wantCalls is what the closer was asked to close.
		wantCalls [][]string
		// wantEvents is the expected count of EventSessionRevoked.
		wantEvents int
		// wantLog is a fragment the audit line must contain.
		wantLog string
	}{
		{
			name:       "a connected spoke is disconnected and recorded",
			wire:       wireSessions(func(f *fakeSessions) { f.stage("prod-eu") }),
			wantStatus: http.StatusNoContent,
			wantCalls:  [][]string{{serial}},
			wantEvents: 1,
			wantLog:    `"clusters":"prod-eu"`,
		},
		{
			name: "several pods of one cluster are counted as sessions, named once",
			wire: wireSessions(func(f *fakeSessions) {
				f.stage("prod-eu", "prod-eu", "prod-us")
			}),
			wantStatus: http.StatusNoContent,
			wantCalls:  [][]string{{serial}},
			wantEvents: 1,
			wantLog:    `"sessions":3,"clusters":"prod-eu,prod-us"`,
		},
		{
			name:       "revoking a certificate nothing is holding records no session event",
			wire:       wireSessions(func(*fakeSessions) {}),
			wantStatus: http.StatusNoContent,
			wantCalls:  [][]string{{serial}},
			wantEvents: 0,
		},
		{
			name: "a hub with no session registry still revokes",
			wire: func(t *testing.T) (*harness, *fakeSessions) {
				t.Helper()
				return newHarness(t, nil), nil
			},
			wantStatus: http.StatusNoContent,
			wantEvents: 0,
		},
		{
			name: "a revocation the store refused closes nothing",
			wire: func(t *testing.T) (*harness, *fakeSessions) {
				t.Helper()
				sessions := newFakeSessions()
				sessions.stage("prod-eu")
				h := newHarness(t, func(o *Options) { o.Sessions = sessions })
				h.store.inject(t, func(f *fakeStore) { f.errRevokeCert = errors.New("state secret unwritable") })
				return h, sessions
			},
			wantStatus: http.StatusInternalServerError,
			wantCalls:  nil,
			wantEvents: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, sessions := tt.wire(t)

			resp := h.adminDo(http.MethodPost, "/admin/v1/certs/"+serial+"/revoke",
				RevokeCertRequest{Reason: "key material leaked"})
			resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if sessions != nil {
				if diff := cmp.Diff(tt.wantCalls, sessions.calls()); diff != "" {
					t.Errorf("CloseRevoked calls (-want +got):\n%s", diff)
				}
			}
			if got := h.metrics.securityEvents(EventSessionRevoked); got != tt.wantEvents {
				t.Errorf("%s events = %d, want %d", EventSessionRevoked, got, tt.wantEvents)
			}
			if tt.wantLog != "" && !strings.Contains(h.logs.String(), tt.wantLog) {
				t.Errorf("audit log does not contain %s:\n%s", tt.wantLog, h.logs.String())
			}
			if tt.wantEvents > 0 {
				// The operator's own reason belongs in the hub's audit trail;
				// the spoke is told a fixed reason by the registry, so the
				// reason must not travel with the close request.
				if !strings.Contains(h.logs.String(), `"event":"`+EventCertRevoked+`"`) {
					t.Error("the certificate revocation itself was not recorded")
				}
			}
		})
	}
}

// wireSessions returns a harness builder with a staged session closer.
func wireSessions(stage func(*fakeSessions)) func(*testing.T) (*harness, *fakeSessions) {
	return func(t *testing.T) (*harness, *fakeSessions) {
		t.Helper()
		sessions := newFakeSessions()
		stage(sessions)
		return newHarness(t, func(o *Options) { o.Sessions = sessions }), sessions
	}
}

// TestNewRevocationEnforcer covers construction: the two required collaborators
// and the defaults.
func TestNewRevocationEnforcer(t *testing.T) {
	t.Parallel()

	sessions := newFakeSessions()
	always := func(string) bool { return true }

	tests := []struct {
		name    string
		opts    RevocationEnforcerOptions
		wantErr string
		check   func(t *testing.T, e *RevocationEnforcer)
	}{
		{
			name:    "sessions are required",
			opts:    RevocationEnforcerOptions{IsRevoked: always},
			wantErr: "Sessions is required",
		},
		{
			name:    "a revocation predicate is required",
			opts:    RevocationEnforcerOptions{Sessions: sessions},
			wantErr: "IsRevoked is required",
		},
		{
			name:    "a negative interval is a configuration mistake",
			opts:    RevocationEnforcerOptions{Sessions: sessions, IsRevoked: always, Interval: -time.Second},
			wantErr: "Interval is negative",
		},
		{
			name: "defaults are applied",
			opts: RevocationEnforcerOptions{Sessions: sessions, IsRevoked: always},
			check: func(t *testing.T, e *RevocationEnforcer) {
				if e.interval != DefaultRevocationInterval {
					t.Errorf("interval = %s, want %s", e.interval, DefaultRevocationInterval)
				}
				if e.log == nil || e.metrics == nil {
					t.Error("a nil logger or metrics survived construction")
				}
			},
		},
		{
			name: "an explicit interval is kept",
			opts: RevocationEnforcerOptions{Sessions: sessions, IsRevoked: always, Interval: time.Minute},
			check: func(t *testing.T, e *RevocationEnforcer) {
				if e.interval != time.Minute {
					t.Errorf("interval = %s, want 1m", e.interval)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, err := NewRevocationEnforcer(tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				if e != nil {
					t.Error("an enforcer was returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRevocationEnforcer: %v", err)
			}
			tt.check(t, e)
		})
	}
}

// TestRevocationEnforcerEnforce covers the pass itself: what it closes, and
// what it records when it does.
func TestRevocationEnforcerEnforce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// live are the serial -> cluster sessions this replica holds.
		live map[string]string
		// revoked is the shared revocation list.
		revoked []string
		want    []string
		// wantLog is a fragment the audit line must contain, or "" for no line.
		wantLog string
	}{
		{
			name:    "a revocation performed on another replica closes the session here",
			live:    map[string]string{"0a1b": "prod-eu"},
			revoked: []string{"0a1b"},
			want:    []string{"prod-eu"},
			wantLog: `"event":"session.revoked","actor":"system","actor_class":"","sessions":1,"clusters":"prod-eu"`,
		},
		{
			name:    "sibling pods on unrevoked certificates keep serving",
			live:    map[string]string{"0a1b": "prod-eu", "0c2d": "prod-eu-sibling"},
			revoked: []string{"0a1b"},
			want:    []string{"prod-eu"},
			wantLog: `"sessions":1`,
		},
		{
			name:    "nothing revoked records nothing",
			live:    map[string]string{"0a1b": "prod-eu"},
			revoked: nil,
			want:    nil,
		},
		{
			name:    "a revoked certificate nobody is holding records nothing",
			live:    nil,
			revoked: []string{"0a1b"},
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := newFakeSessions()
			for serial, cluster := range tt.live {
				sessions.hold(serial, cluster)
			}
			logs := &syncBuffer{}
			metrics := newFakeMetrics()
			e, err := NewRevocationEnforcer(RevocationEnforcerOptions{
				Sessions:  sessions,
				IsRevoked: func(s string) bool { return slicesContains(tt.revoked, s) },
				Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
				Metrics:   metrics,
			})
			if err != nil {
				t.Fatalf("NewRevocationEnforcer: %v", err)
			}

			got := e.Enforce(t.Context())
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Enforce() (-want +got):\n%s", diff)
			}

			wantEvents := 0
			if tt.wantLog != "" {
				wantEvents = 1
			}
			if got := metrics.securityEvents(EventSessionRevoked); got != wantEvents {
				t.Errorf("%s events = %d, want %d", EventSessionRevoked, got, wantEvents)
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("audit log does not contain %s:\n%s", tt.wantLog, logs.String())
			}
			if tt.wantLog == "" && logs.String() != "" {
				t.Errorf("a pass that closed nothing logged: %s", logs.String())
			}

			// A second pass has nothing left to do: the sessions are gone.
			if got := e.Enforce(t.Context()); got != nil {
				t.Errorf("second Enforce() = %v, want nil", got)
			}
		})
	}
}

// TestRevocationEnforcerRun proves the loop actually runs and actually stops:
// a replica that never polls never learns about a revocation performed
// elsewhere, and one that never stops holds the process open at shutdown.
func TestRevocationEnforcerRun(t *testing.T) {
	t.Parallel()

	sessions := newFakeSessions()
	sessions.hold("0a1b", "prod-eu")
	metrics := newFakeMetrics()
	var refreshes atomic.Int64
	e, err := NewRevocationEnforcer(RevocationEnforcerOptions{
		Sessions:  sessions,
		IsRevoked: func(s string) bool { return s == "0a1b" },
		// The refresh runs at the top of every sweep, so an idle replica's
		// revocation list -- and the staleness gauge watching it -- stays
		// current with no handshake ever consulting the predicate.
		Refresh:  func(context.Context) { refreshes.Add(1) },
		Interval: time.Millisecond,
		Metrics:  metrics,
	})
	if err != nil {
		t.Fatalf("NewRevocationEnforcer: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()

	waitUntil(t, "the revoked session to be closed", func() bool {
		return metrics.securityEvents(EventSessionRevoked) == 1
	})
	waitUntil(t, "a second pass with nothing to do", func() bool {
		return sessions.sweeps() > 1
	})
	if refreshes.Load() < 2 {
		t.Errorf("refreshes = %d, want one per sweep", refreshes.Load())
	}
	if got := metrics.securityEvents(EventSessionRevoked); got != 1 {
		t.Errorf("%s events = %d, want exactly 1: an empty pass must not record one",
			EventSessionRevoked, got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// TestUniqueSorted covers the audit line's cluster set directly, including the
// empty case the callers never reach.
func TestUniqueSorted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", in: nil, want: nil},
		{name: "sorted and deduplicated", in: []string{"b", "a", "b"}, want: []string{"a", "b"}},
		{name: "already unique", in: []string{"a"}, want: []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := append([]string(nil), tt.in...)
			if diff := cmp.Diff(tt.want, uniqueSorted(in)); diff != "" {
				t.Errorf("uniqueSorted() (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.in, in); diff != "" {
				t.Errorf("the caller's slice was reordered (-want +got):\n%s", diff)
			}
		})
	}
}

// waitUntil polls cond until it holds or the test's patience runs out.
func waitUntil(t *testing.T, what string, cond func() bool) {
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

// slicesContains reports whether v is in s. It is spelled out rather than
// imported so this file's assertions do not depend on the same helper the code
// under test uses.
func slicesContains(s []string, v string) bool {
	for _, got := range s {
		if got == v {
			return true
		}
	}
	return false
}
