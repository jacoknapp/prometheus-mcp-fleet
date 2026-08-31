// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// fakeSession is a tunnel.Session under the test's control. It is written here
// rather than borrowed from internal/tunnel/memtun so that the registry's
// contract is exercised against the interface alone: nothing in these tests can
// pass because of a behaviour only the in-process transport happens to have.
type fakeSession struct {
	ident tunnel.Identity
	gen   int64

	mu sync.Mutex
	// describeArgs records the knownFingerprint of every Describe, which is
	// what proves the registry passes the fingerprint it already holds.
	describeArgs []string
	// describeFn answers the nth Describe. Nil answers with facts.
	describeFn func(n int, known string) (tunnel.Facts, error)
	facts      tunnel.Facts
	// closeReasons records every Close, so a displaced session's reason is
	// assertable.
	closeReasons []string
	closeErr     error

	// describeCh is signalled after every Describe so a test can wait for a
	// poll instead of sleeping.
	describeCh chan struct{}

	doneOnce sync.Once
	done     chan struct{}
}

// newFakeSession returns a session for cluster id at the given generation whose
// Describe reports reachable Prometheus.
func newFakeSession(id string, gen int64) *fakeSession {
	return &fakeSession{
		ident: tunnel.Identity{
			ClusterID:    id,
			CertSerial:   "serial-" + id,
			CertNotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			RemoteAddr:   "10.0.0.1:4242",
		},
		gen: gen,
		facts: tunnel.Facts{
			Fingerprint: "fp-1",
			Changed:     true,
			Generation:  gen,
			Cluster: fleet.Cluster{
				ID:          id,
				DisplayName: id,
				Labels:      map[string]string{"env": "prod"},
				Prometheus:  fleet.PrometheusInfo{Reachable: true, Version: "3.0.0"},
			},
		},
		describeCh: make(chan struct{}, 128),
		done:       make(chan struct{}),
	}
}

func (f *fakeSession) Identity() tunnel.Identity { return f.ident }

func (f *fakeSession) Generation() int64 { return f.gen }

func (f *fakeSession) Do(context.Context, *tunnel.Request) (*tunnel.Response, error) {
	return nil, errors.New("fakeSession: Do is not used by the registry")
}

func (f *fakeSession) Describe(ctx context.Context, known string) (tunnel.Facts, error) {
	f.mu.Lock()
	n := len(f.describeArgs)
	f.describeArgs = append(f.describeArgs, known)
	fn := f.describeFn
	facts := f.facts
	f.mu.Unlock()

	defer func() {
		select {
		case f.describeCh <- struct{}{}:
		default:
		}
	}()

	if err := ctx.Err(); err != nil {
		return tunnel.Facts{}, err
	}
	if fn != nil {
		return fn(n, known)
	}
	return facts, nil
}

func (f *fakeSession) Close(reason string) error {
	f.mu.Lock()
	f.closeReasons = append(f.closeReasons, reason)
	err := f.closeErr
	f.mu.Unlock()
	f.doneOnce.Do(func() { close(f.done) })
	return err
}

func (f *fakeSession) Done() <-chan struct{} { return f.done }

// closes returns the reasons Close was called with.
func (f *fakeSession) closes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.closeReasons...)
}

// describes returns the knownFingerprint of every Describe so far.
func (f *fakeSession) describes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.describeArgs...)
}

// testClock is a manually advanced clock. internal/testutil has one, but the
// registry sits below it in the layering and importing upward from a test would
// hide a real dependency cycle from the architecture test.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingMetrics records every Metrics call. It is safe for concurrent use
// because the registry calls it from session goroutines.
type countingMetrics struct {
	mu               sync.Mutex
	connected        map[string]bool
	connectedCalls   int
	spokesConnected  []int
	certExpiry       map[string]time.Time
	identityMismatch map[string]int
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{
		connected:        map[string]bool{},
		certExpiry:       map[string]time.Time{},
		identityMismatch: map[string]int{},
	}
}

func (m *countingMetrics) SpokeConnected(id string, up bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected[id] = up
	m.connectedCalls++
}

func (m *countingMetrics) SpokesConnected(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spokesConnected = append(m.spokesConnected, n)
}

func (m *countingMetrics) SpokeCertExpiry(id string, notAfter time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certExpiry[id] = notAfter
}

func (m *countingMetrics) IdentityMismatch(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identityMismatch[id]++
}

func (m *countingMetrics) mismatches(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.identityMismatch[id]
}

func (m *countingMetrics) isConnected(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected[id]
}

func (m *countingMetrics) expiry(id string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.certExpiry[id]
	return v, ok
}

func (m *countingMetrics) lastSpokesConnected() (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.spokesConnected) == 0 {
		return 0, false
	}
	return m.spokesConnected[len(m.spokesConnected)-1], true
}

var _ Metrics = (*countingMetrics)(nil)
var _ tunnel.Session = (*fakeSession)(nil)

// mustNew builds a registry and fails the test if the options are rejected.
func mustNew(t *testing.T, opts Options) *Registry {
	t.Helper()
	r, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// recordingHandler is a minimal slog.Handler that keeps every record it
// receives, so a test can assert on log messages without a dependency.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// messages returns every record's message, in the order received.
func (h *recordingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.records))
	for i, r := range h.records {
		out[i] = r.Message
	}
	return out
}

// stringAttrs returns the string value of attr key from every record whose
// message equals msg, in the order received. It exists so a test can check a
// log line is attributed to the right entity, not merely that some line with
// that message exists.
func (h *recordingHandler) stringAttrs(msg, key string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Message != msg {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				out = append(out, a.Value.String())
			}
			return true
		})
	}
	return out
}

// attach admits s and returns its release function.
func attach(t *testing.T, r *Registry, s *fakeSession) func() {
	t.Helper()
	rel, err := r.OnSession(context.Background(), s)
	if err != nil {
		t.Fatalf("OnSession(%s): %v", s.ident.ClusterID, err)
	}
	return rel
}
