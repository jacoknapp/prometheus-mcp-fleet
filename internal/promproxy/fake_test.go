// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/registry"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// observedCall is what the fake spoke saw. Recording the deadline is the only
// way to prove the proxy propagates a bounded context rather than merely
// remembering to time itself out locally.
type observedCall struct {
	Method           string
	Path             string
	Form             string
	MaxResponseBytes int64
	AcceptGzip       bool
	RequestID        string
	Deadline         time.Time
	HasDeadline      bool
}

// fakeSession is a tunnel.Session under the test's control. It is written here
// rather than borrowed from internal/tunnel/memtun so that the proxy is
// exercised against the interface alone.
type fakeSession struct {
	ident tunnel.Identity
	gen   int64
	facts tunnel.Facts

	mu       sync.Mutex
	calls    []observedCall
	ctxErrs  []error
	inflight int
	maxSeen  int

	// doFn answers the nth Do. Nil answers 200 with an empty JSON object.
	doFn func(ctx context.Context, n int, req *tunnel.Request) (*tunnel.Response, error)

	// entered is signalled on every Do so a test can wait for a call to be in
	// flight instead of sleeping.
	entered chan struct{}

	doneOnce sync.Once
	done     chan struct{}
}

func newFakeSession(id string) *fakeSession {
	return &fakeSession{
		ident: tunnel.Identity{
			ClusterID:    id,
			CertSerial:   "serial-" + id,
			CertNotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			RemoteAddr:   "10.0.0.1:4242",
		},
		gen: 1,
		facts: tunnel.Facts{
			Fingerprint: "fp-1",
			Changed:     true,
			Generation:  1,
			Cluster: fleet.Cluster{
				ID:         id,
				Labels:     map[string]string{"env": "prod"},
				Prometheus: fleet.PrometheusInfo{Reachable: true},
			},
		},
		entered: make(chan struct{}, 256),
		done:    make(chan struct{}),
	}
}

func (f *fakeSession) Identity() tunnel.Identity { return f.ident }

func (f *fakeSession) Generation() int64 { return f.gen }

func (f *fakeSession) Describe(context.Context, string) (tunnel.Facts, error) {
	return f.facts, nil
}

func (f *fakeSession) Close(string) error { f.doneOnce.Do(func() { close(f.done) }); return nil }

func (f *fakeSession) Done() <-chan struct{} { return f.done }

func (f *fakeSession) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	deadline, hasDeadline := ctx.Deadline()
	f.mu.Lock()
	n := len(f.calls)
	f.calls = append(f.calls, observedCall{
		Method:           req.Method,
		Path:             req.Path,
		Form:             string(req.Form),
		MaxResponseBytes: req.MaxResponseBytes,
		AcceptGzip:       req.AcceptGzip,
		RequestID:        req.RequestID,
		Deadline:         deadline,
		HasDeadline:      hasDeadline,
	})
	f.inflight++
	f.maxSeen = max(f.maxSeen, f.inflight)
	fn := f.doFn
	f.mu.Unlock()

	select {
	case f.entered <- struct{}{}:
	default:
	}

	defer func() {
		f.mu.Lock()
		f.inflight--
		f.ctxErrs = append(f.ctxErrs, ctx.Err())
		f.mu.Unlock()
	}()

	if fn != nil {
		return fn(ctx, n, req)
	}
	return jsonResponse(200, []byte(`{"status":"success"}`)), nil
}

// observed returns every call the spoke saw.
func (f *fakeSession) observed() []observedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]observedCall(nil), f.calls...)
}

// lastCall returns the most recent observation.
func (f *fakeSession) lastCall(t *testing.T) observedCall {
	t.Helper()
	calls := f.observed()
	if len(calls) == 0 {
		t.Fatal("the spoke saw no calls")
	}
	return calls[len(calls)-1]
}

// peakConcurrency reports the most simultaneous Do calls observed.
func (f *fakeSession) peakConcurrency() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxSeen
}

// contextErrors reports ctx.Err() as each Do returned, which is how a test
// proves cancellation reached the remote cluster instead of being swallowed.
func (f *fakeSession) contextErrors() []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]error(nil), f.ctxErrs...)
}

// waitEntered blocks until one more Do has started.
func (f *fakeSession) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-f.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a call to reach the spoke")
	}
}

// jsonResponse is a plain 200 with an uncompressed body.
func jsonResponse(status int, body []byte) *tunnel.Response {
	return &tunnel.Response{
		StatusCode:  status,
		ContentType: "application/json",
		Body:        io.NopCloser(bytes.NewReader(body)),
	}
}

// gzipResponse compresses body so that a test can distinguish the cap on the
// wire bytes from the cap on the inflated bytes.
func gzipResponse(t *testing.T, status int, body []byte) *tunnel.Response {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return &tunnel.Response{
		StatusCode:      status,
		ContentType:     "application/json",
		ContentEncoding: "gzip",
		Body:            io.NopCloser(bytes.NewReader(buf.Bytes())),
	}
}

// trailerResponse attaches a trailer to a plain response.
func trailerResponse(status int, body []byte, tr tunnel.Trailer) *tunnel.Response {
	r := jsonResponse(status, body)
	r.Trailer = func() tunnel.Trailer { return tr }
	return r
}

// errReader fails partway through a body, which is the shape of a spoke that
// died mid-transfer.
type errReader struct {
	prefix []byte
	err    error
	off    int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.off < len(r.prefix) {
		n := copy(p, r.prefix[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

func (r *errReader) Close() error { return nil }

// countingMetrics records every Metrics call. It is safe for concurrent use
// because the proxy reports from every request goroutine.
type countingMetrics struct {
	mu       sync.Mutex
	requests []metricRequest
	inflight map[string]int
	peak     map[string]int
	bytes    []int64
	duration []time.Duration
}

type metricRequest struct {
	Cluster  string
	Endpoint promapi.Endpoint
	Code     string
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{inflight: map[string]int{}, peak: map[string]int{}}
}

func (m *countingMetrics) ProxyRequest(cluster string, e promapi.Endpoint, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, metricRequest{cluster, e, code})
}

func (m *countingMetrics) ProxyDuration(_ string, _ promapi.Endpoint, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.duration = append(m.duration, d)
}

func (m *countingMetrics) ProxyInflight(cluster string, delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inflight[cluster] += delta
	m.peak[cluster] = max(m.peak[cluster], m.inflight[cluster])
}

func (m *countingMetrics) ProxyResponseBytes(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes = append(m.bytes, n)
}

func (m *countingMetrics) codes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.requests))
	for i, r := range m.requests {
		out[i] = r.Code
	}
	return out
}

func (m *countingMetrics) lastCode(t *testing.T) string {
	t.Helper()
	codes := m.codes()
	if len(codes) == 0 {
		t.Fatal("no request metric was reported")
	}
	return codes[len(codes)-1]
}

func (m *countingMetrics) inflightGauge(cluster string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inflight[cluster]
}

func (m *countingMetrics) responseBytes() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int64(nil), m.bytes...)
}

var (
	_ Metrics        = (*countingMetrics)(nil)
	_ tunnel.Session = (*fakeSession)(nil)
)

// fixture is a proxy wired to a real registry holding real (fake) sessions.
// The registry is not stubbed out: the denial-does-not-confirm-existence
// property is a property of the two together.
type fixture struct {
	proxy    *Proxy
	reg      *registry.Registry
	metrics  *countingMetrics
	sessions map[string]*fakeSession
}

// newFixture builds a proxy over clusters named by id, each with a live fake
// session. opts.Registry is filled in.
func newFixture(t *testing.T, opts Options, clusterIDs ...string) *fixture {
	t.Helper()

	reg, err := registry.New(registry.Options{
		// The facts poller is irrelevant here and a short interval would only
		// add noise to the Describe counts.
		FactsPollInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	t.Cleanup(func() { reg.Close("test") })

	f := &fixture{reg: reg, sessions: map[string]*fakeSession{}}
	for _, id := range clusterIDs {
		s := newFakeSession(id)
		if _, err := reg.OnSession(context.Background(), s); err != nil {
			t.Fatalf("OnSession(%s): %v", id, err)
		}
		f.sessions[id] = s
	}

	if opts.Metrics == nil {
		f.metrics = newCountingMetrics()
		opts.Metrics = f.metrics
	}
	opts.Registry = reg
	p, err := New(opts)
	if err != nil {
		t.Fatalf("promproxy.New: %v", err)
	}
	f.proxy = p
	return f
}

// session returns the fake spoke for a cluster.
func (f *fixture) session(t *testing.T, id string) *fakeSession {
	t.Helper()
	s, ok := f.sessions[id]
	if !ok {
		t.Fatalf("no fake session for cluster %q", id)
	}
	return s
}

// budgetsAreClean asserts that neither semaphore leaked a permit. A leaked byte
// permit is invisible until the hub starts refusing unrelated callers hours
// later, so every error-path test ends here.
func (f *fixture) budgetsAreClean(t *testing.T, clusterID string) {
	t.Helper()
	if got, want := f.proxy.bytes.available(), f.proxy.bytes.capacity; got != want {
		t.Errorf("global byte budget = %d, want the full %d: a permit leaked", got, want)
	}
	if got := f.proxy.inflight.held(clusterID); got != 0 {
		t.Errorf("in-flight slots held for %s = %d, want 0: a slot leaked", clusterID, got)
	}
	if f.metrics != nil {
		if got := f.metrics.inflightGauge(clusterID); got != 0 {
			t.Errorf("in-flight gauge for %s = %d, want 0", clusterID, got)
		}
	}
}

// allowAll is a principal scoped to the whole fleet.
func allowAll() *fleet.Principal {
	return &fleet.Principal{
		KID:   "kid-all",
		Name:  "test",
		Class: fleet.ClassAgent,
		Role:  fleet.RoleViewer,
		Scope: &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"*"}},
			Tools:    fleet.ToolScope{Allow: []string{"*"}},
		},
	}
}

// withLimits returns a fleet-wide principal carrying the given limits.
func withLimits(l fleet.Limits) *fleet.Principal {
	p := allowAll()
	p.Scope.Limits = l
	return p
}

// queryCall is a valid instant query against one cluster.
func queryCall(clusterID string) Call {
	return Call{
		ClusterID: clusterID,
		Endpoint:  promapi.EndpointQuery,
		Form:      map[string][]string{"query": {"up"}},
		RequestID: "req-1",
	}
}

// errBoom is a generic upstream failure with no special meaning.
var errBoom = errors.New("spoke exploded")
