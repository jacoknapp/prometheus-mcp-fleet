// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package tunneltest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Values every Factory must use, so the suite can assert on them.
const (
	// ClusterID is the certificate-derived cluster identity the session must
	// report from Identity().
	ClusterID = "conformance-cluster"
	// Generation is the spoke process start time the session must report from
	// Generation() once Describe has returned changed facts, and only then.
	Generation int64 = 1735689600000000000
	// Fingerprint is the facts fingerprint the handler reports.
	Fingerprint = "sha256:conformance"
)

// Factory produces a live session wired to h, plus a cleanup func the caller
// must invoke. Implementations must configure the session with [ClusterID] as
// the certificate-derived cluster identity and [Generation] as the spoke's
// process start time; the suite asserts on both.
//
// The returned session must already be usable: for a real transport that means
// the handshake has completed and the far end is serving h.
type Factory func(t *testing.T, h tunnel.Handler) (tunnel.Session, func())

// inFlightReporter is implemented by both transports so leak tests can assert
// that every response body was released. It is optional: a transport that does
// not implement it simply skips that assertion.
type inFlightReporter interface {
	InFlight() int
}

// RunConformance exercises every behaviour the tunnel contract promises. Both
// internal/tunnel/memtun and internal/tunnel/grpctun must pass it unchanged;
// that is what makes the in-process transport safe to test hub logic against.
func RunConformance(t *testing.T, newSession Factory) {
	t.Helper()

	// Goroutine accounting is only meaningful when nothing else is running, so
	// the leak test is deliberately not parallel: Go starts parallel subtests
	// only after every sequential one has finished.
	t.Run("early_body_close_does_not_leak", func(t *testing.T) {
		testNoLeakOnAbort(t, newSession)
	})

	t.Run("simple_request_response", func(t *testing.T) {
		t.Parallel()
		testSimpleRequestResponse(t, newSession)
	})
	t.Run("multi_chunk_body_is_byte_exact", func(t *testing.T) {
		t.Parallel()
		testMultiChunkBody(t, newSession)
	})
	t.Run("concurrent_streams_interleave", func(t *testing.T) {
		t.Parallel()
		testConcurrentStreams(t, newSession)
	})
	t.Run("cancellation_aborts_handler", func(t *testing.T) {
		t.Parallel()
		testCancellationAbortsHandler(t, newSession)
	})
	t.Run("deadline_propagates_to_handler", func(t *testing.T) {
		t.Parallel()
		testDeadlinePropagation(t, newSession)
	})
	t.Run("max_response_bytes_truncates", func(t *testing.T) {
		t.Parallel()
		testMaxResponseBytes(t, newSession)
	})
	t.Run("handler_error_in_trailer", func(t *testing.T) {
		t.Parallel()
		testTrailerError(t, newSession)
	})
	t.Run("handler_error_before_head", func(t *testing.T) {
		t.Parallel()
		testHandlerErrorBeforeHead(t, newSession)
	})
	t.Run("describe", func(t *testing.T) {
		t.Parallel()
		testDescribe(t, newSession)
	})
	t.Run("close_semantics", func(t *testing.T) {
		t.Parallel()
		testCloseSemantics(t, newSession)
	})
	t.Run("slow_reader_does_not_deadlock_writer", func(t *testing.T) {
		t.Parallel()
		testSlowReader(t, newSession)
	})
	t.Run("invalid_requests_are_rejected", func(t *testing.T) {
		t.Parallel()
		testInvalidRequests(t, newSession)
	})
}

func testSimpleRequestResponse(t *testing.T, newSession Factory) {
	t.Helper()
	want := []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`)
	h := &EchoHandler{
		StatusCode:      206,
		ContentType:     "application/json; charset=utf-8",
		ContentEncoding: "gzip",
		Body:            want,
		Warnings:        []string{"partial data"},
		UpstreamLatency: 42 * time.Millisecond,
	}
	s, cleanup := newSession(t, h)
	defer cleanup()

	if got := s.Identity().ClusterID; got != ClusterID {
		t.Errorf("Identity().ClusterID = %q, want %q", got, ClusterID)
	}

	req := &tunnel.Request{
		Method:           "POST",
		Path:             "/api/v1/query",
		Form:             []byte("query=up&time=1735689600"),
		MaxResponseBytes: 1 << 20,
		AcceptGzip:       true,
		RequestID:        "req-simple",
	}
	resp, err := s.Do(t.Context(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusPartialContent {
		t.Errorf("StatusCode = %d, want 206", resp.StatusCode)
	}
	if resp.ContentType != h.ContentType {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, h.ContentType)
	}
	if resp.ContentEncoding != "gzip" {
		t.Errorf("ContentEncoding = %q, want %q", resp.ContentEncoding, "gzip")
	}
	if resp.Body == nil || resp.Trailer == nil {
		t.Fatal("Response.Body and Response.Trailer must never be nil")
	}
	if got := resp.Trailer(); !trailerIsZero(got) {
		t.Errorf("Trailer() before the body was read = %+v, want the zero value", got)
	}

	got, err := drain(resp.Body)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("terminal read error = %v, want io.EOF", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body = %q, want %q", got, want)
	}

	tr := resp.Trailer()
	if tr.BytesTotal != int64(len(want)) {
		t.Errorf("Trailer().BytesTotal = %d, want %d", tr.BytesTotal, len(want))
	}
	if tr.Truncated {
		t.Error("Trailer().Truncated = true, want false")
	}
	if tr.Err != nil {
		t.Errorf("Trailer().Err = %v, want nil", tr.Err)
	}
	if len(tr.Warnings) != 1 || tr.Warnings[0] != "partial data" {
		t.Errorf("Trailer().Warnings = %v, want [partial data]", tr.Warnings)
	}
	if tr.UpstreamLatency <= 0 {
		t.Errorf("Trailer().UpstreamLatency = %v, want > 0", tr.UpstreamLatency)
	}

	calls := h.Calls()
	if len(calls) != 1 {
		t.Fatalf("handler saw %d calls, want 1", len(calls))
	}
	c := calls[0]
	if c.Method != req.Method || c.Path != req.Path || !bytes.Equal(c.Form, req.Form) {
		t.Errorf("handler saw %+v, want method %q path %q form %q", c, req.Method, req.Path, req.Form)
	}
	if c.RequestID != req.RequestID {
		t.Errorf("handler saw RequestID %q, want %q", c.RequestID, req.RequestID)
	}
	if c.MaxResponseBytes != req.MaxResponseBytes {
		t.Errorf("handler saw MaxResponseBytes %d, want %d", c.MaxResponseBytes, req.MaxResponseBytes)
	}
}

func testMultiChunkBody(t *testing.T, newSession Factory) {
	t.Helper()
	// Deliberately not a multiple of the 64 KiB wire chunk, so an off-by-one in
	// reassembly cannot cancel out.
	const size = 7*(64<<10) + 1234
	want := DeterministicBody(size)

	s, cleanup := newSession(t, &EchoHandler{BodySize: size})
	defer cleanup()

	resp, err := s.Do(t.Context(), &tunnel.Request{
		Method:           "GET",
		Path:             "/api/v1/query_range",
		MaxResponseBytes: 32 << 20,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	got, err := drain(resp.Body)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("terminal read error = %v, want io.EOF", err)
	}
	if len(got) != len(want) {
		t.Fatalf("body length = %d, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body differs from the source at offset %d", firstDiff(got, want))
	}
	tr := resp.Trailer()
	if tr.BytesTotal != size {
		t.Errorf("Trailer().BytesTotal = %d, want %d", tr.BytesTotal, size)
	}
	// The handler reported no UpstreamLatency of its own (its zero value), so
	// the trailer must carry the transport's own measured latency rather than
	// silently reporting zero.
	if tr.UpstreamLatency <= 0 {
		t.Errorf("Trailer().UpstreamLatency = %v, want the transport's own measured latency (> 0)", tr.UpstreamLatency)
	}
}

// testConcurrentStreams is the reason the transport is shaped the way it is: it
// proves a second request completes end to end while the first is still
// streaming on the same session.
func testConcurrentStreams(t *testing.T, newSession Factory) {
	t.Helper()
	const slowSize = 512 << 10
	slowBody := DeterministicBody(slowSize)
	fastBody := bytes.Repeat([]byte("fast."), 4096)

	gate := make(chan struct{})
	h := &EchoHandler{
		BodyFor: func(req *tunnel.Request) []byte {
			if req.Path == "/slow" {
				return slowBody
			}
			return fastBody
		},
		Gate: func(req *tunnel.Request) (int, <-chan struct{}) {
			if req.Path == "/slow" {
				return 4096, gate
			}
			return 0, nil
		},
	}
	s, cleanup := newSession(t, h)
	defer cleanup()
	ctx := t.Context()

	slow, err := s.Do(ctx, &tunnel.Request{Method: "GET", Path: "/slow", MaxResponseBytes: 32 << 20})
	if err != nil {
		t.Fatalf("Do(/slow): %v", err)
	}
	defer func() { _ = slow.Body.Close() }()

	type slowResult struct {
		body []byte
		err  error
	}
	slowDone := make(chan slowResult, 1)
	go func() {
		b, err := drain(slow.Body)
		slowDone <- slowResult{b, err}
	}()

	// Stream 1 is now parked mid-body inside the handler. Stream 2 must still
	// run to completion; if the transport serialised requests this would block
	// until the test timed out.
	fastDone := make(chan error, 1)
	go func() {
		fast, err := s.Do(ctx, &tunnel.Request{Method: "GET", Path: "/fast", MaxResponseBytes: 1 << 20})
		if err != nil {
			fastDone <- err
			return
		}
		defer func() { _ = fast.Body.Close() }()
		got, err := drain(fast.Body)
		if !errors.Is(err, io.EOF) {
			fastDone <- err
			return
		}
		if !bytes.Equal(got, fastBody) {
			fastDone <- errors.New("fast body mismatch")
			return
		}
		fastDone <- nil
	}()

	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("concurrent request on /fast: %v", err)
		}
	case res := <-slowDone:
		t.Fatalf("/slow finished before /fast: %v", res.err)
	case <-time.After(20 * time.Second):
		t.Fatal("/fast did not complete while /slow was still streaming: requests are not multiplexed")
	}

	close(gate)
	select {
	case res := <-slowDone:
		if !errors.Is(res.err, io.EOF) {
			t.Fatalf("/slow terminal read error = %v, want io.EOF", res.err)
		}
		if !bytes.Equal(res.body, slowBody) {
			t.Fatalf("/slow body differs at offset %d", firstDiff(res.body, slowBody))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("/slow did not finish after the gate opened")
	}
}

func testCancellationAbortsHandler(t *testing.T, newSession Factory) {
	t.Helper()
	never := make(chan struct{})
	h := &EchoHandler{
		BodySize: 1 << 20,
		Gate:     func(*tunnel.Request) (int, <-chan struct{}) { return 0, never },
	}
	s, cleanup := newSession(t, h)
	defer cleanup()

	ctx, cancel := context.WithCancel(t.Context())
	resp, err := s.Do(ctx, &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: 32 << 20})
	if err != nil {
		cancel()
		t.Fatalf("Do: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := drain(resp.Body)
		readErr <- err
	}()

	// Nothing can be read: the handler is parked before the first byte.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-readErr:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("read error after cancel = %v, want context.Canceled", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("body read did not unblock after the request context was cancelled")
	}
	select {
	case <-h.Aborted():
	case <-time.After(20 * time.Second):
		t.Fatal("the handler never observed ctx.Done(): cancellation did not reach the far end")
	}
	_ = resp.Body.Close()
}

func testDeadlinePropagation(t *testing.T, newSession Factory) {
	t.Helper()
	h := &EchoHandler{Body: []byte("ok")}
	s, cleanup := newSession(t, h)
	defer cleanup()

	const budget = 4 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()

	resp, err := s.Do(ctx, &tunnel.Request{Method: "GET", Path: "/api/v1/labels", MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = drain(resp.Body)
	_ = resp.Body.Close()

	calls := h.Calls()
	if len(calls) != 1 {
		t.Fatalf("handler saw %d calls, want 1", len(calls))
	}
	if !calls[0].HasDeadline {
		t.Fatal("the handler context had no deadline: the caller's deadline did not propagate")
	}
	remaining := time.Until(calls[0].Deadline)
	if remaining <= 0 || remaining > budget {
		t.Errorf("handler deadline is %v away, want it in (0, %v]", remaining, budget)
	}
}

func testMaxResponseBytes(t *testing.T, newSession Factory) {
	t.Helper()
	tests := []struct {
		name   string
		size   int
		budget int64
	}{
		{name: "just_over_budget", size: 4097, budget: 4096},
		{name: "many_chunks_over_budget", size: 1 << 20, budget: 100_000},
		{name: "sub_chunk_budget", size: 200_000, budget: 17},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			full := DeterministicBody(tc.size)
			s, cleanup := newSession(t, &EchoHandler{Body: full})
			defer cleanup()

			resp, err := s.Do(t.Context(), &tunnel.Request{
				Method:           "GET",
				Path:             "/api/v1/query_range",
				MaxResponseBytes: tc.budget,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			got, err := drain(resp.Body)
			if !errors.Is(err, tunnel.ErrResponseTooLarge) {
				t.Fatalf("terminal read error = %v, want tunnel.ErrResponseTooLarge", err)
			}
			if int64(len(got)) != tc.budget {
				t.Fatalf("delivered %d bytes, want exactly the budget of %d", len(got), tc.budget)
			}
			if !bytes.Equal(got, full[:tc.budget]) {
				t.Errorf("the delivered prefix differs from the source at offset %d", firstDiff(got, full[:tc.budget]))
			}
			tr := resp.Trailer()
			if !tr.Truncated {
				t.Error("Trailer().Truncated = false, want true")
			}
			if tr.BytesTotal != tc.budget {
				t.Errorf("Trailer().BytesTotal = %d, want %d", tr.BytesTotal, tc.budget)
			}
			// The error must stay latched, not vanish on the next read.
			if _, err := resp.Body.Read(make([]byte, 8)); !errors.Is(err, tunnel.ErrResponseTooLarge) {
				t.Errorf("second read after truncation = %v, want tunnel.ErrResponseTooLarge", err)
			}
		})
	}
}

func testTrailerError(t *testing.T, newSession Factory) {
	t.Helper()
	const msg = "prometheus: context deadline exceeded while querying"
	body := []byte("partial payload")
	s, cleanup := newSession(t, &EchoHandler{Body: body, TrailerErr: errors.New(msg)})
	defer cleanup()

	resp, err := s.Do(t.Context(), &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	got, err := drain(resp.Body)
	if !bytes.Equal(got, body) {
		t.Errorf("body = %q, want %q", got, body)
	}
	// An incomplete response must not be indistinguishable from a complete one.
	if errors.Is(err, io.EOF) {
		t.Fatalf("terminal read error = %v, want the upstream failure", err)
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("terminal read error = %v, want it to mention %q", err, msg)
	}
	tr := resp.Trailer()
	if tr.Err == nil {
		t.Fatal("Trailer().Err = nil, want the upstream failure")
	}
	if !strings.Contains(tr.Err.Error(), msg) {
		t.Errorf("Trailer().Err = %v, want it to mention %q", tr.Err, msg)
	}
}

func testHandlerErrorBeforeHead(t *testing.T, newSession Factory) {
	t.Helper()
	const msg = "prometheus is unreachable"
	s, cleanup := newSession(t, &EchoHandler{DoErr: errors.New(msg)})
	defer cleanup()

	resp, err := s.Do(t.Context(), &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: 1 << 20})
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("Do returned no error, want the handler's failure")
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("Do error = %v, want it to mention %q", err, msg)
	}
	if resp != nil {
		t.Error("Do returned both a response and an error")
	}
}

func testDescribe(t *testing.T, newSession Factory) {
	t.Helper()
	facts := fleet.Cluster{
		ID:              "advisory-id-the-hub-must-ignore",
		DisplayName:     "prod-us-east-1",
		Description:     "customer-facing API tier",
		Labels:          map[string]string{"env": "prod", "region": "us-east-1"},
		AgentVersion:    "0.1.0",
		ProtocolVersion: "v1",
		Kubernetes: fleet.KubernetesInfo{
			Available: true, Version: "v1.31.4", ClusterUID: "abc-123", NodeCount: 42,
		},
		Prometheus: fleet.PrometheusInfo{
			Reachable: true, Flavor: "prometheus", Version: "3.1.0",
			Retention: "15d", ScrapeInterval: "30s", LookbackDelta: "5m",
			ExternalLabels: map[string]string{"cluster": "prod"},
			ActiveSeries:   1_234_567, MetricNames: 8_910,
			Jobs: []string{"kubelet", "node-exporter"}, Namespaces: []string{"monitoring"},
			MetricPrefixes: []string{"container_", "node_"},
			RuleGroups:     12, AlertingRules: 34, FiringAlerts: 5, HasAlertmanager: true,
		},
	}
	h := &EchoHandler{Fingerprint: Fingerprint, Facts: facts}
	s, cleanup := newSession(t, h)
	defer cleanup()

	if got := s.Generation(); got != 0 {
		t.Errorf("Generation() before the first Describe = %d, want 0", got)
	}

	full, err := s.Describe(t.Context(), "")
	if err != nil {
		t.Fatalf("Describe(\"\"): %v", err)
	}
	if !full.Changed {
		t.Error("Describe with no fingerprint returned Changed=false, want true")
	}
	if full.Fingerprint != Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", full.Fingerprint, Fingerprint)
	}
	if full.Generation != Generation {
		t.Errorf("Facts.Generation = %d, want %d", full.Generation, Generation)
	}
	if got := s.Generation(); got != Generation {
		t.Errorf("Generation() after Describe = %d, want %d", got, Generation)
	}
	if diff := diffCluster(full.Cluster, facts); diff != "" {
		t.Errorf("facts round-trip: %s", diff)
	}

	unchanged, err := s.Describe(t.Context(), Fingerprint)
	if err != nil {
		t.Fatalf("Describe(matching): %v", err)
	}
	if unchanged.Changed {
		t.Error("Describe with a matching fingerprint returned Changed=true, want false")
	}
	if unchanged.Fingerprint != Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", unchanged.Fingerprint, Fingerprint)
	}
	if !isZeroCluster(unchanged.Cluster) {
		t.Errorf("an unchanged reply carried a payload: %+v", unchanged.Cluster)
	}
	if got := s.Generation(); got != Generation {
		t.Errorf("Generation() after an unchanged Describe = %d, want the retained %d", got, Generation)
	}

	stale, err := s.Describe(t.Context(), "sha256:something-else")
	if err != nil {
		t.Fatalf("Describe(stale): %v", err)
	}
	if !stale.Changed {
		t.Error("Describe with a stale fingerprint returned Changed=false, want true")
	}

	if got := h.DescribeCalls(); len(got) != 3 {
		t.Errorf("handler saw %d Describe calls, want 3", len(got))
	}
}

func testCloseSemantics(t *testing.T, newSession Factory) {
	t.Helper()
	s, cleanup := newSession(t, &EchoHandler{Body: []byte("ok")})
	defer cleanup()

	select {
	case <-s.Done():
		t.Fatal("Done() was closed on a live session")
	default:
	}

	if err := s.Close("conformance"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done() was not closed after Close")
	}
	// Close is idempotent.
	if err := s.Close("again"); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if _, err := s.Do(t.Context(), &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: 1 << 20}); !errors.Is(err, tunnel.ErrSessionClosed) {
		t.Errorf("Do after Close = %v, want tunnel.ErrSessionClosed", err)
	}
	if _, err := s.Describe(t.Context(), ""); !errors.Is(err, tunnel.ErrSessionClosed) {
		t.Errorf("Describe after Close = %v, want tunnel.ErrSessionClosed", err)
	}
}

// testSlowReader proves flow control works in the direction that matters: a hub
// that reads slowly must throttle the spoke, not deadlock it.
func testSlowReader(t *testing.T, newSession Factory) {
	t.Helper()
	const size = 1 << 20
	want := DeterministicBody(size)
	s, cleanup := newSession(t, &EchoHandler{Body: want})
	defer cleanup()

	resp, err := s.Do(t.Context(), &tunnel.Request{
		Method:           "GET",
		Path:             "/api/v1/query_range",
		MaxResponseBytes: 32 << 20,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	done := make(chan error, 1)
	var got bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for i := 0; ; i++ {
			if i%32 == 0 {
				time.Sleep(time.Millisecond)
			}
			n, err := resp.Body.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				done <- err
				return
			}
		}
	}()

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("terminal read error = %v, want io.EOF", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("a slow reader deadlocked the writer")
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("body differs at offset %d", firstDiff(got.Bytes(), want))
	}
}

func testInvalidRequests(t *testing.T, newSession Factory) {
	t.Helper()
	// Held, not discarded: the whole point below is to assert that none of these
	// requests reached it.
	echo := &EchoHandler{Body: []byte("ok")}
	s, cleanup := newSession(t, echo)
	defer cleanup()

	tests := []struct {
		name string
		req  *tunnel.Request
	}{
		{"unsupported_method", &tunnel.Request{Method: "DELETE", Path: "/api/v1/query", MaxResponseBytes: 1 << 20}},
		{"relative_path", &tunnel.Request{Method: "GET", Path: "api/v1/query", MaxResponseBytes: 1 << 20}},
		{"zero_budget", &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: 0}},
		{"negative_budget", &tunnel.Request{Method: "GET", Path: "/api/v1/query", MaxResponseBytes: -1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.Do(t.Context(), tc.req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("Do(%+v) succeeded, want a rejection", tc.req)
			}
		})
	}
	ident, ok := s.(interface{ Identity() tunnel.Identity })
	if !ok {
		t.Fatalf("session %T does not expose Identity()", s)
	}
	if ident.Identity().ClusterID == "" {
		t.Error("Identity().ClusterID is empty")
	}
	// A rejected request must be refused by the transport, not merely fail after
	// the spoke has already acted on it. Every case above is invalid on its
	// face -- a method the protocol does not allow, a relative path, a
	// nonsensical byte budget -- so the handler in the monitored cluster should
	// never see any of them.
	//
	// This used to call a helper that returned nil unconditionally, so the
	// assertion was `len(nil) != 0` and could not fail for any transport. The
	// property was never actually tested.
	if calls := echo.Calls(); len(calls) != 0 {
		t.Errorf("%d invalid request(s) reached the handler, want 0: %+v", len(calls), calls)
	}
}

// testNoLeakOnAbort aborts many requests mid-body and checks that neither the
// session's in-flight accounting nor the goroutine count drifts.
func testNoLeakOnAbort(t *testing.T, newSession Factory) {
	t.Helper()
	const (
		iterations = 40
		bodySize   = 2 << 20
	)
	s, cleanup := newSession(t, &EchoHandler{BodySize: bodySize})
	defer cleanup()
	ctx := t.Context()

	newReq := func() *tunnel.Request {
		return &tunnel.Request{Method: "GET", Path: "/api/v1/query_range", MaxResponseBytes: 32 << 20}
	}

	// One warm-up request so the baseline includes whatever the transport
	// allocates lazily on first use.
	warm, err := s.Do(ctx, newReq())
	if err != nil {
		t.Fatalf("warm-up Do: %v", err)
	}
	_, _ = io.CopyN(io.Discard, warm.Body, 1024)
	_ = warm.Body.Close()
	settle()
	base := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.Do(ctx, newReq())
			if err != nil {
				t.Errorf("Do: %v", err)
				return
			}
			if _, err := io.CopyN(io.Discard, resp.Body, 1024); err != nil {
				t.Errorf("read: %v", err)
			}
			// Abandon the rest. The transport must cancel the upstream stream.
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			// Closing twice must not panic or double-release.
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()

	if r, ok := s.(inFlightReporter); ok {
		deadline := time.Now().Add(10 * time.Second)
		for r.InFlight() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := r.InFlight(); n != 0 {
			t.Errorf("InFlight() = %d after every body was closed, want 0", n)
		}
	}

	// A leak would show up as roughly one goroutine per aborted request; the
	// tolerance only absorbs transport bookkeeping.
	const tolerance = 8
	deadline := time.Now().Add(15 * time.Second)
	var now int
	for {
		settle()
		now = runtime.NumGoroutine()
		if now <= base+tolerance || time.Now().After(deadline) {
			break
		}
	}
	if now > base+tolerance {
		t.Errorf("goroutines went from %d to %d across %d aborted requests", base, now, iterations)
	}
}

// drain reads r to completion and reports the terminal error, which io.ReadAll
// would have swallowed.
func drain(r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}

// firstDiff reports the first index at which a and b differ, or -1.
func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// trailerIsZero reports whether t carries no accounting at all.
func trailerIsZero(t tunnel.Trailer) bool {
	return t.BytesTotal == 0 && t.UpstreamLatency == 0 && !t.Truncated && len(t.Warnings) == 0 && t.Err == nil
}

// settle gives finished goroutines a chance to actually exit.
func settle() {
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
}

// diffCluster reports a human-readable difference between two cluster fact
// payloads, or the empty string when they match. It exists so the conformance
// suite does not depend on a particular diffing library.
func diffCluster(got, want fleet.Cluster) string {
	gotJSON, err := json.Marshal(got)
	if err != nil {
		return fmt.Sprintf("marshal got: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return fmt.Sprintf("marshal want: %v", err)
	}
	if bytes.Equal(gotJSON, wantJSON) {
		return ""
	}
	return fmt.Sprintf("\n got: %s\nwant: %s", gotJSON, wantJSON)
}

// isZeroCluster reports whether c carries no payload, which is what a Describe
// reply must contain when the caller's fingerprint was already current.
func isZeroCluster(c fleet.Cluster) bool {
	return c.ID == "" && c.DisplayName == "" && c.Description == "" &&
		len(c.Labels) == 0 && c.AgentVersion == "" && c.ProtocolVersion == "" &&
		c.Kubernetes == (fleet.KubernetesInfo{}) &&
		!c.Prometheus.Reachable && c.Prometheus.Version == "" &&
		len(c.Prometheus.Jobs) == 0
}
