// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package memtun_test

import (
	"io"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/memtun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
)

// TestConformance runs the shared tunnel contract suite against the in-process
// transport. It is the baseline: anything memtun cannot do, no real transport
// will be expected to do either.
func TestConformance(t *testing.T) {
	t.Parallel()

	tunneltest.RunConformance(t, func(t *testing.T, h tunnel.Handler) (tunnel.Session, func()) {
		t.Helper()
		s := memtun.Pair(tunnel.Identity{ClusterID: tunneltest.ClusterID}, tunneltest.Generation, h)
		return s, func() { _ = s.Close("test cleanup") }
	})
}

// TestPartialTrailerReflectsBytesDeliveredBeforeEarlyClose proves that closing
// a response body before it is drained still yields a meaningful trailer: the
// documented contract is that BytesTotal reports what actually reached the
// caller, not the zero value a body that never finished would otherwise carry.
func TestPartialTrailerReflectsBytesDeliveredBeforeEarlyClose(t *testing.T) {
	t.Parallel()

	const delivered = 4096
	h := &tunneltest.EchoHandler{
		BodySize: 1 << 20,
		// The body stalls once `delivered` bytes have been produced, and only
		// resumes on context cancellation (Close cancels the handler, exactly
		// as an early Close does on the real transport).
		Gate: func(*tunnel.Request) (int, <-chan struct{}) { return delivered, nil },
	}
	s := memtun.Pair(tunnel.Identity{ClusterID: tunneltest.ClusterID}, tunneltest.Generation, h)
	defer func() { _ = s.Close("test cleanup") }()

	resp, err := s.Do(t.Context(), &tunnel.Request{Method: "GET", Path: "/api/v1/query_range", MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	buf := make([]byte, delivered)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	tr := resp.Trailer()
	if tr.BytesTotal != delivered {
		t.Errorf("Trailer().BytesTotal = %d, want %d", tr.BytesTotal, delivered)
	}
}
