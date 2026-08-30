// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package memtun_test

import (
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
