// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestPeerCounterCountsPodsNotAddresses pins the dual-stack behaviour.
//
// A headless Service publishes an A record AND an AAAA record per ready pod on
// a dual-stack cluster. Counting raw addresses reports twice the replica count,
// and because only the real number of distinct ServerIDs exist, every spoke
// would spawn surplus dialers hunting replicas that do not exist and never
// reach full coverage — presenting exactly like the Ingress-affinity fault the
// runbook describes, and so misdiagnosed as one.
func TestPeerCounterCountsPodsNotAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		addrs []string
		want  int
	}{{
		name:  "single stack IPv4",
		addrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		want:  3,
	}, {
		name: "dual stack counts each pod once",
		addrs: []string{
			"10.0.0.1", "fd00::1",
			"10.0.0.2", "fd00::2",
			"10.0.0.3", "fd00::3",
		},
		want: 3,
	}, {
		// IPv4 and IPv6 counts deliberately differ so that preferring the
		// wrong family is visible in the result: a stray AAAA record with no
		// A counterpart -- plausible during a rolling update -- must not
		// change which family the count is taken from. A build that kept the
		// IPv6 records instead (a CONDITIONALS_NEGATION mutant on the To4()
		// check) would report 3 here, not 2.
		name: "IPv4 is preferred even when IPv6 has more records",
		addrs: []string{
			"10.0.0.1", "10.0.0.2",
			"fd00::1", "fd00::2", "fd00::3",
		},
		want: 2,
	}, {
		// Nothing to prefer, so the full set is the pod count.
		name:  "IPv6 only",
		addrs: []string{"fd00::1", "fd00::2"},
		want:  2,
	}, {
		name:  "duplicate records collapse",
		addrs: []string{"10.0.0.1", "10.0.0.1"},
		want:  1,
	}, {
		name:  "no ready pods",
		addrs: []string{},
		want:  0,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newPeerCounter("pmf-hub-peers.default.svc", slog.New(slog.DiscardHandler), nil)
			p.resolve = func(context.Context, string) ([]string, error) {
				return tc.addrs, nil
			}
			// Resolve synchronously rather than through the cached, background
			// path, so the assertion is about counting and nothing else.
			p.refresh()

			if got := p.Count(); got != tc.want {
				t.Errorf("Count() = %d, want %d for %v", got, tc.want, tc.addrs)
			}
		})
	}
}

// TestPeerCounterKeepsLastCountOnResolveFailure guards the fail-static
// direction: dropping to zero on a momentary NXDOMAIN would tell every spoke to
// stop seeking full coverage, silently collapsing the fleet onto one replica.
func TestPeerCounterKeepsLastCountOnResolveFailure(t *testing.T) {
	t.Parallel()

	p := newPeerCounter("pmf-hub-peers.default.svc", slog.New(slog.DiscardHandler), nil)
	p.resolve = func(context.Context, string) ([]string, error) {
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}
	p.refresh()
	if got := p.Count(); got != 2 {
		t.Fatalf("Count() = %d, want 2 before the failure", got)
	}

	p.resolve = func(context.Context, string) ([]string, error) {
		return nil, context.DeadlineExceeded
	}
	p.fetched = p.now().Add(-time.Hour) // force the refresh path
	p.refresh()

	if got := p.Count(); got != 2 {
		t.Errorf("Count() = %d after a resolver failure, want the previous 2 retained", got)
	}
}
