// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"sync"
	"testing"
)

// TestCoverageJoin covers the duplicate decision: a duplicate is only asked to
// step aside while coverage is incomplete. Once every replica is covered, a
// redundant tunnel is harmless and closing it would just start another dial.
func TestCoverageJoin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup runs against a fresh coverage before the join under test.
		setup         func(c *coverage)
		serverID      string
		replicas      int
		wantDuplicate bool
		wantCovered   int
		wantWant      int
	}{
		{
			name:          "a new replica is never a duplicate",
			serverID:      "hub-0",
			replicas:      3,
			wantDuplicate: false,
			wantCovered:   1,
			wantWant:      3,
		},
		{
			name: "a second join of the same replica while coverage is incomplete steps aside",
			setup: func(c *coverage) {
				c.join("hub-0", 3)
			},
			serverID:      "hub-0",
			replicas:      3,
			wantDuplicate: true,
			wantCovered:   1,
			wantWant:      3,
		},
		{
			name: "a second join once coverage is complete is the probe, and steps aside",
			setup: func(c *coverage) {
				c.join("hub-0", 1)
			},
			serverID:      "hub-0",
			replicas:      1,
			wantDuplicate: true,
			wantCovered:   1,
			wantWant:      1,
		},
		{
			name: "a replica of zero leaves want unset",
			setup: func(c *coverage) {
				c.join("hub-0", 3)
			},
			serverID:      "hub-1",
			replicas:      0,
			wantDuplicate: false,
			wantCovered:   2,
			wantWant:      3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCoverage(true)
			if tc.setup != nil {
				tc.setup(c)
			}
			got := c.join(tc.serverID, tc.replicas)
			if got != tc.wantDuplicate {
				t.Errorf("join(%q, %d) duplicate = %v, want %v", tc.serverID, tc.replicas, got, tc.wantDuplicate)
			}
			covered, want := c.state()
			if covered != tc.wantCovered || want != tc.wantWant {
				t.Errorf("state() = (%d, %d), want (%d, %d)", covered, want, tc.wantCovered, tc.wantWant)
			}
		})
	}
}

// TestCoverageJoinCompleteDuplicateIsTheProbe: covering the last replica does
// not change WHETHER a duplicate steps aside -- it always does -- it changes
// the pacing dialLoop applies, which reads state(). This pins that state()
// reports completeness correctly at the moment of the duplicate join.
func TestCoverageJoinCompleteDuplicateIsTheProbe(t *testing.T) {
	t.Parallel()

	c := newCoverage(true)
	if dup := c.join("hub-0", 2); dup {
		t.Fatal("first join of hub-0 reported a duplicate")
	}
	if dup := c.join("hub-1", 2); dup {
		t.Fatal("first join of hub-1 (which completes coverage) reported a duplicate")
	}
	if covered, want := c.state(); covered != 2 || want != 2 {
		t.Fatalf("state() = (%d, %d), want (2, 2)", covered, want)
	}
	if dup := c.join("hub-0", 2); !dup {
		t.Error("the probe's redundant join was kept; it must step aside to come around again")
	}
	c.leave("hub-0")
	if covered, want := c.state(); covered != 2 || want != 2 {
		t.Fatalf("state() after the probe left = (%d, %d), want (2, 2): the probe must not dent coverage", covered, want)
	}
}

// TestCoverageLeave covers decrementing a doubled replica, removing one at
// zero, and the no-op on an id that was never joined.
func TestCoverageLeave(t *testing.T) {
	t.Parallel()

	t.Run("decrements a doubled count without removing the replica", func(t *testing.T) {
		t.Parallel()
		c := newCoverage(true)
		c.join("hub-0", 2)
		c.join("hub-0", 2) // two tunnels to the same replica, briefly.
		if covered, _ := c.state(); covered != 1 {
			t.Fatalf("state() covered = %d, want 1 with two live tunnels to one replica", covered)
		}

		c.leave("hub-0")
		if covered, _ := c.state(); covered != 1 {
			t.Fatalf("state() covered = %d after leaving one of two, want the replica still covered", covered)
		}

		c.leave("hub-0")
		if covered, _ := c.state(); covered != 0 {
			t.Fatalf("state() covered = %d after leaving the last tunnel, want 0", covered)
		}
	})

	t.Run("leave of an unknown id is safe", func(t *testing.T) {
		t.Parallel()
		c := newCoverage(true)
		c.leave("never-joined")
		if covered, want := c.state(); covered != 0 || want != 0 {
			t.Errorf("state() = (%d, %d), want (0, 0)", covered, want)
		}
	})
}

// TestCoverageWantOnlyUpdatesWhenReplicasIsPositive. Zero means "the hub
// could not tell us", and must not overwrite a want that a previous handshake
// already established.
func TestCoverageWantOnlyUpdatesWhenReplicasIsPositive(t *testing.T) {
	t.Parallel()

	c := newCoverage(true)
	c.join("hub-0", 3)
	if _, want := c.state(); want != 3 {
		t.Fatalf("want = %d after replicas=3, want 3", want)
	}
	c.join("hub-1", 0)
	if _, want := c.state(); want != 3 {
		t.Fatalf("want = %d after a replicas=0 join, want the previous 3 kept", want)
	}
}

// TestCoverageDialers covers the floor of one and the pass-through of want.
// TestCoverageClampsAdvertisedReplicas pins the ceiling on the one handshake
// field that sizes a goroutine pool: the count arrives before the hub has
// proven anything, so a hostile two-billion answer must produce at most
// maxAdvertisedReplicas dial loops, not an OOM.
func TestCoverageClampsAdvertisedReplicas(t *testing.T) {
	t.Parallel()
	c := newCoverage(true)
	c.join("hub-0", 2_000_000_000)
	if got := c.dialers(); got != maxAdvertisedReplicas+1 {
		t.Fatalf("dialers() = %d after a hostile replica count, want the clamp %d plus the probe", got, maxAdvertisedReplicas+1)
	}
	// The clamp is a ceiling, not a floor: a sane count passes through.
	c.join("hub-1", 3)
	if got := c.dialers(); got != 4 {
		t.Fatalf("dialers() = %d, want 3 replicas plus the probe", got)
	}
}

func TestCoverageDialers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		replicas int
		want     int
	}{
		// Zero is "unknown", and the probe must already exist then: the
		// established tunnel never handshakes again, so a spoke that dialed a
		// cold-cached hub would otherwise hold one tunnel forever with both
		// coverage alerts blind to it.
		{name: "an unknown count runs one dialer plus the probe", replicas: 0, want: 2},
		{name: "one replica plus the probe", replicas: 1, want: 2},
		{name: "several replicas plus the probe", replicas: 5, want: 6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCoverage(true)
			if tc.replicas > 0 {
				c.join("hub-0", tc.replicas)
			}
			if got := c.dialers(); got != tc.want {
				t.Errorf("dialers() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestCoverageConcurrentJoinLeaveState hammers join/leave/state from many
// goroutines under -race, so the mutex protecting the shared map is exercised
// rather than assumed.
func TestCoverageConcurrentJoinLeaveState(t *testing.T) {
	t.Parallel()

	c := newCoverage(true)
	const goroutines = 20
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			id := "hub-" + string(rune('a'+g%5))
			for range iterations {
				c.join(id, 5)
				_, _ = c.state()
				_ = c.dialers()
				c.leave(id)
			}
		}(g)
	}
	wg.Wait()
}

// TestCoverageExplicitEndpointsMode pins the second addressing mode: several
// configured endpoints mean the operator pinned each hostname to one replica,
// so the advertised count is ignored, each endpoint wants exactly one tunnel,
// and no probe runs -- a pinned hostname can never reach a new replica, so
// probing it is pure churn. Before this mode existed, an explicit-endpoints
// fleet on default values ran surplus dialers against every pinned hostname
// forever and paged a false TunnelFlapping for every cluster.
func TestCoverageExplicitEndpointsMode(t *testing.T) {
	t.Parallel()
	c := newCoverage(false)
	if got := c.dialers(); got != 1 {
		t.Fatalf("dialers() = %d before any hello, want 1", got)
	}
	// The hub advertises three replicas; a pinned endpoint must not care.
	if dup := c.join("hub-0", 3); dup {
		t.Fatal("the first join reported a duplicate")
	}
	if covered, want := c.state(); covered != 1 || want != 1 {
		t.Fatalf("state() = (%d, %d), want (1, 1): the advertised count leaked into explicit mode", covered, want)
	}
	if got := c.dialers(); got != 1 {
		t.Fatalf("dialers() = %d, want exactly 1: no probe in explicit mode", got)
	}
}
