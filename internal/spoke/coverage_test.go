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
			name: "a second join once coverage is complete is not a duplicate",
			setup: func(c *coverage) {
				c.join("hub-0", 1)
			},
			serverID:      "hub-0",
			replicas:      1,
			wantDuplicate: false,
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
			c := newCoverage()
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

// TestCoverageJoinBecomesCompleteMidStream: the "once every replica is
// covered" branch has to be evaluated against the coverage that exists at the
// moment of the join under test, not a snapshot taken earlier -- covering the
// last replica must itself flip the answer for the next duplicate.
func TestCoverageJoinBecomesCompleteMidStream(t *testing.T) {
	t.Parallel()

	c := newCoverage()
	if dup := c.join("hub-0", 2); dup {
		t.Fatal("first join of hub-0 reported a duplicate")
	}
	if dup := c.join("hub-1", 2); dup {
		t.Fatal("first join of hub-1 (which completes coverage) reported a duplicate")
	}
	if covered, want := c.state(); covered != 2 || want != 2 {
		t.Fatalf("state() = (%d, %d), want (2, 2)", covered, want)
	}
	if dup := c.join("hub-0", 2); dup {
		t.Error("a redundant join once coverage is complete was told to step aside")
	}
}

// TestCoverageLeave covers decrementing a doubled replica, removing one at
// zero, and the no-op on an id that was never joined.
func TestCoverageLeave(t *testing.T) {
	t.Parallel()

	t.Run("decrements a doubled count without removing the replica", func(t *testing.T) {
		t.Parallel()
		c := newCoverage()
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
		c := newCoverage()
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

	c := newCoverage()
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
func TestCoverageDialers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		replicas int
		want     int
	}{
		{name: "nothing advertised yet floors to one", replicas: 0, want: 1},
		{name: "one replica", replicas: 1, want: 1},
		{name: "several replicas", replicas: 5, want: 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCoverage()
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

	c := newCoverage()
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
