// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// principalAt builds an agent principal with a rate limit.
func principalAt(kid string, rps float64, burst int) *fleet.Principal {
	return &fleet.Principal{
		KID:   kid,
		Class: fleet.ClassAgent,
		Scope: &fleet.Scope{Limits: fleet.Limits{RateRPS: rps, RateBurst: burst}},
	}
}

// TestRateLimiterEnforcesTheScopesRate is the property that was advertised in
// fleet.Limits and in the security guide, and enforced nowhere: a key with a
// rate must actually be bounded by it.
func TestRateLimiterEnforcesTheScopesRate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	l := newRateLimiter(clock)
	p := principalAt("agent-1", 1, 3) // 1/s, burst 3

	for i := range 3 {
		if ok, _ := l.allow(p); !ok {
			t.Fatalf("call %d refused inside the burst", i+1)
		}
	}
	ok, retry := l.allow(p)
	if ok {
		t.Fatal("a fourth immediate call was allowed; the burst is not enforced")
	}
	if retry <= 0 || retry > time.Second {
		t.Errorf("retryAfter = %v, want a wait inside one second at 1 rps", retry)
	}

	// A second later exactly one token exists.
	now = now.Add(time.Second)
	if ok, _ := l.allow(p); !ok {
		t.Error("no token after a full second at 1 rps")
	}
	if ok, _ := l.allow(p); ok {
		t.Error("two tokens appeared after one second at 1 rps")
	}
}

// TestRateLimiterIsPerKey proves one key cannot spend another's allowance,
// which is the whole point of attaching the limit to a scope.
func TestRateLimiterIsPerKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(func() time.Time { return now })
	noisy, quiet := principalAt("noisy", 1, 1), principalAt("quiet", 1, 1)

	if ok, _ := l.allow(noisy); !ok {
		t.Fatal("the first call for the noisy key was refused")
	}
	if ok, _ := l.allow(noisy); ok {
		t.Fatal("the noisy key exceeded its own burst")
	}
	if ok, _ := l.allow(quiet); !ok {
		t.Error("the quiet key was refused because another key was noisy")
	}
}

// TestRateLimiterUnlimitedByDefault keeps every key minted before this existed
// working exactly as it did.
func TestRateLimiterUnlimitedByDefault(t *testing.T) {
	t.Parallel()

	l := newRateLimiter(time.Now)
	tests := []struct {
		name string
		p    *fleet.Principal
	}{
		{"no principal", nil},
		{"no rate configured", &fleet.Principal{KID: "agent-1"}},
		{"negative rate", principalAt("agent-2", -1, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for i := range 50 {
				if ok, _ := l.allow(tc.p); !ok {
					t.Fatalf("call %d refused for an unlimited principal", i+1)
				}
			}
		})
	}
}

// TestRateLimiterBurstFloor covers a rate set without a burst. Zero would admit
// nothing at all, which is a broken key rather than a limited one.
func TestRateLimiterBurstFloor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(func() time.Time { return now })
	p := principalAt("agent-1", 10, 0)

	if ok, _ := l.allow(p); !ok {
		t.Fatal("a rate with no burst admitted nothing; the key would be unusable")
	}
}

// TestRateLimiterEvictsIdleKeys stops a hub that has issued many keys over its
// life from keeping a bucket for every one of them forever.
func TestRateLimiterEvictsIdleKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(func() time.Time { return now })

	if ok, _ := l.allow(principalAt("retired", 1, 1)); !ok {
		t.Fatal("first call refused")
	}
	now = now.Add(bucketIdleEviction + time.Minute)
	// A new key arriving is what triggers the sweep.
	if ok, _ := l.allow(principalAt("fresh", 1, 1)); !ok {
		t.Fatal("the new key was refused")
	}

	l.mu.Lock()
	_, stillThere := l.buckets["retired"]
	l.mu.Unlock()
	if stillThere {
		t.Error("an idle bucket survived eviction; the map grows without bound")
	}
}

// TestToolCallRefusedByTheKeysRateLimit is the end-to-end half: the limiter is
// consulted in the tool path, the caller gets a usable error, and no upstream
// work is done.
//
// The scenario is a leaked key. Before this, a key's advertised rate was
// decorative, so a leaked credential could run flat out until the hub's global
// byte budget was exhausted and every other key started failing as busy.
func TestToolCallRefusedByTheKeysRateLimit(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	p := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"*"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
		// One call, then nothing until a token refills.
		Limits: fleet.Limits{RateRPS: 0.001, RateBurst: 1},
	})

	if err := callTool(t, h, ToolListClusters, p); err != nil {
		t.Fatalf("the first call inside the burst failed: %v", err)
	}
	upstreamAfterFirst := len(h.prom.calls)

	// The second is over the limit. It is a tool error, not a protocol error:
	// the caller is authenticated and in scope, it is simply going too fast.
	if err := callTool(t, h, ToolListClusters, p); err != nil {
		t.Fatalf("a rate-limited call returned a protocol error, want a tool error: %v", err)
	}
	if h.metrics.count(ToolListClusters, CodeRateLimited) != 1 {
		t.Error("the refusal was not counted as RATE_LIMITED")
	}
	if got := len(h.prom.calls); got != upstreamAfterFirst {
		t.Errorf("%d upstream calls after the limit was hit, want no new ones", got-upstreamAfterFirst)
	}
}

// TestToolCallUnlimitedKeyIsNotRateLimited keeps every key minted before rate
// limits existed working exactly as it did.
func TestToolCallUnlimitedKeyIsNotRateLimited(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	p := principal(&fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"*"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
	for i := range 5 {
		if err := callTool(t, h, ToolListClusters, p); err != nil {
			t.Fatalf("call %d failed for a key with no rate limit: %v", i+1, err)
		}
	}
	if h.metrics.count(ToolListClusters, CodeRateLimited) != 0 {
		t.Error("an unlimited key was rate limited")
	}
}
