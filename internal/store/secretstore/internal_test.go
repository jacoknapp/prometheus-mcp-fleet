// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
)

func TestSleepCtxStopsOnCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx = %v, want context.Canceled", err)
	}
}

func TestBackoffCapsOverflowingShift(t *testing.T) {
	t.Parallel()
	s := &Store{backoff: time.Second, jitter: func() float64 { return 0.5 }}
	if got := s.backoffFor(63); got != maxBackoff/2 {
		t.Errorf("backoffFor(63) = %s, want capped jitter %s", got, maxBackoff/2)
	}
}

// TestBackoffDoesNotCapBelowMax proves the cap in backoffFor is not applied
// when the shifted delay is comfortably under maxBackoff. A mutant that
// negates the "d > maxBackoff" comparison turns it into "d <= maxBackoff",
// which -- since it is ORed with "d <= 0" -- collapses to "always cap when
// d <= maxBackoff", forcing every small, uncapped delay up to maxBackoff.
func TestBackoffDoesNotCapBelowMax(t *testing.T) {
	t.Parallel()
	s := &Store{backoff: 20 * time.Millisecond, jitter: func() float64 { return 1 }}
	const want = 20 * time.Millisecond
	if got := s.backoffFor(0); got != want {
		t.Errorf("backoffFor(0) = %s, want %s: a delay under maxBackoff must not be capped", got, want)
	}
}

// TestBackoffCapBoundaryIsEquivalent documents why "d > maxBackoff" in
// backoffFor cannot be killed by widening it to "d >= maxBackoff" (a
// CONDITIONALS_BOUNDARY mutant): whichever comparison trips, the branch does
// the same thing -- assign d = maxBackoff. At d == maxBackoff exactly, the
// unmutated branch is not taken but d is already maxBackoff, and the mutated
// branch is taken and assigns the same value. No input makes the two
// versions of backoffFor return different durations, so this boundary is a
// genuinely equivalent mutant. This test pins the boundary value itself so a
// future change to the cap logic (e.g. min() instead of an if) is still
// checked at exactly this point.
func TestBackoffCapBoundaryIsEquivalent(t *testing.T) {
	t.Parallel()
	s := &Store{backoff: maxBackoff, jitter: func() float64 { return 1 }}
	if got := s.backoffFor(0); got != maxBackoff {
		t.Errorf("backoffFor(0) at d == maxBackoff = %s, want %s", got, maxBackoff)
	}
}

// TestCachedSecretZeroTTLDisablesCache proves "s.ttl <= 0" in cachedSecret
// disables the cache for a zero ttl even when the elapsed time since caching
// is negative (a clock that has not yet reached cachedAt). A
// CONDITIONALS_BOUNDARY mutant narrowing this to "s.ttl < 0" would fall
// through to the elapsed check, which -- for a negative elapsed duration --
// evaluates false, wrongly serving the stale cache.
//
// Open() itself never constructs a Store with ttl == 0 (CacheTTL == 0 is
// replaced by DefaultCacheTTL before the field is set), so this constructs
// the Store directly to exercise the method's own contract.
func TestCachedSecretZeroTTLDisablesCache(t *testing.T) {
	t.Parallel()
	cachedAt := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	s := &Store{
		ttl:      0,
		cached:   &kube.Secret{Name: "s"},
		cachedAt: cachedAt,
		now:      func() time.Time { return cachedAt.Add(-time.Second) },
	}
	if got := s.cachedSecret(); got != nil {
		t.Errorf("cachedSecret() = %v, want nil: a zero ttl must disable the cache regardless of elapsed sign", got)
	}
}

// TestCachedSecretExpiresExactlyAtTTL proves the cache expires at exactly its
// ttl, not only strictly after it. A CONDITIONALS_BOUNDARY mutant narrowing
// "elapsed >= ttl" to "elapsed > ttl" would serve one extra read from a
// stale cache at the exact expiry instant.
func TestCachedSecretExpiresExactlyAtTTL(t *testing.T) {
	t.Parallel()
	cachedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const ttl = time.Second
	s := &Store{
		ttl:      ttl,
		cached:   &kube.Secret{Name: "s"},
		cachedAt: cachedAt,
		now:      func() time.Time { return cachedAt.Add(ttl) }, // elapsed == ttl exactly
	}
	if got := s.cachedSecret(); got != nil {
		t.Errorf("cachedSecret() = %v, want nil: the cache must expire at exactly its ttl", got)
	}
}

// TestOpenBackoffDefaulting proves Open applies DefaultBackoff only when
// Backoff is exactly zero, and otherwise keeps the caller's value verbatim.
// A CONDITIONALS_NEGATION mutant on "backoff == 0" would invert this: a zero
// Backoff would stay zero (defeating retry pacing) and any explicit nonzero
// Backoff would silently be replaced by the default.
func TestOpenBackoffDefaulting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input time.Duration
		want  time.Duration
	}{
		{"zero takes the default", 0, DefaultBackoff},
		{"nonzero is kept as given", 5 * time.Millisecond, 5 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := Open(Options{Client: &kube.Client{}, Backoff: tc.input})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if s.backoff != tc.want {
				t.Errorf("backoff = %s, want %s", s.backoff, tc.want)
			}
		})
	}
}
