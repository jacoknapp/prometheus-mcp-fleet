// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// rateLimiter bounds how fast one agent key may call tools.
//
// It exists because fleet.Limits has advertised RateRPS and RateBurst since the
// beginning, and docs/security.md presented them as a control, while nothing
// enforced them. A scope that says a key is limited and is not is worse than
// one that says nothing: an operator issues the key believing it is bounded.
//
// What it bounds is TOOL CALLS, which is what the scope field says. The
// per-cluster concurrency and byte budgets in internal/promproxy bound the work
// one call may do; this bounds how many calls arrive. Both are needed: eight
// slow fan-out calls can hold the global byte budget without ever exceeding a
// concurrency limit, which is exactly the shape of a leaked key.
//
// A hand-rolled token bucket rather than golang.org/x/time/rate: the dependency
// budget is closed (ADR-0010) and this is thirty lines.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// bucket is one key's allowance.
type bucket struct {
	tokens float64
	last   time.Time
	// seen is used to evict keys that have stopped calling, so a hub that has
	// issued many keys over its life does not accumulate a bucket per key
	// forever.
	seen time.Time
}

// bucketIdleEviction is how long an unused bucket is kept. Long enough that a
// key calling even occasionally keeps its allowance, short enough that revoked
// or retired keys do not accumulate.
const bucketIdleEviction = time.Hour

// newRateLimiter builds a limiter on the caller's clock. Tools settles its own
// clock before constructing this, so now is never nil and there is deliberately
// no fallback here: an unreachable default is code nothing can exercise.
func newRateLimiter(now func() time.Time) *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket), now: now}
}

// allow reports whether this principal may make a call now, and how long to
// wait when it may not.
//
// A principal with no rate configured is unlimited, which keeps the default
// behaviour of every key minted before this existed.
func (l *rateLimiter) allow(p *fleet.Principal) (ok bool, retryAfter time.Duration) {
	// Scope is a pointer and a principal may legitimately carry none, so this
	// guards a nil dereference as well as an unset rate.
	if p == nil || p.Scope == nil || p.Scope.Limits.RateRPS <= 0 {
		return true, 0
	}
	rps := p.Scope.Limits.RateRPS
	burst := float64(p.Scope.Limits.RateBurst)
	if burst < 1 {
		// A rate without a burst still has to admit one call at a time, or the
		// key is simply broken rather than limited.
		burst = 1
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, found := l.buckets[p.KID]
	if !found {
		b = &bucket{tokens: burst, last: now}
		l.buckets[p.KID] = b
		l.evictIdleLocked(now)
	}

	// Refill for elapsed time, capped at the burst.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed.Seconds()*rps)
		b.last = now
	}
	b.seen = now

	if b.tokens < 1 {
		// Time until one whole token exists.
		wait := time.Duration((1 - b.tokens) / rps * float64(time.Second))
		return false, wait
	}
	b.tokens--
	return true, 0
}

// evictIdleLocked drops buckets nothing has touched recently. Callers hold the
// mutex. It runs only when a new bucket appears, so the cost is paid by the
// event that grows the map rather than by every call.
func (l *rateLimiter) evictIdleLocked(now time.Time) {
	for kid, b := range l.buckets {
		if !b.seen.IsZero() && now.Sub(b.seen) > bucketIdleEviction {
			delete(l.buckets, kid)
		}
	}
}
