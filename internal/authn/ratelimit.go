// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"sync"
	"time"
)

// Failure rate limiting constants.
//
// The limiter exists because a cache miss is the expensive path: it costs a
// store round trip plus an HMAC. Without a limit, an attacker who knows only
// the token *shape* could turn a single connection into unbounded store load,
// and the decoy HMAC that closes the timing oracle would become the
// amplification. Ten failures a minute is far above what any correct client
// produces and far below what is useful for a brute-force attempt against 256
// bits of entropy.
const (
	// failureBurst is how many authentication failures a single source address
	// may produce before it enters backoff.
	failureBurst = 10
	// failureWindow is the period over which failureBurst is replenished.
	failureWindow = time.Minute
	// firstPenalty is the backoff imposed the first time a source exhausts its
	// budget. It doubles on each subsequent exhaustion.
	firstPenalty = time.Second
	// maxPenalty caps the backoff, so a source that stops misbehaving recovers
	// in bounded time and the limiter cannot be used to lock out an address
	// permanently.
	maxPenalty = 5 * time.Minute
	// limiterEntries bounds how many source addresses are tracked. The map is
	// LRU-evicted, so a source-address flood costs memory proportional to this
	// constant and nothing more.
	limiterEntries = 8192
)

// failureLimiter throttles authentication failures per source address.
//
// It is a token bucket over failures, not over attempts: a client presenting a
// valid credential is never slowed down no matter how fast it calls. Only
// failures consume budget, and exhausting the budget starts an exponentially
// growing penalty window during which every attempt from that source is
// refused before any store or cryptographic work happens.
//
// It is safe for concurrent use.
type failureLimiter struct {
	mu    sync.Mutex
	cache *lruCache[string, *failureBucket]
}

// failureBucket is one source address's state.
type failureBucket struct {
	tokens       float64
	last         time.Time
	penalty      time.Duration
	penaltyUntil time.Time
}

// newFailureLimiter returns a limiter tracking at most [limiterEntries]
// addresses.
func newFailureLimiter() *failureLimiter {
	return &failureLimiter{cache: newLRU[string, *failureBucket](limiterEntries)}
}

// Allow reports whether ip may attempt an authentication at time now. An empty
// ip is always allowed: an unattributable request cannot be rate limited
// fairly, and bucketing every such request together would let one caller deny
// service to the rest.
func (l *failureLimiter) Allow(ip string, now time.Time) bool {
	if ip == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.cache.Get(ip)
	if !ok {
		return true
	}
	l.refill(b, now)
	return !now.Before(b.penaltyUntil)
}

// Fail records one authentication failure from ip at time now.
func (l *failureLimiter) Fail(ip string, now time.Time) {
	if ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.cache.Get(ip)
	if !ok {
		b = &failureBucket{tokens: failureBurst, last: now}
		l.cache.Put(ip, b)
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return
	}
	// Budget exhausted: start or extend the penalty window.
	if b.penalty == 0 {
		b.penalty = firstPenalty
	} else if now.After(b.penaltyUntil) {
		b.penalty = min(b.penalty*2, maxPenalty)
	}
	if until := now.Add(b.penalty); until.After(b.penaltyUntil) {
		b.penaltyUntil = until
	}
}

// Succeed clears the penalty state for ip after a successful authentication,
// so a client that fixes its credential is not held in backoff.
func (l *failureLimiter) Succeed(ip string, now time.Time) {
	if ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.cache.Get(ip); ok {
		b.tokens = failureBurst
		b.last = now
		b.penalty = 0
		b.penaltyUntil = time.Time{}
	}
}

// refill adds the failure budget accrued since b.last. The caller holds l.mu.
func (l *failureLimiter) refill(b *failureBucket, now time.Time) {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 {
		return
	}
	b.last = now
	b.tokens = min(b.tokens+float64(elapsed)/float64(failureWindow)*failureBurst, failureBurst)
}
