// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"sync"
	"testing"
	"time"
)

func TestFailureLimiter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// run drives the limiter and reports whether the address should be
		// allowed at the returned instant.
		run       func(l *failureLimiter, now time.Time) (bool, time.Time)
		wantAllow bool
	}{
		{
			name: "an unseen address is allowed",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				return l.Allow("192.0.2.1", now), now
			},
			wantAllow: true,
		},
		{
			name: "an empty address is never limited",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst * 5 {
					l.Fail("", now)
				}
				return l.Allow("", now), now
			},
			wantAllow: true,
		},
		{
			name: "failures within the burst stay allowed",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst {
					l.Fail("192.0.2.2", now)
				}
				return l.Allow("192.0.2.2", now), now
			},
			wantAllow: true,
		},
		{
			name: "one failure past the burst starts backoff",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst + 1 {
					l.Fail("192.0.2.3", now)
				}
				return l.Allow("192.0.2.3", now), now
			},
			wantAllow: false,
		},
		{
			name: "backoff expires",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst + 1 {
					l.Fail("192.0.2.4", now)
				}
				later := now.Add(firstPenalty + time.Millisecond)
				return l.Allow("192.0.2.4", later), later
			},
			wantAllow: true,
		},
		{
			name: "success clears the penalty",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst + 1 {
					l.Fail("192.0.2.5", now)
				}
				l.Succeed("192.0.2.5", now)
				return l.Allow("192.0.2.5", now), now
			},
			wantAllow: true,
		},
		{
			name: "success on an unseen address is a no-op",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				l.Succeed("192.0.2.6", now)
				l.Succeed("", now)
				return l.Allow("192.0.2.6", now), now
			},
			wantAllow: true,
		},
		{
			name: "budget refills over the window",
			run: func(l *failureLimiter, now time.Time) (bool, time.Time) {
				for range failureBurst {
					l.Fail("192.0.2.7", now)
				}
				// A full window later the budget is back, so one more failure
				// does not trip the penalty.
				later := now.Add(failureWindow)
				l.Fail("192.0.2.7", later)
				return l.Allow("192.0.2.7", later), later
			},
			wantAllow: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newFailureLimiter()
			got, _ := tc.run(l, testNow)
			if got != tc.wantAllow {
				t.Errorf("Allow() = %v, want %v", got, tc.wantAllow)
			}
		})
	}
}

// TestFailureLimiterBackoffGrows proves the penalty doubles rather than
// staying at the first step, so a source that keeps hammering keeps losing.
func TestFailureLimiterBackoffGrows(t *testing.T) {
	t.Parallel()
	l := newFailureLimiter()
	const ip = "203.0.113.1"
	now := testNow

	exhaust := func(at time.Time) {
		for range failureBurst + 1 {
			l.Fail(ip, at)
		}
	}
	exhaust(now)
	first := penaltyOf(t, l, ip)

	// Wait out the first penalty, then misbehave again.
	now = now.Add(first + time.Second)
	exhaust(now)
	second := penaltyOf(t, l, ip)

	if second <= first {
		t.Errorf("penalty did not grow: %s then %s", first, second)
	}
	if second > maxPenalty {
		t.Errorf("penalty %s exceeds the cap %s", second, maxPenalty)
	}
}

func TestFailureLimiterPenaltyIsCapped(t *testing.T) {
	t.Parallel()
	l := newFailureLimiter()
	const ip = "203.0.113.2"
	now := testNow
	for range 20 {
		for range failureBurst + 1 {
			l.Fail(ip, now)
		}
		now = now.Add(penaltyOf(t, l, ip) + time.Second)
	}
	if got := penaltyOf(t, l, ip); got != maxPenalty {
		t.Errorf("penalty = %s, want it pinned at the cap %s", got, maxPenalty)
	}
}

func TestFailureLimiterIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	l := newFailureLimiter()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := "198.51.100." + string(rune('0'+g))
			for i := range 200 {
				at := testNow.Add(time.Duration(i) * time.Millisecond)
				l.Allow(ip, at)
				l.Fail(ip, at)
				if i%25 == 0 {
					l.Succeed(ip, at)
				}
			}
		}()
	}
	wg.Wait()
}

// penaltyOf reads the current penalty step for an address.
func penaltyOf(t *testing.T, l *failureLimiter, ip string) time.Duration {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.cache.Get(ip)
	if !ok {
		t.Fatalf("no bucket for %s", ip)
	}
	return b.penalty
}
