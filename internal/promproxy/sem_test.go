// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// queued reports how many callers are waiting. Test-only: production code has
// no reason to look, and a caller that branched on it would be racing.
func (s *byteSem) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiters)
}

// waitQueued blocks until the semaphore has n waiters parked.
func waitQueued(t *testing.T, s *byteSem, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.queued() == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d queued waiters, have %d", n, s.queued())
}

func TestInflightSem(t *testing.T) {
	t.Parallel()

	t.Run("refuses past the limit and never blocks", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		for i := range 3 {
			if !s.acquire("prod-eu", 3) {
				t.Fatalf("acquire %d was refused below the limit", i)
			}
		}
		if s.acquire("prod-eu", 3) {
			t.Error("acquire succeeded past the limit")
		}
		if got := s.held("prod-eu"); got != 3 {
			t.Errorf("held = %d, want 3", got)
		}
	})

	t.Run("a limit of zero admits nothing", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		if s.acquire("prod-eu", 0) {
			t.Error("acquire succeeded with a limit of zero")
		}
	})

	t.Run("the limit is per call, so a tighter scope tightens it", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		if !s.acquire("prod-eu", 4) {
			t.Fatal("first acquire refused")
		}
		// A principal limited to one concurrent call is refused even though the
		// hub would allow four.
		if s.acquire("prod-eu", 1) {
			t.Error("a caller with a tighter limit was admitted")
		}
	})

	t.Run("counters are per cluster", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		if !s.acquire("prod-eu", 1) || !s.acquire("prod-us", 1) {
			t.Fatal("a saturated cluster blocked a different one")
		}
		if s.acquire("prod-eu", 1) {
			t.Error("prod-eu was admitted past its limit")
		}
	})

	t.Run("a cluster back at zero is dropped from the map", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		s.acquire("prod-eu", 2)
		s.acquire("prod-eu", 2)
		s.release("prod-eu")
		if got := s.held("prod-eu"); got != 1 {
			t.Errorf("held = %d, want 1", got)
		}
		s.release("prod-eu")
		if got := s.held("prod-eu"); got != 0 {
			t.Errorf("held = %d, want 0", got)
		}
		s.mu.Lock()
		n := len(s.inflight)
		s.mu.Unlock()
		if n != 0 {
			t.Errorf("map holds %d entries, want the cluster dropped once idle", n)
		}
		// An unbalanced release must not underflow into a negative count that
		// would then admit callers forever.
		s.release("prod-eu")
		if got := s.held("prod-eu"); got != 0 {
			t.Errorf("held = %d after an extra release, want 0", got)
		}
	})

	t.Run("concurrent acquire never exceeds the limit", func(t *testing.T) {
		t.Parallel()
		s := newInflightSem()
		const limit = 5
		var admitted atomic.Int64
		var wg sync.WaitGroup
		for range 200 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.acquire("prod-eu", limit) {
					admitted.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := admitted.Load(); got != limit {
			t.Errorf("admitted %d, want exactly %d", got, limit)
		}
	})
}

func TestByteSemBasics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		capacity int64
		n        int64
		wantErr  error
		wantFree int64
	}{
		{name: "zero is a no-op", capacity: 100, n: 0, wantFree: 100},
		{name: "negative is a no-op", capacity: 100, n: -5, wantFree: 100},
		{name: "a fitting reservation", capacity: 100, n: 40, wantFree: 60},
		{name: "the whole budget", capacity: 100, n: 100, wantFree: 0},
		{
			// A reservation that can never be satisfied must not be queued: it
			// would wait for its whole deadline and then report "busy", which
			// is a configuration error dressed up as a load condition.
			name: "larger than the whole budget", capacity: 100, n: 101,
			wantErr: errBudgetTooLarge, wantFree: 100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newByteSem(tc.capacity)
			err := s.acquire(context.Background(), tc.n)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("acquire error = %v, want %v", err, tc.wantErr)
			}
			if got := s.available(); got != tc.wantFree {
				t.Errorf("available = %d, want %d", got, tc.wantFree)
			}
		})
	}
}

func TestByteSemBlocksAndReleases(t *testing.T) {
	t.Parallel()

	s := newByteSem(100)
	if err := s.acquire(context.Background(), 100); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.acquire(context.Background(), 60) }()
	waitQueued(t, s, 1)

	select {
	case err := <-done:
		t.Fatalf("acquire did not wait for the budget: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	s.release(100)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("acquire after release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a released budget never reached the waiter")
	}
	if got := s.available(); got != 40 {
		t.Errorf("available = %d, want 40", got)
	}
	s.release(60)
	if got := s.available(); got != 100 {
		t.Errorf("available = %d, want the full budget back", got)
	}
	s.release(0) // a no-op release must not disturb the accounting
	if got := s.available(); got != 100 {
		t.Errorf("available = %d after a zero release", got)
	}
}

// TestByteSemZeroAcquireBypassesTheQueue pins that acquire treats n <= 0 as
// an immediate no-op even when another caller is already queued behind a
// full budget. acquire's n <= 0 guard runs before the queue is ever
// consulted; a version that only special-cased zero at the empty-queue fast
// path would instead enqueue the zero-byte waiter behind the existing one and
// leave it blocked in FIFO order until the head is granted.
func TestByteSemZeroAcquireBypassesTheQueue(t *testing.T) {
	t.Parallel()

	s := newByteSem(100)
	if err := s.acquire(context.Background(), 100); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- s.acquire(context.Background(), 60) }()
	waitQueued(t, s, 1)

	done := make(chan error, 1)
	go func() { done <- s.acquire(context.Background(), 0) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("acquire(0) with a caller already queued = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("acquire(0) waited behind the queue instead of returning immediately")
	}
	if got := s.queued(); got != 1 {
		t.Errorf("queued = %d, want the zero acquire to never have joined the queue", got)
	}

	s.release(100)
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("acquire after release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a released budget never reached the waiter")
	}
}

// TestByteSemIsFIFO pins the deliberate head-of-line blocking. Letting a small
// reservation overtake a large one starves the large one under sustained small
// traffic, which in this system means range queries never run while instant
// queries always do.
func TestByteSemIsFIFO(t *testing.T) {
	t.Parallel()

	s := newByteSem(100)
	if err := s.acquire(context.Background(), 100); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	big := make(chan error, 1)
	go func() { big <- s.acquire(context.Background(), 100) }()
	waitQueued(t, s, 1)

	small := make(chan error, 1)
	go func() { small <- s.acquire(context.Background(), 10) }()
	waitQueued(t, s, 2)

	// A new caller must not barge past a queue even when it would fit.
	barge := make(chan error, 1)
	go func() { barge <- s.acquire(context.Background(), 1) }()
	waitQueued(t, s, 3)

	s.release(100)

	select {
	case err := <-big:
		if err != nil {
			t.Fatalf("the head waiter failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the head of the queue was not served first")
	}
	select {
	case <-small:
		t.Fatal("a smaller reservation overtook the head of the queue")
	case <-barge:
		t.Fatal("a late, tiny reservation overtook the queue")
	case <-time.After(30 * time.Millisecond):
	}

	// One release now covers both remaining waiters, and grantLocked must hand
	// them out in one pass rather than one per release.
	s.release(100)
	for range 2 {
		select {
		case err := <-small:
			if err != nil {
				t.Fatalf("small: %v", err)
			}
		case err := <-barge:
			if err != nil {
				t.Fatalf("barge: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a single release did not drain every waiter that fits")
		}
	}
	if got := s.available(); got != 89 {
		t.Errorf("available = %d, want 100-10-1", got)
	}
}

// TestByteSemCancelledOversizedHeadUnblocksTheQueue is the case the grant
// refactor exists for. A waiter that is too big to ever fit under the current
// load sits at the head of the queue; when its caller gives up, the smaller
// reservations behind it already fit and must be granted immediately. Waiting
// for the next unrelated release instead would stall them for the lifetime of
// whatever is in flight.
func TestByteSemCancelledOversizedHeadUnblocksTheQueue(t *testing.T) {
	t.Parallel()

	s := newByteSem(100)
	// 50 bytes are in flight and will not be returned during this test.
	if err := s.acquire(context.Background(), 50); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	headCtx, cancelHead := context.WithCancel(context.Background())
	head := make(chan error, 1)
	go func() { head <- s.acquire(headCtx, 100) }() // cannot fit until the 50 comes back
	waitQueued(t, s, 1)

	behind := make(chan error, 2)
	for range 2 {
		go func() { behind <- s.acquire(context.Background(), 20) }() // fits in the free 50
	}
	waitQueued(t, s, 3)

	select {
	case err := <-behind:
		t.Fatalf("a waiter was served ahead of the queue head: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	cancelHead()

	if err := <-head; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled head returned %v, want context.Canceled", err)
	}
	for range 2 {
		select {
		case err := <-behind:
			if err != nil {
				t.Fatalf("a waiter behind the cancelled head failed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("removing the oversized head did not unblock the waiters behind it")
		}
	}
	if got := s.available(); got != 10 {
		t.Errorf("available = %d, want 100-50-20-20", got)
	}
	// Giving up must not consume budget.
	s.release(50)
	s.release(20)
	s.release(20)
	if got := s.available(); got != 100 {
		t.Errorf("available = %d, want the full budget: a cancelled waiter leaked", got)
	}
}

func TestByteSemCancellationDoesNotLeak(t *testing.T) {
	t.Parallel()

	t.Run("a cancelled waiter is dequeued", func(t *testing.T) {
		t.Parallel()
		s := newByteSem(100)
		if err := s.acquire(context.Background(), 100); err != nil {
			t.Fatalf("acquire: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.acquire(ctx, 100) }()
		waitQueued(t, s, 1)
		cancel()

		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("acquire = %v, want context.Canceled", err)
		}
		if got := s.queued(); got != 0 {
			t.Errorf("queued = %d, want the waiter removed", got)
		}
		s.release(100)
		if got := s.available(); got != 100 {
			t.Errorf("available = %d, want the full budget", got)
		}
	})

	t.Run("a deadline that expires while queued", func(t *testing.T) {
		t.Parallel()
		s := newByteSem(100)
		if err := s.acquire(context.Background(), 100); err != nil {
			t.Fatalf("acquire: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := s.acquire(ctx, 10); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("acquire = %v, want context.DeadlineExceeded", err)
		}
		if got := s.queued(); got != 0 {
			t.Errorf("queued = %d, want 0", got)
		}
	})

	// The nastiest window: a release grants the reservation at the same instant
	// the caller's context expires. The bytes have already been deducted, so
	// the caller has to hand them back on its way out or they are gone for the
	// lifetime of the process.
	t.Run("a grant that lands as the context expires is handed back", func(t *testing.T) {
		t.Parallel()
		s := newByteSem(100)
		if err := s.acquire(context.Background(), 100); err != nil {
			t.Fatalf("acquire: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.acquire(ctx, 40) }()
		waitQueued(t, s, 1)

		// Hold the lock so the waiter, once woken by cancel, parks on it. That
		// pins the interleaving: it has committed to the cancellation branch
		// but has not yet dequeued itself when the grant happens.
		s.mu.Lock()
		cancel()
		time.Sleep(50 * time.Millisecond)
		s.free += 100
		s.grantLocked()
		s.mu.Unlock()

		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("acquire = %v, want context.Canceled", err)
		}
		if got := s.available(); got != 100 {
			t.Errorf("available = %d, want the granted-then-abandoned bytes returned", got)
		}
		if got := s.queued(); got != 0 {
			t.Errorf("queued = %d, want 0", got)
		}
	})
}

// TestByteSemConcurrent is a stress run for -race whose real assertion is that
// the budget is whole at the end: every acquire is matched by a release, and
// none of the cancellation paths swallows a permit.
func TestByteSemConcurrent(t *testing.T) {
	t.Parallel()

	const capacity = 1000
	s := newByteSem(capacity)

	var wg sync.WaitGroup
	for i := range 300 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := int64(1 + i%400)
			ctx := context.Background()
			if i%5 == 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(i%7)*time.Millisecond)
				defer cancel()
			}
			if err := s.acquire(ctx, n); err != nil {
				return
			}
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			s.release(n)
		}()
	}
	wg.Wait()

	if got := s.available(); got != capacity {
		t.Errorf("available = %d, want the full %d: a permit leaked", got, capacity)
	}
	if got := s.queued(); got != 0 {
		t.Errorf("queued = %d, want 0", got)
	}
}
