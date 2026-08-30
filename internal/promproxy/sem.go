// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"context"
	"slices"
	"sync"
)

// inflightSem is a per-cluster counting semaphore that refuses instead of
// queueing. Each cluster's counter is created on first use and dropped when it
// returns to zero, so a fleet of a hundred clusters does not permanently hold a
// hundred entries once traffic moves on.
//
// The per-call limit is passed to acquire rather than fixed at construction
// because a principal's fleet.Limits may be stricter than the hub's
// configuration; the effective ceiling is the smaller of the two and is
// computed per call.
type inflightSem struct {
	mu       sync.Mutex
	inflight map[string]int
}

// newInflightSem returns an empty semaphore.
func newInflightSem() *inflightSem {
	return &inflightSem{inflight: make(map[string]int)}
}

// acquire takes a slot for clusterID when fewer than limit are held. It never
// blocks.
func (s *inflightSem) acquire(clusterID string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[clusterID] >= limit {
		return false
	}
	s.inflight[clusterID]++
	return true
}

// release returns a slot.
func (s *inflightSem) release(clusterID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.inflight[clusterID] - 1
	if n <= 0 {
		delete(s.inflight, clusterID)
		return
	}
	s.inflight[clusterID] = n
}

// byteSem is a weighted semaphore over the hub's global response-byte budget.
// It is acquired for a call's worst case before the call is made, which is the
// only way to bound the hub's memory: by the time a body is arriving it is too
// late to decide there was no room for it.
//
// Waiters are served strictly first-in, first-out. Head-of-line blocking is
// deliberate: letting a small request overtake a large one starves the large
// one indefinitely under load, and a range query that never runs is a worse
// outcome than a metadata lookup that waits.
type byteSem struct {
	capacity int64

	mu      sync.Mutex
	free    int64
	waiters []*byteWaiter
}

// byteWaiter is one queued acquisition. ready is closed by whichever release
// grants it, at which point n has already been deducted from free.
type byteWaiter struct {
	n     int64
	ready chan struct{}
}

// newByteSem returns a semaphore holding capacity bytes.
func newByteSem(capacity int64) *byteSem {
	return &byteSem{capacity: capacity, free: capacity}
}

// acquire reserves n bytes, waiting until they are free or ctx ends. It
// returns ctx.Err() if the wait is cut short, and errBudgetTooLarge if n
// exceeds the whole budget, which can never be satisfied and so must not be
// queued.
func (s *byteSem) acquire(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	if n > s.capacity {
		return errBudgetTooLarge
	}
	s.mu.Lock()
	if len(s.waiters) == 0 && s.free >= n {
		s.free -= n
		s.mu.Unlock()
		return nil
	}
	w := &byteWaiter{n: n, ready: make(chan struct{})}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()

	select {
	case <-w.ready:
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		if i := slices.Index(s.waiters, w); i >= 0 {
			s.waiters = slices.Delete(s.waiters, i, i+1)
			// Removing a waiter frees no bytes, but it can unblock the queue:
			// if w was the oversized head holding up smaller reservations that
			// already fit, the new head must be granted now. Waiting for the
			// next release instead would stall those callers for the lifetime
			// of an unrelated in-flight request.
			s.grantLocked()
			s.mu.Unlock()
			return ctx.Err()
		}
		s.mu.Unlock()
		// Lost the race: a release granted the reservation as ctx expired, so
		// the bytes are ours to hand back.
		<-w.ready
		s.release(n)
		return ctx.Err()
	}
}

// release returns n bytes and grants as many queued waiters as now fit.
func (s *byteSem) release(n int64) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.free += n
	s.grantLocked()
}

// grantLocked hands the free budget to as many queued waiters as fit, in FIFO
// order. The caller must hold s.mu.
//
// Grants are strictly head-first rather than best-fit. Serving a smaller
// waiter that happens to fit while a larger one waits would starve large
// requests indefinitely under sustained small traffic, which in this system
// means range queries never running while instant queries always do. FIFO
// trades a little utilisation for the guarantee that every caller eventually
// runs.
func (s *byteSem) grantLocked() {
	for len(s.waiters) > 0 && s.waiters[0].n <= s.free {
		w := s.waiters[0]
		s.waiters = s.waiters[1:]
		s.free -= w.n
		close(w.ready)
	}
}
