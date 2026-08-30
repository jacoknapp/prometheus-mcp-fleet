// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"sync"
	"time"
)

// Clock is a manually advanced clock. It exists so that tests of latency
// accounting, refresh scheduling and expiry are deterministic instead of
// depending on the machine's wall clock or on sleeps.
//
// Clock is safe for concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a Clock reading t.
func NewClock(t time.Time) *Clock {
	return &Clock{now: t}
}

// Now returns the clock's current time. Its signature matches the
// func() time.Time that the production packages accept for injection.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d. Negative durations move it backwards,
// which is occasionally useful for exercising clock-skew handling.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set moves the clock to an absolute time.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
