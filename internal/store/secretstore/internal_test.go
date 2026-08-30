// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstore

import (
	"context"
	"errors"
	"testing"
	"time"
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
