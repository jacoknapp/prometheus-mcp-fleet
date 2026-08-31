// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
)

// TestJitterStaysInItsWindow pins the ±10% band. The band is the whole point:
// too narrow and a synchronised fleet stays synchronised, too wide and a
// "hourly" check stops being hourly.
func TestJitterStaysInItsWindow(t *testing.T) {
	t.Parallel()

	d := time.Hour
	low, high := time.Duration(float64(d)*0.9), time.Duration(float64(d)*1.1)
	sawBelow, sawAbove := false, false
	for range 2000 {
		got := jitter(d)
		if got < low || got >= high {
			t.Fatalf("jitter(%s) = %s, want [%s, %s)", d, got, low, high)
		}
		if got < d {
			sawBelow = true
		}
		if got > d {
			sawAbove = true
		}
	}
	if !sawBelow || !sawAbove {
		t.Errorf("jitter never varied in both directions (below=%v above=%v); "+
			"a fleet that all jitters the same way is not jittered",
			sawBelow, sawAbove)
	}
}

// TestJitterOfANonPositiveDurationIsANoOp keeps a zero interval from becoming
// a negative one, which time.NewTimer fires immediately on.
func TestJitterOfANonPositiveDurationIsANoOp(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second} {
		if got := jitter(d); got != d {
			t.Errorf("jitter(%s) = %s, want it returned unchanged", d, got)
		}
	}
}

// TestFullJitterWindowGrowsAndIsCapped is the backoff contract: the window
// doubles per attempt, stops at max, and every delay is drawn from inside it.
//
// Full jitter is load-shedding, not politeness. If the delay ever exceeded the
// window, a hundred spokes retrying a restarted hub would stretch their
// reconnects out past the point an operator would wait; if it ever collapsed
// to a constant, they would arrive together.
func TestFullJitterWindowGrowsAndIsCapped(t *testing.T) {
	t.Parallel()

	const (
		base = 100 * time.Millisecond
		max  = 800 * time.Millisecond
	)
	// window(attempt) is base*2^attempt capped at max; the delay is drawn from
	// [base/4, window+base/4).
	for attempt, window := range []time.Duration{
		base, 2 * base, 4 * base, max, max, max,
	} {
		lo, hi := base/4, window+base/4
		distinct := map[time.Duration]struct{}{}
		for range 500 {
			got := fullJitter(base, max, attempt)
			if got < lo || got >= hi {
				t.Fatalf("fullJitter(attempt=%d) = %s, want [%s, %s)", attempt, got, lo, hi)
			}
			distinct[got] = struct{}{}
		}
		if len(distinct) < 2 {
			t.Errorf("attempt %d produced a constant delay; that is not jitter", attempt)
		}
	}
}

// TestFullJitterDefaultsRepairAMisconfiguredBackoff pins that a zero or
// inverted configuration still produces a usable window instead of panicking
// in rand.Int64N or hot-looping on a zero delay.
func TestFullJitterDefaultsRepairAMisconfiguredBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		base, max  time.Duration
		attempt    int
		wantLo     time.Duration
		wantHiExcl time.Duration
	}{
		{
			name: "no base falls back to 500ms",
			base: 0, max: time.Minute, attempt: 0,
			wantLo: 125 * time.Millisecond, wantHiExcl: 625 * time.Millisecond,
		},
		{
			name: "no max falls back to 30s",
			base: 20 * time.Second, max: 0, attempt: 5,
			wantLo: 5 * time.Second, wantHiExcl: 35 * time.Second,
		},
		{
			// The cap is repaired to the base rather than left below it: a
			// window smaller than the configured minimum delay would make the
			// documented rand(0, min(max, base*2^attempt)) untrue on the very
			// first attempt.
			name: "a max below base is raised to it",
			base: time.Minute, max: time.Second, attempt: 0,
			wantLo: 15 * time.Second, wantHiExcl: 75 * time.Second,
		},
		{
			name: "a negative attempt count never doubles the window",
			base: time.Second, max: time.Minute, attempt: -3,
			wantLo: 250 * time.Millisecond, wantHiExcl: 1250 * time.Millisecond,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for range 200 {
				got := fullJitter(tc.base, tc.max, tc.attempt)
				if got < tc.wantLo || got >= tc.wantHiExcl {
					t.Fatalf("fullJitter(%s, %s, %d) = %s, want [%s, %s)",
						tc.base, tc.max, tc.attempt, got, tc.wantLo, tc.wantHiExcl)
				}
			}
		})
	}
}

// TestSleepCtxReportsWhetherItSlept is what every loop in this package branches
// on to decide between "carry on" and "we are shutting down".
func TestSleepCtxReportsWhetherItSlept(t *testing.T) {
	t.Parallel()

	t.Run("a completed sleep reports true", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		if !sleepCtx(t.Context(), 20*time.Millisecond) {
			t.Fatal("sleepCtx reported cancellation for a sleep that completed")
		}
		if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
			t.Errorf("sleepCtx returned after %s, want at least 20ms", elapsed)
		}
	})

	t.Run("a cancelled sleep reports false and returns early", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		if sleepCtx(ctx, time.Hour) {
			t.Fatal("sleepCtx reported a completed sleep after cancellation")
		}
		if elapsed := time.Since(start); elapsed > 30*time.Second {
			t.Errorf("sleepCtx waited %s after cancellation", elapsed)
		}
	})

	t.Run("a non-positive duration still reports the context", func(t *testing.T) {
		t.Parallel()
		if !sleepCtx(t.Context(), 0) {
			t.Error("sleepCtx(0) on a live context reported cancellation")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if sleepCtx(ctx, -time.Second) {
			t.Error("sleepCtx(-1s) on a cancelled context reported a completed sleep")
		}
	})
}

// TestClassifyBelievesTheTransport pins that a reason the transport already
// determined is used verbatim rather than being re-derived from the error
// text. grpctun.Reason is a closed enum; re-deriving it here is how the two
// would drift.
func TestClassifyBelievesTheTransport(t *testing.T) {
	t.Parallel()

	for _, reason := range []grpctun.Reason{
		grpctun.ReasonDial,
		grpctun.ReasonTLSHandshake,
		grpctun.ReasonUpgradeRejected,
		grpctun.ReasonAuthRejected,
		grpctun.ReasonConnClosed,
		grpctun.ReasonContextCancelled,
	} {
		// The wrapped cause deliberately reads like a different category, so a
		// classifier that looked at the text instead would answer differently.
		err := fmt.Errorf("wrapped: %w", &grpctun.DialError{
			Endpoint: "wss://hub.test/tunnel",
			Reason:   reason,
			Err:      errors.New("connection refused"),
		})
		if got := classify(err); got != string(reason) {
			t.Errorf("classify(DialError{%s}) = %q, want %q", reason, got, reason)
		}
	}
}

// TestClassifyMapsEveryShapeToTheClosedSet walks the fallback, which exists for
// errors that did not come from the transport. The label set has to stay
// closed: an unbounded reason on a reconnect counter is a cardinality bomb in
// every spoke at once.
func TestClassifyMapsEveryShapeToTheClosedSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no error at all", err: nil, want: "closed"},
		{
			name: "a DialError with no reason falls through to the text",
			err: &grpctun.DialError{
				Endpoint: "wss://hub.test/tunnel",
				Err:      errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
			},
			want: "dial",
		},
		{name: "cancellation", err: context.Canceled, want: "context-cancelled"},
		{name: "wrapped cancellation", err: fmt.Errorf("dial: %w", context.Canceled), want: "context-cancelled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "timeout"},
		{name: "a certificate complaint", err: errors.New("bad certificate"), want: "tls-handshake"},
		{name: "a tls alert", err: errors.New("remote error: tls: handshake failure"), want: "tls-handshake"},
		{name: "an x509 complaint", err: errors.New("x509: certificate signed by unknown authority"), want: "tls-handshake"},
		{name: "connection refused", err: errors.New("connect: connection refused"), want: "dial"},
		{name: "dns", err: errors.New("lookup hub.test: no such host"), want: "dial"},
		{name: "a network timeout", err: errors.New("dial tcp: i/o timeout"), want: "dial"},
		{name: "end of stream", err: errors.New("unexpected EOF"), want: "conn-closed"},
		{name: "a reset peer", err: errors.New("read: connection reset by peer"), want: "conn-closed"},
		{name: "a hub going down", err: errors.New("rpc error: the server is in shutdown"), want: "server-shutdown"},
		{name: "a hub draining", err: errors.New("draining, refusing new sessions"), want: "server-shutdown"},
		{name: "anything else", err: errors.New("something nobody predicted"), want: "other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := classify(tc.err); got != tc.want {
				t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
