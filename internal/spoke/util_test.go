// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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

// TestFullJitterNoMaxFallsBackToExactly30s pins the fallback's exact value.
// TestFullJitterDefaultsRepairAMisconfiguredBackoff only proves every draw
// lands inside [base/4, 35s), which a fallback smaller than the documented
// 30s -- say, one broken by a mutated multiplication -- would just as happily
// satisfy. This proves draws actually reach up near the 30s ceiling.
func TestFullJitterNoMaxFallsBackToExactly30s(t *testing.T) {
	t.Parallel()

	const base = 20 * time.Second
	var maxSeen time.Duration
	for range 500 {
		if got := fullJitter(base, 0, 5); got > maxSeen {
			maxSeen = got
		}
	}
	// Draws come from [5s, 35s) when the fallback is really 30s, saturated by
	// attempt 5. A fallback that collapsed to 0 or to base (20s) could never
	// produce anything close to 35s.
	if maxSeen < 32*time.Second {
		t.Errorf("largest of 500 draws was %s, want something close to the 30s-fallback ceiling of 35s", maxSeen)
	}
}

// TestFullJitterMaxEqualToBaseIsNotTreatedAsMisconfigured pins the boundary of
// "max < base": a cap exactly equal to the floor is a legitimate
// configuration (no growth headroom, but not inverted), not something the
// "max <= 0 || max < base" repair should touch. At attempt 0 the repair branch
// is never exercised regardless (the window starts at base before any
// doubling), so this needs an attempt that actually doubles past the
// configured cap to tell the repaired case apart from the untouched one.
func TestFullJitterMaxEqualToBaseIsNotTreatedAsMisconfigured(t *testing.T) {
	t.Parallel()

	const base = 5 * time.Second
	lo, hiExcl := base/4, base+base/4 // [1.25s, 6.25s)
	for range 500 {
		got := fullJitter(base, base, 1)
		if got < lo || got >= hiExcl {
			t.Fatalf("fullJitter(base=%s, max=%s, attempt=1) = %s, want [%s, %s); "+
				"a max equal to base must still cap the window at base, not fall back to 30s",
				base, base, got, lo, hiExcl)
		}
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

	// A CONDITIONALS_BOUNDARY mutant narrowing "d <= 0" to "d < 0" leaves d == 0
	// on the timer path instead of the short-circuit. That is not merely
	// slower: with the context already cancelled, select{} on a closed
	// ctx.Done() and an already (or about to be) fired zero-duration timer
	// picks a ready case pseudo-randomly, so the mutant reports "completed"
	// roughly half the time instead of always reporting cancellation. One call
	// only has even odds of catching that; repeating it drives the chance of a
	// false pass to effectively zero while costing the real (deterministic)
	// implementation nothing.
	t.Run("a cancelled context with exactly a zero duration never reports completion", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for i := range 200 {
			if sleepCtx(ctx, 0) {
				t.Fatalf("sleepCtx(cancelled, 0) reported a completed sleep on trial %d", i)
			}
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

// TestLabelsWithSDLC pins the reserved-label merge.
//
// The lifecycle stage is published as an ordinary label so that agent key
// scopes (matchLabels) and fanout_query's label selector can target it with no
// special case. Two properties matter and are asserted here: the caller's map
// is never mutated, because it is the config's own map and the collector holds
// it for the process lifetime; and the validated field beats a hand-written
// "sdlc" label, because one of them went through normalisation and the other
// was typed into a map.
func TestLabelsWithSDLC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		labels map[string]string
		sdlc   string
		want   map[string]string
	}{{
		name:   "merged alongside operator labels",
		labels: map[string]string{"env": "prod", "region": "eu-west-1"},
		sdlc:   "prod",
		want:   map[string]string{"env": "prod", "region": "eu-west-1", "sdlc": "prod"},
	}, {
		name: "no labels at all",
		sdlc: "staging",
		want: map[string]string{"sdlc": "staging"},
	}, {
		// Not reachable through Validate, which requires the field, but the
		// helper must not invent an empty label if it ever is.
		name:   "empty stage leaves labels untouched",
		labels: map[string]string{"env": "dev"},
		want:   map[string]string{"env": "dev"},
	}, {
		name:   "field wins over a hand-written sdlc label",
		labels: map[string]string{"sdlc": "typed-by-hand"},
		sdlc:   "prod",
		want:   map[string]string{"sdlc": "prod"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			original := make(map[string]string, len(tc.labels))
			for k, v := range tc.labels {
				original[k] = v
			}

			got := labelsWithSDLC(tc.labels, tc.sdlc)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("labelsWithSDLC() mismatch (-want +got):\n%s", diff)
			}
			if tc.sdlc != "" && tc.labels != nil {
				if diff := cmp.Diff(original, tc.labels); diff != "" {
					t.Errorf("caller's map was mutated (-before +after):\n%s", diff)
				}
			}
		})
	}
}

// Equivalent-mutant proofs.
//
// Each boundary mutant below is left alive deliberately, with the argument
// for why no test can distinguish it recorded here rather than faked with a
// contrived assertion. Compare internal/render's mutation_edges_test.go,
// which documents the same kind of finding for that package.
//
//   - util.go:26 ("if d <= 0" in jitter) widening to "< " only changes
//     behaviour at d == 0, where the guarded "return d" (0) and falling
//     through to "time.Duration(float64(d) * factor)" (0 * factor == 0)
//     produce the identical value.
//
//   - util.go:39 ("if base <= 0" in fullJitter) is NOT equivalent: at
//     base == 0 the narrowed "< " skips the 500ms default, leaving base and
//     therefore window at 0, and rand.Int64N(0) panics. Already killed by
//     TestFullJitterDefaultsRepairAMisconfiguredBackoff's "no base falls
//     back to 500ms" case.
//
//   - util.go:42 ("if max <= 0 || max < base") widening the first clause to
//     "< " only changes behaviour at max == 0. By this point base is always
//     > 0 (the base <= 0 branch above already defaulted it), so
//     "max < base" is unconditionally true whenever max == 0 and the second
//     clause fires regardless of the first — the widened clause can never be
//     the one that mattered.
//
//   - util.go:45 ("if max < base", the fallback-cap repair) widening to
//     "<= " only changes behaviour at max == base exactly, where the
//     assignment "max = base" is a no-op.
//
//   - util.go:54 ("if window >= max" in the doubling loop) narrowing to "> "
//     only changes behaviour at window == max exactly, where the guarded
//     "window = max" assigns the value window already holds. Any overshoot
//     the narrowed check misses gets corrected on the very next doubling
//     (window is by then > max, and "> " and ">= " agree on that), so the
//     final window used to draw the delay is unaffected either way.
//
//   - coverage.go:80 ("if replicas > maxAdvertisedReplicas") widening to
//     ">= " only changes behaviour at replicas == maxAdvertisedReplicas
//     exactly, where the guarded "replicas = maxAdvertisedReplicas" assigns
//     the value replicas already holds.
//
//   - coverage.go:123 ("if want < 1" in dialers) narrowing to "<= " only
//     changes behaviour at want == 1, where the guarded "return 2" and the
//     fallthrough "return want + 1" (1 + 1 == 2) produce the identical
//     value.
//
//   - spoke.go:151 ("if probe < minProbeInterval" in newTimings) widening to
//     "<= " only changes behaviour at probe == minProbeInterval exactly,
//     where the guarded "probe = minProbeInterval" assigns the value probe
//     already holds.
//
//   - spoke.go:1053 ("make(map[string]string, len(labels)+1)" in
//     labelsWithSDLC) an ARITHMETIC_BASE turning "+1" into "-1" only changes
//     the map's pre-allocation size HINT, which Go accepts even when
//     negative (it is clamped, not validated) and which is not observable
//     through any Go API: the resulting map's contents, length and iteration
//     are identical regardless of the hint that built it.
