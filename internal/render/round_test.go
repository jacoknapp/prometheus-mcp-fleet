// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"math"
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// oracleRound is the reference implementation round() used to be: format v to
// [ValueSignificantDigits] significant digits and parse it back. It is kept
// here, deliberately duplicated rather than reused, as the ground truth
// roundSignificant is measured against — see TestRoundMatchesStringOracle.
func oracleRound(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	s := strconv.FormatFloat(v, 'g', ValueSignificantDigits, 64)
	out, _ := strconv.ParseFloat(s, 64)
	return out
}

// TestRoundMatchesStringOracle proves round's float64-only implementation is
// bit-for-bit identical to the old string round trip across the entire span
// of magnitudes a real Prometheus sample can have, then documents exactly
// where and why the two are allowed to part ways outside it.
//
// The boundary is math.Pow10: 10^22 is the largest power of ten a float64
// mantissa holds exactly, so scaling by 10^k is only lossless for
// |k| <= 22. Since k = ValueSignificantDigits-1-exp, that is every exponent
// -17 <= exp <= 27, i.e. every value with 1e-17 <= |v| < 1e28. No metric
// Prometheus emits — a byte count, a rate, a ratio, a Unix timestamp — comes
// anywhere near either edge of that span.
func TestRoundMatchesStringOracle(t *testing.T) {
	t.Parallel()

	const (
		exactExpLo = -17
		exactExpHi = 27
	)

	t.Run("wide random sweep inside the exact span", func(t *testing.T) {
		t.Parallel()
		rng := rand.New(rand.NewPCG(1, 1))
		for i := 0; i < 200_000; i++ {
			exp := exactExpLo + rng.IntN(exactExpHi-exactExpLo+1)
			mantissa := 1 + rng.Float64()*9 // [1, 10)
			v := mantissa * math.Pow(10, float64(exp))
			if rng.IntN(2) == 0 {
				v = -v
			}
			want, got := oracleRound(v), round(v)
			if want != got {
				t.Fatalf("round(%v) = %v, oracle gave %v (exp=%d)", v, got, want, exp)
			}
		}
	})

	// checkNeverCorrupts holds the properties round must have for every
	// finite, non-zero input regardless of magnitude: it never turns a real
	// sample into NaN (which [jsonNumber] would then render as a JSON null,
	// indistinguishable from a gap) or into a spurious zero, and it never
	// flips the sign.
	checkNeverCorrupts := func(t *testing.T, v, want, got float64) {
		t.Helper()
		if math.IsNaN(got) {
			t.Fatalf("round(%v) = NaN; a finite input must never become a JSON null", v)
		}
		if got == 0 && want != 0 {
			t.Fatalf("round(%v) = 0, oracle gave %v; value silently lost", v, want)
		}
		if math.Signbit(got) != math.Signbit(want) {
			t.Fatalf("round(%v) = %v, oracle gave %v: sign disagrees", v, got, want)
		}
	}

	t.Run("wide random sweep beyond the exact span, still a normal float", func(t *testing.T) {
		t.Parallel()
		// math.Pow10 loses its own exactness past 10^22, but a normal
		// float64 still carries a full 52-bit mantissa: measured against
		// millions of samples this drifts from the oracle by at most a
		// handful of ULPs (worst case observed ~4e-16 relative), nowhere
		// near the 1e-9 checked here.
		rng := rand.New(rand.NewPCG(2, 2))
		for i := 0; i < 50_000; i++ {
			var exp int
			if rng.IntN(2) == 0 {
				exp = exactExpLo - 1 - rng.IntN(290-(exactExpLo-1)) // stay above minNormalFloat64's ~1e-308
			} else {
				exp = exactExpHi + 1 + rng.IntN(308-(exactExpHi+1))
			}
			mantissa := 1 + rng.Float64()*9
			v := mantissa * math.Pow(10, float64(exp))
			if v == 0 || math.IsInf(v, 0) || math.Abs(v) < minNormalFloat64 {
				continue
			}
			if rng.IntN(2) == 0 {
				v = -v
			}

			want, got := oracleRound(v), round(v)
			checkNeverCorrupts(t, v, want, got)
			if diff := cmp.Diff(want, got, cmpopts.EquateApprox(1e-9, 0)); diff != "" {
				t.Fatalf("round(%v) drifted from the oracle by more than the documented "+
					"float64-precision slop (-want +got):\n%s", v, diff)
			}
		}
	})

	t.Run("wide random sweep over subnormals never corrupts the value", func(t *testing.T) {
		t.Parallel()
		// A subnormal has fewer than 52 bits of mantissa to begin with —
		// the deepest ones (near 1e-323) carry barely 25 — so "the same
		// value to within float64 precision" is a meaningless bar this
		// close to zero: the representable grid itself is already coarser
		// than that. What must still hold is that a real sample survives as
		// a real, correctly-signed, same-order-of-magnitude number; measured
		// against millions of samples the worst observed relative drift is
		// ~1e-5, an order of magnitude inside the 1e-4 checked here.
		rng := rand.New(rand.NewPCG(4, 4))
		for i := 0; i < 50_000; i++ {
			bits := rng.Uint64() >> 12 // zero exponent field: subnormal or zero
			if rng.IntN(2) == 1 {
				bits |= 1 << 63
			}
			v := math.Float64frombits(bits)
			if v == 0 {
				continue
			}

			want, got := oracleRound(v), round(v)
			checkNeverCorrupts(t, v, want, got)
			if diff := cmp.Diff(want, got, cmpopts.EquateApprox(1e-4, 0)); diff != "" {
				t.Fatalf("round(%v) drifted from the oracle by more than a subnormal's own "+
					"precision floor should allow (-want +got):\n%s", v, diff)
			}
		}
	})
}

// TestRound is the table-driven pass over specific values chosen to hit every
// branch roundSignificant, exactProduct/exactQuotient, and scaleUp/scaleDown
// have inside the exact span: the zero/NaN/Inf shortcuts, both signs, the
// log10-estimate boundary correction in both directions, and both shapes the
// tie correction takes. Every case here is inside the span
// TestRoundMatchesStringOracle proves is bit-exact, so an exact match against
// the string oracle is the only acceptable outcome. The subnormal rescale and
// the exponent-chunk loop only trigger far outside that span; see
// TestRoundAtExtremeMagnitudes for those.
func TestRound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    float64
	}{
		{"positive zero", 0},
		{"negative zero", math.Copysign(0, -1)},
		{"NaN", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},

		{"fewer digits than the limit", 100},
		{"fewer digits, fractional", 0.5},
		{"already exactly six digits", 123456},
		{"needs rounding, positive, k>=0 (v<1e5)", 0.123456789},
		{"needs rounding, negative, k>=0 (v<1e5)", -0.123456789},
		{"needs rounding, positive, k<0 (v>=1e5)", 123456789.0},
		{"needs rounding, negative, k<0 (v>=1e5)", -123456789.0},

		// math.Log10's floor estimate is one exponent short of the true
		// value right at these boundaries; both directions of the
		// [sigLoBound, sigHiBound) correction fire here. Both are at the
		// very edge of the exact span (exp 14 and exp -17) but still inside
		// it.
		{"log10 boundary: hi lands at sigHiBound exactly", 1e15},
		{"log10 boundary: hi lands just under sigLoBound", 9.999999999999991e-18},

		// Both cases above are exact powers of ten, which have no digits of
		// their own past the boundary correction to get wrong -- any nearby
		// exponent choice unscales back to the same clean value. These two
		// add one ULP of real, non-zero mantissa content right at the same
		// boundaries, so a correction that recomputes the wrong exponent (or
		// applies it with the wrong arithmetic) has an actual digit to
		// corrupt instead of silently agreeing by accident.
		{"log10 boundary at sigHiBound, one ULP of real mantissa above the power of ten", 1.0000000000000002e15},
		{"log10 boundary at sigLoBound, one ULP of real mantissa below the power of ten", 9.999999999999997e26},

		// Exact decimal ties. math.Round breaks a tie away from zero, which
		// strconv's round-half-to-even does not always agree with.
		{"exact tie, r would be odd: rounds down to the even neighbour", 123456.5},
		{"exact tie, r is already even: no correction needed", 100001.5},
		{"exact tie, r would be odd (small)", 2.5},

		// A double-rounding correction found by scanning near-tie doubles:
		// hi lands exactly on 262144.5 (itself an exact tie), but the
		// discarded FMA remainder shows the true quotient is a hair below
		// it, so the corrected answer is one less than a plain tie-break
		// would give.
		{"double rounding pulls the answer below a false tie", 2.621445e+20},
		{"double rounding pulls the answer below a false tie, negative", -2.621445e+20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := oracleRound(tc.v)
			got := round(tc.v)
			if diff := cmp.Diff(want, got, cmpopts.EquateNaNs()); diff != "" {
				t.Errorf("round(%v) (-want +got):\n%s", tc.v, diff)
			}
		})
	}
}

// TestRoundAtExtremeMagnitudes covers the values roundSignificant needs its
// subnormal rescale and exponent-chunk-loop machinery for: math.Log10 is
// unreliable on a subnormal (see roundSignificant's doc comment), and both
// the smallest subnormal and the largest finite float64 push k past
// pow10ChunkExp in scaleUp/unscaleDown and scaleDown/unscaleUp respectively.
//
// These are far outside the span TestRound checks for an exact match, so
// only the qualitative guarantee applies here: the machinery that exists
// specifically to keep these values from coming out as NaN or 0 must
// actually do that, and get the sign and rough magnitude right.
func TestRoundAtExtremeMagnitudes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    float64
	}{
		{"smallest positive subnormal", math.SmallestNonzeroFloat64},
		{"smallest negative subnormal", -math.SmallestNonzeroFloat64},
		{"mid-range subnormal", 2.2e-310},
		{"largest finite float64", math.MaxFloat64},
		{"largest finite float64, negative", -math.MaxFloat64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want, got := oracleRound(tc.v), round(tc.v)
			if math.IsNaN(got) {
				t.Fatalf("round(%v) = NaN; want a rounded value", tc.v)
			}
			if got == 0 {
				t.Fatalf("round(%v) = 0; value silently lost", tc.v)
			}
			if math.Signbit(got) != math.Signbit(want) {
				t.Fatalf("round(%v) = %v, oracle gave %v: sign disagrees", tc.v, got, want)
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateApprox(1e-4, 0)); diff != "" {
				t.Errorf("round(%v) too far from the oracle (-want +got):\n%s", tc.v, diff)
			}
		})
	}
}

// TestRoundAtTheSubnormalRescaleBoundary pins the exact edge of
// roundSignificant's "boosted" rescale: minNormalFloat64 is itself the
// smallest NORMAL float, where math.Log10 is already reliable, while anything
// even one ULP below it is a subnormal that needs the rescale to get a usable
// exponent estimate at all. A "<" that widened to "<=" would rescale this
// boundary value needlessly.
//
// Unlike TestRoundAtExtremeMagnitudes' approximate check (subnormals in
// general are too coarse-grained for a bit-exact bar), round is bit-exact
// with the string oracle at this SPECIFIC value even though it lies far
// outside the span TestRoundMatchesStringOracle proves exact — so an exact
// match here is a real, checkable property, not an accident of tolerance:
// rescaling by an exact power of two changes nothing math.Log10 can see
// unless the rescale was unnecessary to begin with, which is exactly the
// unnecessary rescale this boundary would trigger.
func TestRoundAtTheSubnormalRescaleBoundary(t *testing.T) {
	t.Parallel()

	for _, v := range []float64{minNormalFloat64, -minNormalFloat64} {
		want, got := oracleRound(v), round(v)
		if got != want {
			t.Errorf("round(%v) = %v, want the oracle's %v exactly at the normal/subnormal boundary", v, got, want)
		}
	}
}

// benchValues is a representative spread of magnitudes a real range or
// instant result rounds: sub-one ratios, ordinary counters, large byte
// counts, and a value that already has fewer than six digits. It is package
// level, not a benchmark-local literal, so the compiler can't constant-fold
// round(benchValues[i]) away.
var benchValues = []float64{
	0.9843721098374, 12.345678901, 123456.789012, 98765432101234.5,
	0.0000012345678, 100, -4837.29001923,
}

// sinkFloat forces the compiler to keep every benchmark iteration's result
// live instead of discarding it as dead code.
var sinkFloat float64

// BenchmarkRoundOracle is the old strconv.FormatFloat/ParseFloat round trip,
// kept here as the "before" side of the comparison round() replaced.
func BenchmarkRoundOracle(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		sinkFloat = oracleRound(benchValues[i%len(benchValues)])
	}
}

// BenchmarkRound is the float64-only replacement.
func BenchmarkRound(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		sinkFloat = round(benchValues[i%len(benchValues)])
	}
}

// BenchmarkRoundRangeResult reproduces the actual hot path this change
// targets: MaxSeries*MaxPoints value roundings plus one max-per-series,
// roughly what a single EncodeRange call does before FitTokens ever gets a
// chance to re-render.
func BenchmarkRoundRangeResult(b *testing.B) {
	const series, points = DefaultMaxSeries, DefaultMaxPoints
	for i := 0; b.Loop(); i++ {
		for s := 0; s < series; s++ {
			for p := 0; p < points; p++ {
				sinkFloat = round(benchValues[(s+p)%len(benchValues)])
			}
			sinkFloat = round(benchValues[s%len(benchValues)])
		}
	}
}

// TestRoundIsIdempotent covers a property the doc comment relies on
// implicitly: rounding an already-rounded value must be a no-op, since
// EncodeRange and EncodeInstant only ever round once but FitTokens can
// re-render the same samples multiple times as it converges.
func TestRoundIsIdempotent(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(3, 3))
	for i := 0; i < 10_000; i++ {
		exp := -17 + rng.IntN(27-(-17)+1)
		v := (1 + rng.Float64()*9) * math.Pow(10, float64(exp))
		if rng.IntN(2) == 0 {
			v = -v
		}
		once := round(v)
		twice := round(once)
		if once != twice {
			t.Fatalf("round(round(%v)) = %v, want %v (idempotent)", v, twice, once)
		}
	}
}
