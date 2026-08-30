// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestEstimateTokens covers the estimator and its refusal to fail.
func TestEstimateTokens(t *testing.T) {
	t.Parallel()
	if got := EstimateTokens(map[string]string{}); got != 1 {
		t.Errorf(`EstimateTokens("{}") = %d, want 1`, got)
	}
	if got := EstimateTokensOfBytes(0); got != 0 {
		t.Errorf("EstimateTokensOfBytes(0) = %d", got)
	}
	if got := EstimateTokensOfBytes(-5); got != 0 {
		t.Errorf("EstimateTokensOfBytes(-5) = %d", got)
	}
	if got := EstimateTokensOfBytes(4001); got != 1001 {
		t.Errorf("EstimateTokensOfBytes(4001) = %d, want 1001 (rounds up)", got)
	}
	// A guardrail must not fail the call it exists to protect.
	if got := EstimateTokens(make(chan int)); got != 0 {
		t.Errorf("EstimateTokens of an unmarshalable value = %d, want 0", got)
	}
}

// TestFitTokens covers the convergence, the disabled case and the floor.
func TestFitTokens(t *testing.T) {
	t.Parallel()
	items := make([]string, 200)
	for i := range items {
		items[i] = fmt.Sprintf("item-%04d-with-some-padding", i)
	}
	build := func(s []string) any { return s }

	t.Run("fits already", func(t *testing.T) {
		t.Parallel()
		got, hit := FitTokens(items[:2], 10_000, build)
		if hit || len(got) != 2 {
			t.Errorf("got %d items hit=%v", len(got), hit)
		}
	})
	t.Run("shrinks to fit", func(t *testing.T) {
		t.Parallel()
		got, hit := FitTokens(items, 100, build)
		if !hit {
			t.Fatal("the ceiling did not fire")
		}
		if len(got) == 0 || len(got) >= len(items) {
			t.Fatalf("kept %d of %d", len(got), len(items))
		}
		if EstimateTokens(build(got)) > 100 {
			t.Errorf("the survivors are still %d tokens", EstimateTokens(build(got)))
		}
	})
	t.Run("disabled by a non-positive ceiling", func(t *testing.T) {
		t.Parallel()
		for _, ceiling := range []int{0, -1} {
			got, hit := FitTokens(items, ceiling, build)
			if hit || len(got) != len(items) {
				t.Errorf("ceiling %d: kept %d hit=%v", ceiling, len(got), hit)
			}
		}
	})
	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		got, hit := FitTokens([]string{}, 10, build)
		if hit || len(got) != 0 {
			t.Errorf("got %d hit=%v", len(got), hit)
		}
	})
	t.Run("nothing fits", func(t *testing.T) {
		t.Parallel()
		// A ceiling below even one item: the zero-item case is accepted, so the
		// caller still gets a result explaining why.
		got, hit := FitTokens(items, 1, build)
		if !hit {
			t.Fatal("the ceiling did not fire")
		}
		if len(got) != 0 {
			t.Errorf("kept %d items under a one-token ceiling", len(got))
		}
	})
	t.Run("converges without excessive marshalling", func(t *testing.T) {
		t.Parallel()
		calls := 0
		counting := func(s []string) any {
			calls++
			return s
		}
		if _, hit := FitTokens(items, 50, counting); !hit {
			t.Fatal("the ceiling did not fire")
		}
		// Proportional convergence, not one item at a time.
		if calls > 12 {
			t.Errorf("FitTokens marshalled %d times; it is not converging", calls)
		}
	})
}

// TestTruncateItems covers the explicit truncation contract.
func TestTruncateItems(t *testing.T) {
	t.Parallel()
	items := []int{1, 2, 3, 4, 5}

	kept, trunc := TruncateItems(items, 3, "narrow it")
	if diff := cmp.Diff([]int{1, 2, 3}, kept); diff != "" {
		t.Errorf("kept (-want +got):\n%s", diff)
	}
	want := &Truncation{Returned: 3, Total: 5, Reason: ReasonLimit, Hint: "narrow it"}
	if diff := cmp.Diff(want, trunc); diff != "" {
		t.Errorf("truncation (-want +got):\n%s", diff)
	}

	for _, limit := range []int{5, 6, 0, -1} {
		kept, trunc := TruncateItems(items, limit, "x")
		if trunc != nil {
			t.Errorf("limit %d truncated when it should not have: %+v", limit, trunc)
		}
		if len(kept) != len(items) {
			t.Errorf("limit %d kept %d items", limit, len(kept))
		}
	}
}

// TestTruncationEscalate covers the rule that the ceiling wins the reason while
// the honest total survives.
func TestTruncationEscalate(t *testing.T) {
	t.Parallel()
	fresh := (*Truncation)(nil).Escalate(4, ReasonTokenCeiling, "hint")
	want := &Truncation{
		Returned: 4, Total: 4, Reason: ReasonTokenCeiling, Hint: "hint"}
	if diff := cmp.Diff(want, fresh); diff != "" {
		t.Errorf("escalate from nil (-want +got):\n%s", diff)
	}

	existing := &Truncation{
		Returned: 20, Total: 1043, Reason: ReasonMaxSeries,
		Hint: "old hint", Selection: "top_20_by_max",
	}
	got := existing.Escalate(6, ReasonTokenCeiling, "new hint")
	if got.Reason != ReasonTokenCeiling {
		t.Errorf("reason = %q, want the constraint the caller cannot lift", got.Reason)
	}
	if got.Total != 1043 {
		t.Errorf("total = %d, want the honest 1043", got.Total)
	}
	if got.Returned != 6 || got.Hint != "new hint" || got.Selection != "top_20_by_max" {
		t.Errorf("got = %+v", got)
	}

	// An empty hint leaves the previous one in place rather than blanking it.
	kept := (&Truncation{Hint: "keep me"}).Escalate(1, ReasonLimit, "")
	if kept.Hint != "keep me" {
		t.Errorf("hint = %q", kept.Hint)
	}
}

// TestSelectionTopNByMax pins the machine-readable selection name.
func TestSelectionTopNByMax(t *testing.T) {
	t.Parallel()
	if got := SelectionTopNByMax(20); got != "top_20_by_max" {
		t.Errorf("SelectionTopNByMax(20) = %q", got)
	}
}

// TestTokenCountRegression defends the product claim.
//
// The scenario is the one in docs/adr/0012: rate(container_cpu_usage_seconds_total)
// over six hours at a fifteen-second scrape interval, matching 84 series. The
// native Prometheus JSON for that is on the order of a million tokens and fits
// in no context window that exists. The compact encoding must be smaller by at
// least an order of magnitude, and in practice is far more than that.
//
// This test is here because "10-50x more tokens" appears in the tool
// descriptions an agent reads and in the project's README. A claim a user can
// see is a claim a test should defend.
func TestTokenCountRegression(t *testing.T) {
	t.Parallel()
	const (
		seriesCount = 84
		window      = 6 * time.Hour
		scrape      = 15 * time.Second
	)
	start := baseTime
	end := start.Add(window)
	points := int(window/scrape) + 1 // 1441

	m := make(Matrix, 0, seriesCount)
	for i := range seriesCount {
		s := SeriesStream{
			Metric: map[string]string{
				"__name__":  "container_cpu_usage_seconds_total",
				"namespace": "prod",
				"job":       "kubelet",
				"container": fmt.Sprintf("app-%d", i%7),
				"pod":       fmt.Sprintf("checkout-7d9f%03d-%05d", i, i*37),
				"instance":  fmt.Sprintf("10.42.%d.%d:10250", i/250, i%250),
				"id":        fmt.Sprintf("/kubepods/burstable/pod%08x", i*2654435761),
			},
			Values: make([]Point, 0, points),
		}
		for j := range points {
			// Values with the seventeen digits of float noise Prometheus really
			// returns; the compact encoding's rounding is part of the saving.
			v := 0.43210987654321005 + float64(i)*0.01 +
				math.Sin(float64(j)/17)*0.0000173456789
			s.Values = append(s.Values, Point{
				T: float64(start.Add(time.Duration(j) * scrape).Unix()), V: v,
			})
		}
		m = append(m, s)
	}

	native, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "matrix", "result": m},
	})
	if err != nil {
		t.Fatalf("marshal native: %v", err)
	}

	// Compact, at the documented defaults: 20 series and 120 points.
	step, down := SelectStep(StepRequest{
		Start: start, End: end, ScrapeInterval: scrape, MaxPoints: DefaultMaxPoints,
	})
	compact := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: end, Step: step, Downsampled: down,
	}, Options{})
	encoded, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("marshal compact: %v", err)
	}

	nativeTokens := EstimateTokensOfBytes(len(native))
	compactTokens := EstimateTokensOfBytes(len(encoded))
	ratio := float64(nativeTokens) / float64(compactTokens)

	t.Logf("native:  %8d bytes, ~%8d estimated tokens (%d series x %d points)",
		len(native), nativeTokens, seriesCount, points)
	t.Logf("compact: %8d bytes, ~%8d estimated tokens (%d series x %d points, step %s)",
		len(encoded), compactTokens, len(compact.Series), compact.Points, down.AppliedStep)
	t.Logf("ratio:   %.1fx", ratio)

	if ratio < 10 {
		t.Errorf("compact is only %.1fx smaller than the native shape; the tool "+
			"descriptions and the README claim an order of magnitude or more", ratio)
	}
	// The whole point is that the result fits in a context window with room to
	// think, so pin that too.
	if compactTokens > DefaultTokenCeiling {
		t.Errorf("the compact encoding is ~%d tokens, above the hub ceiling of %d",
			compactTokens, DefaultTokenCeiling)
	}
	// And the reductions must be reported, not silent.
	if compact.Truncated == nil {
		t.Error("84 series were reduced to 20 without a truncation marker")
	} else if compact.Truncated.Total != seriesCount ||
		compact.Truncated.Selection != "top_20_by_max" {
		t.Errorf("truncation = %+v", compact.Truncated)
	}
	if compact.Downsampled.AppliedStep != "5m" {
		t.Errorf("appliedStep = %q, want 5m", compact.Downsampled.AppliedStep)
	}
	if compact.Downsampled.Reason != StepReasonMaxPoints {
		t.Errorf("reason = %q", compact.Downsampled.Reason)
	}
}
