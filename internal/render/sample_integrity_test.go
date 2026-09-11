// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

// Native histogram samples must never masquerade as float zeroes or gaps.
func TestNativeHistogramCannotBecomeFloat(t *testing.T) {
	t.Parallel()
	t.Run("instant", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeVector(json.RawMessage(`[{"metric":{"__name__":"latency"},"histogram":[1,{"count":"2","sum":"3","buckets":[]}]}]`))
		if !errors.Is(err, ErrNativeHistogram) {
			t.Fatalf("native histogram silently decoded as floats: %+v", got)
		}
	})
	t.Run("range", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeMatrix(json.RawMessage(`[{"metric":{"__name__":"latency"},"values":[[1,"4"]],"histograms":[[2,{"count":"2","sum":"3","buckets":[]}]]}]`))
		if !errors.Is(err, ErrNativeHistogram) {
			t.Fatalf("mixed float/histogram range silently lost samples: %+v", got)
		}
	})
}

func TestInclusivePointBudget(t *testing.T) {
	t.Parallel()
	for _, budget := range []int{1, 2, 10, 120} {
		t.Run(strconv.Itoa(budget), func(t *testing.T) {
			t.Parallel()
			start := time.Unix(1756400000, 0)
			end := start.Add(time.Duration(budget) * 15 * time.Second)
			step, _ := SelectStep(StepRequest{Start: start, End: end, MaxPoints: budget})
			if got := int(end.Sub(start)/step) + 1; got > budget {
				t.Fatalf("returned %d points for maxPoints=%d (step %s)", got, budget, step)
			}
		})
	}
}
