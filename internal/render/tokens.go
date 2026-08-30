// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import "encoding/json"

// EstimateTokens estimates how many tokens the JSON encoding of v will cost.
//
// It is bytes divided by [BytesPerToken] and it is an estimate, not a
// measurement: the hub does not ship a tokeniser, tokenisers differ between
// models, and JSON is punctuation-dense in a way that varies with the payload.
// It is used for a guardrail, where being within a factor of two is enough,
// and never for billing or for anything a caller is told is exact.
//
// A value that cannot be marshalled estimates as zero, because a guardrail
// must not fail the call it was meant to protect.
func EstimateTokens(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return EstimateTokensOfBytes(len(b))
}

// EstimateTokensOfBytes converts a serialized size to the same estimate
// [EstimateTokens] uses.
func EstimateTokensOfBytes(n int) int {
	if n <= 0 {
		return 0
	}
	return (n + BytesPerToken - 1) / BytesPerToken
}

// FitTokens shrinks items until the value build produces fits under ceiling,
// and reports whether it had to.
//
// It converges by proportion — the next candidate count is scaled by the ratio
// of the ceiling to the measured size, then decremented if that was not enough
// — so a result twenty times too large costs a handful of marshals rather than
// twenty halvings. A ceiling of zero or less disables the check.
//
// The zero-item case is always accepted even if the surrounding envelope alone
// exceeds the ceiling: refusing to return anything would leave the caller with
// no way to learn why.
func FitTokens[T any](items []T, ceiling int, build func([]T) any) ([]T, bool) {
	if ceiling <= 0 || len(items) == 0 {
		return items, false
	}
	n := len(items)
	if EstimateTokens(build(items)) <= ceiling {
		return items, false
	}
	for n > 0 {
		size := EstimateTokens(build(items[:n]))
		if size <= ceiling {
			return items[:n], true
		}
		next := n * ceiling / max(size, 1)
		n = next
	}
	return items[:0], true
}
