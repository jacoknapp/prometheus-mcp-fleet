// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import "fmt"

// Truncation reasons. This is a closed set so an agent can branch on it.
const (
	// ReasonLimit is the caller's own limit or the tool's default.
	ReasonLimit = "limit"
	// ReasonMaxSeries is the per-result series cap.
	ReasonMaxSeries = "max_series"
	// ReasonTokenCeiling is the hub-side estimated-token ceiling, which
	// overrides the caller's limit.
	ReasonTokenCeiling = "hub_token_ceiling"
	// ReasonUpstreamTruncated reports that the upstream response itself hit
	// the byte budget, so the data is incomplete before this package saw it.
	ReasonUpstreamTruncated = "upstream_response_too_large"
)

// Truncation reports a reduction that was applied to a result. It is always
// emitted when anything was dropped: a silently shortened list is how a model
// ends up confidently reporting a wrong minimum.
type Truncation struct {
	// Returned is how many items the result actually carries.
	Returned int `json:"returned"`
	// Total is how many existed before truncation. It is the honest total
	// where upstream reports one, and equals Returned plus what was dropped
	// otherwise.
	Total int `json:"total"`
	// Reason is one of the Reason constants in this package.
	Reason string `json:"reason"`
	// Hint names a concrete next action, such as narrowing a selector.
	Hint string `json:"hint,omitempty"`
	// Selection names the strategy used to choose what survived, for example
	// "top_20_by_max". It is empty when the selection was simply the first N
	// in upstream order.
	Selection string `json:"selection,omitempty"`
}

// SelectionTopNByMax names the top-N-by-maximum-value selection strategy.
//
// The strategy is named in the response rather than implied because it is
// lossy in a specific, knowable way: a series that flatlined when it should
// have spiked is precisely the one a maximum-based selection discards.
func SelectionTopNByMax(n int) string { return fmt.Sprintf("top_%d_by_max", n) }

// TruncateItems returns at most limit items and, when it dropped any, a
// [Truncation] describing what happened. A non-positive limit returns the
// input untouched. hint is copied into the Truncation and should name a
// concrete next call.
func TruncateItems[T any](items []T, limit int, hint string) ([]T, *Truncation) {
	if limit <= 0 || len(items) <= limit {
		return items, nil
	}
	return items[:limit], &Truncation{
		Returned: limit,
		Total:    len(items),
		Reason:   ReasonLimit,
		Hint:     hint,
	}
}

// Escalate records that a further reduction happened after t was produced. The
// new reason and returned count replace the old ones while Total is preserved,
// so a result cut first by a limit and then by the token ceiling reports the
// ceiling — the constraint the caller cannot lift by raising limit — and still
// reports the true total.
func (t *Truncation) Escalate(returned int, reason, hint string) *Truncation {
	if t == nil {
		return &Truncation{Returned: returned, Total: returned, Reason: reason, Hint: hint}
	}
	t.Returned = returned
	t.Reason = reason
	if hint != "" {
		t.Hint = hint
	}
	return t
}
