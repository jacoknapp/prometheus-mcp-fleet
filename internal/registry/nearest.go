// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"slices"
	"strings"
)

// MaxNearestInputRunes bounds the strings compared by [Registry.Nearest].
// Levenshtein is O(n*m), and the cluster ID grammar caps a real ID at 63
// characters, so anything longer is either a typo of pathological length or an
// attempt to make a did-you-mean lookup expensive. Longer inputs are truncated
// rather than rejected: a suggestion from the first 64 runes is still useful.
const MaxNearestInputRunes = 64

// Nearest returns up to n cluster IDs closest to id by Levenshtein distance,
// nearest first, ties broken lexicographically so the same typo always yields
// the same suggestions. It exists so an UNKNOWN_CLUSTER tool error can say
// "did you mean" instead of leaving an agent to guess.
//
// Comparison is case-insensitive because cluster IDs are lower-case by
// grammar, so a capitalised guess should still match. n <= 0 returns nil.
//
// Callers that must not leak the existence of clusters the principal cannot
// see should filter [Registry.Visible] themselves; Nearest deliberately ranges
// over every known cluster, and is therefore only safe to expose to a caller
// whose scope already covers the fleet.
func (r *Registry) Nearest(id string, n int) []string {
	if n <= 0 {
		return nil
	}
	target := truncateRunes(strings.ToLower(id), MaxNearestInputRunes)

	now := r.now()
	type scored struct {
		id   string
		dist int
	}
	r.mu.RLock()
	cands := make([]scored, 0, len(r.entries))
	for cid, e := range r.entries {
		if !r.presentLocked(e, now) {
			continue
		}
		cands = append(cands, scored{
			id:   cid,
			dist: levenshtein(target, truncateRunes(strings.ToLower(cid), MaxNearestInputRunes)),
		})
	}
	r.mu.RUnlock()

	slices.SortFunc(cands, func(a, b scored) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		return strings.Compare(a.id, b.id)
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.id
	}
	return out
}

// truncateRunes returns the first max runes of s.
func truncateRunes(s string, max int) []rune {
	rs := []rune(s)
	if len(rs) > max {
		rs = rs[:max]
	}
	return rs
}

// levenshtein returns the edit distance between a and b using a single row of
// working state, so the allocation is O(min(len)) rather than O(n*m). No
// dependency, no matrix, and bounded by [MaxNearestInputRunes] at the call
// site.
func levenshtein(a, b []rune) int {
	if len(a) < len(b) {
		a, b = b, a
	}
	if len(b) == 0 {
		return len(a)
	}
	row := make([]int, len(b)+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= len(a); i++ {
		prev := row[0] // row[i-1][j-1]
		row[0] = i
		for j := 1; j <= len(b); j++ {
			cur := row[j] // row[i-1][j]
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			row[j] = min(row[j]+1, row[j-1]+1, prev+cost)
			prev = cur
		}
	}
	return row[len(b)]
}
