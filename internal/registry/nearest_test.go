// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestNearest(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	for _, id := range []string{
		"prod-us-east-1", "prod-us-east-2", "prod-eu-west-1", "stage-us-east-1", "dev",
	} {
		attach(t, r, newFakeSession(id, 100))
	}

	tests := []struct {
		name string
		id   string
		n    int
		want []string
	}{
		{
			name: "a single-character typo ranks first",
			id:   "prod-us-east-l", n: 2,
			want: []string{"prod-us-east-1", "prod-us-east-2"},
		},
		{
			name: "case is ignored because ids are lower-case by grammar",
			id:   "PROD-EU-WEST-1", n: 1,
			want: []string{"prod-eu-west-1"},
		},
		{
			name: "ties break lexicographically so suggestions are stable",
			id:   "prod-us-east-", n: 2,
			want: []string{"prod-us-east-1", "prod-us-east-2"},
		},
		{
			name: "n larger than the fleet returns the whole fleet",
			id:   "dev", n: 99,
			want: []string{"dev", "prod-eu-west-1", "prod-us-east-1", "prod-us-east-2", "stage-us-east-1"},
		},
		{name: "n of zero returns nothing", id: "dev", n: 0},
		{name: "negative n returns nothing", id: "dev", n: -1},
		{
			name: "an empty guess still suggests, shortest first",
			id:   "", n: 1,
			want: []string{"dev"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := r.Nearest(tc.id, tc.n)
			if diff := cmp.Diff(tc.want, got, cmpEmptySlice()); diff != "" {
				t.Errorf("Nearest(%q, %d) (-want +got):\n%s", tc.id, tc.n, diff)
			}
		})
	}
}

// cmpEmptySlice treats a nil and an empty []string as equal, which keeps the
// "returns nothing" cases readable without asserting on an implementation
// detail of the return.
func cmpEmptySlice() cmp.Option {
	return cmp.FilterValues(
		func(a, b []string) bool { return len(a) == 0 && len(b) == 0 },
		cmp.Comparer(func(a, b []string) bool { return true }),
	)
}

// TestNearestIsBoundedOnLongInput pins the O(n*m) guard. A pathological guess
// must not turn a did-you-mean lookup into a CPU sink, and truncating rather
// than rejecting keeps the suggestion useful.
func TestNearestIsBoundedOnLongInput(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	attach(t, r, newFakeSession("prod-eu", 100))

	long := strings.Repeat("prod-eu", 10_000)
	start := time.Now()
	got := r.Nearest(long, 3)
	elapsed := time.Since(start)

	if diff := cmp.Diff([]string{"prod-eu"}, got); diff != "" {
		t.Errorf("Nearest(long) (-want +got):\n%s", diff)
	}
	// The comparison is capped at MaxNearestInputRunes runes on both sides, so
	// this is a few thousand cell updates however long the input is.
	if elapsed > time.Second {
		t.Errorf("Nearest took %s on a %d-byte input; the input bound is not being applied",
			elapsed, len(long))
	}

	// The same bound applies to a cluster id, which is capped by the enrollment
	// grammar but must not be trusted to be.
	huge := newFakeSession(strings.Repeat("z", 5_000), 100)
	attach(t, r, huge)
	if got := r.Nearest(long, 2); len(got) != 2 {
		t.Errorf("Nearest = %v, want two suggestions", got)
	}
}

func TestLevenshtein(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal", a: "prod", b: "prod", want: 0},
		{name: "empty target", a: "", b: "prod", want: 4},
		{name: "empty candidate", a: "prod", b: "", want: 4},
		{name: "both empty", a: "", b: "", want: 0},
		{name: "substitution", a: "prod", b: "pred", want: 1},
		{name: "insertion", a: "prod", b: "prods", want: 1},
		{name: "deletion", a: "prod", b: "pro", want: 1},
		{name: "transposition costs two", a: "prod", b: "pord", want: 2},
		{name: "multibyte runes count once", a: "café", b: "cafe", want: 1},
		{name: "disjoint", a: "abc", b: "xyz", want: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := levenshtein([]rune(tc.a), []rune(tc.b))
			if got != tc.want {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if rev := levenshtein([]rune(tc.b), []rune(tc.a)); rev != got {
				t.Errorf("levenshtein is not symmetric: %d vs %d", got, rev)
			}
		})
	}
}

func TestTruncateRunes(t *testing.T) {
	t.Parallel()

	if got := string(truncateRunes("abcdef", 3)); got != "abc" {
		t.Errorf("truncateRunes = %q, want abc", got)
	}
	if got := string(truncateRunes("ab", 5)); got != "ab" {
		t.Errorf("truncateRunes = %q, want ab", got)
	}
	if got := len(truncateRunes("ααααα", 2)); got != 2 {
		t.Errorf("truncateRunes counted bytes, not runes: %d", got)
	}
}

// TestNearestSkipsForgottenClusters keeps a did-you-mean suggestion from
// naming a cluster the registry no longer has.
func TestNearestSkipsForgottenClusters(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	r := mustNew(t, Options{
		FactsPollInterval: time.Hour,
		DisconnectGrace:   time.Minute,
		Clock:             clock.Now,
	})
	attach(t, r, newFakeSession("prod-eu", 100))
	release := attach(t, r, newFakeSession("prod-us", 100))
	release()

	if got := r.Nearest("prod", 5); !cmp.Equal(got, []string{"prod-eu", "prod-us"}) {
		t.Errorf("Nearest = %v, want both while prod-us is inside its grace window", got)
	}
	clock.Advance(2 * time.Minute)
	if got := r.Nearest("prod", 5); !cmp.Equal(got, []string{"prod-eu"}) {
		t.Errorf("Nearest = %v, want only the cluster that still exists", got)
	}
}
