// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseClusterLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
		reason  string
	}{
		{name: "empty", in: "", want: nil},
		{name: "whitespace only", in: "   ", want: nil},
		{name: "single", in: "env=prod", want: map[string]string{"env": "prod"}},
		{
			name: "several with spaces",
			in:   " env = prod , region=us-east-1 ,tier=web",
			want: map[string]string{"env": "prod", "region": "us-east-1", "tier": "web"},
		},
		{name: "underscore key", in: "_internal=1", want: map[string]string{"_internal": "1"}},
		{name: "empty value is allowed", in: "env=", want: map[string]string{"env": ""}},
		{name: "value may contain equals", in: "expr=a=b", want: map[string]string{"expr": "a=b"}},
		{name: "value may contain spaces", in: "owner=platform team", want: map[string]string{"owner": "platform team"}},
		{name: "value may contain unicode", in: "site=münchen", want: map[string]string{"site": "münchen"}},
		{name: "no equals", in: "env", wantErr: true, reason: "k=v form"},
		{name: "empty key", in: "=prod", wantErr: true, reason: "empty label key"},
		{name: "whitespace key", in: "  =prod", wantErr: true, reason: "empty label key"},
		{name: "empty pair", in: "env=prod,,tier=web", wantErr: true, reason: "empty label pair"},
		{name: "trailing comma", in: "env=prod,", wantErr: true, reason: "empty label pair"},
		{name: "duplicate key", in: "env=prod,env=dev", wantErr: true, reason: "duplicate label key"},
		{name: "key starts with digit", in: "1env=prod", wantErr: true, reason: "must match"},
		{name: "key with dash", in: "my-env=prod", wantErr: true, reason: "must match"},
		{name: "key with dot", in: "my.env=prod", wantErr: true, reason: "must match"},
		{name: "control character in value", in: "env=pr\x1bod", wantErr: true, reason: "control character"},
		{name: "newline in value", in: "env=pr\nod", wantErr: true, reason: "control character"},
		{
			// The control-character scan uses strings.IndexFunc and checks
			// i >= 0. A control character at byte 0 is the only input that
			// distinguishes >= 0 from the off-by-one > 0: any later character
			// satisfies both.
			name: "control character at start of value", in: "env=\x01bad",
			wantErr: true, reason: "control character",
		},
		{
			name:    "too many labels",
			in:      strings.TrimSuffix(strings.Repeat("k=v,", MaxClusterLabels+1), ","),
			wantErr: true, reason: "exceeds the limit",
		},
		{
			// Exactly at the limit must still be accepted: len(pairs) >
			// MaxClusterLabels is the check, and only this boundary
			// distinguishes > from the off-by-one >=.
			name: "exactly at the label limit is accepted",
			in:   nLabels(MaxClusterLabels),
			want: nLabelsMap(MaxClusterLabels),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseClusterLabels(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidLabels) {
					t.Fatalf("ParseClusterLabels(%q) error = %v, want ErrInvalidLabels", tc.in, err)
				}
				if !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("error %q does not mention %q", err, tc.reason)
				}
				if got != nil {
					t.Errorf("ParseClusterLabels(%q) = %v, want nil on error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseClusterLabels(%q) error = %v", tc.in, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseClusterLabels(%q) mismatch (-want +got):\n%s", tc.in, diff)
			}
		})
	}
}

// nLabels builds a "k0=v,k1=v,...,k<n-1>=v" string of n distinct, valid label
// pairs, for exercising the MaxClusterLabels boundary exactly.
func nLabels(n int) string {
	pairs := make([]string, n)
	for i := range pairs {
		pairs[i] = fmt.Sprintf("k%d=v", i)
	}
	return strings.Join(pairs, ",")
}

// nLabelsMap is the map nLabels(n) parses to.
func nLabelsMap(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("k%d", i)] = "v"
	}
	return m
}

func TestFormatClusterLabelsRoundTrips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   map[string]string
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "empty", in: map[string]string{}, want: ""},
		{name: "sorted", in: map[string]string{"tier": "web", "env": "prod"}, want: "env=prod,tier=web"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FormatClusterLabels(tc.in)
			if got != tc.want {
				t.Fatalf("FormatClusterLabels() = %q, want %q", got, tc.want)
			}
			back, err := ParseClusterLabels(got)
			if err != nil {
				t.Fatalf("re-parsing %q failed: %v", got, err)
			}
			if len(tc.in) == 0 {
				if back != nil {
					t.Errorf("re-parse of empty = %v, want nil", back)
				}
				return
			}
			if diff := cmp.Diff(tc.in, back); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateClusterLabels(t *testing.T) {
	t.Parallel()

	if err := validateClusterLabels(nil); err != nil {
		t.Errorf("validateClusterLabels(nil) = %v, want nil", err)
	}
	if err := validateClusterLabels(map[string]string{"env": "prod"}); err != nil {
		t.Errorf("validateClusterLabels(valid) = %v, want nil", err)
	}
	if err := validateClusterLabels(map[string]string{"bad key": "v"}); err == nil {
		t.Error("validateClusterLabels(bad key) = nil, want an error")
	}
	// A control character at byte 0 is the only value that distinguishes the
	// i >= 0 check from the off-by-one i > 0.
	if err := validateClusterLabels(map[string]string{"env": "\x01bad"}); err == nil {
		t.Error("validateClusterLabels(control char at start) = nil, want an error")
	}
	// len(labels) > MaxClusterLabels is the check; exactly at the limit must
	// still validate, which is the only input distinguishing > from >=.
	if err := validateClusterLabels(nLabelsMap(MaxClusterLabels)); err != nil {
		t.Errorf("validateClusterLabels(%d labels) = %v, want nil", MaxClusterLabels, err)
	}
	if err := validateClusterLabels(nLabelsMap(MaxClusterLabels + 1)); err == nil {
		t.Errorf("validateClusterLabels(%d labels) = nil, want an error", MaxClusterLabels+1)
	}
}

// TestIsControl pins the two boundaries of the C1 range explicitly: 0x7f and
// 0x9f are themselves control characters (>= and <=), while 0x7e and 0xa0,
// one step outside the range on either side, are not.
func TestIsControl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		r    rune
		want bool
	}{
		{0x1f, true},  // top of the C0 range
		{0x20, false}, // space: just outside C0
		{0x7e, false}, // just below the C1 range
		{0x7f, true},  // DEL: lower bound of the C1 range
		{0x9f, true},  // upper bound of the C1 range
		{0xa0, false}, // just above the C1 range
	}
	for _, tc := range tests {
		if got := isControl(tc.r); got != tc.want {
			t.Errorf("isControl(%#x) = %v, want %v", tc.r, got, tc.want)
		}
	}
}
