// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
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
			name:    "too many labels",
			in:      strings.TrimSuffix(strings.Repeat("k=v,", MaxClusterLabels+1), ","),
			wantErr: true, reason: "exceeds the limit",
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
}
