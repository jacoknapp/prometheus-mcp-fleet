// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// FuzzClusterLabelsParse asserts that the label parser never panics and that
// whatever it accepts is internally consistent: every key it returns passes the
// key grammar, no value carries a control character, and the result re-parses
// to itself. PMF_CLUSTER_LABELS is operator-set rather than attacker-set, but a
// crash loop from a mistyped variable is still an outage.
func FuzzClusterLabelsParse(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		"env=prod",
		"env=prod,region=us-east-1",
		"env=",
		"=prod",
		"env",
		"env=prod,env=dev",
		"1bad=x",
		"a=b,,c=d",
		"k=v\x00",
		"k=münchen",
		"=,=,=",
		"k==v",
		",",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseClusterLabels(in)
		if err != nil {
			if got != nil {
				t.Fatalf("ParseClusterLabels(%q) returned both a map and an error", in)
			}
			return
		}
		if err := validateClusterLabels(got); err != nil {
			t.Fatalf("ParseClusterLabels(%q) accepted labels that do not validate: %v", in, err)
		}
		round, err := ParseClusterLabels(FormatClusterLabels(got))
		if err != nil {
			t.Fatalf("re-parsing formatted labels from %q failed: %v", in, err)
		}
		if len(round) != len(got) {
			t.Fatalf("round trip of %q changed the label count: %d then %d", in, len(got), len(round))
		}
		for k, v := range got {
			if round[k] != v {
				t.Fatalf("round trip of %q changed %q: %q then %q", in, k, v, round[k])
			}
		}
	})
}
