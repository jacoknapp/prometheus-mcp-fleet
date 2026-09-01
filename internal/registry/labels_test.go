// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestAuthoritativeLabelsOverrideTheSpoke covers a trust boundary, not a
// convenience.
//
// Agent key scopes select clusters by label, so a label is a request to be
// reachable by whichever credentials match it. Left to the spoke, a compromised
// cluster could relabel itself `env: prod` and appear to every key scoped at
// production. Labels on the enrollment token were chosen by the operator who
// decided the cluster should exist, so they win.
//
// It also fixes the documented quickstart, which mints an agent scoped to
// `env=prod`, puts `env=prod` on the enrollment token, and previously produced
// a key that matched nothing because the token's labels never reached here.
func TestAuthoritativeLabelsOverrideTheSpoke(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		reported   map[string]string
		operator   map[string]string
		wantLabels map[string]string
	}{{
		name:       "operator labels reach a cluster that reports none",
		reported:   nil,
		operator:   map[string]string{"env": "prod", "region": "eu-west-1"},
		wantLabels: map[string]string{"env": "prod", "region": "eu-west-1"},
	}, {
		name:       "a spoke cannot relabel itself into a scope",
		reported:   map[string]string{"env": "prod"},
		operator:   map[string]string{"env": "dev"},
		wantLabels: map[string]string{"env": "dev"},
	}, {
		name:       "descriptive labels the operator did not set survive",
		reported:   map[string]string{"team": "platform"},
		operator:   map[string]string{"env": "prod"},
		wantLabels: map[string]string{"team": "platform", "env": "prod"},
	}, {
		name:       "no operator labels leaves the spoke's own in place",
		reported:   map[string]string{"env": "prod"},
		operator:   nil,
		wantLabels: map[string]string{"env": "prod"},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &Registry{authoritativeLabels: func(string) map[string]string {
				return tc.operator
			}}
			got := r.mergeLabels("prod-eu-1", tc.reported)
			if diff := cmp.Diff(tc.wantLabels, got); diff != "" {
				t.Errorf("mergeLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMergeLabelsWithoutAProvider is the single-tenant path: nothing supplies
// operator labels, so the spoke's own are returned untouched rather than
// copied.
func TestMergeLabelsWithoutAProvider(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	in := map[string]string{"env": "prod"}
	if diff := cmp.Diff(in, r.mergeLabels("prod-eu-1", in)); diff != "" {
		t.Errorf("mergeLabels() mismatch (-want +got):\n%s", diff)
	}
}
