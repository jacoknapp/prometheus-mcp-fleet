// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"time"
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

// TestFactsRefreshCannotRelabelACluster drives the PERIODIC path, not the
// helper: admission merged correctly from the start, but applyFacts once
// stored the spoke's next Describe verbatim -- so a spoke that could not
// self-select into an operator's label scope at connect time could simply
// report the coveted label sixty seconds later. The two paths must apply the
// same merge or the override is a decoration.
func TestFactsRefreshCannotRelabelACluster(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{
		FactsPollInterval: time.Hour,
		AuthoritativeLabels: func(id string) map[string]string {
			if id == "prod-eu" {
				return map[string]string{"env": "staging"}
			}
			return nil
		},
	})
	attach(t, r, newFakeSession("prod-eu", 100))
	key, sl := soleSlot(t, r, "prod-eu")

	r.applyFacts("prod-eu", key, sl, tunnel.Facts{
		Fingerprint: "poisoned",
		Changed:     true,
		Cluster: fleet.Cluster{
			DisplayName: "prod-eu",
			// The coveted label, plus a descriptive one that should survive.
			Labels: map[string]string{"env": "prod", "team": "platform"},
		},
	})

	c, ok := r.Cluster("prod-eu")
	if !ok {
		t.Fatal("cluster vanished")
	}
	if got := c.Labels["env"]; got != "staging" {
		t.Errorf(`labels["env"] = %q after a facts refresh, want the operator's "staging"`, got)
	}
	if got := c.Labels["team"]; got != "platform" {
		t.Errorf(`labels["team"] = %q, want the descriptive label kept`, got)
	}
}

// TestLiveCertSerialsReportsPerSession pins the surface the CA rotation
// evidence gate stands on: one entry per live certificate serial, sibling
// pods on different certificates both visible, and nothing once released.
func TestLiveCertSerialsReportsPerSession(t *testing.T) {
	t.Parallel()

	r := mustNew(t, Options{FactsPollInterval: time.Hour})
	if got := r.LiveCertSerials(); len(got) != 0 {
		t.Fatalf("empty registry reports %v", got)
	}

	releaseA := attach(t, r, newFakeSessionInstance("prod-eu", 100, "pod-a"))
	releaseB := attach(t, r, newFakeSessionInstance("prod-eu", 100, "pod-b"))

	want := map[string]bool{"serial-prod-eu-pod-a": true, "serial-prod-eu-pod-b": true}
	if diff := cmp.Diff(want, r.LiveCertSerials()); diff != "" {
		t.Errorf("sibling serials (-want +got):\n%s", diff)
	}

	releaseA()
	releaseB()
	if got := r.LiveCertSerials(); len(got) != 0 {
		t.Errorf("released sessions still report %v", got)
	}
}
