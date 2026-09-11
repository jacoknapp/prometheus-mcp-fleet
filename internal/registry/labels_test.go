// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"

	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

func TestAuthoritativeLabelFailureRejectsAdmission(t *testing.T) {
	t.Parallel()
	unavailable := errors.New("credential store unavailable")
	r := mustNew(t, Options{AuthoritativeLabels: func(context.Context, string) (map[string]string, error) {
		return nil, unavailable
	}})
	s := newFakeSession("prod-eu", 100)
	s.facts.Cluster.Labels = map[string]string{"env": "prod"}
	release, err := r.OnSession(context.Background(), s)
	if release != nil || !errors.Is(err, ErrRejectedSession) || !errors.Is(err, unavailable) {
		t.Fatalf("admission = %v, release present = %v; want rejection with lookup error", err, release != nil)
	}
	if _, ok := r.Cluster("prod-eu"); ok {
		t.Fatal("failed label verification admitted the spoke's claimed labels")
	}
}

func TestAuthoritativeLabelsRefreshIndependentlyOfSpokeFacts(t *testing.T) {
	t.Parallel()
	owned := map[string]string{"env": "staging", "operator_only": "old"}
	var lookupErr error
	r := mustNew(t, Options{
		FactsPollInterval:   time.Hour,
		AuthoritativeLabels: func(context.Context, string) (map[string]string, error) { return owned, lookupErr },
	})
	s := newFakeSession("prod-eu", 100)
	s.facts.Cluster.Labels = map[string]string{"env": "prod", "team": "platform"}
	attach(t, r, s)
	key, sl := soleSlot(t, r, "prod-eu")
	original, _ := r.Cluster("prod-eu")
	originalFP := sl.fingerprint
	changed := tunnel.Facts{Changed: true, Fingerprint: "next", Cluster: fleet.Cluster{
		Labels: map[string]string{"env": "prod", "team": "attacker"},
	}}
	lookupErr = errors.New("credential store unavailable")
	for _, facts := range []tunnel.Facts{changed, {Changed: false}} {
		r.applyFacts(t.Context(), "prod-eu", key, sl, facts)
		got, _ := r.Cluster("prod-eu")
		if diff := cmp.Diff(original, got); diff != "" {
			t.Fatalf("failed verification replaced known facts (-want +got):\n%s", diff)
		}
		if sl.fingerprint != originalFP {
			t.Fatal("failed verification advanced fingerprint and prevented retry")
		}
	}
	lookupErr = nil
	owned = map[string]string{"env": "dev"}
	r.applyFacts(t.Context(), "prod-eu", key, sl, tunnel.Facts{Changed: false})
	got, _ := r.Cluster("prod-eu")
	if diff := cmp.Diff(map[string]string{"env": "dev", "team": "platform"}, got.Labels); diff != "" {
		t.Fatalf("operator edit/delete did not apply without spoke change (-want +got):\n%s", diff)
	}
	// Successful changes must update the raw labels used for later recomputes.
	r.applyFacts(t.Context(), "prod-eu", key, sl, changed)
	changed.Cluster.Labels["team"] = "mutated-after-refresh"
	owned = nil
	r.applyFacts(t.Context(), "prod-eu", key, sl, tunnel.Facts{Changed: false})
	got, _ = r.Cluster("prod-eu")
	if diff := cmp.Diff(map[string]string{"env": "prod", "team": "attacker"}, got.Labels); diff != "" {
		t.Fatalf("raw spoke labels aliased or operator deletion retained (-want +got):\n%s", diff)
	}
}

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

			r := &Registry{authoritativeLabels: func(context.Context, string) (map[string]string, error) {
				return tc.operator, nil
			}}
			got, err := r.mergeLabels(t.Context(), "prod-eu-1", tc.reported)
			if err != nil {
				t.Fatal(err)
			}
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
	got, err := r.mergeLabels(t.Context(), "prod-eu-1", in)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(in, got); diff != "" {
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
		AuthoritativeLabels: func(_ context.Context, id string) (map[string]string, error) {
			if id == "prod-eu" {
				return map[string]string{"env": "staging"}, nil
			}
			return nil, nil
		},
	})
	attach(t, r, newFakeSession("prod-eu", 100))
	key, sl := soleSlot(t, r, "prod-eu")

	r.applyFacts(t.Context(), "prod-eu", key, sl, tunnel.Facts{
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

// A stalled authority read must end with the admission request, without
// admitting unverified labels or waiting for the store's own timeout.
func TestAuthoritativeLabelsAdmissionCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan context.Context, 1)
	r := mustNew(t, Options{AuthoritativeLabels: func(ctx context.Context, _ string) (map[string]string, error) {
		started <- ctx
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
			return nil, errors.New("label lookup did not cancel")
		}
	}})
	t.Cleanup(func() { r.Close("test cleanup") })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.OnSession(ctx, newFakeSession("prod-eu", 100))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("admission did not reach label lookup")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrRejectedSession) {
			t.Fatalf("admission error = %v, want rejected cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admission remained blocked after cancellation")
	}
	if _, ok := r.Cluster("prod-eu"); ok {
		t.Fatal("canceled lookup admitted unverified labels")
	}
}

func TestAuthoritativeLabelsPollCancellation(t *testing.T) {
	t.Parallel()
	for _, stop := range []string{"release", "shutdown", "deadline"} {
		t.Run(stop, func(t *testing.T) {
			t.Parallel()
			started := make(chan context.Context, 1)
			calls := 0 // Admission precedes the single facts poller.
			r := mustNew(t, Options{
				FactsPollInterval: time.Millisecond,
				FactsPollTimeout:  100 * time.Millisecond,
				AuthoritativeLabels: func(ctx context.Context, _ string) (map[string]string, error) {
					calls++
					if calls == 1 {
						return map[string]string{"env": "verified"}, nil
					}
					select {
					case started <- ctx:
					default:
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(3 * time.Second):
						return nil, errors.New("label lookup did not cancel")
					}
				},
			})
			t.Cleanup(func() { r.Close("test cleanup") })
			release := attach(t, r, newFakeSession("prod-eu", 100))
			var lookup context.Context
			select {
			case lookup = <-started:
			case <-time.After(time.Second):
				t.Fatal("facts poll did not reach label lookup")
			}
			switch stop {
			case "release":
				release()
			case "shutdown":
				r.Close("test shutdown")
			}
			select {
			case <-lookup.Done():
				want := context.Canceled
				if stop == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(lookup.Err(), want) {
					t.Fatalf("lookup error = %v, want %v", lookup.Err(), want)
				}
			case <-time.After(time.Second):
				t.Fatal("facts label lookup remained blocked")
			}
			if stop == "deadline" {
				c, ok := r.Cluster("prod-eu")
				if !ok || c.Labels["env"] != "verified" {
					t.Fatal("failed refresh lost verified labels")
				}
			}
		})
	}
}
