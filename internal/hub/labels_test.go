// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
)

// TestEnrollmentLabelsAreTheOperatorsIntent covers the lookup that makes an
// operator's labels authoritative over a spoke's own.
//
// Agent key scopes select clusters by label, so this decides which credentials
// can reach a cluster. It also repairs the documented quickstart, which mints a
// key scoped to env=prod and put env=prod on the enrollment token, and produced
// a key matching nothing because the token's labels stopped at the token.
func TestEnrollmentLabelsAreTheOperatorsIntent(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	grant := func(cluster string, at time.Time, labels map[string]string) *fleet.Key {
		return &fleet.Key{
			KID: cluster + at.Format("150405"), Class: fleet.ClassEnrollment,
			CreatedAt:  at,
			Enrollment: &fleet.EnrollmentGrant{ClusterID: cluster, Labels: labels},
		}
	}

	tests := []struct {
		name    string
		keys    []*fleet.Key
		cluster string
		want    map[string]string
	}{{
		name:    "the token's labels are returned",
		keys:    []*fleet.Key{grant("prod-eu-1", base, map[string]string{"env": "prod"})},
		cluster: "prod-eu-1",
		want:    map[string]string{"env": "prod"},
	}, {
		// A rebuild mints a new token; the newest is current operator intent.
		name: "the most recent token wins",
		keys: []*fleet.Key{
			grant("prod-eu-1", base, map[string]string{"env": "staging"}),
			grant("prod-eu-1", base.Add(time.Hour), map[string]string{"env": "prod"}),
		},
		cluster: "prod-eu-1",
		want:    map[string]string{"env": "prod"},
	}, {
		name:    "another cluster's labels are not borrowed",
		keys:    []*fleet.Key{grant("other", base, map[string]string{"env": "prod"})},
		cluster: "prod-eu-1",
		want:    nil,
	}, {
		// Revocation withdraws the label authority with everything else: a
		// token revoked because it leaked must not keep deciding which
		// scopes select this cluster. The next-newest live token speaks.
		name: "a revoked token's labels are withdrawn",
		keys: []*fleet.Key{
			grant("prod-eu-1", base, map[string]string{"env": "staging"}),
			func() *fleet.Key {
				k := grant("prod-eu-1", base.Add(time.Hour), map[string]string{"env": "prod"})
				at := base.Add(2 * time.Hour)
				k.RevokedAt = &at
				k.RevokedReason = "leaked"
				return k
			}(),
		},
		cluster: "prod-eu-1",
		want:    map[string]string{"env": "staging"},
	}, {
		name:    "a cluster with no token keeps its own labels",
		keys:    nil,
		cluster: "prod-eu-1",
		want:    nil,
	}, {
		name:    "an empty cluster id asks nothing of the store",
		keys:    []*fleet.Key{grant("prod-eu-1", base, map[string]string{"env": "prod"})},
		cluster: "",
		want:    nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, _ := newKeyHub(t, &labelStub{keys: tc.keys})
			got, err := h.enrollmentLabels(t.Context(), tc.cluster)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("enrollmentLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestEnrollmentLabelsFailClosedOnStoreError ensures store unavailability cannot
// remove operator label overrides and expose a cluster to a different key scope.
func TestEnrollmentLabelsFailClosedOnStoreError(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("apiserver unavailable")
	h, sink := newKeyHub(t, &labelStub{err: storeErr})
	got, err := h.enrollmentLabels(t.Context(), "prod-eu-1")
	if got != nil || !errors.Is(err, storeErr) {
		t.Errorf("enrollmentLabels() = %v, %v, want nil and store error", got, err)
	}
	if sink.find("could not read enrollment labels; retaining existing authorization") == nil {
		t.Error("the failed authorization lookup was not logged")
	}
}

// TestEnrollmentLabelsWithoutAStore covers the hub before its store is wired,
// which a nil check guards rather than panicking.
func TestEnrollmentLabelsWithoutAStore(t *testing.T) {
	t.Parallel()

	h := &hub{}
	if got, err := h.enrollmentLabels(t.Context(), "prod-eu-1"); got != nil || err != nil {
		t.Errorf("enrollmentLabels() = %v, %v, want nil, nil with no store", got, err)
	}
}

// labelStub serves a fixed set of enrollment keys.
type labelStub struct {
	store.Store
	keys []*fleet.Key
	err  error
}

func (s *labelStub) ListKeys(context.Context, fleet.KeyClass) ([]*fleet.Key, error) {
	return s.keys, s.err
}

func TestEnrollmentLabelsHonorsCallerCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan context.Context, 1)
	h, _ := newKeyHub(t, &blockingLabelStore{started: started})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.enrollmentLabels(ctx, "prod-eu-1")
		done <- err
	}()
	select {
	case lookup := <-started:
		deadline, ok := lookup.Deadline()
		if !ok || time.Until(deadline) > enrollmentLabelTimeout {
			t.Error("store lookup lost its timeout bound")
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not reach store")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lookup error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("store read continued after caller cancellation")
	}
}

type blockingLabelStore struct {
	store.Store
	started chan context.Context
}

func (s *blockingLabelStore) ListKeys(ctx context.Context, _ fleet.KeyClass) ([]*fleet.Key, error) {
	s.started <- ctx
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(3 * time.Second):
		return nil, errors.New("store read did not cancel")
	}
}
