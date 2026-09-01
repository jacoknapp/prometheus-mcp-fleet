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
			if diff := cmp.Diff(tc.want, h.enrollmentLabels(tc.cluster)); diff != "" {
				t.Errorf("enrollmentLabels() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestEnrollmentLabelsFailOpenOnStoreError keeps a cluster visible when the
// store cannot be read. Returning nothing leaves the spoke's own labels in
// place, which is a degraded view rather than a cluster that disappears from
// every scoped key at once because of a transient API-server error.
func TestEnrollmentLabelsFailOpenOnStoreError(t *testing.T) {
	t.Parallel()

	h, sink := newKeyHub(t, &labelStub{err: errors.New("apiserver unavailable")})
	if got := h.enrollmentLabels("prod-eu-1"); got != nil {
		t.Errorf("enrollmentLabels() = %v, want nil when the store fails", got)
	}
	if sink.find("could not read enrollment labels; using the spoke's own") == nil {
		t.Error("the store failure was not logged; the labels would silently differ")
	}
}

// TestEnrollmentLabelsWithoutAStore covers the hub before its store is wired,
// which a nil check guards rather than panicking.
func TestEnrollmentLabelsWithoutAStore(t *testing.T) {
	t.Parallel()

	h := &hub{}
	if got := h.enrollmentLabels("prod-eu-1"); got != nil {
		t.Errorf("enrollmentLabels() = %v, want nil with no store", got)
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
