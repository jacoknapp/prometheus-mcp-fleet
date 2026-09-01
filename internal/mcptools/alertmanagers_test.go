// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// amCredential is the credential planted in the alertmanagers fixture's
// dropped peer. An Alertmanager discovered through static configuration can
// carry basic-auth in its URL's userinfo the same way a scrape target can, so
// this string is exactly what must never reach a model.
const amCredential = "am-s3cr3t-pass"

// TestAlertmanagersBasic covers the success path and, since this is a
// security property and not just formatting, proves the credential embedded
// in the fixture's dropped peer never escapes.
func TestAlertmanagersBasic(t *testing.T) {
	t.Parallel()

	if !strings.Contains(string(fixture(t, "alertmanagers.json")), amCredential) {
		t.Fatal("the alertmanagers fixture no longer carries a credential; this test is vacuous")
	}

	h := newHarness(t)
	out, terr := h.tools.alertmanagers(ctx(t), h.p, AlertmanagersIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("alertmanagers: %v", terr)
	}
	if out.ActiveCount != 1 || out.DroppedCount != 1 {
		t.Fatalf("counts = active %d dropped %d, want 1 and 1", out.ActiveCount, out.DroppedCount)
	}
	if len(out.Alertmanagers) != 2 {
		t.Fatalf("alertmanagers = %+v, want 2", out.Alertmanagers)
	}
	if out.Alertmanagers[0].Dropped {
		t.Error("the active peer is not listed first")
	}
	if !out.Alertmanagers[1].Dropped {
		t.Error("the dropped peer was not marked dropped")
	}
	if out.Alertmanagers[0].Host != "alertmanager.monitoring.svc:9093" {
		t.Errorf("active host = %q", out.Alertmanagers[0].Host)
	}
	if out.Alertmanagers[1].Host != "old-alertmanager.monitoring.svc:9093" {
		t.Errorf("dropped host = %q", out.Alertmanagers[1].Host)
	}
	encoded := mustJSON(t, out)
	if strings.Contains(encoded, amCredential) || strings.Contains(encoded, "amuser") {
		t.Fatalf("the alertmanager credential reached the tool output:\n%s", encoded)
	}
	if diff := cmp.Diff([]string{"url"}, out.Redacted); diff != "" {
		t.Errorf("redacted fields are not named in the result (-want +got):\n%s", diff)
	}
	if out.Untrusted != render.UntrustedNotice {
		t.Error("alertmanager peers carry remote data and must be marked untrusted")
	}
}

// TestAlertmanagersUnknownCluster covers the resolveCluster failure path.
func TestAlertmanagersUnknownCluster(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if _, terr := h.tools.alertmanagers(ctx(t), h.p,
		AlertmanagersIn{Cluster: "no-such-cluster"}); terr == nil ||
		terr.Code != CodeUnknownCluster {
		t.Fatalf("terr = %v, want UNKNOWN_CLUSTER", terr)
	}
}

// TestAlertmanagersUpstreamFailure covers the status-fetch failure path.
func TestAlertmanagersUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlertmanagers), fakeResponse{err: errors.New("boom")})
	if _, terr := h.tools.alertmanagers(ctx(t), h.p,
		AlertmanagersIn{Cluster: okCluster}); terr == nil {
		t.Fatal("an upstream failure was not reported")
	}
}

// TestAlertmanagersMalformedPayload covers the decode failure path.
func TestAlertmanagersMalformedPayload(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlertmanagers),
		fakeResponse{body: []byte(`{"status":"success","data":"not an object"}`)})
	if _, terr := h.tools.alertmanagers(ctx(t), h.p,
		AlertmanagersIn{Cluster: okCluster}); terr == nil ||
		terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestAlertmanagersNoPeers covers a cluster with neither an active nor a
// dropped Alertmanager, which is the normal state for a fleet that pages
// through something other than this Prometheus.
func TestAlertmanagersNoPeers(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlertmanagers), fakeResponse{
		body: []byte(`{"status":"success","data":{"activeAlertmanagers":[],"droppedAlertmanagers":[]}}`),
	})
	out, terr := h.tools.alertmanagers(ctx(t), h.p, AlertmanagersIn{Cluster: okCluster})
	if terr != nil {
		t.Fatalf("alertmanagers: %v", terr)
	}
	if out.ActiveCount != 0 || out.DroppedCount != 0 || len(out.Alertmanagers) != 0 {
		t.Errorf("out = %+v, want an empty, non-error result", out)
	}
}
