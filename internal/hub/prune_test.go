// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
)

// seedPrunable stores one long-expired credential, which is the simplest
// record a prune is allowed to remove.
func seedPrunable(t *testing.T, h *hub, kid string) {
	t.Helper()
	now := h.clock()
	k := &fleet.Key{
		KID: kid, Class: fleet.ClassAgent, Name: kid,
		SecretHMAC: h.hasher.Sum([]byte("secret-" + kid)),
		CreatedAt:  now.Add(-365 * 24 * time.Hour),
		ExpiresAt:  now.Add(-300 * 24 * time.Hour),
	}
	if err := h.store.PutKey(context.Background(), k); err != nil {
		t.Fatalf("seed %s: %v", kid, err)
	}
}

// TestRunStatePruneSweepsAtStartup pins the immediate first pass: a hub
// adopted with an already-crowded Secret is helped when it starts, not one
// interval later -- which at the six-hour default would be most of a day.
func TestRunStatePruneSweepsAtStartup(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	cfg.StatePruneInterval = time.Hour
	cfg.StateRetention = 24 * time.Hour
	h, sink := newKeyHub(t, newFileStore(t))
	h.cfg = cfg
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))
	seedPrunable(t, h, "agent0070")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.runStatePrune(ctx) }()

	eventually(t, 5*time.Second, "the startup pass to remove the expired credential", func() bool {
		_, err := h.store.GetKey(context.Background(), "agent0070")
		return err != nil
	})
	cancel()
	<-done

	if sink.find("pruned state records that can no longer affect a decision") == nil {
		t.Error("the prune was not logged, so an operator could not tell it had run")
	}
}

// TestRunStatePruneHoldsRevocationsThroughRenewGrace pins the window the
// hub actually prunes with: retention on top of the renew grace. A revoked
// certificate can reach /renew for RenewGrace past its own expiry, and the
// revocation entry is the only thing refusing it there, so a prune keyed to
// retention alone would -- with a short retention -- hand a revoked spoke its
// identity back for the rest of the grace period.
func TestRunStatePruneHoldsRevocationsThroughRenewGrace(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	cfg.StatePruneInterval = time.Hour
	cfg.StateRetention = 0
	cfg.RenewGrace = 30 * 24 * time.Hour
	h, _ := newKeyHub(t, newFileStore(t))
	h.cfg = cfg
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))
	now := h.clock()

	// Expired ten days ago: inside the grace, still renewable, must stay.
	// Expired forty days ago: past the grace, nothing can present it, goes.
	for serial, ago := range map[string]time.Duration{"0a": 10, "0b": 40} {
		if err := h.store.RevokeCert(context.Background(), store.RevokedCert{
			Serial: serial, RevokedAt: now.Add(-50 * 24 * time.Hour),
			NotAfter: now.Add(-ago * 24 * time.Hour), Reason: "stolen",
		}); err != nil {
			t.Fatalf("RevokeCert(%s): %v", serial, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.runStatePrune(ctx) }()
	eventually(t, 5*time.Second, "the startup pass to drop the revocation past the grace", func() bool {
		left, err := h.store.ListRevokedCerts(context.Background())
		return err == nil && len(left) < 2
	})
	cancel()
	<-done

	left, err := h.store.ListRevokedCerts(context.Background())
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	var serials []string
	for _, rc := range left {
		serials = append(serials, rc.Serial)
	}
	if len(serials) != 1 || serials[0] != "0a" {
		t.Fatalf("revocations left = %v, want only 0a: it is still inside the renew grace", serials)
	}
}

// TestRunStatePruneKeepsSweepingOnItsTicker covers the loop past its startup
// pass: records that lapse while the hub is up are collected too, which is
// the case that actually keeps a long-lived fleet under the write ceiling.
func TestRunStatePruneKeepsSweepingOnItsTicker(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	cfg.StatePruneInterval = 10 * time.Millisecond
	cfg.StateRetention = 24 * time.Hour
	h, _ := newKeyHub(t, newFileStore(t))
	h.cfg = cfg
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))

	// Seeded before the loop starts, so its removal marks the startup pass
	// as definitely complete -- without that ordering the second seed could
	// race ahead of the startup pass and be collected by it instead.
	seedPrunable(t, h, "agent0072")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.runStatePrune(ctx) }()

	eventually(t, 5*time.Second, "the startup pass to remove the first record", func() bool {
		_, err := h.store.GetKey(context.Background(), "agent0072")
		return err != nil
	})

	// Only a later tick can collect this one.
	seedPrunable(t, h, "agent0073")
	eventually(t, 5*time.Second, "a later tick to remove the second record", func() bool {
		_, err := h.store.GetKey(context.Background(), "agent0073")
		return err != nil
	})
	cancel()
	<-done
}

// TestRunStatePruneDisabledSaysSo covers the off switch. Silence would be the
// wrong behaviour: an operator who set the interval to zero years ago should
// still be told at every startup that nothing is keeping the Secret in check.
func TestRunStatePruneDisabledSaysSo(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	cfg.StatePruneInterval = 0
	h, sink := newKeyHub(t, newFileStore(t))
	h.cfg = cfg
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))
	seedPrunable(t, h, "agent0071")

	// Returns immediately rather than blocking: no ticker was started.
	h.runStatePrune(context.Background())

	if _, err := h.store.GetKey(context.Background(), "agent0071"); err != nil {
		t.Errorf("pruning ran while disabled: %v", err)
	}
	if sink.find("state pruning is disabled; the state Secret will grow without bound") == nil {
		t.Error("a disabled pruner said nothing at startup")
	}
}

// TestPruneOnceToleratesAStoreFailure: the state is unchanged, the next pass
// tries again, and the size gauge is what escalates. Nothing here should
// raise an alarm on its own.
func TestPruneOnceToleratesAStoreFailure(t *testing.T) {
	t.Parallel()

	h, sink := newKeyHub(t, &keyStub{Store: newFileStore(t), pruneErr: store.ErrClosed})
	h.cfg = newHubConfig(t)
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))

	h.pruneOnce(context.Background(), time.Hour)

	rec := sink.find("state prune did not run")
	if rec == nil {
		t.Fatal("a failed prune was not reported at all")
	}
	if lvl, _ := rec["level"].(string); lvl != "INFO" {
		t.Errorf("level = %q, want INFO: a failed prune changes nothing and wakes nobody", lvl)
	}
}

// TestPruneOnceSaysNothingWhenThereIsNothingToDo keeps the ordinary case
// silent: at the six-hour default this runs four times a day forever.
func TestPruneOnceSaysNothingWhenThereIsNothingToDo(t *testing.T) {
	t.Parallel()

	h, sink := newKeyHub(t, newFileStore(t))
	h.cfg = newHubConfig(t)
	h.metrics = newMetricsAdapter(obs.NewHubMetrics(prometheus.NewRegistry()))

	h.pruneOnce(context.Background(), time.Hour)

	if sink.String() != "" {
		t.Errorf("an empty prune logged:\n%s", sink.String())
	}
}

// TestJitterAround pins the spread that keeps replicas out of lockstep: every
// value inside ±jitterPercent, both halves of the range actually used, and a
// degenerate interval returned untouched rather than turned into a negative
// sleep.
func TestJitterAround(t *testing.T) {
	t.Parallel()

	const base = time.Hour
	lo := base - base*jitterPercent/100
	hi := base + base*jitterPercent/100

	var sawBelow, sawAbove bool
	for range 2000 {
		got := jitterAround(base)
		if got < lo || got > hi {
			t.Fatalf("jitterAround(%s) = %s, outside [%s, %s]", base, got, lo, hi)
		}
		if got < base {
			sawBelow = true
		}
		if got > base {
			sawAbove = true
		}
	}
	if !sawBelow || !sawAbove {
		t.Errorf("jitter only moved one way (below=%v above=%v); replicas would stay clustered", sawBelow, sawAbove)
	}

	// Too small to spread. Returning d unchanged beats computing a negative
	// sleep out of it.
	for _, d := range []time.Duration{0, time.Nanosecond} {
		if got := jitterAround(d); got != d {
			t.Errorf("jitterAround(%s) = %s, want it returned unchanged", d, got)
		}
	}
}
