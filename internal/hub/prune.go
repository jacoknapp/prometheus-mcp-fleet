// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"
)

// runStatePrune drops records from the state document that can no longer
// affect any decision, on a slow timer, for the whole life of the process.
//
// It exists because the hub's state lives in a Kubernetes Secret, which the
// API server caps at 1 MiB and which this build refuses to write past
// [store.MaxStateBytes]. Everything that accumulates there does so in
// proportion to fleet churn rather than fleet size: a cluster rebuilt weekly
// mints an enrollment token each time, a renewed certificate can leave a
// revocation entry, a rotated key leaves its predecessor. None of it is
// large; all of it is permanent without this.
//
// Before this ran, the ceiling was reachable and the only remedy was an
// operator working through the admin API by hand, guided by a runbook
// section -- during, most likely, the incident the full Secret had just
// caused, because the first symptom is enrollments and key mints failing.
//
// The pass is deliberately unhurried. It removes nothing a decision can
// depend on (see [store.State.Prune]), so being hours late costs nothing,
// and running rarely keeps it clear of the compare-and-swap traffic that
// matters. Every replica runs one; they collide harmlessly, because the
// loser of a CAS finds the work already done on its next pass.
func (h *hub) runStatePrune(ctx context.Context) {
	interval, retain := h.cfg.StatePruneInterval, h.cfg.StateRetention
	if interval <= 0 {
		h.logger.InfoContext(ctx, "state pruning is disabled; the state Secret will grow without bound",
			"remedy", "set --state-prune-interval, or prune by hand per the runbook")
		return
	}

	// One immediate pass, so a hub adopted with an already-crowded Secret is
	// helped at startup rather than one interval later. Every replica does
	// this at once on a rollout, and that is fine: one wins the
	// compare-and-swap, the rest re-read, find the work done and write
	// nothing. The cost is a handful of reads, once.
	h.pruneOnce(ctx, retain)

	// Jittered rather than a fixed ticker. Replicas that started together --
	// which is what a rollout produces -- would otherwise wake in lockstep
	// forever, putting their whole contention burst on the same instant of
	// every interval, and on the same instant as each other's retries. The
	// prune is not urgent to the second, so spreading it costs nothing.
	for {
		if !sleepCtx(ctx, jitterAround(interval)) {
			return
		}
		h.pruneOnce(ctx, retain)
	}
}

// jitterPercent is how far either side of the interval a prune may drift.
const jitterPercent = 20

// jitterAround returns d moved by up to ±jitterPercent, which is enough to
// pull a fleet of replicas out of lockstep without letting any of them drift
// far from the schedule an operator configured.
func jitterAround(d time.Duration) time.Duration {
	spread := int64(d) * jitterPercent / 100
	if spread <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(2*spread)-spread)
}

// sleepCtx sleeps for d, reporting false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// pruneOnce runs a single pass and reports what it removed.
func (h *hub) pruneOnce(ctx context.Context, retain time.Duration) {
	res, err := h.store.Prune(ctx, retain)
	if err != nil {
		// Not fatal, and not even a warning worth waking anybody: the state
		// is unchanged, the next pass tries again, and the size gauge is
		// what actually escalates if the document keeps growing.
		h.logger.InfoContext(ctx, "state prune did not run", "error", err)
		return
	}
	if res.Empty() {
		return
	}
	h.logger.LogAttrs(ctx, slog.LevelInfo, "pruned state records that can no longer affect a decision",
		slog.Int("keys", res.Keys),
		slog.Int("revoked_certs", res.RevokedCerts),
		slog.String("retained_for", retain.String()))
	h.metrics.StatePruned(res.Keys, res.RevokedCerts)
}
