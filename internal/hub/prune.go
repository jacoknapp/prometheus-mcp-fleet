// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"log/slog"
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
	// helped at startup rather than one interval later.
	h.pruneOnce(ctx, retain)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.pruneOnce(ctx, retain)
		}
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
