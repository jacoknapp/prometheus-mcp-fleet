// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// DefaultRevocationInterval is how often a [RevocationEnforcer] re-checks its
// live sessions when [RevocationEnforcerOptions.Interval] is zero.
//
// It is short because the thing it bounds is how long a compromised spoke
// keeps answering queries after an operator revoked its certificate on a
// different replica, and long enough that the check is free: one pass compares
// a handful of serials against an in-memory set, and only refreshes the set
// from the shared state when the revocation epoch has moved.
const DefaultRevocationInterval = 15 * time.Second

// RevocationEnforcerOptions configures [NewRevocationEnforcer]. Sessions and
// IsRevoked are required; every other field has a documented default.
type RevocationEnforcerOptions struct {
	// Sessions is the hub's live spoke sessions. Required.
	Sessions SessionCloser
	// IsRevoked reports whether a certificate serial has been revoked.
	// Required.
	//
	// Pass the same predicate the tunnel handshake consults. That one already
	// reads the shared revocation list and already refreshes itself when the
	// revocation epoch moves, so sharing it means admission and eviction can
	// never disagree about what is revoked, and a replica learns about a
	// revocation performed elsewhere through one mechanism rather than two.
	//
	// It is called with no lock held and may reach the credential store. A
	// predicate that fails closed on its cached data -- the shipped one does --
	// keeps a store outage from disconnecting the fleet.
	IsRevoked func(serial string) bool
	// Refresh, when set, is called at the top of every sweep to re-read the
	// revocation list from the store. It exists for the replica with no live
	// sessions: nothing there ever consults IsRevoked, so without this the
	// list -- and the staleness gauge that watches it -- would go stale on a
	// perfectly healthy idle replica. Errors are the predicate's own concern;
	// this call is best-effort by design.
	Refresh func(ctx context.Context)
	// Interval is how often live sessions are checked. Zero means
	// [DefaultRevocationInterval]; it must not be negative.
	Interval time.Duration
	// Logger receives the security event. Nil discards it.
	Logger *slog.Logger
	// Metrics counts the security event. Nil means [NopMetrics].
	Metrics Metrics
}

// RevocationEnforcer disconnects spokes whose certificate has been revoked.
//
// It exists because revocation is checked when a tunnel is established and
// nowhere else, so on its own it stops the next connection while the current
// one keeps serving -- potentially for the rest of the certificate's life,
// which is exactly the window an incident cares about. Closing the session at
// the moment of revocation covers the replica that served the admin request
// ([Options.Sessions]); this covers the others.
//
// It has to be a poll. A session is pinned to the hub replica that accepted
// it, there is deliberately no hub-to-hub forwarding, and the revocation list
// is the only thing all the replicas share. So each replica asks, on a short
// timer, whether any spoke it is holding has been revoked -- and asks it of
// the same cache the handshake uses, which is epoch-gated and therefore costs
// a version check rather than a list read on the overwhelming majority of
// passes.
//
// It is safe for concurrent use, and [RevocationEnforcer.Enforce] is
// idempotent: a session already closed is simply not there to close again.
type RevocationEnforcer struct {
	sessions  SessionCloser
	isRevoked func(serial string) bool
	refresh   func(ctx context.Context)
	interval  time.Duration
	log       *slog.Logger
	metrics   Metrics
}

// NewRevocationEnforcer validates opts and returns the enforcer. Nothing runs
// until [RevocationEnforcer.Run] or [RevocationEnforcer.Enforce] is called.
func NewRevocationEnforcer(opts RevocationEnforcerOptions) (*RevocationEnforcer, error) {
	switch {
	case opts.Sessions == nil:
		return nil, errors.New("hubapi: RevocationEnforcerOptions.Sessions is required")
	case opts.IsRevoked == nil:
		return nil, errors.New("hubapi: RevocationEnforcerOptions.IsRevoked is required")
	case opts.Interval < 0:
		return nil, errors.New("hubapi: RevocationEnforcerOptions.Interval is negative")
	}
	e := &RevocationEnforcer{
		sessions:  opts.Sessions,
		isRevoked: opts.IsRevoked,
		refresh:   opts.Refresh,
		interval:  opts.Interval,
		log:       opts.Logger,
		metrics:   opts.Metrics,
	}
	if e.interval == 0 {
		e.interval = DefaultRevocationInterval
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.metrics == nil {
		e.metrics = NopMetrics{}
	}
	return e, nil
}

// Run enforces revocations on a timer until ctx is cancelled. It is meant to
// be one member of the hub's run group and returns nothing: there is no
// failure mode that should take the process down, because the predicate
// already decides what to do about a store it cannot reach.
func (e *RevocationEnforcer) Run(ctx context.Context) {
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e.refresh != nil {
				// The refresh is driven from HERE, not only from handshakes:
				// on a replica with no live sessions the predicate below is
				// never consulted, the cache would never re-read the store,
				// and the staleness alert built to expose a broken store
				// would fire on a perfectly healthy idle replica -- the one
				// way to teach operators to silence it.
				e.refresh(ctx)
			}
			e.Enforce(ctx)
		}
	}
}

// Enforce runs one pass and returns one cluster ID per session it closed,
// sorted, so len is the session count. It returns nil when nothing was
// revoked, which is the ordinary case.
//
// ctx is used for the audit record only. The pass itself is not cancellable:
// once a session has been identified as revoked, abandoning the close halfway
// would leave it serving.
func (e *RevocationEnforcer) Enforce(ctx context.Context) []string {
	closed := e.sessions.CloseRevokedBy(e.isRevoked)
	if len(closed) == 0 {
		return nil
	}
	clusters := uniqueSorted(closed)
	securityEvent(ctx, e.log, e.metrics, EventSessionRevoked, systemActor, "",
		slog.Int("sessions", len(closed)),
		slog.String("clusters", strings.Join(clusters, ",")))
	return closed
}

// uniqueSorted returns the distinct values of ids, sorted. The input is one
// entry per closed session; this is the set of clusters those sessions were
// serving, which is what an audit line names.
func uniqueSorted(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
