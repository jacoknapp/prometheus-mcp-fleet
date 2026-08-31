// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Defaults applied by [New] when the corresponding [Options] field is zero.
const (
	// DefaultFactsPollInterval is how often a live session is re-Described.
	DefaultFactsPollInterval = 60 * time.Second
	// DefaultFactsPollTimeout bounds one Describe call.
	DefaultFactsPollTimeout = 10 * time.Second
	// DefaultDisconnectGrace is how long a cluster keeps its entry, and its
	// last known facts, after its tunnel drops.
	DefaultDisconnectGrace = 5 * time.Minute
	// ReplacedReason is the close reason recorded on a session displaced by a
	// newer generation of the same spoke.
	ReplacedReason = "replaced-by-newer-session"
)

// Options configures a [Registry]. The zero value is usable: every field has a
// documented default.
type Options struct {
	// Logger receives session lifecycle and identity-mismatch events. Nil
	// discards them.
	Logger *slog.Logger
	// Metrics receives connection and certificate gauges. Nil uses
	// [NopMetrics].
	Metrics Metrics
	// FactsPollInterval is how often each live session is re-Described.
	// Defaults to [DefaultFactsPollInterval]; must not be negative.
	FactsPollInterval time.Duration
	// FactsPollTimeout bounds a single Describe. Defaults to
	// [DefaultFactsPollTimeout]; must not be negative.
	FactsPollTimeout time.Duration
	// DisconnectGrace is how long a disconnected cluster keeps its entry so
	// that an agent is told "last seen 30s ago" rather than "unknown". Zero
	// uses [DefaultDisconnectGrace]; a negative value forgets the cluster the
	// moment its tunnel drops.
	DisconnectGrace time.Duration
	// SweepInterval is how often [Registry.Run] evicts entries whose grace
	// window has elapsed. Zero uses a quarter of the effective
	// DisconnectGrace, clamped to [1s, 1m]. Read methods filter expired
	// entries regardless, so this only bounds memory, not correctness.
	SweepInterval time.Duration
	// Clock supplies the current time. Nil uses [time.Now].
	Clock func() time.Time
}

// entry is the registry's internal state for one cluster. It is never handed
// out: every read path copies out of it under the read lock.
type entry struct {
	cluster     fleet.Cluster
	session     tunnel.Session
	generation  int64
	fingerprint string
	// certSerial is the serial of the certificate that admitted this session.
	// It is written once, before the entry is published, and read-only after,
	// so it needs no lock.
	certSerial string
	// cancel stops this session's facts poller.
	cancel context.CancelFunc
}

// Registry is the hub's in-memory view of the fleet. Create one with [New].
type Registry struct {
	log     *slog.Logger
	metrics Metrics
	now     func() time.Time

	pollInterval  time.Duration
	pollTimeout   time.Duration
	grace         time.Duration
	sweepInterval time.Duration

	mu      sync.RWMutex
	entries map[string]*entry
	closed  bool

	// done is closed by Close and stops every facts poller.
	done chan struct{}
	// wg tracks the facts pollers so Close can be observed as quiescent.
	wg sync.WaitGroup
}

// New returns a Registry configured by opts. It reports an error only for a
// negative duration, which is always a configuration mistake rather than a
// runtime condition — except [Options.DisconnectGrace], where negative is the
// documented way to disable the grace window.
func New(opts Options) (*Registry, error) {
	if opts.FactsPollInterval < 0 {
		return nil, fmt.Errorf("registry: facts poll interval %s is negative", opts.FactsPollInterval)
	}
	if opts.FactsPollTimeout < 0 {
		return nil, fmt.Errorf("registry: facts poll timeout %s is negative", opts.FactsPollTimeout)
	}
	if opts.SweepInterval < 0 {
		return nil, fmt.Errorf("registry: sweep interval %s is negative", opts.SweepInterval)
	}
	r := &Registry{
		log:          opts.Logger,
		metrics:      opts.Metrics,
		now:          opts.Clock,
		pollInterval: opts.FactsPollInterval,
		pollTimeout:  opts.FactsPollTimeout,
		grace:        opts.DisconnectGrace,
		entries:      make(map[string]*entry),
		done:         make(chan struct{}),
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.metrics == nil {
		r.metrics = NopMetrics{}
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.pollInterval == 0 {
		r.pollInterval = DefaultFactsPollInterval
	}
	if r.pollTimeout == 0 {
		r.pollTimeout = DefaultFactsPollTimeout
	}
	if r.grace == 0 {
		r.grace = DefaultDisconnectGrace
	}
	if r.grace < 0 {
		r.grace = 0
	}
	r.sweepInterval = opts.SweepInterval
	if r.sweepInterval == 0 {
		r.sweepInterval = min(max(r.grace/4, time.Second), time.Minute)
	}
	return r, nil
}

// OnSession implements [tunnel.SessionHandler]. It admits a session as the
// live tunnel for its certificate's cluster and returns a release function the
// transport must call once the session ends.
//
// The session is Described before any decision is taken, because
// [tunnel.Session.Generation] reports 0 until the first Describe and the
// generation is what resolves the reconnect race. A session whose Describe
// fails is rejected with [ErrRejectedSession] rather than admitted
// unidentified: an entry with no facts is worse than no entry, since an agent
// would route a query to it.
//
// When a session already exists for the cluster, the newcomer wins only if its
// generation is greater than or equal to the incumbent's. On a win the
// incumbent is closed with reason [ReplacedReason]; on a loss the newcomer is
// rejected with [ErrStaleGeneration] and the transport should hang up. Equal
// generations resolve in favour of the newcomer because a spoke that
// re-dialled without restarting is by definition the one that believes its old
// connection is dead.
//
// ctx is used only for the admission Describe. The facts poller runs on a
// context derived from it with [context.WithoutCancel], so the poller's
// lifetime is the session's — not that of whatever scope the transport chose
// to hand OnSession — and it stops on the session's Done channel, on release,
// or on [Registry.Close].
func (r *Registry) OnSession(ctx context.Context, s tunnel.Session) (func(), error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil session", ErrRejectedSession)
	}
	ident := s.Identity()
	if ident.ClusterID == "" {
		return nil, fmt.Errorf("%w: no cluster id in client certificate", ErrRejectedSession)
	}
	id := ident.ClusterID

	r.mu.RLock()
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return nil, fmt.Errorf("%w: %w", ErrRejectedSession, ErrClosed)
	}

	dctx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	facts, err := s.Describe(dctx, "")
	cancel()
	if err != nil {
		return nil, fmt.Errorf("%w: describe %s: %w", ErrRejectedSession, id, err)
	}

	gen := s.Generation()
	if gen == 0 {
		// A transport may report the generation only in the Describe payload.
		gen = facts.Generation
	}

	cluster := r.clusterFrom(id, ident, facts.Cluster)

	pctx, pcancel := context.WithCancel(context.WithoutCancel(ctx))
	e := &entry{
		cluster:     cluster,
		session:     s,
		generation:  gen,
		fingerprint: facts.Fingerprint,
		certSerial:  ident.CertSerial,
		cancel:      pcancel,
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		pcancel()
		return nil, fmt.Errorf("%w: %w", ErrRejectedSession, ErrClosed)
	}
	prev := r.entries[id]
	if prev != nil && prev.session != nil && gen < prev.generation {
		r.mu.Unlock()
		pcancel()
		return nil, fmt.Errorf("%w: cluster %s generation %d < %d",
			ErrStaleGeneration, id, gen, prev.generation)
	}
	// A reconnect inside the grace window keeps nothing from the old entry:
	// the fresh Describe is authoritative and the identity is re-derived from
	// the certificate.
	r.entries[id] = e
	// Registering the poller under the same lock Close takes is what makes
	// Close's WaitGroup.Wait safe: an Add either precedes it or is refused.
	r.wg.Add(1)
	n := r.connectedLocked()
	r.mu.Unlock()

	if prev != nil && prev.session != nil {
		// Drain and close the displaced session outside the lock. Cancelling
		// its poller first means it cannot resurrect facts for the entry it no
		// longer owns.
		prev.cancel()
		go r.closeSession(prev.session, id, ReplacedReason)
		r.log.WarnContext(ctx, "registry: replacing session",
			"cluster", id, "old_generation", prev.generation, "new_generation", gen)
	}

	r.metrics.SpokeConnected(id, true)
	r.metrics.SpokesConnected(n)
	if !ident.CertNotAfter.IsZero() {
		r.metrics.SpokeCertExpiry(id, ident.CertNotAfter)
	}
	r.log.InfoContext(ctx, "registry: session attached",
		"cluster", id, "generation", gen, "state", string(e.cluster.State),
		"remote_addr", ident.RemoteAddr, "cert_serial", ident.CertSerial)

	go r.pollFacts(pctx, id, e, s)

	return sync.OnceFunc(func() { r.release(id, e) }), nil
}

// clusterFrom folds a Describe payload onto the certificate identity. The
// certificate always wins: a spoke that reports a different ID is logged,
// counted and overwritten, never trusted.
func (r *Registry) clusterFrom(id string, ident tunnel.Identity, reported fleet.Cluster) fleet.Cluster {
	r.noteReportedID(id, reported.ID, ident.CertSerial)
	c := copyCluster(reported)
	c.ID = id
	c.CertNotAfter = ident.CertNotAfter
	now := r.now()
	c.LastSeen = now
	c.ConnectedSince = now
	c.State = connectedState(c)
	return c
}

// noteReportedID logs and counts a self-reported cluster ID that disagrees with
// the certificate-derived one. It is called on admission *and* on every facts
// refresh: a spoke that reports the right ID once and a different one later is
// exactly the case a mismatch counter exists to surface, and the override alone
// leaves no signal. clusterID is always the certificate's value, so the metric
// label can never be steered by a spoke.
//
// Callers must not hold r.mu: this reaches [Metrics].
func (r *Registry) noteReportedID(clusterID, reported, certSerial string) {
	if reported == "" || reported == clusterID {
		return
	}
	r.log.Warn("registry: spoke reported a cluster id that its certificate does not authorize",
		"cluster", clusterID, "reported", reported, "cert_serial", certSerial)
	r.metrics.IdentityMismatch(clusterID)
}

// connectedState is the state of a cluster whose tunnel is live: connected
// when the spoke can reach its Prometheus, degraded when it cannot. A degraded
// cluster is still routable — the query will fail, but it fails with the
// spoke's reason attached, which is more useful to an agent than a silent
// omission from the fleet listing.
func connectedState(c fleet.Cluster) fleet.ClusterState {
	if c.Prometheus.Reachable {
		return fleet.StateConnected
	}
	return fleet.StateDegraded
}

// pollFacts refreshes one session's facts until the session or the registry
// ends. See the package doc for why this is one goroutine per session.
func (r *Registry) pollFacts(ctx context.Context, id string, e *entry, s tunnel.Session) {
	defer r.wg.Done()
	t := time.NewTicker(r.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.done:
			return
		case <-s.Done():
			return
		case <-t.C:
		}

		r.mu.RLock()
		fp := e.fingerprint
		r.mu.RUnlock()

		cctx, cancel := context.WithTimeout(ctx, r.pollTimeout)
		facts, err := s.Describe(cctx, fp)
		cancel()
		if err != nil {
			// Liveness belongs to the transport's keepalive, not to us: a
			// single failed Describe must not evict a cluster that is still
			// answering queries.
			r.log.WarnContext(ctx, "registry: facts poll failed", "cluster", id, "error", err)
			continue
		}
		r.applyFacts(id, e, facts)
	}
}

// applyFacts merges a Describe reply into the entry, if the entry is still the
// live one for its cluster.
func (r *Registry) applyFacts(id string, e *entry, facts tunnel.Facts) {
	if facts.Changed {
		r.noteReportedID(id, facts.Cluster.ID, e.certSerial)
	}
	now := r.now()
	r.mu.Lock()
	if r.entries[id] != e || e.session == nil {
		r.mu.Unlock()
		return
	}
	e.cluster.LastSeen = now
	if !facts.Changed {
		r.mu.Unlock()
		return
	}
	certNotAfter := e.cluster.CertNotAfter
	connectedSince := e.cluster.ConnectedSince
	c := copyCluster(facts.Cluster)
	c.ID = id
	c.CertNotAfter = certNotAfter
	c.ConnectedSince = connectedSince
	c.LastSeen = now
	c.State = connectedState(c)
	e.cluster = c
	e.fingerprint = facts.Fingerprint
	r.mu.Unlock()

	r.log.Debug("registry: facts refreshed",
		"cluster", id, "fingerprint", facts.Fingerprint, "state", string(c.State))
}

// release detaches a session. It is idempotent and is a no-op when the entry
// has already been replaced by a newer session, so a slow release from a
// displaced connection can never evict its successor.
func (r *Registry) release(id string, e *entry) {
	e.cancel()

	now := r.now()
	r.mu.Lock()
	cur, ok := r.entries[id]
	if !ok || cur != e {
		r.mu.Unlock()
		return
	}
	e.session = nil
	e.cluster.State = fleet.StateDisconnected
	e.cluster.LastSeen = now
	e.cluster.ConnectedSince = time.Time{}
	if r.grace == 0 {
		delete(r.entries, id)
	}
	n := r.connectedLocked()
	r.mu.Unlock()

	r.metrics.SpokeConnected(id, false)
	r.metrics.SpokesConnected(n)
	r.log.Info("registry: session detached", "cluster", id, "generation", e.generation)
}

// closeSession closes s, logging rather than propagating the error: nothing
// useful can be done about a failure to close a connection that is already
// being discarded.
func (r *Registry) closeSession(s tunnel.Session, id, reason string) {
	if err := s.Close(reason); err != nil {
		r.log.Warn("registry: closing session", "cluster", id, "reason", reason, "error", err)
	}
}

// Session returns the live tunnel for a cluster.
//
// The error is deliberately layered. It always satisfies
// errors.Is(err, [tunnel.ErrNotConnected]), so a caller that only wants to
// know whether it can route need test nothing else. When the cluster is not in
// the registry at all it additionally satisfies
// errors.Is(err, [ErrUnknownCluster]), which is what a caller building an
// UNKNOWN_CLUSTER tool error with did-you-mean suggestions tests for. A
// cluster inside its disconnect grace window reports only the former, and
// [Registry.Cluster] still yields its LastSeen.
func (r *Registry) Session(clusterID string) (tunnel.Session, error) {
	now := r.now()
	r.mu.RLock()
	e, ok := r.entries[clusterID]
	live := ok && r.presentLocked(e, now)
	var s tunnel.Session
	if live {
		s = e.session
	}
	r.mu.RUnlock()

	if !live {
		return nil, fmt.Errorf("cluster %s: %w",
			clusterID, errors.Join(ErrUnknownCluster, tunnel.ErrNotConnected))
	}
	if s == nil {
		return nil, fmt.Errorf("cluster %s: %w", clusterID, tunnel.ErrNotConnected)
	}
	return s, nil
}

// Cluster returns a copy of one cluster's registry entry. The second result is
// false for a cluster that has never connected or whose disconnect grace
// window has elapsed.
func (r *Registry) Cluster(clusterID string) (fleet.Cluster, bool) {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[clusterID]
	if !ok || !r.presentLocked(e, now) {
		return fleet.Cluster{}, false
	}
	return copyCluster(e.cluster), true
}

// List returns every cluster the registry knows about, ordered by ID. The
// returned slice and every map and slice reachable from it are copies.
func (r *Registry) List() []fleet.Cluster {
	return r.filter(nil)
}

// Visible returns the clusters p is authorized to reach, ordered by ID.
// Filtering happens here rather than in the caller so that a cluster the
// principal cannot see never appears in a listing, an error message or a
// did-you-mean suggestion. A nil principal, or one with no scope, sees
// nothing: [fleet.Scope] is deny-by-default.
func (r *Registry) Visible(p *fleet.Principal) []fleet.Cluster {
	if p == nil || p.Scope == nil {
		return nil
	}
	return r.filter(func(c fleet.Cluster) bool {
		return p.Scope.AllowsCluster(c.ID, c.Labels)
	})
}

// filter copies out the entries that are present and, when keep is non-nil,
// accepted by it.
func (r *Registry) filter(keep func(fleet.Cluster) bool) []fleet.Cluster {
	now := r.now()
	r.mu.RLock()
	out := make([]fleet.Cluster, 0, len(r.entries))
	for _, e := range r.entries {
		if !r.presentLocked(e, now) {
			continue
		}
		c := copyCluster(e.cluster)
		if keep != nil && !keep(c) {
			continue
		}
		out = append(out, c)
	}
	r.mu.RUnlock()
	slices.SortFunc(out, func(a, b fleet.Cluster) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// ConnectedCount reports how many clusters currently hold a live tunnel.
// Degraded clusters count: the tunnel is up, only their Prometheus is not.
func (r *Registry) ConnectedCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connectedLocked()
}

// connectedLocked counts live sessions. Callers hold at least the read lock.
func (r *Registry) connectedLocked() int {
	n := 0
	for _, e := range r.entries {
		if e.session != nil {
			n++
		}
	}
	return n
}

// presentLocked reports whether an entry should still be visible: it either
// holds a live session, or its disconnect grace window has not yet elapsed.
// Read paths apply this rather than relying on the sweeper so that visibility
// is exact even if [Registry.Run] is never started.
func (r *Registry) presentLocked(e *entry, now time.Time) bool {
	if e.session != nil {
		return true
	}
	return now.Sub(e.cluster.LastSeen) <= r.grace
}

// Run drives eviction of entries whose disconnect grace window has elapsed,
// blocking until ctx is cancelled. It does not close sessions: shutdown order
// is the composition root's, which drains MCP traffic before calling
// [Registry.Close].
func (r *Registry) Run(ctx context.Context) {
	t := time.NewTicker(r.sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.done:
			return
		case <-t.C:
			r.sweep(r.now())
		}
	}
}

// sweep drops entries whose grace window has elapsed and returns how many it
// dropped.
func (r *Registry) sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, e := range r.entries {
		if r.presentLocked(e, now) {
			continue
		}
		delete(r.entries, id)
		n++
	}
	if n > 0 {
		r.log.Debug("registry: evicted clusters past the disconnect grace window", "count", n)
	}
	return n
}

// Close closes every live session with the given reason, stops all facts
// polling and empties the registry. Subsequent [Registry.OnSession] calls are
// rejected with [ErrClosed]. It is idempotent.
func (r *Registry) Close(reason string) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	sessions := make(map[string]tunnel.Session, len(r.entries))
	for id, e := range r.entries {
		e.cancel()
		if e.session != nil {
			sessions[id] = e.session
		}
	}
	r.entries = make(map[string]*entry)
	close(r.done)
	r.mu.Unlock()

	var wg sync.WaitGroup
	for id, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.closeSession(s, id, reason)
		}()
	}
	wg.Wait()
	r.wg.Wait()

	for id := range sessions {
		r.metrics.SpokeConnected(id, false)
	}
	r.metrics.SpokesConnected(0)
	r.log.Info("registry: closed", "reason", reason, "sessions", len(sessions))
}

// copyCluster deep-copies the maps and slices reachable from a cluster so that
// a caller can never mutate registry state through a returned value.
func copyCluster(c fleet.Cluster) fleet.Cluster {
	c.Labels = maps.Clone(c.Labels)
	c.Prometheus.ExternalLabels = maps.Clone(c.Prometheus.ExternalLabels)
	c.Prometheus.Jobs = slices.Clone(c.Prometheus.Jobs)
	c.Prometheus.Namespaces = slices.Clone(c.Prometheus.Namespaces)
	c.Prometheus.MetricPrefixes = slices.Clone(c.Prometheus.MetricPrefixes)
	return c
}
