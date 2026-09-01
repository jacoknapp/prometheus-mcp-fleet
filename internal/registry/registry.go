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
	"sync/atomic"
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
	// AuthoritativeLabels returns labels an OPERATOR set for a cluster, which
	// override anything the spoke reports about itself. Nil means the spoke's
	// own labels stand alone.
	//
	// This is a trust boundary, not a convenience. Agent key scopes select
	// clusters by label, so a self-reported label is a cluster asking to be
	// visible to whichever credentials match it -- a compromised spoke could
	// relabel itself `env: prod` and appear to every key scoped at production.
	// Labels attached to the enrollment token were chosen by the operator who
	// minted it, so they are the ones that decide reachability.
	AuthoritativeLabels func(clusterID string) map[string]string
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

// entry is the registry's internal state for one cluster: a pool of sessions,
// one per spoke pod. It is never handed out: every read path copies out of it
// under the read lock.
//
// A cluster runs one pod by convention, but every Prometheus query a spoke
// serves is read-only and idempotent, so a cluster may run several pods for
// its own availability and the registry treats them as an interchangeable
// pool rather than as one pod repeatedly reconnecting. There is deliberately
// no leader election among siblings: nothing they serve needs serialising,
// and an election would add split-brain risk, lease RBAC and failover
// latency for no benefit.
type entry struct {
	// slots holds one session per spoke pod, keyed by [Registry.slotKey]. The
	// same key reconnecting is resolved by the existing generation guard
	// (recorded per slot); a different key is a sibling and gets a slot of
	// its own rather than displacing anything.
	slots map[string]*slot
	// rr is a round-robin cursor across slots, advanced by
	// [Registry.pickLocked]. It is atomic so that the hot Session() path needs
	// only the registry's read lock, matching every other read method.
	rr atomic.Uint64
	// lastCluster is the merged public view frozen at the moment the last
	// live slot left the pool. It is what the read paths serve, via
	// [Registry.presentLocked] and [Registry.mergedLocked], while slots is
	// empty and the entry is still inside its disconnect grace window.
	lastCluster fleet.Cluster
}

// slot is the registry's state for one session: one spoke pod's tunnel within
// a cluster's entry.
type slot struct {
	session     tunnel.Session
	generation  int64
	fingerprint string
	// certSerial is the serial of the certificate that admitted this session.
	// It is written once, before the slot is published, and read-only after,
	// so it needs no lock.
	certSerial string
	// cancel stops this session's facts poller.
	cancel context.CancelFunc
	// facts is this pod's own view of the cluster: its last Describe folded
	// onto its certificate identity. [Registry.mergedLocked] combines every
	// live slot's facts into the entry's public [fleet.Cluster].
	facts fleet.Cluster
}

// Registry is the hub's in-memory view of the fleet. Create one with [New].
type Registry struct {
	log     *slog.Logger
	metrics Metrics
	now     func() time.Time

	pollInterval        time.Duration
	pollTimeout         time.Duration
	grace               time.Duration
	authoritativeLabels func(string) map[string]string
	sweepInterval       time.Duration

	mu      sync.RWMutex
	entries map[string]*entry
	closed  bool

	// anonSeq mints a unique slot key for a session whose identity carries
	// neither InstanceID nor CertSerial, so that two such anonymous sessions
	// never collide into the same slot and evict each other.
	anonSeq atomic.Uint64

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
		log:                 opts.Logger,
		metrics:             opts.Metrics,
		now:                 opts.Clock,
		pollInterval:        opts.FactsPollInterval,
		pollTimeout:         opts.FactsPollTimeout,
		grace:               opts.DisconnectGrace,
		authoritativeLabels: opts.AuthoritativeLabels,
		entries:             make(map[string]*entry),
		done:                make(chan struct{}),
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

// OnSession implements [tunnel.SessionHandler]. It admits a session into its
// certificate's cluster's session pool and returns a release function the
// transport must call once the session ends.
//
// The session is Described before any decision is taken, because
// [tunnel.Session.Generation] reports 0 until the first Describe and the
// generation is what resolves the reconnect race. A session whose Describe
// fails is rejected with [ErrRejectedSession] rather than admitted
// unidentified: a slot with no facts is worse than no slot, since an agent
// would route a query to it.
//
// Which slot in the cluster's pool the session occupies is decided by
// [Registry.slotKey], derived from the certificate-authorized ClusterID plus
// the self-reported [tunnel.Identity.InstanceID] (or, absent that,
// [tunnel.Identity.CertSerial]) — never from anything that could steer it
// into colliding with, or evicting, an unrelated pod's slot.
//
// When a slot with that key already exists, the newcomer wins only if its
// generation is greater than or equal to the incumbent's — this is the same
// reconnect race as before, now scoped to one slot instead of the whole
// cluster. On a win the incumbent is closed with reason [ReplacedReason]; on a
// loss the newcomer is rejected with [ErrStaleGeneration] and the transport
// should hang up. Equal generations resolve in favour of the newcomer because
// a spoke that re-dialled without restarting is by definition the one that
// believes its old connection is dead. A session whose key names no existing
// slot is a sibling pod: it is simply added to the pool alongside whatever is
// already there, never displacing it.
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

	key := r.slotKey(ident)
	cluster := r.clusterFrom(id, ident, facts.Cluster)

	pctx, pcancel := context.WithCancel(context.WithoutCancel(ctx))
	sl := &slot{
		session:     s,
		generation:  gen,
		fingerprint: facts.Fingerprint,
		certSerial:  ident.CertSerial,
		cancel:      pcancel,
		facts:       cluster,
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		pcancel()
		return nil, fmt.Errorf("%w: %w", ErrRejectedSession, ErrClosed)
	}
	e, ok := r.entries[id]
	if !ok {
		e = &entry{slots: make(map[string]*slot, 1)}
		r.entries[id] = e
	}
	prev := e.slots[key]
	if prev != nil && gen < prev.generation {
		r.mu.Unlock()
		pcancel()
		return nil, fmt.Errorf("%w: cluster %s generation %d < %d",
			ErrStaleGeneration, id, gen, prev.generation)
	}
	// A reconnect inside the grace window (or a fresh sibling joining an
	// existing pool) keeps nothing from any prior occupant of this slot: the
	// fresh Describe is authoritative and the identity is re-derived from the
	// certificate.
	e.slots[key] = sl
	// Registering the poller under the same lock Close takes is what makes
	// Close's WaitGroup.Wait safe: an Add either precedes it or is refused.
	r.wg.Add(1)
	n := r.connectedLocked()
	poolSize := len(e.slots)
	r.mu.Unlock()

	if prev != nil {
		// Drain and close the displaced session outside the lock. Cancelling
		// its poller first means it cannot resurrect facts for the slot it no
		// longer owns.
		prev.cancel()
		go r.closeSession(prev.session, id, ReplacedReason)
		r.log.WarnContext(ctx, "registry: replacing session",
			"cluster", id, "old_generation", prev.generation, "new_generation", gen)
	}

	r.metrics.SpokeConnected(id, true)
	r.metrics.SpokesConnected(n)
	r.reportSessions(id, poolSize)
	if !ident.CertNotAfter.IsZero() {
		r.metrics.SpokeCertExpiry(id, ident.CertNotAfter)
	}
	r.log.InfoContext(ctx, "registry: session attached",
		"cluster", id, "generation", gen, "state", string(cluster.State),
		"pool_size", poolSize, "remote_addr", ident.RemoteAddr, "cert_serial", ident.CertSerial)

	go r.pollFacts(pctx, id, key, sl, s)

	return sync.OnceFunc(func() { r.release(id, key, sl) }), nil
}

// slotKey identifies which pod a session occupies within its cluster's pool.
// The same key returning is a reconnect of the same pod, subject to the
// generation guard; a different key is a sibling and gets a slot of its own.
//
// [tunnel.Identity.InstanceID] is preferred, since it is the pod's own
// self-reported identity. [tunnel.Identity.CertSerial] is the fallback for a
// spoke that leaves it empty, so a single-pod spoke still gets exactly one
// stable slot across reconnects. If both are empty the session is anonymous
// and is given a slot manufactured from a monotonic counter, so that two
// anonymous pods can never collide into the same slot and permanently evict
// each other — they simply cannot be recognised as the same pod on reconnect
// either, which is the correct, conservative behaviour for an identity the
// spoke did not provide.
func (r *Registry) slotKey(ident tunnel.Identity) string {
	if ident.InstanceID != "" {
		return "instance:" + ident.InstanceID
	}
	if ident.CertSerial != "" {
		return "cert:" + ident.CertSerial
	}
	return fmt.Sprintf("anon:%d", r.anonSeq.Add(1))
}

// clusterFrom folds a Describe payload onto the certificate identity. The
// certificate always wins: a spoke that reports a different ID is logged,
// counted and overwritten, never trusted.
func (r *Registry) clusterFrom(id string, ident tunnel.Identity, reported fleet.Cluster) fleet.Cluster {
	r.noteReportedID(id, reported.ID, ident.CertSerial)
	c := copyCluster(reported)
	c.ID = id
	c.CertNotAfter = ident.CertNotAfter
	c.Labels = r.mergeLabels(id, c.Labels)
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
func (r *Registry) pollFacts(ctx context.Context, id, key string, sl *slot, s tunnel.Session) {
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
		fp := sl.fingerprint
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
		r.applyFacts(id, key, sl, facts)
	}
}

// applyFacts merges a Describe reply into sl, if sl is still the slot
// registered under key for cluster id — i.e. it has not been displaced by a
// newer generation of the same pod.
func (r *Registry) applyFacts(id, key string, sl *slot, facts tunnel.Facts) {
	if facts.Changed {
		r.noteReportedID(id, facts.Cluster.ID, sl.certSerial)
	}
	now := r.now()
	r.mu.Lock()
	e, ok := r.entries[id]
	if !ok || e.slots[key] != sl {
		r.mu.Unlock()
		return
	}
	sl.facts.LastSeen = now
	if !facts.Changed {
		r.mu.Unlock()
		return
	}
	certNotAfter := sl.facts.CertNotAfter
	connectedSince := sl.facts.ConnectedSince
	c := copyCluster(facts.Cluster)
	c.ID = id
	c.CertNotAfter = certNotAfter
	c.ConnectedSince = connectedSince
	c.LastSeen = now
	c.State = connectedState(c)
	sl.facts = c
	sl.fingerprint = facts.Fingerprint
	r.mu.Unlock()

	r.log.Debug("registry: facts refreshed",
		"cluster", id, "fingerprint", facts.Fingerprint, "state", string(c.State))
}

// release detaches one slot from its cluster's pool. It is idempotent and is a
// no-op when the slot has already been displaced by a newer generation of the
// same pod, so a slow release from a displaced connection can never evict its
// successor.
//
// Emptying the last slot in the pool is what starts the disconnect grace
// window (or, with the window disabled, forgets the cluster immediately): a
// sibling that is still connected is left untouched, so a cluster with any
// live pod is never treated as disconnected.
func (r *Registry) release(id, key string, sl *slot) {
	sl.cancel()

	now := r.now()
	r.mu.Lock()
	e, ok := r.entries[id]
	if !ok || e.slots[key] != sl {
		r.mu.Unlock()
		return
	}
	delete(e.slots, key)
	poolSize := len(e.slots)
	if poolSize == 0 {
		last := copyCluster(sl.facts)
		last.State = fleet.StateDisconnected
		last.LastSeen = now
		last.ConnectedSince = time.Time{}
		e.lastCluster = last
		if r.grace == 0 {
			delete(r.entries, id)
		}
	}
	n := r.connectedLocked()
	r.mu.Unlock()

	r.metrics.SpokeConnected(id, poolSize > 0)
	r.metrics.SpokesConnected(n)
	r.reportSessions(id, poolSize)
	r.log.Info("registry: session detached", "cluster", id, "generation", sl.generation, "pool_size", poolSize)
}

// closeSession closes s, logging rather than propagating the error: nothing
// useful can be done about a failure to close a connection that is already
// being discarded.
func (r *Registry) closeSession(s tunnel.Session, id, reason string) {
	if err := s.Close(reason); err != nil {
		r.log.Warn("registry: closing session", "cluster", id, "reason", reason, "error", err)
	}
}

// Session returns one live tunnel for a cluster, round-robin across its pool
// of pods so load spreads over every one it is running rather than always
// landing on the same pod.
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
		s = r.pickLocked(e)
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

// pickLocked returns one live session from e's pool, round-robin across
// slots. Callers must hold at least the read lock.
//
// A slot whose session has already ended but has not yet been released — the
// transport calls the release function asynchronously from its own teardown,
// so there is a window where a dead session is still in the pool — is skipped
// rather than returned: round-robin visits every other slot first, so one
// dead sibling never starves a healthy one, and only an entirely dead pool
// yields nil, same as an empty one.
func (r *Registry) pickLocked(e *entry) tunnel.Session {
	if len(e.slots) == 0 {
		return nil
	}
	keys := make([]string, 0, len(e.slots))
	for k := range e.slots {
		keys = append(keys, k)
	}
	// Sorting gives round-robin a stable visiting order; map iteration order
	// would make "round-robin" meaningless from one call to the next.
	slices.Sort(keys)
	start := int(e.rr.Add(1) - 1)
	for i := range keys {
		s := e.slots[keys[(start+i)%len(keys)]].session
		select {
		case <-s.Done():
			continue
		default:
			return s
		}
	}
	return nil
}

// Cluster returns the merged public view of one cluster. The second result is
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
	return r.mergedLocked(clusterID, e), true
}

// mergedLocked returns entry e's public view for cluster id: while any slot is
// live, one [fleet.Cluster] merged from every live session's facts; once the
// last slot has left, the snapshot frozen for the disconnect grace window.
// Callers must hold at least the read lock.
//
// The merge exists so that a cluster running several pods for its own
// availability reads as one healthy cluster rather than as flapping copies of
// itself:
//
//   - LastSeen is the newest across sessions.
//   - ConnectedSince is the oldest live session's, so restarting one pod does
//     not make an already-stable cluster look freshly reconnected.
//   - The rest of the reported facts (DisplayName, Labels, Prometheus, ...)
//     come from whichever session refreshed most recently.
//   - The cluster is [fleet.StateConnected] as long as any live session's
//     Prometheus is reachable, and only [fleet.StateDegraded] when every one
//     of them reports it is not.
func (r *Registry) mergedLocked(id string, e *entry) fleet.Cluster {
	if len(e.slots) == 0 {
		return copyCluster(e.lastCluster)
	}
	var freshest *slot
	var lastSeen, connectedSince time.Time
	anyReachable := false
	for _, sl := range e.slots {
		if freshest == nil || sl.facts.LastSeen.After(freshest.facts.LastSeen) {
			freshest = sl
		}
		if sl.facts.LastSeen.After(lastSeen) {
			lastSeen = sl.facts.LastSeen
		}
		if connectedSince.IsZero() || sl.facts.ConnectedSince.Before(connectedSince) {
			connectedSince = sl.facts.ConnectedSince
		}
		if sl.facts.Prometheus.Reachable {
			anyReachable = true
		}
	}
	c := copyCluster(freshest.facts)
	c.ID = id
	c.LastSeen = lastSeen
	c.ConnectedSince = connectedSince
	if anyReachable {
		c.State = fleet.StateConnected
	} else {
		c.State = fleet.StateDegraded
	}
	return c
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
	for id, e := range r.entries {
		if !r.presentLocked(e, now) {
			continue
		}
		c := r.mergedLocked(id, e)
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

// ConnectedCount reports how many clusters currently hold at least one live
// tunnel. This counts clusters, not sessions, so a cluster running several
// pods for its own availability still counts once. Degraded clusters count:
// some tunnel is up, only its Prometheus is not.
func (r *Registry) ConnectedCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connectedLocked()
}

// connectedLocked counts clusters with at least one live slot in their pool.
// Callers hold at least the read lock.
func (r *Registry) connectedLocked() int {
	n := 0
	for _, e := range r.entries {
		if len(e.slots) > 0 {
			n++
		}
	}
	return n
}

// presentLocked reports whether an entry should still be visible: it either
// holds at least one live slot, or its disconnect grace window has not yet
// elapsed since the last one left. Read paths apply this rather than relying
// on the sweeper so that visibility is exact even if [Registry.Run] is never
// started.
func (r *Registry) presentLocked(e *entry, now time.Time) bool {
	if len(e.slots) > 0 {
		return true
	}
	return now.Sub(e.lastCluster.LastSeen) <= r.grace
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
	type target struct {
		id string
		s  tunnel.Session
	}
	var targets []target
	for id, e := range r.entries {
		for _, sl := range e.slots {
			sl.cancel()
			targets = append(targets, target{id, sl.session})
		}
	}
	r.entries = make(map[string]*entry)
	close(r.done)
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, tg := range targets {
		wg.Add(1)
		go func(tg target) {
			defer wg.Done()
			r.closeSession(tg.s, tg.id, reason)
		}(tg)
	}
	wg.Wait()
	r.wg.Wait()

	seen := make(map[string]bool, len(targets))
	for _, tg := range targets {
		if seen[tg.id] {
			continue
		}
		seen[tg.id] = true
		r.metrics.SpokeConnected(tg.id, false)
		r.reportSessions(tg.id, 0)
	}
	r.metrics.SpokesConnected(0)
	r.log.Info("registry: closed", "reason", reason, "sessions", len(targets))
}

// reportSessions notifies an optional [SessionsGauge] implementation of one
// cluster's current pool size. It is a no-op for [NopMetrics] and for any
// [Metrics] implementation that predates pooling and so does not implement
// the extension.
func (r *Registry) reportSessions(id string, n int) {
	if g, ok := r.metrics.(SessionsGauge); ok {
		g.SessionsPerCluster(id, n)
	}
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

// mergeLabels folds operator-set labels over whatever the spoke reported.
//
// The operator's win on collision. A spoke's own labels are useful description
// -- it knows its Prometheus version and its region -- but they are also a
// request to be selected by any agent key scoped to them, and the spoke is the
// party a compromise would control. Labels set on the enrollment token were
// chosen by whoever decided this cluster should exist.
func (r *Registry) mergeLabels(clusterID string, reported map[string]string) map[string]string {
	if r.authoritativeLabels == nil {
		return reported
	}
	owned := r.authoritativeLabels(clusterID)
	if len(owned) == 0 {
		return reported
	}
	merged := make(map[string]string, len(reported)+len(owned))
	for k, v := range reported {
		merged[k] = v
	}
	for k, v := range owned {
		merged[k] = v
	}
	return merged
}
