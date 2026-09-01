// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// prometheusRegistry names the concrete registry type the composition root
// passes around. It is an alias rather than an interface because there is
// exactly one implementation and nothing here benefits from indirection.
type prometheusRegistry = prometheus.Registry

// osHostname is indirected so the "this host cannot name itself" path can be
// exercised, following the same convention internal/ca and internal/token use
// for the syscalls they have to handle failing.
var osHostname = os.Hostname

// newTunnelServer builds the hub side of the WebSocket tunnel.
//
// There is no tunnel certificate and no tunnel listener any more. An Ingress
// terminates TLS, so the hub cannot see a client certificate and does not
// present a server one of its own: it serves plain HTTP, the tunnel is a
// WebSocket on the same listener as MCP, and mutual authentication happens
// inside the connection (ADR-0014).
//
// What survives from the old listener is the part that was never about TLS:
// the revocation predicate, consulted on every connection.
func (h *hub) newTunnelServer(ctx context.Context) (*wstun.Server, error) {
	// One predicate, shared with the revocation enforcer. Building a second
	// here would mean two independent pollers of the state Secret, two caches
	// and two epochs -- so the handshake and the eviction sweep could disagree
	// about whether a certificate is revoked, which is the one thing they must
	// not do.
	revoked, err := h.revocationPredicate(ctx)
	if err != nil {
		return nil, err
	}

	// Name the replica in the ServerHello so a spoke's logs say which hub
	// accepted it. It is diagnostic only and never authenticates anything, so
	// a host that cannot tell us its own name costs a log line, not a startup.
	serverID, err := osHostname()
	if err != nil {
		serverID = ""
	}

	// Peer discovery is what makes replicas: N work behind a single Ingress
	// hostname; see peerCounter. Nil-safe: an empty domain reports zero, which
	// advertises nothing.
	var observePeers func(int)
	if h.metrics != nil {
		observePeers = h.metrics.DiscoveredPeers
	}
	peers := newPeerCounter(h.cfg.PeerDiscoveryDomain, h.logger, observePeers)

	// Verification goes through the issuer tracker rather than straight to the
	// authority. It verifies exactly the same way and additionally records
	// which root admitted each cluster, which is the evidence the last step of
	// a CA rotation is gated on -- and the handshake is the only place the
	// spoke's leaf certificate is ever in scope.
	h.caIssuers = newCAIssuerTracker(h.authority, h.registry.LiveCertSerials)

	srv, err := wstun.NewServer(wstun.ServerConfig{
		Verify:      h.caIssuers.Verify,
		IsRevoked:   revoked,
		Logger:      h.logger,
		MaxSessions: h.cfg.MaxSpokes,
		ServerID:    serverID,
		Replicas:    h.advertisedReplicas(peers),
		Path:        h.cfg.TunnelPath,
	})
	if err != nil {
		return nil, fmt.Errorf("build the tunnel server: %w", err)
	}
	return srv, nil
}

// advertisedReplicas is what the hello tells every spoke about the fleet
// size, and the zero is meaningful: it means "unknown, keep probing".
//
// With no discovery domain configured the count is not unknown -- this
// replica coordinates with nobody, and the only replica a spoke can ever
// reach through this process is this one -- so it advertises exactly 1.
// Advertising 0 there would have every spoke probe forever for a count that
// is never coming. With discovery configured, a cold or failed cache really
// is "unknown": the spoke keeps its probe running until a populated answer
// arrives, which is what closes the bootstrap hole where the FIRST spoke to
// dial a freshly started hub heard zero, kept a single tunnel forever, and
// no alert could see it.
func (h *hub) advertisedReplicas(peers *peerCounter) func() int {
	if h.cfg.PeerDiscoveryDomain == "" {
		return func() int { return 1 }
	}
	return peers.Count
}

// revokedSerials returns a predicate consulted on every tunnel handshake.
//
// It is cached rather than read from the store per handshake: a handshake is on
// the hot path for reconnecting spokes, and a fleet-wide reconnect after a hub
// restart would otherwise hammer the credential store at exactly the moment it
// is least welcome. The cache is refreshed on a short timer and immediately
// whenever the revocation epoch moves, so a revocation takes effect within one
// refresh interval at worst.
func (h *hub) revokedSerials(ctx context.Context) (func(serial string) bool, error) {
	d := &revocationCache{store: h.store, ttl: 30 * time.Second}
	if h.metrics != nil {
		d.refreshed = h.metrics.RevocationRefreshed
	}
	if err := d.refresh(ctx); err != nil {
		return nil, fmt.Errorf("load the revocation list: %w", err)
	}
	// The enforcer ticks this on its own timer, so the list and its
	// staleness gauge stay current on a replica no spoke has dialed.
	h.revocationRefresh = func(ctx context.Context) { _ = d.refresh(ctx) }
	return d.isRevoked, nil
}

// revocationCache holds the revoked-serial set with a short time to live.
type revocationCache struct {
	store store.Store
	ttl   time.Duration
	// refreshed is told the time of every successful refresh. Nil in tests
	// that do not observe it. It is invoked while refreshM is held, which is
	// safe for a gauge setter and would self-deadlock for a callback that
	// re-entered refresh -- do not hand it anything cleverer than a Set.
	refreshed func(time.Time)

	mu       sync.RWMutex
	serials  []string
	epoch    uint64
	fetched  time.Time
	refreshM sync.Mutex
}

// isRevoked reports whether the hex serial has been revoked.
func (c *revocationCache) isRevoked(serial string) bool {
	c.mu.RLock()
	fresh := time.Since(c.fetched) < c.ttl
	revoked := slices.Contains(c.serials, serial)
	c.mu.RUnlock()

	if revoked || fresh {
		// A positive hit is authoritative regardless of age: a serial never
		// becomes un-revoked, so a stale "yes" is still correct.
		return revoked
	}

	// The predicate signature the tunnel server accepts carries no context --
	// it is consulted from inside the TLS handshake, which has none to give --
	// so this refresh is bounded by its own deadline rather than a caller's.
	//nolint:contextcheck // no inheritable context exists at this call site; see above.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.refresh(ctx); err != nil {
		// Serve the last good data rather than failing the handshake: a store
		// outage must not disconnect the entire fleet. Be precise about what
		// that trades away -- for a serial revoked DURING the outage this is
		// fail-OPEN, and the documented revocation bound holds only while
		// refreshes succeed. That is why refresh success is exported as
		// promfleet_hub_revocation_refresh_timestamp_seconds and alerted on:
		// the operator gets "revocations are not landing on this replica" as
		// a page, instead of as a forensic discovery. The certificate
		// lifetime remains the outer backstop.
		return revoked
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Contains(c.serials, serial)
}

// refresh reloads the revoked-serial set, dropping entries whose certificates
// have expired anyway.
func (c *revocationCache) refresh(ctx context.Context) error {
	c.refreshM.Lock()
	defer c.refreshM.Unlock()

	// Re-check freshness AFTER acquiring the refresh lock: a fleet-wide
	// reconnect just past the TTL queues many handshakes here, and without
	// this each of them would issue its own store round trip for a list the
	// first one already fetched.
	c.mu.RLock()
	fresh := time.Since(c.fetched) < c.ttl
	c.mu.RUnlock()
	if fresh {
		return nil
	}

	epoch, err := c.store.Epoch(ctx)
	if err != nil {
		return err
	}

	c.mu.RLock()
	unchanged := epoch == c.epoch && !c.fetched.IsZero()
	c.mu.RUnlock()
	if unchanged {
		now := time.Now()
		c.mu.Lock()
		c.fetched = now
		c.mu.Unlock()
		if c.refreshed != nil {
			c.refreshed(now)
		}
		return nil
	}

	entries, err := c.store.ListRevokedCerts(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	serials := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.NotAfter.IsZero() && now.After(e.NotAfter) {
			continue // the certificate expired; revocation is moot
		}
		serials = append(serials, e.Serial)
	}

	c.mu.Lock()
	c.serials, c.epoch, c.fetched = serials, epoch, now
	c.mu.Unlock()
	if c.refreshed != nil {
		c.refreshed(now)
	}
	return nil
}

// revocationPredicate returns the shared revocation check, building it once.
//
// It is consulted on every tunnel handshake and by the enforcer that evicts
// live sessions, and they must read the same list: a handshake that admits a
// certificate the enforcer is about to evict, or the reverse, is a flapping
// spoke nobody can explain.
func (h *hub) revocationPredicate(ctx context.Context) (func(serial string) bool, error) {
	if h.isRevoked != nil {
		return h.isRevoked, nil
	}
	fn, err := h.revokedSerials(ctx)
	if err != nil {
		return nil, err
	}
	h.isRevoked = fn
	return fn, nil
}
