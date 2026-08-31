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
	revoked, err := h.revokedSerials(ctx)
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
	peers := newPeerCounter(h.cfg.PeerDiscoveryDomain, h.logger)

	srv, err := wstun.NewServer(wstun.ServerConfig{
		Verify:      h.authority.VerifyChain,
		IsRevoked:   revoked,
		Logger:      h.logger,
		MaxSessions: h.cfg.MaxSpokes,
		ServerID:    serverID,
		Replicas:    peers.Count,
		Path:        h.cfg.TunnelPath,
	})
	if err != nil {
		return nil, fmt.Errorf("build the tunnel server: %w", err)
	}
	return srv, nil
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
	if err := d.refresh(ctx); err != nil {
		return nil, fmt.Errorf("load the revocation list: %w", err)
	}
	return d.isRevoked, nil
}

// revocationCache holds the revoked-serial set with a short time to live.
type revocationCache struct {
	store store.Store
	ttl   time.Duration

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
		// Fail closed on the data we have rather than failing the handshake.
		// A store outage must not disconnect the entire fleet; the certificate
		// lifetime remains the backstop.
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

	epoch, err := c.store.Epoch(ctx)
	if err != nil {
		return err
	}

	c.mu.RLock()
	unchanged := epoch == c.epoch && !c.fetched.IsZero()
	c.mu.RUnlock()
	if unchanged {
		c.mu.Lock()
		c.fetched = time.Now()
		c.mu.Unlock()
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
	return nil
}
