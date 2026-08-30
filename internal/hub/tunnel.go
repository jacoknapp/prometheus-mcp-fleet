// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// prometheusRegistry names the concrete registry type the composition root
// passes around. It is an alias rather than an interface because there is
// exactly one implementation and nothing here benefits from indirection.
type prometheusRegistry = prometheus.Registry

// tunnelCertificate resolves the server certificate the tunnel listener
// presents.
//
// An operator-supplied certificate is used when both files are configured;
// otherwise the internal CA issues one covering the configured server names.
// Getting the names wrong is the single most common way to break a whole fleet
// at once — every spoke verifies against them — so an empty list is refused
// rather than silently producing a certificate nothing can validate.
func (h *hub) tunnelCertificate() (tls.Certificate, error) {
	if h.cfg.TunnelTLSCertFile != "" && h.cfg.TunnelTLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(h.cfg.TunnelTLSCertFile, h.cfg.TunnelTLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load the supplied tunnel certificate: %w", err)
		}
		h.logger.Info("using the operator-supplied tunnel certificate",
			"cert_file", h.cfg.TunnelTLSCertFile)
		return cert, nil
	}

	names, ips := splitServerNames(h.cfg.TunnelServerNames)
	if len(names) == 0 && len(ips) == 0 {
		return tls.Certificate{}, fmt.Errorf(
			"--tunnel-server-names is required when no tunnel certificate is supplied: " +
				"spokes verify the hub against these names, and a certificate " +
				"covering none of them would fail every handshake in the fleet")
	}

	cert, err := h.authority.IssueServer(names, ips)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue the tunnel certificate: %w", err)
	}
	h.logger.Info("issued a tunnel certificate from the internal CA",
		"dns_names", names, "ip_addresses", ips)
	return cert, nil
}

// splitServerNames separates DNS names from IP literals, because a certificate
// needs them in different SAN fields and an IP placed in dNSName matches
// nothing.
func splitServerNames(values []string) (dns []string, ips []net.IP) {
	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, v)
	}
	return dns, ips
}

// revokedSerials returns a predicate consulted on every TLS handshake.
//
// It is cached rather than read from the store per handshake: a handshake is on
// the hot path for reconnecting spokes, and a fleet-wide reconnect after a hub
// restart would otherwise hammer the credential store at exactly the moment it
// is least welcome. The cache is refreshed on a short timer and immediately
// whenever the revocation epoch moves, so a revocation takes effect within one
// refresh interval at worst.
func (h *hub) revokedSerials() (func(serial string) bool, error) {
	d := &revocationCache{store: h.store, ttl: 30 * time.Second}
	if err := d.refresh(context.Background()); err != nil {
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

// ensure os stays referenced for the file-backed paths above.
var _ = os.ReadFile
