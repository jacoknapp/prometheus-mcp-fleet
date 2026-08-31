// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// peerCounter reports how many hub replicas are running, by resolving a
// headless Service.
//
// Why DNS rather than the Kubernetes API: a headless Service publishes one A
// record per ready pod, so counting them needs no RBAC, no ServiceAccount
// permissions and no k8s.io/client-go — which this project does not depend on
// and does not intend to. The hub already has a minimal stdlib Kubernetes
// client for its state Secret; adding an EndpointSlice watch would mean new
// RBAC on every install for a number that DNS already publishes.
//
// The count exists to make multi-replica HA work behind ONE Ingress hostname.
// A tunnel terminates on exactly one replica and there is no hub-to-hub
// forwarding, so a spoke has to hold a tunnel to every replica. Told how many
// there are, a spoke can dial the same hostname repeatedly and stop once it has
// seen every distinct ServerID. Without it, HA needs a hostname per replica.
type peerCounter struct {
	domain  string
	resolve func(ctx context.Context, host string) ([]string, error)
	ttl     time.Duration
	now     func() time.Time
	log     *slog.Logger

	mu       sync.Mutex
	count    int
	fetched  time.Time
	inFlight bool
}

// peerCacheTTL bounds how stale a replica count may be.
//
// Short enough that a scale-up is picked up within a few tunnel dials, long
// enough that a hundred spokes reconnecting after a hub restart do not turn
// into a DNS query per handshake. Resolution also happens off the handshake
// path: a stale value is served while a refresh runs.
const peerCacheTTL = 15 * time.Second

// newPeerCounter builds a counter for a headless Service FQDN. An empty domain
// yields a counter that always reports zero, which advertises nothing and
// leaves spokes on one tunnel per configured endpoint.
func newPeerCounter(domain string, log *slog.Logger) *peerCounter {
	return &peerCounter{
		domain:  domain,
		resolve: net.DefaultResolver.LookupHost,
		ttl:     peerCacheTTL,
		now:     time.Now,
		log:     log,
	}
}

// Count returns the cached replica count, refreshing in the background when the
// cache is stale.
//
// It never blocks the caller on DNS. This runs inside a tunnel handshake, and a
// resolver that has become slow must not turn every spoke's reconnection into a
// timeout — an out-of-date count costs a spoke one extra dial, whereas a stalled
// handshake costs it the tunnel.
func (p *peerCounter) Count() int {
	if p == nil || p.domain == "" {
		return 0
	}
	p.mu.Lock()
	fresh := p.now().Sub(p.fetched) < p.ttl
	count := p.count
	start := !fresh && !p.inFlight
	if start {
		p.inFlight = true
	}
	p.mu.Unlock()

	if start {
		go p.refresh()
	}
	return count
}

// refresh resolves the domain and replaces the cached count.
func (p *peerCounter) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := p.resolve(ctx, p.domain)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight = false
	if err != nil {
		// Keep the previous count rather than dropping to zero. Zero means "no
		// idea", which would tell every spoke to stop dialing for full
		// coverage; a momentary NXDOMAIN during a rolling update must not
		// silently collapse the fleet onto one replica.
		p.log.Debug("peer discovery failed; keeping the previous replica count",
			"domain", p.domain, "count", p.count, "error", err)
		p.fetched = p.now()
		return
	}
	unique := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		unique[a] = struct{}{}
	}
	if len(unique) != p.count {
		p.log.Info("hub replica count changed",
			"domain", p.domain, "from", p.count, "to", len(unique))
	}
	p.count = len(unique)
	p.fetched = p.now()
}
