// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// revoke records a revocation with an expiry far enough out that it is still
// meaningful.
func revoke(t *testing.T, st store.Store, serial string) {
	t.Helper()
	if err := st.RevokeCert(context.Background(), store.RevokedCert{
		Serial:    serial,
		RevokedAt: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		Reason:    "decommissioned",
	}); err != nil {
		t.Fatalf("revoke %s: %v", serial, err)
	}
}

func TestRevokedSerialsLoadsTheDenylistBeforeServing(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	revoke(t, st, "0a0b0c")
	h := &hub{store: st}

	isRevoked, err := h.revokedSerials(context.Background())
	if err != nil {
		t.Fatalf("revokedSerials: %v", err)
	}
	if !isRevoked("0a0b0c") {
		t.Fatal("a revoked serial was not recognised")
	}
	if isRevoked("ffffff") {
		t.Fatal("an unrevoked serial was refused")
	}
}

func TestRevokedSerialsRefusesToStartWithAnUnreadableDenylist(t *testing.T) {
	t.Parallel()

	fs := &faultyStore{Store: newFileStore(t)}
	fs.failEpoch(errors.New("the store is down"))
	h := &hub{store: fs}

	_, err := h.revokedSerials(context.Background())
	// Starting with an empty denylist would silently admit every revoked
	// spoke, so this is a startup failure rather than a warning.
	if err == nil || !strings.Contains(err.Error(), "load the revocation list") {
		t.Fatalf("error = %v, want a refusal to start", err)
	}
}

// TestRevokedSerialsCachesForItsFullConfiguredTTL proves the cache
// revokedSerials builds is seeded with a genuinely positive TTL (30 seconds),
// not zero: immediately after construction a lookup must be served from
// cache, not by re-consulting the store. An ARITHMETIC_BASE mutant turning
// "30 * time.Second" into "30 / time.Second" collapses the TTL to 0, which --
// since a lookup taken any measurable instant after fetching is never fresher
// than a 0 TTL -- would make every lookup re-hit the store.
func TestRevokedSerialsCachesForItsFullConfiguredTTL(t *testing.T) {
	t.Parallel()

	fs := &faultyStore{Store: newFileStore(t)}
	h := &hub{store: fs}
	isRevoked, err := h.revokedSerials(context.Background())
	if err != nil {
		t.Fatalf("revokedSerials: %v", err)
	}
	epochBefore, listBefore := fs.calls()

	if isRevoked("ffffff") {
		t.Fatal("an unrevoked serial was refused")
	}
	if epoch, list := fs.calls(); epoch != epochBefore || list != listBefore {
		t.Fatalf("the store was consulted (%d,%d -> %d,%d) well inside the 30s ttl",
			epochBefore, listBefore, epoch, list)
	}
}

func TestRevocationCacheReportsAFailureToListRevokedCertificates(t *testing.T) {
	t.Parallel()

	fs := &faultyStore{Store: newFileStore(t)}
	fs.failRevoked(errors.New("the store is down"))
	c := &revocationCache{store: fs, ttl: 30 * time.Second}

	if err := c.refresh(context.Background()); err == nil {
		t.Fatal("expected the list failure to surface")
	}
}

func TestRevocationCacheTreatsAPositiveHitAsAuthoritativeRegardlessOfAge(t *testing.T) {
	t.Parallel()

	base := newFileStore(t)
	revoke(t, base, "deadbeef")
	fs := &faultyStore{Store: base}
	// A zero TTL makes every entry stale, so nothing but the "already revoked"
	// rule can produce a positive answer here.
	c := &revocationCache{store: fs, ttl: 0}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	epochBefore, listBefore := fs.calls()

	if !c.isRevoked("deadbeef") {
		t.Fatal("a stale positive was not honoured; a serial never becomes un-revoked")
	}
	if epoch, list := fs.calls(); epoch != epochBefore || list != listBefore {
		t.Fatalf("the store was consulted (%d,%d -> %d,%d) for an answer already known",
			epochBefore, listBefore, epoch, list)
	}
}

func TestRevocationCacheRefreshesWhenTheEpochMoves(t *testing.T) {
	t.Parallel()

	base := newFileStore(t)
	fs := &faultyStore{Store: base}
	c := &revocationCache{store: fs, ttl: 0}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Nothing changed: the epoch is re-read but the list is not, which is the
	// point of the epoch — a fleet-wide reconnect must not re-read the whole
	// denylist per handshake.
	_, listAfterFirst := fs.calls()
	if c.isRevoked("cafe01") {
		t.Fatal("an unknown serial was refused")
	}
	if _, list := fs.calls(); list != listAfterFirst {
		t.Fatalf("the denylist was re-read (%d -> %d) although the epoch had not moved",
			listAfterFirst, list)
	}

	// A revocation bumps the epoch, and the very next handshake must see it.
	revoke(t, base, "cafe01")
	if !c.isRevoked("cafe01") {
		t.Fatal("a revocation did not take effect after the epoch moved")
	}
}

func TestRevocationCacheFailsOnStaleDataRatherThanDisconnectingTheFleet(t *testing.T) {
	t.Parallel()

	base := newFileStore(t)
	revoke(t, base, "aaaa")
	fs := &faultyStore{Store: base}
	c := &revocationCache{store: fs, ttl: 0}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	fs.failEpoch(errors.New("the store is down"))

	// A store outage must not turn into a fleet-wide disconnect: the answer
	// falls back to what was last known, and the certificate lifetime remains
	// the backstop.
	if c.isRevoked("bbbb") {
		t.Fatal("a store outage refused a spoke that was never revoked")
	}
	if !c.isRevoked("aaaa") {
		t.Fatal("a store outage forgot a revocation it already knew about")
	}
}

func TestRevocationCacheForgetsEntriesWhoseCertificateHasExpired(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	if err := st.RevokeCert(context.Background(), store.RevokedCert{
		Serial:    "expired1",
		RevokedAt: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// A revocation with no expiry recorded is kept: nothing says it is moot.
	if err := st.RevokeCert(context.Background(), store.RevokedCert{
		Serial:    "forever1",
		RevokedAt: time.Now().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	c := &revocationCache{store: st, ttl: time.Minute}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if c.isRevoked("expired1") {
		t.Fatal("an entry whose certificate has expired is still carried")
	}
	if !c.isRevoked("forever1") {
		t.Fatal("an entry with no recorded expiry was dropped")
	}
}

func TestRevocationCacheRefreshFailureLeavesTheAnswerUnchanged(t *testing.T) {
	t.Parallel()

	base := newFileStore(t)
	fs := &faultyStore{Store: base}
	c := &revocationCache{store: fs, ttl: 0}
	if err := c.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// The epoch read succeeds and the list read does not, which is the other
	// half of a partial store outage.
	revoke(t, base, "zz01")
	fs.failRevoked(errors.New("the store is down"))

	if c.isRevoked("zz01") {
		t.Fatal("a failed refresh invented a revocation")
	}
}

func TestNewTunnelServerMountsTheConfiguredPath(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--tunnel-path", "/spokes")
	h, _ := newWiredHub(t, cfg)

	srv, err := h.newTunnelServer(context.Background())
	if err != nil {
		t.Fatalf("newTunnelServer: %v", err)
	}
	if srv.Handler() == nil {
		t.Fatal("the tunnel server has no handler to mount")
	}
	if addr := srv.Listener().Addr(); !strings.Contains(addr, "/spokes") {
		t.Fatalf("listener addr = %q, want the configured tunnel path", addr)
	}
}

func TestNewTunnelServerRefusesToStartWithoutTheRevocationList(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	fs := &faultyStore{Store: h.store}
	fs.failEpoch(errors.New("the store is down"))
	h.store = fs

	if _, err := h.newTunnelServer(context.Background()); err == nil {
		t.Fatal("expected an unreadable denylist to fail startup")
	}
}

func TestNewTunnelServerRejectsANegativeSpokeLimit(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.cfg.MaxSpokes = -1

	_, err := h.newTunnelServer(context.Background())
	if err == nil || !strings.Contains(err.Error(), "build the tunnel server") {
		t.Fatalf("error = %v, want a tunnel server construction failure", err)
	}
}

// Not parallel: it swaps a package-level indirection that every other test in
// this file reads.
func TestNewTunnelServerStartsOnAHostThatCannotNameItself(t *testing.T) {
	h, _ := newWiredHub(t, newHubConfig(t))
	restore := osHostname
	osHostname = func() (string, error) { return "", errors.New("no hostname") }
	t.Cleanup(func() { osHostname = restore })

	// The replica name is diagnostic only, so losing it must cost a log line
	// rather than the whole tunnel.
	if _, err := h.newTunnelServer(context.Background()); err != nil {
		t.Fatalf("newTunnelServer: %v", err)
	}
}

// TestNewTunnelServerReportsItsHostnameOnSuccess proves the ServerHello
// carries the real hostname when osHostname succeeds, by performing a real
// handshake through the WebSocket tunnel and reading the spoke-side
// "hub_server_id" log field the handshake produces.
//
// A CONDITIONALS_NEGATION mutant on "err != nil" (guarding the clear-on-error
// branch) would invert it into "err == nil", wiping serverID to "" on every
// success instead of on failure -- silently dropping this diagnostic on every
// hub replica that can name itself, which is the common case.
//
// Not parallel: it swaps the package-level osHostname indirection.
func TestNewTunnelServerReportsItsHostnameOnSuccess(t *testing.T) {
	const clusterID = "prod"
	const hostname = "hub-replica-7"

	cfg := newHubConfig(t)
	h, _ := newWiredHub(t, cfg)

	restore := osHostname
	osHostname = func() (string, error) { return hostname, nil }
	t.Cleanup(func() { osHostname = restore })

	h.tunnel = mustTunnelServer(t, h)
	public := mustStartPublic(t, h)
	listener := h.tunnel.Listener()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.serveTunnel(ctx, listener) }()
	go h.registry.Run(ctx)

	var logBuf bytes.Buffer
	spokeLogger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	dialed := make(chan error, 1)
	go func() {
		dialed <- wstun.Dial(ctx, wstun.ClientConfig{
			URL:         "ws://" + public.Addr() + cfg.TunnelPath,
			Certificate: issueSpokeCert(t, h, clusterID),
			ClusterID:   clusterID,
			Logger:      spokeLogger,
			Generation:  time.Now().UnixNano(),
		}, &tunneltest.EchoHandler{})
	}()

	eventually(t, 15*time.Second, "the spoke to register a routable session", func() bool {
		_, err := h.registry.Session(clusterID)
		return err == nil
	})
	cancel()
	select {
	case <-dialed:
	case <-time.After(15 * time.Second):
		t.Fatal("the spoke never returned from Dial")
	}

	var got string
	for line := range strings.SplitSeq(logBuf.String(), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] == "tunnel connected" {
			got, _ = rec["hub_server_id"].(string)
		}
	}
	if got != hostname {
		t.Fatalf("hub_server_id = %q, want the hostname %q reported by osHostname", got, hostname)
	}
}
