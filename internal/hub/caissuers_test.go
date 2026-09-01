// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/memtun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
)

// stubAuthority is a caAuthority whose two halves can disagree, which no real
// CA can: it exists to reach the branch where a chain verifies but no root in
// the bundle claims the leaf.
type stubAuthority struct {
	identity tunnel.Identity
	verifyer error
	issuer   string
	issuerOK bool
}

func (s stubAuthority) VerifyChain([]*x509.Certificate) (tunnel.Identity, error) {
	return s.identity, s.verifyer
}

func (s stubAuthority) IssuerFingerprint(*x509.Certificate) (string, bool) {
	return s.issuer, s.issuerOK
}

// trackerHarness is a tracker over a real authority, plus the live-session
// bookkeeping the registry would provide: a set of certificate serials with a
// session attached, grouped by cluster so tests can speak in clusters.
type trackerHarness struct {
	authority *ca.CA
	tracker   *caIssuerTracker

	mu               sync.Mutex
	serialsByCluster map[string][]string
	extra            map[string]bool
}

func newTrackerHarness(t *testing.T) *trackerHarness {
	t.Helper()
	cfg := newHubConfig(t)
	certPEM, keyPEM, err := ca.NewRootPEM(ca.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	authority, err := ca.Parse(certPEM, keyPEM, ca.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := &trackerHarness{
		authority:        authority,
		serialsByCluster: map[string][]string{},
		extra:            map[string]bool{},
	}
	h.tracker = newCAIssuerTracker(authority, h.live)
	return h
}

func (h *trackerHarness) live() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]bool)
	for _, serials := range h.serialsByCluster {
		for _, s := range serials {
			out[s] = true
		}
	}
	for s := range h.extra {
		out[s] = true
	}
	return out
}

func (h *trackerHarness) disconnect(cluster string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.serialsByCluster, cluster)
}

// reviveSerial marks a serial live again WITHOUT a handshake, which no real
// session can do: it exists to exercise the sighting grace.
func (h *trackerHarness) reviveSerial(serial string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.extra[serial] = true
}

// disconnectSerial removes one revived serial from the live set.
func (h *trackerHarness) disconnectSerial(serial string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.extra, serial)
}

// handshake issues a certificate for a cluster and pushes it through the
// tracker exactly as the tunnel server's verify hook would, then REPLACES the
// cluster's live session with it -- the single-pod shape, where a renewal's
// reconnect supersedes the old session.
func (h *trackerHarness) handshake(t *testing.T, clusterID string) *x509.Certificate {
	leaf := h.verify(t, clusterID)
	h.mu.Lock()
	h.serialsByCluster[clusterID] = []string{leaf.SerialNumber.Text(16)}
	h.mu.Unlock()
	return leaf
}

// handshakeSibling is handshake for an ADDITIONAL pod of the same cluster: the
// existing session stays live alongside the new one. This is the shape that
// broke the per-cluster tracker -- siblings converge on a shared identity
// asynchronously, so for a while one holds the renewed certificate and one
// still holds the certificate the outgoing root signed.
func (h *trackerHarness) handshakeSibling(t *testing.T, clusterID string) *x509.Certificate {
	leaf := h.verify(t, clusterID)
	h.mu.Lock()
	h.serialsByCluster[clusterID] = append(h.serialsByCluster[clusterID], leaf.SerialNumber.Text(16))
	h.mu.Unlock()
	return leaf
}

func (h *trackerHarness) verify(t *testing.T, clusterID string) *x509.Certificate {
	t.Helper()
	_, leaf, err := h.authority.IssueSpokeFromCSR(newSpokeCSR(t), clusterID)
	if err != nil {
		t.Fatalf("issue %s: %v", clusterID, err)
	}
	id, err := h.tracker.Verify([]*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("verify %s: %v", clusterID, err)
	}
	if id.ClusterID != clusterID {
		t.Fatalf("identity = %q, want %q", id.ClusterID, clusterID)
	}
	return leaf
}

func TestCAIssuerTrackerCountsSessionsOnARoot(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	fingerprint := ca.Fingerprint(h.authority.Certificate())

	h.handshake(t, "alpha")
	h.handshake(t, "beta")

	if got := h.tracker.holdoutsOn(fingerprint); got != 2 {
		t.Errorf("holdoutsOn = %d, want 2", got)
	}
	if got := h.tracker.holdoutsOn("some-other-root"); got != 0 {
		t.Errorf("holdoutsOn(other) = %d, want 0", got)
	}
	// "" is what the gate passes outside the signing phase; it must match
	// nothing rather than everything.
	if got := h.tracker.holdoutsOn(""); got != 0 {
		t.Errorf("holdoutsOn(empty) = %d, want 0", got)
	}
}

func TestCAIssuerTrackerForgetsDisconnectedClusters(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	fingerprint := ca.Fingerprint(h.authority.Certificate())
	alphaLeaf := h.handshake(t, "alpha")
	h.handshake(t, "beta")

	alphaSerial := alphaLeaf.SerialNumber.Text(16)
	h.disconnect("alpha")
	if got := h.tracker.holdoutsOn(fingerprint); got != 1 {
		t.Fatalf("holdoutsOn = %d, want 1 once alpha's tunnel is gone", got)
	}
	// Within the sighting grace the entry is retained but not counted -- the
	// session may simply not have attached yet -- so coming back live before
	// the grace lapses IS counted again, without a fresh handshake.
	h.reviveSerial(alphaSerial)
	if got := h.tracker.holdoutsOn(fingerprint); got != 2 {
		t.Errorf("holdoutsOn = %d, want 2; a sighting inside the grace was not restored", got)
	}
	// Past the grace, a dead sighting is dropped for good: liveness alone
	// must not resurrect it.
	h.disconnectSerial(alphaSerial)
	base := time.Now()
	h.tracker.now = func() time.Time { return base.Add(sightingGrace + time.Minute) }
	if got := h.tracker.holdoutsOn(fingerprint); got != 1 {
		t.Fatalf("holdoutsOn = %d, want 1 with the sighting past its grace", got)
	}
	h.reviveSerial(alphaSerial)
	if got := h.tracker.holdoutsOn(fingerprint); got != 1 {
		t.Errorf("holdoutsOn = %d, want 1; a pruned sighting came back without a handshake", got)
	}
}

// TestCAIssuerTrackerSightingGraceBoundaryIsInclusive pins the exact instant
// a dead sighting flips from retained to pruned: AT sightingGrace elapsed the
// sighting must still survive (a serial that comes back live without a fresh
// handshake is still counted), and one tick past it the sighting must be
// gone for good. This is the "> sightingGrace" comparison itself, not just
// its neighbourhood: a gremlins CONDITIONALS_BOUNDARY mutant turning it into
// ">=" would prune one grace-period earlier than intended, silently
// shortening the window a reconnecting-but-not-yet-attached holdout has to
// avoid being miscounted as retired.
func TestCAIssuerTrackerSightingGraceBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	fingerprint := ca.Fingerprint(h.authority.Certificate())

	base := time.Now()
	h.tracker.now = func() time.Time { return base }
	leaf := h.handshake(t, "alpha")
	serial := leaf.SerialNumber.Text(16)
	h.disconnect("alpha")

	// Exactly at the boundary: now.Sub(sighting.at) == sightingGrace, so
	// "> sightingGrace" is false and the sighting must be retained. The
	// prune decision is made HERE, while the serial is still not live --
	// revive only afterwards, or the decision is never reached at all.
	h.tracker.now = func() time.Time { return base.Add(sightingGrace) }
	h.tracker.holdoutsOn(fingerprint)
	h.reviveSerial(serial)
	if got := h.tracker.holdoutsOn(fingerprint); got != 1 {
		t.Errorf("holdoutsOn = %d, want 1: a sighting exactly at the grace boundary must still be retained", got)
	}

	// One tick past the boundary, the same sighting must be pruned for good:
	// coming back live can no longer resurrect it without a fresh handshake.
	h.disconnectSerial(serial)
	h.tracker.now = func() time.Time { return base.Add(sightingGrace + time.Nanosecond) }
	h.tracker.holdoutsOn(fingerprint) // triggers the prune decision while not live
	h.reviveSerial(serial)
	if got := h.tracker.holdoutsOn(fingerprint); got != 0 {
		t.Errorf("holdoutsOn = %d, want 0: a sighting one tick past the grace boundary must be pruned", got)
	}
}

// TestCAIssuerTrackerFollowsARenewalOntoTheNewRoot is the property the
// retirement gate depends on: a spoke that renews reconnects, and the
// reconnection is what moves it off the outgoing root's tally.
func TestCAIssuerTrackerFollowsARenewalOntoTheNewRoot(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	outgoing := ca.Fingerprint(h.authority.Certificate())
	h.handshake(t, "alpha")

	successorCert, successorKey, err := ca.NewRootPEM(ca.Options{TrustDomain: h.authority.TrustDomain()})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	outgoingPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.authority.Certificate().Raw})
	if err := h.authority.AdoptPEM(successorCert, successorKey, outgoingPEM); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got := h.tracker.holdoutsOn(outgoing); got != 1 {
		t.Fatalf("holdoutsOn = %d before the spoke renews, want 1", got)
	}

	h.handshake(t, "alpha") // renewal makes the spoke reconnect
	if got := h.tracker.holdoutsOn(outgoing); got != 0 {
		t.Errorf("holdoutsOn = %d after the spoke renewed, want 0", got)
	}
	if got := h.tracker.holdoutsOn(ca.Fingerprint(h.authority.Certificate())); got != 1 {
		t.Errorf("the renewed session was not counted against the successor: %d, want 1", got)
	}
}

func TestCAIssuerTrackerRecordsNothingForARejectedChain(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	other := newTrackerHarness(t)
	_, foreign, err := other.authority.IssueSpokeFromCSR(newSpokeCSR(t), "alpha")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := h.tracker.Verify([]*x509.Certificate{foreign}); !errors.Is(err, ca.ErrUntrustedChain) {
		t.Fatalf("Verify() = %v, want ErrUntrustedChain", err)
	}
	h.reviveSerial(foreign.SerialNumber.Text(16))
	if got := h.tracker.holdoutsOn(ca.Fingerprint(other.authority.Certificate())); got != 0 {
		t.Errorf("a rejected chain was recorded: %d, want 0", got)
	}
}

// TestCAIssuerTrackerIgnoresAnUnattributableLeaf covers the defensive branch:
// a real CA cannot verify a chain whose issuer is not in its bundle, and if
// one ever could, recording "" would count every cluster as a holdout of a
// root that does not exist.
func TestCAIssuerTrackerIgnoresAnUnattributableLeaf(t *testing.T) {
	t.Parallel()

	stub := stubAuthority{identity: tunnel.Identity{ClusterID: "alpha"}}
	tracker := newCAIssuerTracker(stub, func() map[string]bool { return map[string]bool{"alpha": true} })

	// A one-element chain: VerifyChain guarantees a non-empty chain on
	// success, and the stub stands in for a verifier whose bundle somehow does
	// not claim the leaf it just accepted.
	if _, err := tracker.Verify([]*x509.Certificate{{}}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := tracker.holdoutsOn(""); got != 0 {
		t.Errorf("holdoutsOn = %d, want 0 for a leaf no root claimed", got)
	}
}

// TestCAIssuerTrackerIsRaceClean runs handshakes and counts concurrently, the
// way the handshake path and the rotation poll actually run.
func TestCAIssuerTrackerIsRaceClean(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	fingerprint := ca.Fingerprint(h.authority.Certificate())
	_, leaf, err := h.authority.IssueSpokeFromCSR(newSpokeCSR(t), "alpha")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	h.reviveSerial(leaf.SerialNumber.Text(16))

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if _, verr := h.tracker.Verify([]*x509.Certificate{leaf}); verr != nil {
					t.Errorf("Verify: %v", verr)
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				h.tracker.holdoutsOn(fingerprint)
			}
		}()
	}
	wg.Wait()
}

// TestLiveCertSerials pins the registry surface the evidence gate stands on:
// serials of sessions actually attached, one entry per certificate however
// many siblings share it, and nothing for a cluster inside its disconnect
// grace window -- last facts retained, but no tunnel, so it presents no
// certificate and cannot be a reason to keep the outgoing root alive.
func TestLiveCertSerials(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	if diff := cmp.Diff(map[string]bool{}, h.registry.LiveCertSerials()); diff != "" {
		t.Errorf("an empty registry reports live serials (-want +got):\n%s", diff)
	}

	sessionA := memtun.Pair(tunnel.Identity{ClusterID: "alpha", CertSerial: "aa", InstanceID: "pod-a"}, 1, &tunneltest.EchoHandler{})
	releaseA, err := h.registry.OnSession(context.Background(), sessionA)
	if err != nil {
		t.Fatalf("OnSession: %v", err)
	}
	// A sibling pod of the same cluster on a DIFFERENT certificate: both
	// serials must be visible, which is the whole reason this is not keyed by
	// cluster -- during renewal convergence the old certificate's session is
	// the holdout, and it must not be hidden behind its renewed sibling.
	sessionB := memtun.Pair(tunnel.Identity{ClusterID: "alpha", CertSerial: "bb", InstanceID: "pod-b"}, 1, &tunneltest.EchoHandler{})
	releaseB, err := h.registry.OnSession(context.Background(), sessionB)
	if err != nil {
		t.Fatalf("OnSession (sibling): %v", err)
	}
	if diff := cmp.Diff(map[string]bool{"aa": true, "bb": true}, h.registry.LiveCertSerials()); diff != "" {
		t.Errorf("sibling serials (-want +got):\n%s", diff)
	}

	releaseA()
	releaseB()
	if diff := cmp.Diff(map[string]bool{}, h.registry.LiveCertSerials()); diff != "" {
		t.Errorf("released sessions still report serials (-want +got):\n%s", diff)
	}
	if len(h.registry.List()) == 0 {
		t.Fatal("the registry forgot the cluster entirely; this test no longer covers the grace window")
	}
}

// TestCAIssuerTrackerSeesAHoldoutBehindARenewedSibling is the scenario the
// per-cluster keying missed: sibling pods of one cluster converge on a shared
// identity asynchronously, so sibling A reconnects on a certificate from the
// NEW root while sibling B's session, admitted by the outgoing root, is still
// live. Keyed per cluster, A's handshake overwrote the record naming B, and
// the retirement gate would drop the outgoing root with B still chained to
// it -- a hard lockout for B at its next reconnect. Keyed per serial, B stays
// visible until its session actually ends.
func TestCAIssuerTrackerSeesAHoldoutBehindARenewedSibling(t *testing.T) {
	t.Parallel()

	h := newTrackerHarness(t)
	outgoing := ca.Fingerprint(h.authority.Certificate())

	// Sibling B connects while the outgoing root is still the signer.
	h.handshake(t, "alpha")

	// The rotation promotes a successor; the outgoing root stays trusted.
	successorCert, successorKey, err := ca.NewRootPEM(ca.Options{TrustDomain: h.authority.TrustDomain()})
	if err != nil {
		t.Fatalf("mint successor: %v", err)
	}
	outgoingPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.authority.Certificate().Raw})
	if err := h.authority.AdoptPEM(successorCert, successorKey, outgoingPEM); err != nil {
		t.Fatalf("promote successor: %v", err)
	}

	// Sibling A renews and reconnects on the new root, WITHOUT displacing B.
	h.handshakeSibling(t, "alpha")

	if got := h.tracker.holdoutsOn(outgoing); got != 1 {
		t.Fatalf("holdoutsOn(outgoing) = %d, want 1: the renewed sibling hid the live holdout", got)
	}
}
