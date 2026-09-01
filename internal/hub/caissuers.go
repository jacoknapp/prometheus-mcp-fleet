// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// caIssuerTracker remembers which root admitted each live certificate, so
// that the last step of a CA rotation can be gated on evidence.
//
// Retiring the outgoing root is the one step of a rotation that takes trust
// away, and a spoke still holding a certificate that root issued is
// disconnected by it the moment it next reconnects. The elapsed-time gate
// alone cannot see that spoke; this can. It is the instrument
// [ca.CA.IssuerFingerprint] exists for.
//
// It sits on the verification path rather than in the registry because the
// registry never sees a certificate: [tunnel.Identity] carries a serial and an
// expiry, not an issuer, and successive roots for one trust domain share a
// subject, so nothing downstream of the handshake can tell them apart. The
// handshake is the last place the leaf exists.
//
// One entry per certificate SERIAL, not per cluster. Sibling pods of one
// cluster converge on a shared identity asynchronously, so one sibling can
// hold a session on the renewed certificate while another still holds one on
// the certificate the outgoing root signed; keyed per cluster, the renewed
// sibling's handshake would overwrite the record that named the holdout, and
// the gate would retire a root a live session still chains to. Serials
// collapse only sessions holding the same certificate, which really are
// indistinguishable here. Entries whose serial no longer has a live session
// are dropped when the count is taken, which is the only pruning needed: the
// map is bounded by live sessions either way.
type caIssuerTracker struct {
	verify func([]*x509.Certificate) (tunnel.Identity, error)
	issuer func(*x509.Certificate) (string, bool)
	// liveSerials reports the certificate serial of every session currently
	// attached to this replica.
	liveSerials func() map[string]bool

	// now is the clock; tests pin it. Nil means time.Now.
	now func() time.Time

	mu       sync.Mutex
	bySerial map[string]issuerSighting
}

// issuerSighting is one verified certificate's issuer, and when it was last
// seen on a handshake.
type issuerSighting struct {
	fingerprint string
	at          time.Time
}

// sightingGrace is how long a sighting whose serial is not (yet) in the live
// set survives a count. The registry attaches a session only AFTER an
// admission Describe that can take seconds, so a handshake's sighting can
// briefly precede its session -- pruned instantly, a holdout that connected
// moments ago would read as zero until its next handshake.
const sightingGrace = 2 * time.Minute

// caAuthority is the part of *ca.CA this tracker needs. Declaring it here
// keeps the tracker testable without minting a real authority for cases that
// are about bookkeeping rather than about cryptography.
type caAuthority interface {
	VerifyChain(chain []*x509.Certificate) (tunnel.Identity, error)
	IssuerFingerprint(leaf *x509.Certificate) (string, bool)
}

// newCAIssuerTracker wraps an authority's chain verification. liveSerials
// reports the certificate serial of every session currently attached to this
// replica.
func newCAIssuerTracker(authority caAuthority, liveSerials func() map[string]bool) *caIssuerTracker {
	return &caIssuerTracker{
		verify:      authority.VerifyChain,
		issuer:      authority.IssuerFingerprint,
		liveSerials: liveSerials,
		now:         time.Now,
		bySerial:    map[string]issuerSighting{},
	}
}

// Verify is the tunnel server's verification hook: it verifies the chain
// exactly as the authority does and records which root signed the leaf.
//
// The recording is a side effect of a decision already made. A chain that does
// not verify is not recorded, so nothing an unauthenticated peer sends can
// enter the map, and a leaf whose issuer is not in the trust bundle cannot
// verify in the first place.
func (t *caIssuerTracker) Verify(chain []*x509.Certificate) (tunnel.Identity, error) {
	id, err := t.verify(chain)
	if err != nil {
		return id, err
	}
	// A verified chain has a leaf and an issuer in the bundle by construction;
	// the second return is honoured anyway rather than assumed, because the
	// alternative is recording "" as a fingerprint and counting every cluster
	// as a holdout of a root that does not exist.
	if fp, ok := t.issuer(chain[0]); ok && chain[0].SerialNumber != nil {
		// ca.SerialHex, not Text(16): the registry keys sessions by the
		// serial the tunnel layer formatted, and the two spellings differ on
		// a negative serial. The built-in CA never issues one, but a tracker
		// key that silently diverges from the registry's would prune a live
		// holdout on every count.
		serial := ca.SerialHex(chain[0].SerialNumber)
		t.mu.Lock()
		t.bySerial[serial] = issuerSighting{fingerprint: fp, at: t.now()}
		t.mu.Unlock()
	}
	return id, nil
}

// holdoutsOn reports how many certificates with a live session on this
// replica were admitted by the root with this fingerprint, and forgets every
// certificate that no longer has one.
//
// It counts this replica only. A tunnel terminates on exactly one replica and
// there is no hub-to-hub forwarding, so no replica can see the whole fleet;
// what makes the answer fleet-wide is that every replica publishes its own
// observation into the CA Secret and the retirement gate reads the fleet's
// most recent sighting, not just its own. See caRotator.plan.
func (t *caIssuerTracker) holdoutsOn(fingerprint string) int {
	live := t.liveSerials()

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	n := 0
	for serial, sighting := range t.bySerial {
		if !live[serial] {
			if now.Sub(sighting.at) > sightingGrace {
				delete(t.bySerial, serial)
			}
			// Inside the grace it is neither counted nor forgotten: the
			// session may simply not have attached yet, and counting an
			// unattached sighting would let a handshake that never became a
			// session hold the rotation open.
			continue
		}
		if sighting.fingerprint == fingerprint {
			n++
		}
	}
	return n
}
