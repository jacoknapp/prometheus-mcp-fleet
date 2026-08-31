// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package certproof is the proof-of-possession construction the fleet uses
// wherever a spoke must prove it holds the private key of the certificate it
// presents, at the application layer rather than at the TLS layer.
//
// It exists because ADR-0014 put the hub behind a standard Kubernetes Ingress
// that terminates TLS and forwards plain HTTP. crypto/tls on the hub therefore
// never sees a spoke's client certificate and cannot run the CertificateVerify
// step on the hub's behalf. Both places that used to rely on that step — the
// WebSocket tunnel handshake and certificate renewal — perform it here instead.
//
// There is deliberately exactly one implementation. Two transcript builders
// that agree today and drift tomorrow is precisely how a signature ends up
// covering something other than what the verifier believes it covers, so the
// tunnel and the renewal endpoint call the same three functions and differ only
// in the protocol version string they pass.
//
// The package is pure: it performs no I/O, holds no state, and is safe for
// concurrent use. It sits at the bottom of the dependency graph beside
// internal/tunnel so that internal/tunnel/wstun, internal/hubapi and the spoke
// can all reach it without any of them reaching each other.
package certproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBadSignature means the peer did not prove possession of the private key
// matching the certificate it presented. Callers branch on it with errors.Is.
var ErrBadSignature = errors.New("certproof: signature does not verify")

// RenewProtocolVersion is the protocol version label the certificate renewal
// exchange binds into its transcript.
//
// It is deliberately not the tunnel handshake's version string. The
// transcript's protocol version field is length-prefixed, so giving the two
// exchanges different values domain-separates them: a signature produced for
// one can never verify as the other, whatever nonce it covers.
//
// That separation is load-bearing, not decorative. GET /renew/challenge is
// necessarily unauthenticated, so anybody at all can obtain a valid renewal
// nonce; and ADR-0014 places the terminating Ingress inside the trust boundary,
// where it sees and could rewrite the tunnel's handshake frames. Without
// separation, anything in that position could hand a connecting spoke a renewal
// nonce in place of the hub's tunnel nonce, collect the spoke's signature over
// it, and redeem that signature at POST /renew for a certificate bound to the
// spoke's cluster but keyed to the attacker — turning a transient position on
// the path into a permanent forged identity. With separation the collected
// signature is worthless outside the exchange it was made for.
const RenewProtocolVersion = "renew-v1"

// domainTag prefixes every transcript, so a signature produced here can never
// be mistaken for a signature over some other structure this project signs.
//
// The value still reads "tunnel-auth" because it is on the wire: every spoke
// already deployed computes exactly these bytes, and changing them would break
// the tunnel handshake fleet-wide to gain nothing. Per-exchange separation is
// carried by the protocol version field instead.
const domainTag = "prometheus-mcp-fleet/tunnel-auth\x00"

// MaxFieldBytes bounds a single transcript field.
//
// The length prefix is 32 bits, so a field of 4 GiB or more would truncate it
// and let two different inputs produce the same transcript — defeating the one
// property this function exists to provide. Every real field is orders of
// magnitude below this cap, so the bound is not a limitation; it is what makes
// the uniqueness guarantee structural rather than a consequence of callers
// happening to pass small values today.
const MaxFieldBytes = 64 << 10

// ErrFieldTooLarge means a transcript field exceeded [MaxFieldBytes].
var ErrFieldTooLarge = errors.New("certproof: transcript field is too large")

// Transcript builds the byte string both sides sign and verify.
//
// Every field is length-prefixed and the whole is domain-separated, so no
// combination of values can produce the same transcript as a different
// combination. Concatenating without lengths is the classic way to make a
// signature cover something other than what it appears to.
//
// The returned slice is freshly allocated and owned by the caller.
func Transcript(nonce []byte, protocolVersion, clusterID string) ([]byte, error) {
	fields := [][]byte{nonce, []byte(protocolVersion), []byte(clusterID)}
	for _, f := range fields {
		if len(f) > MaxFieldBytes {
			return nil, fmt.Errorf("%w: %d bytes, limit %d",
				ErrFieldTooLarge, len(f), MaxFieldBytes)
		}
	}

	buf := make([]byte, 0, len(domainTag)+len(fields)*4+
		len(nonce)+len(protocolVersion)+len(clusterID))
	buf = append(buf, domainTag...)
	for _, f := range fields {
		var n [4]byte
		//nolint:gosec // G115: the loop above rejects any field longer than MaxFieldBytes (64 KiB), so len(f) always fits a uint32.
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		buf = append(buf, n[:]...)
		buf = append(buf, f...)
	}
	return buf, nil
}

// Sign produces a proof of possession over
// [Transcript](nonce, protocolVersion, clusterID), hashed with SHA-256.
//
// key is the private half of the presented certificate's public key. It is a
// crypto.Signer rather than a concrete type so the key may stay behind an
// interface; crypto/tls hands one back for every key type it parses.
func Sign(key crypto.Signer, nonce []byte, protocolVersion, clusterID string) ([]byte, error) {
	t, err := Transcript(nonce, protocolVersion, clusterID)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(t)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign the proof-of-possession transcript: %w", err)
	}
	return sig, nil
}

// Verify checks a proof against the public key in leaf.
//
// Every rejection, including an unsupported key type, satisfies
// errors.Is(err, [ErrBadSignature]): a certificate whose key this build cannot
// verify has not proven anything, and reporting that as a separate class would
// invite a caller to treat it as a soft failure.
func Verify(leaf *x509.Certificate, sig, nonce []byte, protocolVersion, clusterID string) error {
	if leaf == nil {
		return fmt.Errorf("%w: no certificate presented", ErrBadSignature)
	}
	t, err := Transcript(nonce, protocolVersion, clusterID)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(t)

	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return ErrBadSignature
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrBadSignature, err)
		}
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrBadSignature, leaf.PublicKey)
	}
	return nil
}
