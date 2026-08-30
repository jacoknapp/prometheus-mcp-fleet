// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Handshake errors. Callers branch on these with errors.Is.
var (
	// ErrHandshakeFailed means the peer did not complete the exchange.
	ErrHandshakeFailed = errors.New("wstun: handshake failed")
	// ErrUntrustedCertificate means the presented chain did not verify against
	// the configured authority.
	ErrUntrustedCertificate = errors.New("wstun: certificate is not trusted")
	// ErrBadSignature means the peer did not prove possession of the private
	// key matching the certificate it presented.
	ErrBadSignature = errors.New("wstun: signature does not verify")
	// ErrRevoked means the certificate's serial is on the hub's denylist.
	ErrRevoked = errors.New("wstun: certificate has been revoked")
	// ErrProtocolVersion means the peer speaks an incompatible wire version.
	ErrProtocolVersion = errors.New("wstun: incompatible protocol version")
)

// ProtocolVersion is the handshake wire version. The hub accepts this and, per
// the project's skew policy, the previous minor — a hundred clusters never
// upgrade in lockstep.
const ProtocolVersion = "v1"

// nonceLen is the size of the server challenge. 32 bytes is well beyond any
// birthday concern for a value that is used exactly once.
const nonceLen = 32

// maxHandshakeBytes bounds each handshake message. A certificate chain is a few
// kilobytes; anything larger is a malformed or hostile peer, and reading it
// unbounded before authentication would be a trivial memory exhaustion.
const maxHandshakeBytes = 64 << 10

// handshakeTimeout bounds the whole exchange. An unauthenticated peer holds a
// goroutine and a file descriptor for at most this long.
const handshakeTimeout = 10 * time.Second

// serverHello is the hub's challenge, sent first.
type serverHello struct {
	// Nonce is fresh for every connection and is never reused. It is what makes
	// a captured ClientAuth useless: the signature covers it.
	Nonce []byte `json:"nonce"`
	// ProtocolVersion is the hub's handshake version.
	ProtocolVersion string `json:"protocolVersion"`
	// ServerID identifies the accepting hub replica, for spoke-side logging.
	ServerID string `json:"serverId,omitempty"`
}

// clientAuth is the spoke's response.
type clientAuth struct {
	// Chain is the spoke's certificate followed by any intermediates, DER
	// encoded, leaf first.
	Chain [][]byte `json:"chain"`
	// Signature is over transcript(nonce, protocolVersion, clusterID).
	Signature []byte `json:"signature"`
	// ClusterID is what the spoke believes it is. It is bound into the
	// signature so it cannot be altered in flight, but it is advisory: the hub
	// takes the authoritative value from the certificate's URI SAN and rejects
	// the connection if the two disagree.
	ClusterID string `json:"clusterId"`
	// AgentVersion is reported for diagnostics only.
	AgentVersion string `json:"agentVersion,omitempty"`
	// ProtocolVersion is the spoke's handshake version.
	ProtocolVersion string `json:"protocolVersion"`
}

// serverAccept closes the exchange.
type serverAccept struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
	// ClusterID echoes the identity the hub derived from the certificate, so a
	// spoke can log a mismatch against what it believes it is.
	ClusterID string `json:"clusterId,omitempty"`
}

// transcript is the byte string both sides sign and verify.
//
// Every field that could be attacker-influenced is length-prefixed, so no
// combination of values can produce the same transcript as a different
// combination. Concatenating without lengths is the classic way to make a
// signature cover something other than what it appears to.
func transcript(nonce []byte, protocolVersion, clusterID string) []byte {
	var buf []byte
	appendField := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf = append(buf, n[:]...)
		buf = append(buf, b...)
	}
	buf = append(buf, "prometheus-mcp-fleet/tunnel-auth\x00"...)
	appendField(nonce)
	appendField([]byte(protocolVersion))
	appendField([]byte(clusterID))
	return buf
}

// signTranscript produces the spoke's proof of possession.
func signTranscript(key crypto.Signer, nonce []byte, protocolVersion, clusterID string) ([]byte, error) {
	digest := sha256.Sum256(transcript(nonce, protocolVersion, clusterID))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign the handshake transcript: %w", err)
	}
	return sig, nil
}

// verifyTranscript checks the spoke's proof against its certificate.
func verifyTranscript(leaf *x509.Certificate, sig, nonce []byte, protocolVersion, clusterID string) error {
	digest := sha256.Sum256(transcript(nonce, protocolVersion, clusterID))

	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return ErrBadSignature
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("%w: %s", ErrBadSignature, err)
		}
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrBadSignature, leaf.PublicKey)
	}
	return nil
}

// writeMessage writes one length-prefixed JSON handshake message.
func writeMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode handshake message: %w", err)
	}
	if len(body) > maxHandshakeBytes {
		return fmt.Errorf("%w: message is %d bytes", ErrHandshakeFailed, len(body))
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if _, err := w.Write(n[:]); err != nil {
		return fmt.Errorf("write handshake length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write handshake body: %w", err)
	}
	return nil
}

// readMessage reads one length-prefixed JSON handshake message.
//
// The length is checked before allocating, so a hostile peer cannot make an
// unauthenticated connection reserve arbitrary memory.
func readMessage(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return fmt.Errorf("%w: read length: %w", ErrHandshakeFailed, err)
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > maxHandshakeBytes {
		return fmt.Errorf("%w: declared message size %d", ErrHandshakeFailed, size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("%w: read body: %w", ErrHandshakeFailed, err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrHandshakeFailed, err)
	}
	return nil
}

// compatibleVersion reports whether a peer's handshake version is acceptable.
//
// The hub must tolerate the previous spoke minor, because a hundred clusters
// never upgrade at once. Today there is one version, so this is a simple
// equality — but it exists as a function so the skew policy has somewhere to
// live when there are two.
func compatibleVersion(peer string) bool { return peer == ProtocolVersion }
