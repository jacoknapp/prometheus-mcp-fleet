// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
)

// Handshake errors. Callers branch on these with errors.Is.
var (
	// ErrHandshakeFailed means the peer did not complete the exchange.
	ErrHandshakeFailed = errors.New("wstun: handshake failed")
	// ErrUntrustedCertificate means the presented chain did not verify against
	// the configured authority.
	ErrUntrustedCertificate = errors.New("wstun: certificate is not trusted")
	// ErrBadSignature means the peer did not prove possession of the private
	// key matching the certificate it presented. It is the sentinel from
	// internal/certproof rather than one of this package's own, so that a
	// caller which has verified a proof through either path branches on one
	// value.
	ErrBadSignature = certproof.ErrBadSignature
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
	// ServerID identifies the accepting hub replica. It is the pod's hostname,
	// so it is stable for the life of a replica and distinct between replicas.
	//
	// It began as a diagnostic and is now load-bearing for HA: a tunnel
	// terminates on exactly one replica and there is no hub-to-hub forwarding,
	// so a spoke must hold a tunnel to EVERY replica or a fraction of tool
	// calls find no session. Behind a single Ingress hostname the spoke cannot
	// address replicas individually, so it discovers them instead — it dials
	// repeatedly and uses this field to tell which replica it landed on.
	ServerID string `json:"serverId,omitempty"`
	// Replicas is how many hub replicas the accepting hub believes are running.
	//
	// It is what tells the spoke when to stop dialing: coverage is complete
	// once it holds one tunnel per distinct ServerID and that count equals this
	// number. Zero means the hub cannot discover its own peers, in which case
	// the spoke keeps exactly one tunnel per configured endpoint, which is the
	// behaviour that predates this field.
	Replicas int `json:"replicas,omitempty"`
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
	// InstanceID distinguishes one spoke POD from another within the same
	// cluster. It is the pod hostname, falling back to a random value.
	//
	// A cluster may run more than one spoke for its own availability, and those
	// pods share a cluster ID by definition -- that is what makes them the same
	// cluster -- and may share a certificate too, if they share the identity
	// Secret. Without a per-pod identifier the hub cannot tell a second pod
	// from a reconnect of the first, and would keep replacing one with the
	// other. It is advisory and authenticates nothing: it partitions sessions
	// that have ALREADY been authenticated by the certificate.
	InstanceID string `json:"instanceId,omitempty"`
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

// The transcript, its signature and its verification live in
// internal/certproof: the renewal endpoint in internal/hubapi proves possession
// of the same certificates with the same construction, and a second
// implementation that drifted from this one is exactly how a signature scheme
// breaks. This package supplies the wire framing and the exchange; certproof
// supplies the bytes that get signed.

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
	binary.BigEndian.PutUint32(n[:], uint32(len(body))) //nolint:gosec // G115: len(body) <= maxHandshakeBytes, checked immediately above.
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
