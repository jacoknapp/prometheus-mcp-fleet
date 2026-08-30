// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"errors"
	"fmt"
)

// Sentinel errors reported by this package. Callers branch on them with
// errors.Is. The transport-level sentinels a caller normally cares about
// (tunnel.ErrSessionClosed, tunnel.ErrResponseTooLarge) live in the tunnel
// package and are returned unchanged from here.
var (
	// ErrProtocol reports a peer that violated the ProxyChunk sequencing rules
	// (head, then zero or more data chunks, then exactly one trail).
	ErrProtocol = errors.New("grpctun: tunnel protocol violation")

	// ErrUpstream wraps the failure string a spoke reported in ResponseTrail.
	// It means the tunnel worked and the spoke's call to Prometheus did not.
	// The remote error is a string on the wire, so the original error value is
	// not recoverable; only its message survives.
	ErrUpstream = errors.New("grpctun: upstream failure reported by spoke")

	// ErrBodyClosed is returned by Response.Body.Read after the body has been
	// closed early by the caller.
	ErrBodyClosed = errors.New("grpctun: response body closed")

	// ErrInvalidRequest reports a tunnel.Request this transport refuses to put
	// on the wire, such as one with a non-positive MaxResponseBytes.
	ErrInvalidRequest = errors.New("grpctun: invalid request")

	// ErrTooManySessions is reported when a spoke is turned away because the
	// listener is already at ListenerConfig.MaxSessions.
	ErrTooManySessions = errors.New("grpctun: session limit reached")

	// ErrListenerClosed is returned by Serve after Shutdown.
	ErrListenerClosed = errors.New("grpctun: listener closed")
)

// Reason classifies why a spoke-side Dial ended. It is a closed enum so it can
// be used directly as a Prometheus label value on
// promfleet_spoke_tunnel_reconnects_total{reason}.
type Reason string

const (
	// ReasonDial means the connection could not be established at all: DNS,
	// TCP connect, or a proxy that never answered.
	ReasonDial Reason = "dial"
	// ReasonTLSHandshake means the connection was made but TLS to the hub (or
	// to the ingress terminating on its behalf) did not complete.
	ReasonTLSHandshake Reason = "tls-handshake"
	// ReasonUpgradeRejected means the HTTP request reached something that
	// answered, and that something did not switch protocols. The usual cause
	// is an ingress that is not routing the tunnel path to the hub.
	ReasonUpgradeRejected Reason = "upgrade-rejected"
	// ReasonAuthRejected means the transport was established and the hub
	// refused the spoke's identity: an untrusted, revoked or mismatched
	// certificate, or a signature that did not verify.
	ReasonAuthRejected Reason = "auth-rejected"
	// ReasonConnClosed means an established tunnel dropped: the hub closed the
	// session, the process on the far end died, or keepalive timed out.
	ReasonConnClosed Reason = "conn-closed"
	// ReasonContextCancelled means the spoke itself gave up, normally because
	// the process is shutting down.
	ReasonContextCancelled Reason = "context-cancelled"
)

// DialError is what a spoke-side Dial always returns. Dial never returns a bare
// io.EOF: a reconnect loop needs a reason it can log and label a metric with,
// and "EOF" is neither.
type DialError struct {
	// Endpoint is the hub endpoint that was dialled, in whatever form the
	// caller configured it.
	Endpoint string
	// Reason is the closed-enum classification, safe as a metric label.
	Reason Reason
	// Err is the underlying cause, and may be nil for a clean remote close.
	Err error
}

// Error implements error.
func (e *DialError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("tunnel %s: %s", e.Endpoint, e.Reason)
	}
	return fmt.Sprintf("tunnel %s: %s: %v", e.Endpoint, e.Reason, e.Err)
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e *DialError) Unwrap() error { return e.Err }

// dialErr builds a *DialError, which is the only error shape Dial produces.
func dialErr(endpoint string, reason Reason, err error) *DialError {
	return &DialError{Endpoint: endpoint, Reason: reason, Err: err}
}
