// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import "errors"

// Errors this package adds to the handshake sentinels. Callers branch on them
// with errors.Is.
var (
	// ErrClusterMismatch means the spoke's self-reported cluster ID disagreed
	// with the one in its certificate's URI SAN. The certificate is
	// authoritative, so this is never reconciled: a disagreement is a
	// misconfiguration or an attempt to be somebody else, and either way the
	// connection is refused rather than silently resolved in the certificate's
	// favour.
	ErrClusterMismatch = errors.New("wstun: reported cluster id disagrees with the certificate")

	// ErrSubprotocol means the WebSocket subprotocol was not negotiated. A
	// peer that did not ask for it is not a spoke.
	ErrSubprotocol = errors.New("wstun: tunnel subprotocol was not negotiated")

	// ErrTooManySessions means the hub is already carrying MaxSessions spokes.
	ErrTooManySessions = errors.New("wstun: session limit reached")

	// ErrUpgradeRejected means the HTTP request was answered by something that
	// declined to switch protocols. Behind an ingress this is far more often a
	// routing rule than a broken hub.
	ErrUpgradeRejected = errors.New("wstun: the server did not upgrade the connection")

	// ErrServerClosed is returned by Listener.Serve after Shutdown, and to a
	// handshake that completed just as the hub stopped accepting.
	ErrServerClosed = errors.New("wstun: server closed")

	// ErrInvalidEndpoint means a hub endpoint could not be parsed as a tunnel
	// URL. Its message names a valid value, because this is the string an
	// operator typed.
	ErrInvalidEndpoint = errors.New("wstun: invalid hub endpoint")
)
