// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package mtls builds the client side of the hub tunnel's TLS configuration.
//
// It exists as its own package for one reason: the spoke needs to present a
// certificate, and nothing else. Keeping this helper in internal/ca would force
// the spoke binary to link the certificate authority — the code that issues,
// renews and revokes identities for the entire fleet — in order to construct a
// tls.Config. An architecture test forbids that edge, and this package is what
// makes obeying it easy rather than annoying.
//
// The package is pure: it performs no I/O and holds no state.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// Errors returned when the supplied material cannot be used.
var (
	// ErrNoServerName means serverName was empty.
	ErrNoServerName = errors.New("mtls: server name is required")
	// ErrInvalidBundle means the PEM bundle contained no certificates.
	ErrInvalidBundle = errors.New("mtls: trust bundle contains no certificates")
)

// alpnH2 is the only protocol the tunnel negotiates. gRPC runs over HTTP/2 and
// pinning ALPN means a proxy that downgrades the connection fails at the
// handshake, loudly, instead of producing a confusing protocol error later.
const alpnH2 = "h2"

// ClientTLSConfig returns the spoke side of the tunnel: it presents clientCert,
// verifies the hub against the PEM bundle in caPEM, speaks TLS 1.3 only, and
// negotiates only "h2".
//
// serverName is required and supplies both the SNI value and the name the hub's
// certificate must match. There is deliberately no skip-verify path: the spoke
// dials out across an untrusted network, and the hub's certificate is the only
// thing proving it reached the real hub rather than whatever answered.
func ClientTLSConfig(clientCert tls.Certificate, caPEM []byte, serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, ErrNoServerName
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w (%d bytes supplied)", ErrInvalidBundle, len(caPEM))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpnH2},
	}, nil
}
