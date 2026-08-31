// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tunnel defines the transport-agnostic contract between the hub and a
// spoke. It contains no gRPC symbols and performs no I/O, so the hub's routing
// and proxy layers can be tested against an in-process transport (memtun) and
// the real one (grpctun) with the same suite.
//
// Direction note: the spoke always dials the hub. Once the mTLS handshake
// completes the roles invert and the spoke serves requests over the connection
// it opened. Everything below is expressed from the hub's point of view.
package tunnel

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// Errors returned by transports. Callers branch on these with errors.Is.
var (
	// ErrSessionClosed is returned when a request is made on a session whose
	// underlying connection has gone away.
	ErrSessionClosed = errors.New("tunnel: session closed")
	// ErrNotConnected is returned when no session exists for a cluster.
	ErrNotConnected = errors.New("tunnel: cluster not connected")
	// ErrResponseTooLarge is returned when a response exceeded the caller's
	// byte budget and was aborted mid-transfer.
	ErrResponseTooLarge = errors.New("tunnel: response exceeded byte budget")
)

// Identity is the authenticated identity of a spoke, derived exclusively from
// its verified client certificate. Nothing the spoke reports at runtime may
// alter it.
type Identity struct {
	// ClusterID is taken from the certificate's URI SAN.
	ClusterID string
	// CertSerial is the hex serial of the presented certificate.
	CertSerial string
	// CertNotAfter is when that certificate expires.
	CertNotAfter time.Time
	// RemoteAddr is the observed peer address, for audit logs only.
	RemoteAddr string
	// InstanceID distinguishes one spoke pod from another inside the same
	// cluster, so a cluster can run several for its own availability and the
	// hub can treat them as an interchangeable pool rather than as repeated
	// reconnections of one pod.
	//
	// It is self-reported and authenticates nothing. Authority comes from the
	// certificate: ClusterID decides what a session may serve, and this only
	// decides which slot it occupies within that cluster. A spoke that lied
	// about it could at worst displace its own sibling's session.
	InstanceID string
}

// Request is one allow-listed HTTP call to a spoke's Prometheus.
type Request struct {
	// Method is "GET" or "POST".
	Method string
	// Path is an absolute Prometheus API path such as "/api/v1/query".
	Path string
	// Form carries the parameters. They are always sent in the request body so
	// that long PromQL never meets a proxy's URI length limit.
	Form []byte
	// MaxResponseBytes aborts the transfer once exceeded. Must be > 0.
	MaxResponseBytes int64
	// AcceptGzip asks the spoke to forward Prometheus' compressed bytes
	// verbatim; the caller is responsible for inflating them.
	AcceptGzip bool
	// RequestID correlates hub and spoke logs for one agent tool call.
	RequestID string
}

// Response is the head of an upstream reply. Body must always be closed, and
// reading it may return ErrResponseTooLarge.
type Response struct {
	StatusCode int
	// ContentType is the upstream Content-Type.
	ContentType string
	// ContentEncoding is "gzip" when Body is still compressed.
	ContentEncoding string
	// Body streams the upstream response. It is never nil.
	Body io.ReadCloser
	// Trailer is populated once Body returns io.EOF.
	Trailer func() Trailer
}

// Trailer carries per-request accounting reported by the spoke.
type Trailer struct {
	BytesTotal      int64
	UpstreamLatency time.Duration
	Truncated       bool
	Warnings        []string
	// Err is set when the spoke could not complete the upstream call.
	Err error
}

// Session is a live tunnel to one spoke.
type Session interface {
	// Identity returns the certificate-derived identity of the peer.
	Identity() Identity
	// Generation is the spoke process start time in Unix nanoseconds. The
	// registry uses it to resolve reconnect races deterministically.
	Generation() int64
	// Do performs one Prometheus request over the tunnel. The returned
	// Response.Body must be closed by the caller. Cancelling ctx aborts the
	// upstream query inside the remote cluster.
	Do(ctx context.Context, req *Request) (*Response, error)
	// Describe fetches the spoke's cluster facts. Passing the fingerprint the
	// caller already holds lets an unchanged spoke reply with Changed=false.
	Describe(ctx context.Context, knownFingerprint string) (Facts, error)
	// Close tears the session down, recording reason for the audit log.
	Close(reason string) error
	// Done is closed when the session ends.
	Done() <-chan struct{}
}

// Facts is a Describe reply.
type Facts struct {
	// Fingerprint identifies this exact facts payload.
	Fingerprint string
	// Changed is false when the caller's fingerprint was already current, in
	// which case Cluster is the zero value.
	Changed bool
	// Cluster holds the reported facts. Its ID field is advisory only: the
	// registry overwrites it with the certificate-derived identity.
	Cluster fleet.Cluster
	// Generation is the spoke's process start time in Unix nanoseconds.
	Generation int64
}

// SessionHandler is invoked by a Listener for each authenticated session. It
// must return promptly; long-lived work belongs on its own goroutine. The
// returned release function is called when the session ends.
type SessionHandler interface {
	OnSession(ctx context.Context, s Session) (release func(), err error)
}

// SessionHandlerFunc adapts a function to SessionHandler.
type SessionHandlerFunc func(ctx context.Context, s Session) (func(), error)

// OnSession implements SessionHandler.
func (f SessionHandlerFunc) OnSession(ctx context.Context, s Session) (func(), error) {
	return f(ctx, s)
}

// Listener accepts spoke-initiated tunnels on the hub.
type Listener interface {
	// Addr reports the address the listener is bound to.
	Addr() string
	// Serve blocks, dispatching each authenticated session to h, until ctx is
	// cancelled or a non-recoverable error occurs.
	Serve(ctx context.Context, h SessionHandler) error
	// Shutdown stops accepting and closes live sessions.
	Shutdown(ctx context.Context) error
}

// Handler is implemented on the spoke side: it answers the requests the hub
// sends down the tunnel.
type Handler interface {
	// Do executes one allow-listed Prometheus request.
	Do(ctx context.Context, req *Request) (*Response, error)
	// Describe returns the spoke's cluster facts.
	Describe(ctx context.Context, knownFingerprint string) (Facts, error)
}

// Dialer is the spoke side of the tunnel. Dial connects to one hub endpoint
// and serves h until the connection drops or ctx is cancelled; it is the
// caller's job to retry with backoff.
type Dialer interface {
	Dial(ctx context.Context, endpoint string, h Handler) error
}
