// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// defaultDialTimeout bounds TCP connect plus the TLS handshake.
const defaultDialTimeout = 15 * time.Second

// DialerConfig configures the spoke side of the tunnel.
type DialerConfig struct {
	// TLSConfig carries the spoke's client certificate and the trust bundle for
	// the hub. Required. ServerName is filled in from the endpoint when empty.
	TLSConfig *tls.Config
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// Generation is the spoke process start time in Unix nanoseconds. It is
	// stamped onto every Describe reply and is what the hub's
	// Session.Generation reports.
	Generation int64
	// Keepalive configures the spoke's HTTP/2 ping enforcement policy. See
	// KeepaliveParams.
	Keepalive KeepaliveParams
	// DialTimeout bounds connect plus handshake. Default 15s.
	DialTimeout time.Duration
	// MaxChunkBytes is the body chunk size. Default and maximum 64 KiB, which
	// is what the proto documents.
	MaxChunkBytes int
}

// dialer is the tunnel.Dialer returned by NewDialer.
type dialer struct {
	cfg   DialerConfig
	log   *slog.Logger
	to    time.Duration
	chunk int
}

var _ tunnel.Dialer = (*dialer)(nil)

// NewDialer returns the spoke side of the tunnel. The returned Dialer is
// stateless and may be used for every hub endpoint concurrently; the spoke
// holds one tunnel per endpoint in PMF_HUB_ENDPOINTS.
func NewDialer(cfg DialerConfig) tunnel.Dialer {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	to := cfg.DialTimeout
	if to <= 0 {
		to = defaultDialTimeout
	}
	chunk := cfg.MaxChunkBytes
	if chunk <= 0 || chunk > defaultChunkBytes {
		chunk = defaultChunkBytes
	}
	return &dialer{cfg: cfg, log: log, to: to, chunk: chunk}
}

// Dial connects to one hub endpoint, completes the mTLS handshake, and then
// serves h as a gRPC server over the connection it just opened, until the
// connection drops or ctx is cancelled.
//
// It always returns a non-nil *DialError, even for an orderly remote close.
// A reconnect loop needs something it can log and turn into a metric label, and
// a bare io.EOF is neither; use errors.As to recover the Reason.
func (d *dialer) Dial(ctx context.Context, endpoint string, h tunnel.Handler) error {
	if h == nil {
		return dialErr(endpoint, ReasonDial, errors.New("handler is required"))
	}
	if d.cfg.TLSConfig == nil {
		return dialErr(endpoint, ReasonDial, errors.New("TLSConfig is required"))
	}

	dialCtx, cancel := context.WithTimeout(ctx, d.to)
	defer cancel()

	var nd net.Dialer
	raw, err := nd.DialContext(dialCtx, "tcp", endpoint)
	if err != nil {
		if ctx.Err() != nil {
			return dialErr(endpoint, ReasonContextCancelled, ctx.Err())
		}
		return dialErr(endpoint, ReasonDial, err)
	}

	tlsCfg := d.cfg.TLSConfig
	if tlsCfg.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(endpoint); splitErr == nil && host != "" {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = host
		}
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return dialErr(endpoint, ReasonContextCancelled, ctx.Err())
		}
		return dialErr(endpoint, ReasonTLSHandshake, err)
	}

	d.log.Info("tunnel connected",
		slog.String("endpoint", endpoint),
		slog.String("local", tlsConn.LocalAddr().String()))

	return d.serve(ctx, endpoint, tlsConn, h)
}

// serve runs the gRPC server on the freshly dialled connection. This is the
// role reversal: the side that dialled is the server.
func (d *dialer) serve(ctx context.Context, endpoint string, conn net.Conn, h tunnel.Handler) error {
	nc := newNotifyConn(conn)
	lis := newOneShotListener(nc)

	srv := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(d.cfg.Keepalive.enforcementPolicy()),
		grpc.KeepaliveParams(d.cfg.Keepalive.serverParams()),
		grpc.MaxRecvMsgSize(maxCallBytes),
		grpc.MaxSendMsgSize(maxCallBytes),
	)
	fleetv1.RegisterSpokeServiceServer(srv, &spokeServer{
		h:          h,
		generation: d.cfg.Generation,
		chunkBytes: d.chunk,
		log:        d.log,
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	var (
		err       error
		cancelled bool
	)
	select {
	case err = <-serveErr:
	case <-ctx.Done():
		cancelled = true
		// Stop, not GracefulStop: the hub has already been told to go away by
		// the caller's shutdown sequence, and a spoke that lingers keeps the
		// hub routing queries at a process that is exiting.
		srv.Stop()
		<-serveErr
	}
	_ = lis.Close()
	srv.Stop()
	_ = nc.Close()

	switch {
	case cancelled:
		return dialErr(endpoint, ReasonContextCancelled, ctx.Err())
	case errors.Is(err, grpc.ErrServerStopped):
		return dialErr(endpoint, ReasonServerShutdown, err)
	default:
		// Serve returned because the one-shot listener's second Accept woke up,
		// which only happens when the connection died.
		cause := err
		if reason := nc.DeathReason(); reason != "" {
			cause = errors.New(reason)
		}
		return dialErr(endpoint, ReasonConnClosed, cause)
	}
}
