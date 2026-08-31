// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"google.golang.org/grpc"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// DialerConfig configures the spoke side of the tunnel.
//
// It carries no transport settings. Establishing and authenticating the
// connection belongs to the caller — internal/tunnel/wstun does it over a
// WebSocket — and what remains here is only how the spoke behaves once it has
// one.
type DialerConfig struct {
	// Endpoint labels errors so a reconnect loop can log which hub ended. It
	// is not dialled by anything in this package.
	Endpoint string
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// Generation is the spoke process start time in Unix nanoseconds. It is
	// stamped onto every Describe reply and is what the hub's
	// Session.Generation reports.
	Generation int64
	// Keepalive configures the spoke's HTTP/2 ping enforcement policy. See
	// KeepaliveParams.
	Keepalive KeepaliveParams
	// MaxChunkBytes is the body chunk size. Default and maximum 64 KiB, which
	// is what the proto documents.
	MaxChunkBytes int
}

// ServeConn runs the spoke half of the tunnel over an already-connected,
// already-authenticated net.Conn, until the connection drops or ctx is
// cancelled.
//
// This is the role reversal of ADR-0002: the side that dialled runs the gRPC
// *server*. conn is owned by ServeConn from here on and is closed before it
// returns.
//
// It always returns a non-nil *DialError, even for an orderly remote close. A
// reconnect loop needs something it can log and turn into a metric label, and a
// bare io.EOF is neither; use errors.As to recover the Reason.
func ServeConn(ctx context.Context, conn net.Conn, cfg DialerConfig, h tunnel.Handler) error {
	if conn == nil {
		return dialErr(cfg.Endpoint, ReasonDial, errors.New("conn is required"))
	}
	if h == nil {
		_ = conn.Close()
		return dialErr(cfg.Endpoint, ReasonDial, errors.New("handler is required"))
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	chunk := cfg.MaxChunkBytes
	if chunk <= 0 || chunk > defaultChunkBytes {
		chunk = defaultChunkBytes
	}

	nc := newNotifyConn(conn)
	lis := newOneShotListener(nc)

	srv := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(cfg.Keepalive.enforcementPolicy()),
		grpc.KeepaliveParams(cfg.Keepalive.serverParams()),
		grpc.MaxRecvMsgSize(maxCallBytes),
		grpc.MaxSendMsgSize(maxCallBytes),
	)
	fleetv1.RegisterSpokeServiceServer(srv, &spokeServer{
		h:          h,
		generation: cfg.Generation,
		chunkBytes: chunk,
	})

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	var (
		cancelled bool
	)
	select {
	case <-serveErr:
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
		log.InfoContext(ctx, "spoke tunnel stopped: context cancelled",
			slog.String("endpoint", cfg.Endpoint))
		return dialErr(cfg.Endpoint, ReasonContextCancelled, ctx.Err())
	default:
		// Serve returned because the one-shot listener's second Accept woke up,
		// which only happens when the connection died. The notify wrapper always
		// records that failure before waking Accept.
		reason := nc.DeathReason()
		log.WarnContext(ctx, "spoke tunnel connection closed",
			slog.String("endpoint", cfg.Endpoint), slog.String("reason", reason))
		return dialErr(cfg.Endpoint, ReasonConnClosed, errors.New(reason))
	}
}
