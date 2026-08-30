// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
)

// quietLogger keeps the suite's output readable; the transport logs every
// session open and close at Info.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tcpSource is a grpctun.ConnSource over a plain TCP listener.
//
// It stands in for a real transport: authentication is somebody else's job by
// the time a connection reaches this interface, so a test source simply
// declares the identity it would have derived. That the suite passes over this
// and over internal/tunnel/wstun with the same code below the seam is the
// property the ConnSource split exists to give.
type tcpSource struct {
	lis net.Listener
	id  tunnel.Identity
}

func (s *tcpSource) Accept(context.Context) (net.Conn, tunnel.Identity, error) {
	// Close is what unblocks this, which is why the context is unused: a
	// net.Listener has no context-aware Accept.
	conn, err := s.lis.Accept()
	if err != nil {
		return nil, tunnel.Identity{}, err
	}
	return conn, s.id, nil
}

func (s *tcpSource) Addr() string { return s.lis.Addr().String() }

func (s *tcpSource) Close() error { return s.lis.Close() }

// TestConformance runs the shared tunnel contract suite against the real
// reversed-role gRPC transport over a real socket.
func TestConformance(t *testing.T) {
	t.Parallel()
	tunneltest.RunConformance(t, newSession)
}

// newSession stands up a hub-side listener and a spoke-side ServeConn over one
// loopback TCP connection, and returns the resulting session.
func newSession(t *testing.T, h tunnel.Handler) (tunnel.Session, func()) {
	t.Helper()

	netLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	src := &tcpSource{lis: netLis, id: tunnel.Identity{ClusterID: tunneltest.ClusterID}}

	// Keepalive is deliberately slack. The suite runs ~13 parallel subtests in
	// each of three transport packages under -race, and the production 10s/5s
	// ping budget is not survivable on an oversubscribed CI box — a ping ACK
	// that arrives late would fail the test for a reason that has nothing to
	// do with the tunnel contract.
	lis, err := grpctun.NewSourceListener(src, grpctun.ListenerConfig{
		Logger:    quietLogger(),
		Keepalive: grpctun.KeepaliveParams{Time: time.Minute, Timeout: 30 * time.Second, PermitWithoutStream: true},
	})
	if err != nil {
		t.Fatalf("NewSourceListener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sessions := make(chan tunnel.Session, 1)
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = lis.Serve(ctx, tunnel.SessionHandlerFunc(func(_ context.Context, s tunnel.Session) (func(), error) {
			sessions <- s
			return nil, nil
		}))
	}()

	conn, err := net.Dial("tcp", netLis.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	spokeDone := make(chan struct{})
	go func() {
		defer close(spokeDone)
		_ = grpctun.ServeConn(ctx, conn, grpctun.DialerConfig{
			Endpoint:   netLis.Addr().String(),
			Logger:     quietLogger(),
			Generation: tunneltest.Generation,
		}, h)
	}()

	sess := waitForSession(t, sessions)
	cleanup := func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = lis.Shutdown(shutCtx)
		<-serveDone
		<-spokeDone
	}
	return sess, cleanup
}

// waitForSession fails the test rather than hanging when nothing connects.
func waitForSession(t *testing.T, sessions <-chan tunnel.Session) tunnel.Session {
	t.Helper()
	select {
	case s := <-sessions:
		return s
	case <-time.After(15 * time.Second):
		t.Fatal("no tunnel session was established within 15s")
		return nil
	}
}
