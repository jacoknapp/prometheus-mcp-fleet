// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/keepalive"
)

// KeepaliveParams configures HTTP/2 PING-based liveness. The same struct is
// used on both sides but means different things, because the roles are
// reversed:
//
//   - On a hub listener it becomes grpc keepalive.ClientParameters. Defaults:
//     Time 10s, Timeout 5s, PermitWithoutStream true. A spoke that stops
//     answering PINGs is therefore detected within ~15s.
//   - On a spoke dialer, Time becomes keepalive.EnforcementPolicy.MinTime, the
//     fastest ping rate the spoke will tolerate before it sends a GOAWAY with
//     "too_many_pings". Defaults: MinTime 5s, PermitWithoutStream true. It must
//     be less than or equal to the hub's Time or healthy hubs get disconnected.
//     Timeout is unused on that side: liveness detection is the hub's job.
//
// The spoke's grpc keepalive.ServerParameters deliberately leave
// MaxConnectionIdle, MaxConnectionAge and MaxConnectionAgeGrace at infinity. A
// tunnel that is idle for an hour is a healthy tunnel, not a stale one, and
// periodic forced reconnects across 100 clusters buy nothing.
type KeepaliveParams struct {
	// Time is the ping interval (hub) or the minimum tolerated ping interval
	// (spoke).
	Time time.Duration
	// Timeout is how long the hub waits for a ping ack before declaring the
	// connection dead. Unused on the spoke.
	Timeout time.Duration
	// PermitWithoutStream keeps pinging when no RPC is in flight, which is the
	// normal state of an idle tunnel.
	PermitWithoutStream bool
}

// Default keepalive values, from the fleet spec.
const (
	defaultClientPingTime    = 10 * time.Second
	defaultClientPingTimeout = 5 * time.Second
	defaultServerMinPingTime = 5 * time.Second
)

// clientParams renders the hub-side (gRPC client) keepalive configuration. A
// wholly zero KeepaliveParams means "the spec defaults"; once any field is set
// the caller is in charge and PermitWithoutStream is taken literally.
func (k KeepaliveParams) clientParams() keepalive.ClientParameters {
	if k == (KeepaliveParams{}) {
		k = KeepaliveParams{
			Time:                defaultClientPingTime,
			Timeout:             defaultClientPingTimeout,
			PermitWithoutStream: true,
		}
	}
	if k.Time <= 0 {
		k.Time = defaultClientPingTime
	}
	if k.Timeout <= 0 {
		k.Timeout = defaultClientPingTimeout
	}
	return keepalive.ClientParameters{
		Time:                k.Time,
		Timeout:             k.Timeout,
		PermitWithoutStream: k.PermitWithoutStream,
	}
}

// enforcementPolicy renders the spoke-side (gRPC server) keepalive policy,
// with the same zero-value rule as clientParams.
func (k KeepaliveParams) enforcementPolicy() keepalive.EnforcementPolicy {
	if k == (KeepaliveParams{}) {
		k = KeepaliveParams{Time: defaultServerMinPingTime, PermitWithoutStream: true}
	}
	if k.Time <= 0 {
		k.Time = defaultServerMinPingTime
	}
	return keepalive.EnforcementPolicy{
		MinTime:             k.Time,
		PermitWithoutStream: k.PermitWithoutStream,
	}
}

// serverParams renders spoke-side grpc keepalive.ServerParameters. Every
// connection-age knob stays at infinity so the tunnel is never torn down on a
// timer; only a real failure ends it.
func (KeepaliveParams) serverParams() keepalive.ServerParameters {
	const infinity = time.Duration(1<<63 - 1)
	return keepalive.ServerParameters{
		MaxConnectionIdle:     infinity,
		MaxConnectionAge:      infinity,
		MaxConnectionAgeGrace: infinity,
	}
}

// notifyConn is a net.Conn that closes a channel the moment the connection
// becomes unusable, whichever way that happens: a read error, a write error, or
// a local Close. Both sides of the tunnel need that signal, because "the socket
// died" is the only event that ends a session.
type notifyConn struct {
	net.Conn

	dead   chan struct{}
	once   sync.Once
	reason atomic.Pointer[string]
}

// newNotifyConn wraps c.
func newNotifyConn(c net.Conn) *notifyConn {
	return &notifyConn{Conn: c, dead: make(chan struct{})}
}

// Read implements net.Conn.
func (c *notifyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.kill("read: " + err.Error())
	}
	return n, err
}

// Write implements net.Conn.
func (c *notifyConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.kill("write: " + err.Error())
	}
	return n, err
}

// Close implements net.Conn. It is safe to call more than once.
func (c *notifyConn) Close() error {
	c.kill("local close")
	err := c.Conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Dead is closed once the connection is no longer usable.
func (c *notifyConn) Dead() <-chan struct{} { return c.dead }

// DeathReason reports why the connection ended, or "" while it is alive.
func (c *notifyConn) DeathReason() string {
	if r := c.reason.Load(); r != nil {
		return *r
	}
	return ""
}

func (c *notifyConn) kill(reason string) {
	c.once.Do(func() {
		c.reason.Store(&reason)
		close(c.dead)
	})
}

// oneShotListener is a net.Listener that yields exactly one, already-connected
// net.Conn and then parks. It is how the spoke hands the socket it dialled to a
// grpc.Server.
//
// The parking matters. grpc.Server.Serve returns as soon as Accept returns a
// non-temporary error, and it does not close live connections on the way out,
// so an Accept that returned io.EOF immediately would leave Serve returning
// while the tunnel was still running. Instead the second Accept blocks until
// the connection dies or the listener is closed, which makes "Serve returned"
// mean exactly "the tunnel ended".
type oneShotListener struct {
	conn *notifyConn

	mu       sync.Mutex
	handed   bool
	closed   bool
	closeCh  chan struct{}
	closeErr error
}

func newOneShotListener(c *notifyConn) *oneShotListener {
	return &oneShotListener{conn: c, closeCh: make(chan struct{})}
}

// Accept returns the single connection on its first call and blocks afterwards
// until the connection dies or the listener is closed.
func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !l.handed {
		l.handed = true
		c := l.conn
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()

	select {
	case <-l.conn.Dead():
		return nil, &net.OpError{Op: "accept", Net: "tunnel", Err: errors.New("tunnel connection closed: " + l.conn.DeathReason())}
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close stops the listener. It does not close the handed-out connection: the
// grpc.Server owns that once Accept has returned it.
func (l *oneShotListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.closeCh)
	return l.closeErr
}

// Addr reports the local address of the underlying connection.
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// oneShotDialer feeds an already-accepted connection to grpc.NewClient exactly
// once.
//
// grpc-go owns reconnection: when a transport dies the ClientConn calls the
// dialer again. There is nothing to redial here - the spoke owns the socket and
// will open a fresh one - so the second call must fail loudly. Returning an
// error puts the ClientConn permanently in TRANSIENT_FAILURE, which the hub
// observes and turns into a session teardown, instead of the connection
// silently hanging in a reconnect backoff loop forever.
type oneShotDialer struct {
	mu       sync.Mutex
	conn     net.Conn
	used     bool
	once     sync.Once
	redialed chan struct{}
}

func newOneShotDialer(c net.Conn) *oneShotDialer {
	return &oneShotDialer{conn: c, redialed: make(chan struct{})}
}

// dial satisfies grpc.WithContextDialer.
func (d *oneShotDialer) dial(_ context.Context, _ string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.used {
		d.once.Do(func() { close(d.redialed) })
		return nil, errors.New("grpctun: tunnel connection is single-use and has already been consumed")
	}
	d.used = true
	c := d.conn
	d.conn = nil
	return c, nil
}

// Redialed is closed the first time grpc-go asks for a second connection, which
// only happens after the first one has died.
func (d *oneShotDialer) Redialed() <-chan struct{} { return d.redialed }
