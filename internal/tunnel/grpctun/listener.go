// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// maxCallBytes is the per-message gRPC limit on both sides. Chunks are capped
// at 64 KiB, so 1 MiB is 16x headroom. It is intentionally small: needing to
// raise it would mean a response was being sent as one message, which is the
// bug this transport exists to avoid.
const maxCallBytes = 1 << 20

// defaultHandshakeTimeout bounds the HTTP/2 preface exchange that follows
// adoption of an authenticated connection.
const defaultHandshakeTimeout = 10 * time.Second

// ConnSource supplies connections whose peer identity is already established.
//
// It is the seam between "how a spoke reaches the hub" and "what the hub does
// with the connection once it has". Authentication belongs entirely to the
// implementation — by the time Accept returns, the identity is settled and
// this package treats it as certificate-derived fact. That is what lets the
// WebSocket transport in internal/tunnel/wstun reuse this reversed-role gRPC
// machinery without a second copy of it existing.
//
// Implementations must be safe for concurrent use.
type ConnSource interface {
	// Accept blocks until an authenticated connection is available, ctx is
	// cancelled, or the source is closed. The returned connection is owned by
	// the caller, which closes it when the session ends.
	Accept(ctx context.Context) (net.Conn, tunnel.Identity, error)
	// Addr describes where the source takes connections from, for logs and
	// readiness reporting. It need not be a network address.
	Addr() string
	// Close stops the source and unblocks any Accept in progress. It is
	// idempotent.
	Close() error
}

// ListenerConfig configures the hub side of the tunnel.
type ListenerConfig struct {
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// MaxSessions caps concurrently attached spokes. Zero means unlimited.
	// The cap is claimed before any per-connection goroutine exists, so a
	// burst of simultaneous connections cannot exceed it.
	//
	// A ConnSource that can reject a peer more cheaply than this — the
	// WebSocket source answers 503 before it upgrades — should do so and leave
	// this at zero rather than counting the same sessions twice.
	MaxSessions int
	// HandshakeTimeout bounds the initial HTTP/2 exchange on an adopted
	// connection. Default 10s.
	HandshakeTimeout time.Duration
	// Keepalive configures HTTP/2 PING liveness. See KeepaliveParams.
	Keepalive KeepaliveParams
}

// listener is the tunnel.Listener implementation returned by NewSourceListener.
type listener struct {
	cfg  ListenerConfig
	log  *slog.Logger
	src  ConnSource
	ka   KeepaliveParams
	hsTO time.Duration

	mu sync.Mutex
	// active counts reserved session slots: it is incremented before the
	// session exists and decremented after it has fully ended, so MaxSessions
	// cannot be exceeded by a burst of simultaneous connections.
	active   int
	sessions map[*session]struct{}
	closed   bool

	wg       sync.WaitGroup
	stopOnce sync.Once
	stopped  chan struct{}
}

var _ tunnel.Listener = (*listener)(nil)

// NewSourceListener returns a tunnel.Listener that adopts connections from src.
//
// The listener owns src from this point on and closes it during Shutdown. It
// does not authenticate anything: src has already done that, which is the
// whole point of the seam.
func NewSourceListener(src ConnSource, cfg ListenerConfig) (tunnel.Listener, error) {
	if src == nil {
		return nil, errors.New("grpctun: ConnSource is required")
	}
	if cfg.MaxSessions < 0 {
		return nil, fmt.Errorf("grpctun: MaxSessions must not be negative, got %d", cfg.MaxSessions)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	hsTO := cfg.HandshakeTimeout
	if hsTO <= 0 {
		hsTO = defaultHandshakeTimeout
	}
	return &listener{
		cfg:      cfg,
		log:      log,
		src:      src,
		ka:       cfg.Keepalive,
		hsTO:     hsTO,
		sessions: make(map[*session]struct{}),
		stopped:  make(chan struct{}),
	}, nil
}

// Addr implements tunnel.Listener.
func (l *listener) Addr() string { return l.src.Addr() }

// Serve implements tunnel.Listener. It blocks until ctx is cancelled, Shutdown
// is called, or the source fails unrecoverably.
func (l *listener) Serve(ctx context.Context, h tunnel.SessionHandler) error {
	if h == nil {
		return errors.New("grpctun: SessionHandler is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Cancelling ctx must unblock Accept, and only closing the source reliably
	// does that for every implementation.
	stopWatch := context.AfterFunc(ctx, func() { l.stopAccepting() })
	defer stopWatch()

	for {
		conn, id, err := l.src.Accept(ctx)
		if err != nil {
			l.wg.Wait()
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case l.isClosed():
				return ErrListenerClosed
			default:
				return fmt.Errorf("accept from %s: %w", l.Addr(), err)
			}
		}
		// Claim the slot here, on the accept goroutine, before anything else
		// exists. A cap applied inside the per-connection goroutine is not a
		// cap: the goroutine, its buffers and its handshake have already been
		// paid for by the time it says no.
		if !l.reserve() {
			l.log.WarnContext(ctx, "tunnel rejected",
				slog.String("remote", id.RemoteAddr),
				slog.String("cluster", id.ClusterID),
				slog.Int("max_sessions", l.cfg.MaxSessions),
				slog.Any("err", ErrTooManySessions))
			_ = conn.Close()
			continue
		}
		go func() {
			defer l.wg.Done()
			l.attach(ctx, conn, id, h)
		}()
	}
}

// attach builds the reversed-role gRPC client over an authenticated connection
// and hands the resulting session to h. It owns the session slot reserved by
// Serve and releases it on every path.
func (l *listener) attach(ctx context.Context, conn net.Conn, id tunnel.Identity, h tunnel.SessionHandler) {
	if id.RemoteAddr == "" && conn.RemoteAddr() != nil {
		id.RemoteAddr = conn.RemoteAddr().String()
	}

	sess, err := l.newSession(ctx, conn, id)
	if err != nil {
		l.release()
		// A peer that vanished between authenticating and the session
		// becoming ready is routine, not alarming: it is what a spoke's
		// coverage probe does by design, once a minute per spoke -- connect,
		// hear the hello, hang up. At WARN, a hundred spokes bury a real
		// setup failure under a hundred lines a minute of expected ones.
		level := slog.LevelWarn
		if errors.Is(err, errPeerGoneBeforeReady) {
			level = slog.LevelInfo
		}
		l.log.LogAttrs(ctx, level, "tunnel setup failed",
			slog.String("remote", id.RemoteAddr),
			slog.String("cluster", id.ClusterID),
			slog.Any("err", err))
		_ = conn.Close()
		return
	}

	release, err := h.OnSession(ctx, sess)
	if err != nil {
		l.log.WarnContext(ctx, "tunnel refused by session handler",
			slog.String("remote", id.RemoteAddr),
			slog.String("cluster", id.ClusterID),
			slog.Any("err", err))
		_ = sess.Close("rejected by hub: " + err.Error())
		l.forget(sess)
		l.release()
		return
	}

	l.log.InfoContext(ctx, "tunnel session established",
		slog.String("remote", id.RemoteAddr),
		slog.String("cluster", id.ClusterID),
		slog.String("cert_serial", id.CertSerial))

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.watch(ctx, sess)
		if release != nil {
			release()
		}
		l.forget(sess)
		l.release()
	}()
}

// newSession builds the gRPC client over an already-accepted connection.
func (l *listener) newSession(ctx context.Context, raw net.Conn, id tunnel.Identity) (*session, error) {
	nc := newNotifyConn(raw)
	od := newOneShotDialer(nc)

	cc, err := grpc.NewClient("passthrough:///"+id.ClusterID,
		// The peer is already authenticated by the ConnSource; a second TLS
		// layer inside the connection would be theatre.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(od.dial),
		// Idle mode would drop the transport after 30 minutes of quiet and try
		// to redial a connection that cannot be redialled. A quiet tunnel is a
		// healthy tunnel.
		grpc.WithIdleTimeout(0),
		grpc.WithKeepaliveParams(l.ka.clientParams()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxCallBytes),
			grpc.MaxCallSendMsgSize(maxCallBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}

	sctx, scancel := context.WithCancel(context.WithoutCancel(ctx))
	sess := &session{
		identity: id,
		client:   fleetv1.NewSpokeServiceClient(cc),
		cc:       cc,
		conn:     nc,
		log:      l.log,
		ctx:      sctx,
		cancel:   scancel,
		done:     make(chan struct{}),
	}

	// NewClient is lazy. Connect explicitly and wait for the HTTP/2 preface so
	// that a session handed to the hub is a session that actually works.
	cc.Connect()
	waitCtx, cancel := context.WithTimeout(ctx, l.hsTO)
	defer cancel()
	if err := waitReady(waitCtx, cc); err != nil {
		_ = sess.Close("handshake: " + err.Error())
		return nil, err
	}

	l.mu.Lock()
	l.sessions[sess] = struct{}{}
	l.mu.Unlock()

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.deathWatch(sess, nc, od)
	}()
	return sess, nil
}

// errPeerGoneBeforeReady marks the peer hanging up between authenticating and
// the session becoming ready. Sentinel rather than prose because the caller
// logs it at a lower level: a spoke's coverage probe produces exactly this,
// deliberately, about once a minute per spoke.
var errPeerGoneBeforeReady = errors.New("client connection ended before becoming ready")

// waitReady blocks until the ClientConn reaches READY or ctx expires.
func waitReady(ctx context.Context, cc *grpc.ClientConn) error {
	for {
		switch st := cc.GetState(); st {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return fmt.Errorf("%w: shut down", errPeerGoneBeforeReady)
		case connectivity.TransientFailure:
			return fmt.Errorf("%w: transport failure", errPeerGoneBeforeReady)
		default:
			if !cc.WaitForStateChange(ctx, st) {
				return fmt.Errorf("wait for ready: %w", ctx.Err())
			}
		}
	}
}

// deathWatch ends the session the moment the socket does. Two signals feed it:
// the wrapped connection (a read, write or close error) and the one-shot dialer
// (grpc-go asking for a redial, which only happens after a transport failure).
func (l *listener) deathWatch(s *session, nc *notifyConn, od *oneShotDialer) {
	select {
	case <-s.done:
		return
	case <-nc.Dead():
		_ = s.Close("connection closed: " + nc.DeathReason())
	case <-od.Redialed():
		_ = s.Close("transport failed; tunnel is single-use and cannot be redialled")
	}
}

// watch blocks until the session ends.
func (l *listener) watch(ctx context.Context, s *session) {
	select {
	case <-s.done:
	case <-l.stopped:
		_ = s.Close("hub-shutdown")
		<-s.done
	case <-ctx.Done():
		_ = s.Close("hub-shutdown")
		<-s.done
	}
}

// reserve claims a session slot, honouring MaxSessions.
func (l *listener) reserve() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	if l.cfg.MaxSessions > 0 && l.active >= l.cfg.MaxSessions {
		return false
	}
	l.active++
	// Counted HERE, in the same critical section as the closed check, and
	// that is what makes the WaitGroup safe rather than merely lucky.
	// Shutdown sets closed under this mutex before it waits, so once it is
	// waiting no further Add can begin, and every Add that will ever happen
	// already has. Counting after this lock was released instead left a
	// window -- a few microseconds between claiming the slot and starting
	// the goroutine -- in which the accept loop could take the counter from
	// zero to one while Shutdown was already inside Wait. That is concurrent
	// Add and Wait, which Go's WaitGroup contract forbids; it survived a
	// long time because the window is so narrow that only CI's parallelism
	// ever hit it.
	//
	// The other two Add sites need no such care: both run inside a goroutine
	// this one already counted, so the counter cannot be zero underneath
	// them.
	l.wg.Add(1)
	return true
}

func (l *listener) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active > 0 {
		l.active--
	}
}

func (l *listener) forget(s *session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, s)
}

func (l *listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// stopAccepting closes the source and marks the listener closed.
func (l *listener) stopAccepting() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		close(l.stopped)
		_ = l.src.Close()
	})
}

// Shutdown implements tunnel.Listener: stop accepting, close every live session
// with the reason "hub-shutdown", and return once the accept loop and all
// session goroutines have finished or ctx expires.
func (l *listener) Shutdown(ctx context.Context) error {
	l.stopAccepting()

	l.mu.Lock()
	live := make([]*session, 0, len(l.sessions))
	for s := range l.sessions {
		live = append(live, s)
	}
	l.mu.Unlock()
	for _, s := range live {
		_ = s.Close("hub-shutdown")
	}

	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown tunnel listener: %w", ctx.Err())
	}
}
