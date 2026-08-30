// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// defaultHandshakeTimeout bounds the mTLS handshake plus the HTTP/2 preface.
const defaultHandshakeTimeout = 10 * time.Second

// ListenerConfig configures the hub side of the tunnel.
type ListenerConfig struct {
	// Addr is the TCP address to bind, e.g. ":8443".
	Addr string
	// TLSConfig must already be configured to require and verify client
	// certificates: NewListener refuses anything weaker, because spoke identity
	// is the certificate and nothing else.
	TLSConfig *tls.Config
	// IdentityFromCert derives the spoke identity from the verified leaf
	// certificate. Returning an error rejects the connection. Required.
	IdentityFromCert func(*x509.Certificate) (tunnel.Identity, error)
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// MaxSessions caps concurrently attached spokes. Zero means unlimited.
	// Connections beyond the cap are logged and closed, not accepted and
	// dropped on the floor.
	MaxSessions int
	// HandshakeTimeout bounds TLS and the initial HTTP/2 exchange. Default 10s.
	HandshakeTimeout time.Duration
	// Keepalive configures HTTP/2 PING liveness. See KeepaliveParams.
	Keepalive KeepaliveParams
}

// listener is the tunnel.Listener implementation returned by NewListener.
type listener struct {
	cfg  ListenerConfig
	log  *slog.Logger
	net  net.Listener
	ka   KeepaliveParams
	hsTO time.Duration

	mu sync.Mutex
	// active counts reserved session slots: it is incremented before the
	// session exists and decremented after it has fully ended, so MaxSessions
	// cannot be exceeded by a burst of simultaneous handshakes.
	active   int
	sessions map[*session]struct{}
	closed   bool

	wg       sync.WaitGroup
	stopOnce sync.Once
	stopped  chan struct{}
}

var _ tunnel.Listener = (*listener)(nil)

// NewListener binds cfg.Addr and returns a hub-side tunnel listener.
//
// The returned listener owns the socket immediately, so /readyz can report
// "tunnel listener bound" before Serve is called.
func NewListener(cfg ListenerConfig) (tunnel.Listener, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("grpctun: TLSConfig is required")
	}
	if cfg.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, fmt.Errorf("grpctun: TLSConfig.ClientAuth must be RequireAndVerifyClientCert, got %v", cfg.TLSConfig.ClientAuth)
	}
	if cfg.IdentityFromCert == nil {
		return nil, errors.New("grpctun: IdentityFromCert is required")
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

	raw, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}
	return &listener{
		cfg:      cfg,
		log:      log,
		net:      tls.NewListener(raw, cfg.TLSConfig),
		ka:       cfg.Keepalive,
		hsTO:     hsTO,
		sessions: make(map[*session]struct{}),
		stopped:  make(chan struct{}),
	}, nil
}

// Addr implements tunnel.Listener.
func (l *listener) Addr() string { return l.net.Addr().String() }

// Serve implements tunnel.Listener. It blocks until ctx is cancelled, Shutdown
// is called, or accepting fails unrecoverably.
func (l *listener) Serve(ctx context.Context, h tunnel.SessionHandler) error {
	if h == nil {
		return errors.New("grpctun: SessionHandler is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Cancelling ctx must unblock Accept, and only closing the socket does
	// that.
	stopWatch := context.AfterFunc(ctx, func() { l.stopAccepting() })
	defer stopWatch()

	for {
		conn, err := l.net.Accept()
		if err != nil {
			l.wg.Wait()
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case l.isClosed():
				return ErrListenerClosed
			default:
				return fmt.Errorf("accept on %s: %w", l.Addr(), err)
			}
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.attach(ctx, conn, h)
		}()
	}
}

// attach completes the handshake, derives the identity and, if everything
// checks out, builds the reversed-role gRPC client and hands the session to h.
func (l *listener) attach(ctx context.Context, raw net.Conn, h tunnel.SessionHandler) {
	remote := raw.RemoteAddr().String()

	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		l.log.Warn("tunnel connection is not TLS", slog.String("remote", remote))
		_ = raw.Close()
		return
	}
	hsCtx, cancel := context.WithTimeout(ctx, l.hsTO)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		l.log.Warn("tunnel handshake failed", slog.String("remote", remote), slog.Any("err", err))
		_ = raw.Close()
		return
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		// Unreachable with RequireAndVerifyClientCert, but identity is the only
		// thing standing between a stranger and the fleet, so check anyway.
		l.log.Warn("tunnel peer presented no certificate", slog.String("remote", remote))
		_ = raw.Close()
		return
	}
	leaf := certs[0]
	id, err := l.cfg.IdentityFromCert(leaf)
	if err != nil {
		l.log.Warn("tunnel identity rejected",
			slog.String("remote", remote),
			slog.String("subject", leaf.Subject.String()),
			slog.Any("err", err))
		_ = raw.Close()
		return
	}
	id.RemoteAddr = remote
	if id.CertSerial == "" && leaf.SerialNumber != nil {
		id.CertSerial = fmt.Sprintf("%x", leaf.SerialNumber)
	}
	if id.CertNotAfter.IsZero() {
		id.CertNotAfter = leaf.NotAfter
	}

	if !l.reserve() {
		l.log.Warn("tunnel rejected: session limit reached",
			slog.String("remote", remote),
			slog.String("cluster", id.ClusterID),
			slog.Int("max_sessions", l.cfg.MaxSessions))
		_ = raw.Close()
		return
	}

	sess, err := l.newSession(ctx, tlsConn, id)
	if err != nil {
		l.release()
		l.log.Warn("tunnel setup failed",
			slog.String("remote", remote),
			slog.String("cluster", id.ClusterID),
			slog.Any("err", err))
		_ = raw.Close()
		return
	}

	release, err := h.OnSession(ctx, sess)
	if err != nil {
		l.log.Warn("tunnel refused by session handler",
			slog.String("remote", remote),
			slog.String("cluster", id.ClusterID),
			slog.Any("err", err))
		_ = sess.Close("rejected by hub: " + err.Error())
		l.forget(sess)
		l.release()
		return
	}

	l.log.Info("tunnel session established",
		slog.String("remote", remote),
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
		// The socket is already mTLS; a second TLS layer inside it would be
		// theatre.
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

// waitReady blocks until the ClientConn reaches READY or ctx expires.
func waitReady(ctx context.Context, cc *grpc.ClientConn) error {
	for {
		switch st := cc.GetState(); st {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errors.New("client connection shut down before becoming ready")
		case connectivity.TransientFailure:
			return errors.New("client connection failed before becoming ready")
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

// stopAccepting closes the socket and marks the listener closed.
func (l *listener) stopAccepting() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		close(l.stopped)
		_ = l.net.Close()
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
