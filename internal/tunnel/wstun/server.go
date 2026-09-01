// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
)

// Subprotocol is the WebSocket subprotocol both sides must negotiate. It is
// part of the wire contract: a client that did not ask for it is not one of
// ours, and saying so during the upgrade is cheaper than discovering it after.
const Subprotocol = "pmf.tunnel.v1"

// DefaultPath is where the hub mounts the tunnel handler.
const DefaultPath = "/tunnel"

// defaultMaxPendingHandshakes bounds how many peers may be between the upgrade
// and a completed ClientAuth at once.
//
// MaxSessions alone does not cover this. A flood of connections that upgrade
// and then say nothing would otherwise sit in the hub for the whole handshake
// timeout each, and if they held session slots while doing it they would lock
// real spokes out. They hold one of these instead, which is a much smaller and
// much cheaper thing to run out of.
const defaultMaxPendingHandshakes = 32

// offerTimeout bounds how long an authenticated connection waits to be adopted
// by a Serve loop. It is not zero: if nothing is serving the listener, the peer
// deserves a closed connection rather than an indefinite hang.
const offerTimeout = 10 * time.Second

// ServerConfig configures the hub side of the WebSocket tunnel.
type ServerConfig struct {
	// Verify checks the presented chain against the fleet's authority and
	// returns the identity derived from the leaf's URI SAN. It is the whole of
	// the trust decision and is required; internal/ca supplies it.
	Verify func(chain []*x509.Certificate) (tunnel.Identity, error)
	// IsRevoked reports whether a certificate serial has been revoked. It is
	// consulted on every connection and must be fast and safe for concurrent
	// use. A nil predicate treats nothing as revoked.
	IsRevoked func(serial string) bool
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// MaxSessions caps concurrently attached spokes. Zero means unlimited. The
	// cap is applied before the WebSocket upgrade, so a spoke over the limit
	// gets a 503 it can act on rather than a connection that dies later.
	MaxSessions int
	// Replicas reports how many hub replicas are currently running, for the
	// ServerHello. It is a func because replicas come and go under a rolling
	// update or an autoscaler, and a spoke that learned a stale count would
	// either stop dialing short of full coverage or dial forever. Nil or a
	// non-positive result advertises nothing, and a spoke then keeps one tunnel
	// per configured endpoint.
	Replicas func() int
	// ServerID identifies this hub replica in the ServerHello, for spoke-side
	// logging. Empty is fine.
	ServerID string
	// Keepalive configures HTTP/2 PING liveness inside the tunnel. Its default
	// 10s interval is what keeps an ingress from closing the connection as
	// idle; see ADR-0014.
	Keepalive grpctun.KeepaliveParams
	// Path is where the handler is mounted. It is used only for Addr() and log
	// lines — routing is the caller's mux. Empty means DefaultPath.
	Path string
	// HandshakeTimeout bounds the whole ServerHello/ClientAuth/Accepted
	// exchange. Zero means 10s.
	HandshakeTimeout time.Duration
	// MaxPendingHandshakes bounds simultaneous unauthenticated handshakes.
	// Zero means 32.
	MaxPendingHandshakes int
}

// Server is the hub half of the WebSocket tunnel: an http.Handler that
// authenticates spokes and a tunnel.Listener that yields the resulting
// sessions.
//
// It is safe for concurrent use.
type Server struct {
	cfg  ServerConfig
	log  *slog.Logger
	hsTO time.Duration
	rand io.Reader

	src *connSource
	lis tunnel.Listener

	// sessions counts peers that authenticated and whose handler is still
	// running, which is exactly the set of live tunnels.
	sessions atomic.Int64
	// pending is a counting semaphore over unauthenticated handshakes.
	pending chan struct{}
}

// NewServer builds the hub side of the tunnel. The returned Server owns a
// tunnel.Listener from this point on; call [Server.Listener] to get it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Verify == nil {
		return nil, errors.New("wstun: Verify is required")
	}
	if cfg.MaxSessions < 0 {
		return nil, fmt.Errorf("wstun: MaxSessions must not be negative, got %d", cfg.MaxSessions)
	}
	if cfg.MaxPendingHandshakes < 0 {
		return nil, fmt.Errorf("wstun: MaxPendingHandshakes must not be negative, got %d", cfg.MaxPendingHandshakes)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	path := cfg.Path
	if path == "" {
		path = DefaultPath
	}
	hsTO := cfg.HandshakeTimeout
	if hsTO <= 0 {
		hsTO = handshakeTimeout
	}
	pendingN := cfg.MaxPendingHandshakes
	if pendingN == 0 {
		pendingN = defaultMaxPendingHandshakes
	}

	src := newConnSource("websocket://" + path)
	// MaxSessions is deliberately not passed down. The cap belongs where it can
	// answer 503 before an upgrade, which is here; counting the same sessions
	// again below would only create a second, racier answer to the same
	// question.
	// src is non-nil and MaxSessions is deliberately left at its valid zero
	// value, so NewSourceListener has no error path for these arguments.
	lis, _ := grpctun.NewSourceListener(src, grpctun.ListenerConfig{
		Logger:    log,
		Keepalive: cfg.Keepalive,
	})

	cfg.Path = path
	return &Server{
		cfg:     cfg,
		log:     log,
		hsTO:    hsTO,
		rand:    rand.Reader,
		src:     src,
		lis:     lis,
		pending: make(chan struct{}, pendingN),
	}, nil
}

// Handler returns the HTTP handler to mount at the tunnel path. It upgrades
// the request, authenticates the spoke and then blocks for the lifetime of the
// session, so the connection is not reclaimed underneath the tunnel.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

// Listener returns the tunnel.Listener that yields authenticated sessions.
// Hand it to the registry exactly as the previous TLS listener was handed over;
// nothing above the transport can tell the difference.
func (s *Server) Listener() tunnel.Listener { return s.lis }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	remote := remoteAddr(r)

	// Refuse before upgrading. A cap enforced after the upgrade has already
	// paid for the goroutine, the buffers and the handshake it was meant to
	// prevent, and it cannot tell the peer why.
	if s.atSessionLimit() {
		s.log.WarnContext(r.Context(), "tunnel upgrade refused: session limit reached",
			slog.String("remote", remote),
			slog.Int("max_sessions", s.cfg.MaxSessions))
		w.Header().Set("Retry-After", "5")
		http.Error(w, "hub is at its spoke session limit", http.StatusServiceUnavailable)
		return
	}

	if !requestsSubprotocol(r) {
		s.log.WarnContext(r.Context(), "tunnel upgrade refused: subprotocol not requested",
			slog.String("remote", remote))
		http.Error(w, "this endpoint speaks the "+Subprotocol+" websocket subprotocol",
			http.StatusBadRequest)
		return
	}

	select {
	case s.pending <- struct{}{}:
	default:
		s.log.WarnContext(r.Context(), "tunnel upgrade refused: too many handshakes in flight",
			slog.String("remote", remote),
			slog.Int("max_pending_handshakes", cap(s.pending)))
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many tunnel handshakes in flight", http.StatusServiceUnavailable)
		return
	}
	releasePending := sync.OnceFunc(func() { <-s.pending })
	defer releasePending()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{Subprotocol},
		// Compression buys nothing on a stream that is already gRPC-framed
		// protobuf, and costs a per-connection flate window on both sides.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept has already written a response.
		s.log.WarnContext(r.Context(), "tunnel upgrade failed", slog.String("remote", remote), slog.Any("err", err))
		return
	}
	if ws.Subprotocol() != Subprotocol {
		s.log.WarnContext(r.Context(), "tunnel upgrade refused: subprotocol not negotiated",
			slog.String("remote", remote), slog.String("subprotocol", ws.Subprotocol()))
		_ = ws.Close(websocket.StatusPolicyViolation, ErrSubprotocol.Error())
		return
	}

	// The net.Conn outlives the request, so it must not be bound to a request
	// context that a hijack has already made meaningless.
	connCtx, cancelConn := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancelConn()
	conn := websocket.NetConn(connCtx, ws, websocket.MessageBinary)

	id, err := s.authenticate(conn, remote)
	if err != nil {
		s.log.WarnContext(connCtx, "tunnel authentication failed",
			slog.String("remote", remote), slog.Any("err", err))
		_ = writeMessage(conn, serverAccept{Accepted: false, Reason: rejectionReason(err)})
		_ = conn.Close()
		return
	}

	// Now that the peer has proved who it is, take the slot for real. The
	// pre-upgrade check above is a cheap early answer; this is the atomic one.
	if !s.reserveSession() {
		s.log.WarnContext(connCtx, "tunnel rejected: session limit reached",
			slog.String("remote", remote), slog.String("cluster", id.ClusterID))
		_ = writeMessage(conn, serverAccept{Accepted: false, Reason: ErrTooManySessions.Error()})
		_ = conn.Close()
		return
	}
	defer s.sessions.Add(-1)

	if err := writeMessage(conn, serverAccept{Accepted: true, ClusterID: id.ClusterID}); err != nil {
		s.log.WarnContext(connCtx, "tunnel accept could not be sent",
			slog.String("remote", remote), slog.String("cluster", id.ClusterID), slog.Any("err", err))
		_ = conn.Close()
		return
	}
	// The handshake budget is spent; the tunnel itself must not carry a
	// deadline, because a quiet tunnel is a healthy one.
	_ = conn.SetDeadline(time.Time{})
	releasePending()

	done := make(chan struct{})
	offerCtx, cancelOffer := context.WithTimeout(context.WithoutCancel(r.Context()), offerTimeout)
	defer cancelOffer()
	if err := s.src.offer(offerCtx, &adoption{conn: &sessionConn{Conn: conn, done: done}, id: id}); err != nil {
		s.log.WarnContext(connCtx, "tunnel could not be adopted",
			slog.String("remote", remote), slog.String("cluster", id.ClusterID), slog.Any("err", err))
		_ = conn.Close()
		return
	}

	// Hold the handler open for the life of the session: returning would end
	// the request, and with it the connection the tunnel is running on.
	<-done
}

// authenticate runs the hub half of the handshake and returns the identity the
// certificate proves. It never trusts anything the peer says about itself.
func (s *Server) authenticate(conn net.Conn, remote string) (tunnel.Identity, error) {
	// One deadline for the whole exchange, so a peer that stalls anywhere in it
	// releases its slot on schedule.
	if err := conn.SetDeadline(time.Now().Add(s.hsTO)); err != nil {
		return tunnel.Identity{}, fmt.Errorf("%w: set handshake deadline: %w", ErrHandshakeFailed, err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return tunnel.Identity{}, fmt.Errorf("%w: generate nonce: %w", ErrHandshakeFailed, err)
	}
	hello := serverHello{Nonce: nonce, ProtocolVersion: ProtocolVersion, ServerID: s.cfg.ServerID}
	if s.cfg.Replicas != nil {
		if n := s.cfg.Replicas(); n > 0 {
			hello.Replicas = n
		}
	}
	if err := writeMessage(conn, hello); err != nil {
		return tunnel.Identity{}, fmt.Errorf("%w: %w", ErrHandshakeFailed, err)
	}

	var auth clientAuth
	if err := readMessage(conn, &auth); err != nil {
		return tunnel.Identity{}, err
	}
	if !compatibleVersion(auth.ProtocolVersion) {
		return tunnel.Identity{}, fmt.Errorf("%w: spoke speaks %q, hub speaks %q",
			ErrProtocolVersion, auth.ProtocolVersion, ProtocolVersion)
	}
	if len(auth.Chain) == 0 {
		return tunnel.Identity{}, fmt.Errorf("%w: no certificate presented", ErrUntrustedCertificate)
	}

	chain := make([]*x509.Certificate, 0, len(auth.Chain))
	for i, der := range auth.Chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return tunnel.Identity{}, fmt.Errorf("%w: certificate %d is unparseable: %w",
				ErrUntrustedCertificate, i, err)
		}
		chain = append(chain, cert)
	}

	id, err := s.cfg.Verify(chain)
	if err != nil {
		return tunnel.Identity{}, fmt.Errorf("%w: %w", ErrUntrustedCertificate, err)
	}
	leaf := chain[0]
	if id.CertSerial == "" && leaf.SerialNumber != nil {
		// TrimPrefix mirrors ca.SerialHex (not importable here: wstun is a
		// transport and depends on no CA). %x keeps a minus sign on a
		// negative serial; every other formatter of this value strips it,
		// and a serial spelled two ways is two different registry keys.
		id.CertSerial = strings.TrimPrefix(fmt.Sprintf("%x", leaf.SerialNumber), "-")
	}
	if id.CertNotAfter.IsZero() {
		id.CertNotAfter = leaf.NotAfter
	}
	if auth.InstanceID != "" {
		// Self-reported and authenticates nothing, but it becomes a registry
		// map key, a per-session goroutine, and a log field -- so its size
		// and character set are bounded here. A spoke sending anything else
		// is not a version skew to tolerate; it is broken or hostile.
		if err := validInstanceID(auth.InstanceID); err != nil {
			return tunnel.Identity{}, fmt.Errorf("%w: instanceId: %w", ErrHandshakeFailed, err)
		}
		id.InstanceID = auth.InstanceID
	}
	if s.cfg.IsRevoked != nil && s.cfg.IsRevoked(id.CertSerial) {
		return tunnel.Identity{}, fmt.Errorf("%w: serial %s", ErrRevoked, id.CertSerial)
	}

	// Possession of the private key, over a nonce this hub chose for this
	// connection. Everything before this proves only that the peer holds a
	// copy of a certificate, which is public.
	//
	// The transcript is verified against the hub's OWN protocol version, not
	// the string the peer sent. compatibleVersion above is strict equality
	// today, so the two are the same bytes -- but the moment a skew policy
	// accepts more than one version, an echoed field would hand the peer a
	// choice of transcript, and a domain-separation field the attacker
	// selects is not domain separation.
	if err := certproof.Verify(leaf, auth.Signature, nonce, ProtocolVersion, auth.ClusterID); err != nil {
		return tunnel.Identity{}, err
	}

	// The certificate is authoritative. A spoke that signed a different cluster
	// ID than the one it was issued is either misconfigured or trying to be
	// somebody else, and neither is something to paper over by preferring the
	// certificate silently.
	if auth.ClusterID != id.ClusterID {
		return tunnel.Identity{}, fmt.Errorf("%w: spoke reported %q, certificate says %q",
			ErrClusterMismatch, auth.ClusterID, id.ClusterID)
	}

	// Audit only. It comes from a header an ingress sets, so it is never an
	// input to any decision above.
	id.RemoteAddr = remote
	return id, nil
}

// atSessionLimit reports whether the hub is already full. It is an advisory
// read: reserveSession makes the decision that counts.
func (s *Server) atSessionLimit() bool {
	return s.cfg.MaxSessions > 0 && s.sessions.Load() >= int64(s.cfg.MaxSessions)
}

// reserveSession claims a session slot, or reports that the hub is full.
func (s *Server) reserveSession() bool {
	if s.cfg.MaxSessions <= 0 {
		s.sessions.Add(1)
		return true
	}
	limit := int64(s.cfg.MaxSessions)
	for {
		n := s.sessions.Load()
		if n >= limit {
			return false
		}
		if s.sessions.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// rejectionReason renders a refusal the spoke can act on without describing the
// hub's internals. The peer already knows which certificate it presented, so
// naming the category is help, not disclosure.
func rejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrRevoked):
		return "certificate has been revoked"
	case errors.Is(err, ErrClusterMismatch):
		return "reported cluster id does not match the certificate"
	case errors.Is(err, ErrBadSignature):
		return "signature does not verify"
	case errors.Is(err, ErrUntrustedCertificate):
		return "certificate is not trusted by this hub"
	case errors.Is(err, ErrProtocolVersion):
		return "incompatible tunnel protocol version"
	default:
		return "handshake failed"
	}
}

// requestsSubprotocol reports whether the client offered the tunnel
// subprotocol in its upgrade request.
func requestsSubprotocol(r *http.Request) bool {
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), Subprotocol) {
				return true
			}
		}
	}
	return false
}

// remoteAddr reports the peer address for the audit log, preferring
// X-Forwarded-For because the tunnel arrives through an ingress and
// RemoteAddr is therefore the ingress.
//
// It is never an input to an authorization decision: the header is
// client-settable, and identity comes from the certificate.
func remoteAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if i := strings.IndexByte(first, ','); i >= 0 {
			first = first[:i]
		}
		if first = strings.TrimSpace(first); first != "" {
			return first
		}
	}
	return r.RemoteAddr
}

// adoption is one authenticated connection on its way to the Serve loop.
type adoption struct {
	conn net.Conn
	id   tunnel.Identity
}

// connSource adapts HTTP handler invocations to grpctun.ConnSource.
//
// The channel is unbuffered on purpose: an authenticated connection is handed
// straight to a waiting Serve loop or not at all, so there is never a queue of
// live tunnels that nobody has adopted.
type connSource struct {
	addr   string
	ch     chan *adoption
	closed chan struct{}
	once   sync.Once
}

var _ grpctun.ConnSource = (*connSource)(nil)

func newConnSource(addr string) *connSource {
	return &connSource{addr: addr, ch: make(chan *adoption), closed: make(chan struct{})}
}

// Accept implements grpctun.ConnSource.
func (s *connSource) Accept(ctx context.Context) (net.Conn, tunnel.Identity, error) {
	select {
	case <-ctx.Done():
		return nil, tunnel.Identity{}, ctx.Err()
	case <-s.closed:
		return nil, tunnel.Identity{}, ErrServerClosed
	case a := <-s.ch:
		return a.conn, a.id, nil
	}
}

// Addr implements grpctun.ConnSource.
func (s *connSource) Addr() string { return s.addr }

// Close implements grpctun.ConnSource. It is idempotent.
func (s *connSource) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// offer hands one authenticated connection to a waiting Accept.
func (s *connSource) offer(ctx context.Context, a *adoption) error {
	select {
	case s.ch <- a:
		return nil
	case <-s.closed:
		return ErrServerClosed
	case <-ctx.Done():
		return fmt.Errorf("%w: no serve loop adopted the connection: %w", ErrServerClosed, ctx.Err())
	}
}

// sessionConn signals the HTTP handler when the session ends, so it can return
// and let net/http reclaim the hijacked connection.
type sessionConn struct {
	net.Conn

	once sync.Once
	done chan struct{}
}

var _ io.Closer = (*sessionConn)(nil)

// Close implements net.Conn. It is idempotent and always closes done, whether
// the session ended because the hub closed it or because the peer vanished.
func (c *sessionConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// maxInstanceIDLen bounds the self-reported instance identifier. Real values
// are pod names plus a short suffix; 128 leaves room for any sane naming
// scheme while keeping a hostile 64 KiB value out of the registry and logs.
const maxInstanceIDLen = 128

// validInstanceID enforces the bound above and a printable character set,
// because the value is stored as a map key and printed into structured logs.
func validInstanceID(v string) error {
	if len(v) > maxInstanceIDLen {
		return fmt.Errorf("longer than %d bytes", maxInstanceIDLen)
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("contains a byte outside printable ASCII")
		}
	}
	return nil
}
