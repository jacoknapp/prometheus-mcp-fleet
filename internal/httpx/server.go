// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Errors returned by [Server]. Callers branch on these with errors.Is.
var (
	// ErrAlreadyStarted is returned by a second call to [Server.Start].
	ErrAlreadyStarted = errors.New("httpx: server already started")
	// ErrNotStarted is returned by [Server.Wait] when [Server.Start] never
	// succeeded, so that waiting on a server that failed to bind returns
	// immediately instead of blocking forever.
	ErrNotStarted = errors.New("httpx: server not started")
)

// Default timeouts applied when the corresponding [ServerConfig] field is
// zero.
const (
	// DefaultReadHeaderTimeout bounds how long a client may take to send its
	// request head. It is never left at zero: an unbounded header read is the
	// Slowloris hole, where a handful of connections dribbling one byte at a
	// time exhaust the listener.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout bounds how long a keep-alive connection may sit idle.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultShutdownGrace bounds how long [Server.Shutdown] waits for
	// in-flight requests when the caller's context has no deadline of its own.
	DefaultShutdownGrace = 30 * time.Second
)

// ServerConfig describes one listener. The zero value of every timeout field
// selects a documented default, except WriteTimeout -- see [NewServer].
type ServerConfig struct {
	// Name identifies the listener in log lines and errors, for example "mcp",
	// "admin" or "tunnel".
	Name string
	// Addr is the bind address, for example ":8080". ":0" binds an arbitrary
	// free port, which [Server.Addr] then reports.
	Addr string
	// Handler serves the requests. A nil Handler serves 404.
	Handler http.Handler
	// TLS, when non-nil, makes the listener serve TLS.
	TLS *tls.Config
	// Logger receives lifecycle lines and the http.Server's own error output.
	// A nil Logger uses slog.Default.
	Logger *slog.Logger
	// ReadHeaderTimeout bounds the request head. Zero means
	// [DefaultReadHeaderTimeout].
	ReadHeaderTimeout time.Duration
	// ReadTimeout bounds the whole request including the body. Zero means no
	// limit, which is intentional: a large remote-write-shaped upload or a
	// slow client on a long POST must not be cut off by a clock. Body size is
	// bounded by [MaxBody] instead, which is the right control for it.
	ReadTimeout time.Duration
	// WriteTimeout bounds the whole response. Zero means no limit -- see
	// [NewServer] for why that is the default here.
	WriteTimeout time.Duration
	// IdleTimeout bounds an idle keep-alive connection. Zero means
	// [DefaultIdleTimeout].
	IdleTimeout time.Duration
	// ShutdownGrace bounds [Server.Shutdown] when the caller's context carries
	// no deadline. Zero means [DefaultShutdownGrace].
	ShutdownGrace time.Duration
}

// Server is an http.Server that binds before it serves and shuts down
// gracefully.
//
// Binding happens synchronously inside [Server.Start], so a port conflict is
// returned to the caller as a startup error. The common alternative -- calling
// ListenAndServe in a goroutine -- reports "address already in use" into a
// channel nobody is reading yet, and the process comes up looking healthy
// while serving nothing.
//
// A Server is safe for concurrent use and is not reusable: once shut down, it
// stays down.
type Server struct {
	name          string
	addr          string
	tlsConfig     *tls.Config
	logger        *slog.Logger
	shutdownGrace time.Duration
	srv           *http.Server

	mu        sync.Mutex
	listener  net.Listener
	boundAddr string
	started   bool

	serveErr chan error
}

// NewServer builds a server from cfg. It binds nothing; call [Server.Start].
//
// Defaults for zero fields: ReadHeaderTimeout 10s, IdleTimeout 120s,
// ShutdownGrace 30s.
//
// WriteTimeout deliberately defaults to 0, meaning no limit. The MCP endpoint
// answers over Streamable HTTP and streams Server-Sent Events, and a tool call
// that fans out a range query across clusters can legitimately hold the
// response open for minutes. http.Server's WriteTimeout is an absolute
// deadline measured from the start of the request, not an idle timeout, so any
// non-zero value silently severs a long stream mid-body -- the agent sees a
// truncated JSON document with no error. Response duration is bounded where it
// belongs instead: per-request context deadlines (PMF_QUERY_TIMEOUT,
// PMF_RANGE_QUERY_TIMEOUT) and the response byte budget. Set WriteTimeout only
// on a listener that never streams.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	handler := cfg.Handler
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	readHeaderTimeout := cfg.ReadHeaderTimeout
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = DefaultReadHeaderTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	grace := cfg.ShutdownGrace
	if grace <= 0 {
		grace = DefaultShutdownGrace
	}
	name := cfg.Name
	if name == "" {
		name = "http"
	}

	return &Server{
		name:          name,
		addr:          cfg.Addr,
		tlsConfig:     cfg.TLS,
		logger:        logger,
		shutdownGrace: grace,
		serveErr:      make(chan error, 1),
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			TLSConfig:         cfg.TLS,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       idleTimeout,
			// Route the server's own connection-level errors into structured
			// logging instead of the standard logger's stderr.
			ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}
}

// Addr returns the address the server is listening on.
//
// Before [Server.Start] succeeds this is the configured address; afterwards it
// is the resolved one, which is what makes a ":0" bind usable -- a test can
// read the real port instead of guessing a free one and racing another test
// for it.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.boundAddr != "" {
		return s.boundAddr
	}
	return s.addr
}

// Start binds the listener synchronously and then serves in a goroutine.
//
// A bind failure -- a port already in use, a privileged port, a bad address --
// is returned here. Once Start returns nil the listener is accepting, so a
// caller may immediately connect to [Server.Addr] without polling for
// readiness.
//
// Calling Start twice returns [ErrAlreadyStarted].
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("listen %s on %s: %w", s.name, s.addr, err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.listener = ln
	s.boundAddr = ln.Addr().String()
	s.started = true
	bound := s.boundAddr
	s.mu.Unlock()

	s.logger.LogAttrs(context.Background(), slog.LevelInfo, "listener started",
		slog.String("server", s.name),
		slog.String("addr", bound),
		slog.Bool("tls", s.tlsConfig != nil),
	)

	go func() {
		err := s.srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		s.serveErr <- err
	}()
	return nil
}

// Wait blocks until the server stops serving and reports why.
//
// A graceful [Server.Shutdown] reports nil; http.ErrServerClosed is not an
// error worth propagating to a composition root. Wait returns [ErrNotStarted]
// when Start was never called or did not succeed. It is safe to call from
// several goroutines only in the sense that exactly one of them receives the
// result; use it from the goroutine that owns the process lifecycle.
func (s *Server) Wait() error {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if !started {
		return ErrNotStarted
	}
	return <-s.serveErr
}

// Shutdown stops accepting new connections and waits for in-flight requests to
// finish.
//
// When ctx carries no deadline of its own, the configured ShutdownGrace is
// applied, so a caller cannot accidentally wait forever for a wedged handler.
// Shutdown is idempotent and is safe to call before [Server.Start]; in that
// case it also makes a subsequent Start a no-op that stops immediately, which
// is the behaviour a composition root wants when one listener fails to bind
// and it has to unwind the others.
//
// It returns the context's error when the grace period expires with work still
// in flight, which the caller should surface as a non-zero exit code.
func (s *Server) Shutdown(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok && s.shutdownGrace > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.shutdownGrace)
		defer cancel()
	}
	if err := s.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown %s: %w", s.name, err)
	}
	return nil
}
