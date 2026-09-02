// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startTestServer starts a server on an ephemeral port and shuts it down when
// the test ends.
func startTestServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()

	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Logger == nil {
		cfg.Logger, _ = newTestLogger()
	}
	s := NewServer(cfg)
	if err := s.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func TestNewServerDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		cfg                   ServerConfig
		wantName              string
		wantReadHeaderTimeout time.Duration
		wantReadTimeout       time.Duration
		wantWriteTimeout      time.Duration
		wantIdleTimeout       time.Duration
		wantGrace             time.Duration
	}{
		{
			name:                  "zero config takes every default",
			cfg:                   ServerConfig{},
			wantName:              "http",
			wantReadHeaderTimeout: DefaultReadHeaderTimeout,
			wantReadTimeout:       DefaultReadTimeout,
			wantWriteTimeout:      0, // SSE: an absolute write deadline would sever a stream.
			wantIdleTimeout:       DefaultIdleTimeout,
			wantGrace:             DefaultShutdownGrace,
		},
		{
			name: "explicit values are respected",
			cfg: ServerConfig{
				Name:              "mcp",
				ReadHeaderTimeout: time.Second,
				ReadTimeout:       2 * time.Second,
				WriteTimeout:      3 * time.Second,
				IdleTimeout:       4 * time.Second,
				ShutdownGrace:     5 * time.Second,
			},
			wantName:              "mcp",
			wantReadHeaderTimeout: time.Second,
			wantReadTimeout:       2 * time.Second,
			wantWriteTimeout:      3 * time.Second,
			wantIdleTimeout:       4 * time.Second,
			wantGrace:             5 * time.Second,
		},
		{
			name:                  "a negative ReadTimeout disables it",
			cfg:                   ServerConfig{ReadTimeout: -1},
			wantName:              "http",
			wantReadHeaderTimeout: DefaultReadHeaderTimeout,
			wantReadTimeout:       0,
			wantWriteTimeout:      0,
			wantIdleTimeout:       DefaultIdleTimeout,
			wantGrace:             DefaultShutdownGrace,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := NewServer(tc.cfg)
			if s.name != tc.wantName {
				t.Errorf("name = %q, want %q", s.name, tc.wantName)
			}
			if s.srv.ReadHeaderTimeout != tc.wantReadHeaderTimeout {
				t.Errorf("ReadHeaderTimeout = %v, want %v", s.srv.ReadHeaderTimeout, tc.wantReadHeaderTimeout)
			}
			if s.srv.ReadHeaderTimeout == 0 {
				t.Error("ReadHeaderTimeout must never be zero: that is the Slowloris hole")
			}
			if s.srv.ReadTimeout != tc.wantReadTimeout {
				t.Errorf("ReadTimeout = %v, want %v", s.srv.ReadTimeout, tc.wantReadTimeout)
			}
			if s.srv.WriteTimeout != tc.wantWriteTimeout {
				t.Errorf("WriteTimeout = %v, want %v", s.srv.WriteTimeout, tc.wantWriteTimeout)
			}
			if s.srv.IdleTimeout != tc.wantIdleTimeout {
				t.Errorf("IdleTimeout = %v, want %v", s.srv.IdleTimeout, tc.wantIdleTimeout)
			}
			if s.shutdownGrace != tc.wantGrace {
				t.Errorf("ShutdownGrace = %v, want %v", s.shutdownGrace, tc.wantGrace)
			}
			if s.srv.Handler == nil {
				t.Error("Handler is nil, want the 404 fallback")
			}
			if s.srv.ErrorLog == nil {
				t.Error("ErrorLog is nil, want http server errors routed into slog")
			}
		})
	}
}

func TestServerStartAndServe(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, ServerConfig{
		Name: "mcp",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "pong")
		}),
	})

	addr := s.Addr()
	if addr == "127.0.0.1:0" || !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("Addr = %q, want the resolved ephemeral address", addr)
	}

	resp, err := http.Get("http://" + addr + "/ping") //nolint:noctx // local test request
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "pong" {
		t.Errorf("body = %q, want pong", body)
	}
}

func TestServerAddrBeforeStart(t *testing.T) {
	t.Parallel()

	s := NewServer(ServerConfig{Addr: "127.0.0.1:12345"})
	if got := s.Addr(); got != "127.0.0.1:12345" {
		t.Errorf("Addr = %q, want the configured address", got)
	}
}

func TestServerStartBindError(t *testing.T) {
	t.Parallel()

	// Occupy a port, then ask the server for the same one. The conflict must
	// surface from Start, not vanish into a goroutine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	logger, _ := newTestLogger()
	s := NewServer(ServerConfig{Name: "conflicted", Addr: ln.Addr().String(), Logger: logger})

	startErr := s.Start(t.Context())
	if startErr == nil {
		t.Fatal("Start on a busy port returned nil")
	}
	if !strings.Contains(startErr.Error(), "listen conflicted") {
		t.Errorf("error = %v, want it to name the listener", startErr)
	}
	var opErr *net.OpError
	if !errors.As(startErr, &opErr) {
		t.Errorf("error = %v, want a wrapped *net.OpError", startErr)
	}
	if err := s.Wait(); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Wait after a failed Start = %v, want ErrNotStarted", err)
	}
}

func TestServerStartTwice(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, ServerConfig{})
	if err := s.Start(t.Context()); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

func TestServerShutdownBeforeStart(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	s := NewServer(ServerConfig{Name: "never-started", Addr: "127.0.0.1:0", Logger: logger})

	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown before Start = %v, want nil", err)
	}
	// Idempotent.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown = %v, want nil", err)
	}
	if err := s.Wait(); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Wait = %v, want ErrNotStarted", err)
	}
}

func TestServerShutdownIsIdempotent(t *testing.T) {
	t.Parallel()

	s := startTestServer(t, ServerConfig{})
	for i := range 3 {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown %d = %v, want nil", i, err)
		}
	}
	if err := s.Wait(); err != nil {
		t.Errorf("Wait after a graceful shutdown = %v, want nil", err)
	}
}

// TestServerShutdownDrainsInFlight proves a request that is already being
// served survives the shutdown instead of being cut off.
func TestServerShutdownDrainsInFlight(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	s := startTestServer(t, ServerConfig{
		Name: "draining",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(w, "finished")
		}),
	})

	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/slow") //nolint:noctx // local test request
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		done <- result{body: string(b), err: err}
	}()

	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("in-flight request failed across shutdown: %v", got.err)
	}
	if got.body != "finished" {
		t.Errorf("body = %q, want the handler allowed to finish", got.body)
	}
	if err := s.Wait(); err != nil {
		t.Errorf("Wait = %v, want nil after a graceful shutdown", err)
	}
}

// TestServerShutdownGraceExpires proves the grace period is enforced and the
// timeout is reported rather than swallowed.
func TestServerShutdownGraceExpires(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan struct{})
	s := startTestServer(t, ServerConfig{
		Name:          "stuck",
		ShutdownGrace: 50 * time.Millisecond,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			<-release
			_, _ = io.WriteString(w, "late")
		}),
	})
	t.Cleanup(func() { close(release) })

	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/stuck") //nolint:noctx // local test request
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-entered

	// No deadline on the context, so the configured grace applies.
	err := s.Shutdown(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "shutdown stuck") {
		t.Errorf("error = %v, want it to name the listener", err)
	}
}

// TestServerShutdownZeroGraceAppliesNoOverride pins that shutdownGrace == 0
// leaves an already-deadline-less context untouched. NewServer clamps
// ShutdownGrace to always be positive (see TestNewServerDefaults), so this
// reaches into the unexported field directly to exercise Shutdown's own
// boundary check: s.shutdownGrace > 0 vs a widened >= 0. At exactly zero, the
// widened form would still wrap the caller's context in
// context.WithTimeout(ctx, 0), a deadline that has already passed the instant
// it is created, aborting a slow-but-finishing handler instead of leaving the
// context alone as documented.
func TestServerShutdownZeroGraceAppliesNoOverride(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	s := startTestServer(t, ServerConfig{
		Name: "no-grace-override",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			<-release
			_, _ = io.WriteString(w, "done")
		}),
	})
	s.shutdownGrace = 0

	go func() {
		resp, err := http.Get("http://" + s.Addr() + "/slow") //nolint:noctx // local test request
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-entered
	time.AfterFunc(50*time.Millisecond, func() { close(release) })

	// context.Background carries no deadline of its own, so a zero grace
	// must fall through untouched rather than manufacturing an already-
	// expired one.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() = %v, want nil: a zero grace must not impose a deadline of its own", err)
	}
}

// TestServerStartLogsTLSState pins that the "listener started" log line
// reports the server's actual TLS state in both directions, not a constant or
// an inverted reading of s.tlsConfig != nil.
func TestServerStartLogsTLSState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tls     bool
		wantTLS bool
	}{
		{name: "plaintext listener reports tls false", tls: false, wantTLS: false},
		{name: "tls listener reports tls true", tls: true, wantTLS: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logger, buf := newTestLogger()
			cfg := ServerConfig{Name: "tls-state", Logger: logger}
			if tc.tls {
				tlsCfg, _ := newTestTLS(t)
				cfg.TLS = tlsCfg
			}
			startTestServer(t, cfg)

			var found bool
			for _, rec := range logLines(t, buf) {
				if rec["msg"] != "listener started" {
					continue
				}
				found = true
				if got := rec["tls"]; got != tc.wantTLS {
					t.Errorf(`"listener started" tls = %v, want %v`, got, tc.wantTLS)
				}
			}
			if !found {
				t.Fatal(`no "listener started" log record found`)
			}
		})
	}
}

func TestServerTLS(t *testing.T) {
	t.Parallel()

	tlsCfg, pool := newTestTLS(t)
	logger, _ := newTestLogger()

	s := startTestServer(t, ServerConfig{
		Name:   "tunnel",
		TLS:    tlsCfg,
		Logger: logger,
		Handler: Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "secure")
		}), RequestID, SecurityHeaders),
	})

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("https://" + s.Addr() + "/") //nolint:noctx // local test request
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "secure" {
		t.Errorf("body = %q, want secure", body)
	}
	// HSTS is meaningful here and must be present, unlike over plaintext.
	if got := resp.Header.Get("Strict-Transport-Security"); got != hstsValue {
		t.Errorf("Strict-Transport-Security = %q, want %q", got, hstsValue)
	}
}

// TestReadTimeoutSparesLongHandlers pins the net/http behaviour the default
// ReadTimeout relies on: once the body has been read to EOF the server clears
// the read deadline, so a handler that then runs well past ReadTimeout -- a
// long tool call, a streaming response -- still completes. A body that
// dribbles in slower than ReadTimeout is what the deadline is for, and it is
// cut off.
func TestReadTimeoutSparesLongHandlers(t *testing.T) {
	t.Parallel()

	const readTimeout = 300 * time.Millisecond
	s := startTestServer(t, ServerConfig{
		ReadTimeout: readTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Outlive ReadTimeout by a wide margin before answering, and
			// keep answering past it in the streaming shape.
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for range 3 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(readTimeout):
				}
				_, _ = io.WriteString(w, "tick\n")
				if flusher != nil {
					flusher.Flush()
				}
			}
		}),
	})
	url := "http://" + s.Addr() + "/slow"

	resp, err := http.Post(url, "text/plain", strings.NewReader("prompt body")) //nolint:noctx // local test request
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("a handler that outlived ReadTimeout after reading its body was cut off: %v", err)
	}
	if got, want := string(body), "tick\ntick\ntick\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}

	// The same request with a body that never finishes arriving is refused
	// once ReadTimeout elapses: the handler's ReadAll fails and the
	// connection is closed rather than parked forever.
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, pr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.ContentLength = 1 << 20
	start := time.Now()
	resp2, err := http.DefaultClient.Do(req)
	if err == nil {
		defer func() { _ = resp2.Body.Close() }()
		if resp2.StatusCode != http.StatusBadRequest {
			t.Fatalf("dribbling body: status %d, want 400 or a severed connection", resp2.StatusCode)
		}
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("dribbling body took %v to be refused; ReadTimeout %v did not bite", elapsed, readTimeout)
	}
}
