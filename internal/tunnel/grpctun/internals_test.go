// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

var errFixture = errors.New("grpctun fixture failure")

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

type writeErrorConn struct{ net.Conn }

func (writeErrorConn) Write([]byte) (int, error) { return 0, errFixture }

func TestKeepaliveParameters(t *testing.T) {
	t.Parallel()

	def := (KeepaliveParams{}).clientParams()
	if def.Time != defaultClientPingTime || def.Timeout != defaultClientPingTimeout || !def.PermitWithoutStream {
		t.Errorf("default client parameters = %+v", def)
	}
	custom := (KeepaliveParams{Time: -1, Timeout: -1}).clientParams()
	if custom.Time != defaultClientPingTime || custom.Timeout != defaultClientPingTimeout || custom.PermitWithoutStream {
		t.Errorf("partially invalid client parameters = %+v", custom)
	}
	policy := (KeepaliveParams{Time: -1}).enforcementPolicy()
	if policy.MinTime != defaultServerMinPingTime || policy.PermitWithoutStream {
		t.Errorf("custom enforcement policy = %+v", policy)
	}
	defPolicy := (KeepaliveParams{}).enforcementPolicy()
	if defPolicy.MinTime != defaultServerMinPingTime || !defPolicy.PermitWithoutStream {
		t.Errorf("default enforcement policy = %+v", defPolicy)
	}
	server := (KeepaliveParams{}).serverParams()
	if server.MaxConnectionIdle <= 0 || server.MaxConnectionAge <= 0 || server.MaxConnectionAgeGrace <= 0 {
		t.Errorf("server parameters are not effectively infinite: %+v", server)
	}
}

func TestNotifyConnAndOneShotAdapters(t *testing.T) {
	t.Parallel()

	t.Run("write failure records death", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		nc := newNotifyConn(writeErrorConn{Conn: local})
		if got := nc.DeathReason(); got != "" {
			t.Errorf("DeathReason while live = %q", got)
		}
		if _, err := nc.Write([]byte("x")); !errors.Is(err, errFixture) {
			t.Fatalf("Write = %v, want fixture failure", err)
		}
		<-nc.Dead()
		if got := nc.DeathReason(); !strings.Contains(got, "write") {
			t.Errorf("DeathReason = %q, want write failure", got)
		}
	})

	t.Run("listener closed before first accept", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		lis := newOneShotListener(newNotifyConn(local))
		lis.closeErr = errFixture
		if err := lis.Close(); !errors.Is(err, errFixture) {
			t.Fatalf("Close = %v, want fixture failure", err)
		}
		if err := lis.Close(); err != nil {
			t.Fatalf("second Close = %v", err)
		}
		if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept = %v, want net.ErrClosed", err)
		}
	})

	t.Run("second accept observes connection death", func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		nc := newNotifyConn(local)
		lis := newOneShotListener(nc)
		got, err := lis.Accept()
		if err != nil || got != nc {
			t.Fatalf("first Accept = (%v, %v), want wrapped connection", got, err)
		}
		if lis.Addr() != local.LocalAddr() {
			t.Errorf("Addr = %v, want %v", lis.Addr(), local.LocalAddr())
		}
		_ = nc.Close()
		if _, err := lis.Accept(); err == nil || !strings.Contains(err.Error(), "local close") {
			t.Errorf("second Accept = %v, want recorded connection death", err)
		}
	})

	t.Run("second accept observes listener close", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		lis := newOneShotListener(newNotifyConn(local))
		_, _ = lis.Accept()
		done := make(chan error, 1)
		go func() { _, err := lis.Accept(); done <- err }()
		_ = lis.Close()
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Errorf("second Accept = %v, want net.ErrClosed", err)
		}
	})

	t.Run("dialer rejects reuse", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		d := newOneShotDialer(local)
		got, err := d.dial(context.Background(), "ignored")
		if err != nil || got != local {
			t.Fatalf("first dial = (%v, %v)", got, err)
		}
		if _, err := d.dial(context.Background(), "ignored"); err == nil {
			t.Fatal("second dial succeeded")
		}
		<-d.Redialed()
		if _, err := d.dial(context.Background(), "ignored"); err == nil {
			t.Fatal("third dial succeeded")
		}
	})
}

func TestConversionsAndDialError(t *testing.T) {
	t.Parallel()

	if err := validateRequest(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("validateRequest(nil) = %v", err)
	}
	if _, err := requestFromProto(&fleetv1.ProxyRequest{Method: http.MethodGet, Path: "/x", MaxResponseBytes: 1<<62 + 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("requestFromProto(overflow) = %v", err)
	}
	if _, err := requestFromProto(&fleetv1.ProxyRequest{Method: "DELETE", Path: "/x", MaxResponseBytes: 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("requestFromProto(invalid) = %v", err)
	}

	withoutCause := &DialError{Endpoint: "hub", Reason: ReasonConnClosed}
	if got := withoutCause.Error(); !strings.Contains(got, "hub") || strings.Contains(got, errFixture.Error()) {
		t.Errorf("Error() = %q", got)
	}
	withCause := &DialError{Endpoint: "hub", Reason: ReasonDial, Err: errFixture}
	if got := withCause.Error(); !strings.Contains(got, errFixture.Error()) {
		t.Errorf("Error() = %q, want cause", got)
	}
	if !errors.Is(withCause, errFixture) || withoutCause.Unwrap() != nil {
		t.Error("DialError does not expose exactly its configured cause")
	}
}

type handlerFuncs struct {
	do       func(context.Context, *tunnel.Request) (*tunnel.Response, error)
	describe func(context.Context, string) (tunnel.Facts, error)
}

func (h handlerFuncs) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	return h.do(ctx, req)
}
func (h handlerFuncs) Describe(ctx context.Context, fingerprint string) (tunnel.Facts, error) {
	return h.describe(ctx, fingerprint)
}

type fakeProxyServer struct {
	grpc.ServerStreamingServer[fleetv1.ProxyChunk]
	ctx      context.Context
	sent     []*fleetv1.ProxyChunk
	failSend int
}

func (s *fakeProxyServer) Context() context.Context { return s.ctx }
func (s *fakeProxyServer) Send(chunk *fleetv1.ProxyChunk) error {
	if len(s.sent)+1 == s.failSend {
		return errFixture
	}
	s.sent = append(s.sent, chunk)
	return nil
}

type errorAfterData struct {
	data []byte
	err  error
}

func (r *errorAfterData) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestSpokeServerFailuresAndStreaming(t *testing.T) {
	t.Parallel()

	baseHandler := handlerFuncs{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("abc"))}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}

	t.Run("describe failure", func(t *testing.T) {
		s := &spokeServer{h: handlerFuncs{describe: func(context.Context, string) (tunnel.Facts, error) {
			return tunnel.Facts{}, errFixture
		}}, chunkBytes: 2}
		if _, err := s.Describe(context.Background(), &fleetv1.DescribeRequest{}); status.Code(err) != codes.Unavailable {
			t.Errorf("Describe = %v, want Unavailable", err)
		}
	})

	for _, tc := range []struct {
		name string
		req  *fleetv1.ProxyRequest
		h    tunnel.Handler
		fail int
		code codes.Code
	}{
		{name: "invalid request", req: &fleetv1.ProxyRequest{}, h: baseHandler, code: codes.InvalidArgument},
		{name: "handler error", req: validProtoRequest(), h: handlerFuncs{do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) { return nil, errFixture }}, code: codes.Unavailable},
		{name: "nil body", req: validProtoRequest(), h: handlerFuncs{do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) { return &tunnel.Response{}, nil }}, code: codes.Internal},
		{name: "head send fails", req: validProtoRequest(), h: baseHandler, fail: 1, code: codes.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &fakeProxyServer{ctx: context.Background(), failSend: tc.fail}
			err := (&spokeServer{h: tc.h, chunkBytes: 2}).Proxy(tc.req, stream)
			codeMatches := status.Code(err) == tc.code
			injectedSendFailure := tc.fail > 0 && errors.Is(err, errFixture)
			if !codeMatches && !injectedSendFailure {
				t.Errorf("Proxy = %v, want code %v", err, tc.code)
			}
		})
	}

	t.Run("copy failure is reported in trailer", func(t *testing.T) {
		h := handlerFuncs{do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{Body: io.NopCloser(&errorAfterData{data: []byte("abc"), err: errFixture})}, nil
		}}
		stream := &fakeProxyServer{ctx: context.Background()}
		if err := (&spokeServer{h: h, chunkBytes: 2}).Proxy(validProtoRequest(), stream); err != nil {
			t.Fatalf("Proxy: %v", err)
		}
		trail := stream.sent[len(stream.sent)-1].GetTrail()
		if trail == nil || !strings.Contains(trail.GetError(), errFixture.Error()) {
			t.Errorf("trailer = %+v, want copy failure", trail)
		}
	})

	t.Run("trailer send failure is returned", func(t *testing.T) {
		stream := &fakeProxyServer{ctx: context.Background(), failSend: 4}
		err := (&spokeServer{h: baseHandler, chunkBytes: 2}).Proxy(validProtoRequest(), stream)
		if !errors.Is(err, errFixture) {
			t.Errorf("Proxy = %v, want trailer send failure", err)
		}
	})

	t.Run("budget probe reports reader failure", func(t *testing.T) {
		stream := &fakeProxyServer{ctx: context.Background()}
		s := &spokeServer{chunkBytes: 4}
		sent, truncated, err := s.streamBody(stream, &errorAfterData{data: []byte("abc"), err: errFixture}, 3)
		if sent != 3 || truncated || !errors.Is(err, errFixture) {
			t.Errorf("streamBody = (%d, %v, %v)", sent, truncated, err)
		}
	})

	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want codes.Code
	}{
		{name: "cancelled error", ctx: context.Background(), err: context.Canceled, want: codes.Canceled},
		{name: "deadline context", ctx: expiredContext(t), err: errFixture, want: codes.DeadlineExceeded},
		{name: "too large", ctx: context.Background(), err: tunnel.ErrResponseTooLarge, want: codes.ResourceExhausted},
		{name: "invalid", ctx: context.Background(), err: ErrInvalidRequest, want: codes.InvalidArgument},
	} {
		if got := codeFor(tc.ctx, tc.err); got != tc.want {
			t.Errorf("codeFor(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func validProtoRequest() *fleetv1.ProxyRequest {
	return &fleetv1.ProxyRequest{Method: http.MethodGet, Path: "/x", MaxResponseBytes: 16}
}

func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

type recvResult struct {
	chunk *fleetv1.ProxyChunk
	err   error
}

type fakeClientStream struct {
	grpc.ServerStreamingClient[fleetv1.ProxyChunk]
	results []recvResult
	index   int
}

func (s *fakeClientStream) Recv() (*fleetv1.ProxyChunk, error) {
	if s.index >= len(s.results) {
		return nil, io.EOF
	}
	r := s.results[s.index]
	s.index++
	return r.chunk, r.err
}

type fakeSpokeClient struct {
	describeResp *fleetv1.DescribeResponse
	describeErr  error
	proxyStream  grpc.ServerStreamingClient[fleetv1.ProxyChunk]
	proxyErr     error
}

func (c *fakeSpokeClient) Describe(context.Context, *fleetv1.DescribeRequest, ...grpc.CallOption) (*fleetv1.DescribeResponse, error) {
	return c.describeResp, c.describeErr
}
func (c *fakeSpokeClient) Proxy(context.Context, *fleetv1.ProxyRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[fleetv1.ProxyChunk], error) {
	return c.proxyStream, c.proxyErr
}

func bareSession(client fleetv1.SpokeServiceClient) *session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		identity: tunnel.Identity{ClusterID: "prod"}, client: client,
		log: discardLogger(), ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
}

func TestSessionErrorMappingAndProtocol(t *testing.T) {
	t.Parallel()

	t.Run("describe rpc failure", func(t *testing.T) {
		s := bareSession(&fakeSpokeClient{describeErr: status.Error(codes.Canceled, "stop")})
		if _, err := s.Describe(context.Background(), "old"); !errors.Is(err, context.Canceled) {
			t.Errorf("Describe = %v, want context.Canceled", err)
		}
	})

	t.Run("proxy creation failure", func(t *testing.T) {
		s := bareSession(&fakeSpokeClient{proxyErr: status.Error(codes.DeadlineExceeded, "late")})
		if _, err := s.Do(context.Background(), validRequest()); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Do = %v, want deadline", err)
		}
	})

	t.Run("first receive failure", func(t *testing.T) {
		stream := &fakeClientStream{results: []recvResult{{err: status.Error(codes.Unavailable, "gone")}}}
		s := bareSession(&fakeSpokeClient{proxyStream: stream})
		if _, err := s.Do(context.Background(), validRequest()); !errors.Is(err, tunnel.ErrSessionClosed) {
			t.Errorf("Do = %v, want session closed", err)
		}
	})

	t.Run("first chunk is not a head", func(t *testing.T) {
		stream := &fakeClientStream{results: []recvResult{{chunk: dataChunk("x")}}}
		s := bareSession(&fakeSpokeClient{proxyStream: stream})
		if _, err := s.Do(context.Background(), validRequest()); !errors.Is(err, ErrProtocol) {
			t.Errorf("Do = %v, want ErrProtocol", err)
		}
	})

	t.Run("map error vocabulary", func(t *testing.T) {
		s := bareSession(nil)
		if s.CloseReason() != "" {
			t.Error("live session has a close reason")
		}
		if got := s.mapErr(context.Background(), nil); got != nil {
			t.Errorf("mapErr(nil) = %v", got)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := s.mapErr(ctx, errFixture); !errors.Is(got, context.Canceled) {
			t.Errorf("mapErr(caller cancelled) = %v", got)
		}
		if got := s.mapErr(context.Background(), status.Error(codes.Unavailable, "lost")); !errors.Is(got, tunnel.ErrSessionClosed) {
			t.Errorf("mapErr(unavailable) = %v", got)
		}
		if got := s.mapErr(context.Background(), status.Error(codes.Unknown, "odd")); status.Code(got) != codes.Unknown {
			t.Errorf("mapErr(unknown) = %v", got)
		}
		close(s.done)
		if got := s.mapErr(context.Background(), errFixture); !errors.Is(got, tunnel.ErrSessionClosed) || !errors.Is(got, errFixture) {
			t.Errorf("mapErr(closed) = %v", got)
		}
	})
}

func validRequest() *tunnel.Request {
	return &tunnel.Request{Method: http.MethodGet, Path: "/x", MaxResponseBytes: 3}
}

func dataChunk(data string) *fleetv1.ProxyChunk {
	return &fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Data{Data: []byte(data)}}
}
func headChunk() *fleetv1.ProxyChunk {
	return &fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Head{Head: &fleetv1.ResponseHead{StatusCode: 200}}}
}
func trailChunk(t *fleetv1.ResponseTrail) *fleetv1.ProxyChunk {
	return &fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Trail{Trail: t}}
}

func TestBodyReaderProtocolAndTerminalPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		results []recvResult
		budget  int64
		want    error
	}{
		{name: "stream ends before trailer", results: nil, budget: 3, want: ErrProtocol},
		{name: "receive fails", results: []recvResult{{err: errFixture}}, budget: 3, want: errFixture},
		{name: "second head", results: []recvResult{{chunk: headChunk()}}, budget: 3, want: ErrProtocol},
		{name: "empty chunk", results: []recvResult{{chunk: &fleetv1.ProxyChunk{}}}, budget: 3, want: ErrProtocol},
		{name: "oversized data", results: []recvResult{{chunk: dataChunk("abcd")}}, budget: 3, want: tunnel.ErrResponseTooLarge},
		{name: "truncated trailer", results: []recvResult{{chunk: trailChunk(&fleetv1.ResponseTrail{Truncated: true})}, {err: io.EOF}}, budget: 3, want: tunnel.ErrResponseTooLarge},
		{name: "upstream trailer", results: []recvResult{{chunk: trailChunk(&fleetv1.ResponseTrail{Error: "boom"})}, {err: io.EOF}}, budget: 3, want: ErrUpstream},
		{name: "final status fails", results: []recvResult{{chunk: trailChunk(&fleetv1.ResponseTrail{})}, {err: errFixture}}, budget: 3, want: errFixture},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cleanup, release atomic.Int32
			b := &bodyReader{
				stream: &fakeClientStream{results: tc.results}, budget: tc.budget,
				cleanup: func() { cleanup.Add(1) }, release: func() { release.Add(1) },
				mapErr: func(err error) error { return err },
			}
			got, err := io.ReadAll(b)
			if tc.name == "oversized data" && string(got) != "abc" {
				t.Errorf("body = %q, want abc", got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("ReadAll = %v, want %v", err, tc.want)
			}
			if cleanup.Load() != 1 || release.Load() != 1 {
				t.Errorf("cleanup/release = %d/%d, want once each", cleanup.Load(), release.Load())
			}
			_ = b.Close()
		})
	}

	t.Run("empty data and zero read are skipped", func(t *testing.T) {
		b := &bodyReader{
			stream: &fakeClientStream{results: []recvResult{
				{chunk: dataChunk("")}, {chunk: dataChunk("x")},
				{chunk: trailChunk(&fleetv1.ResponseTrail{BytesTotal: 1})}, {err: io.EOF},
			}}, budget: 3, cleanup: func() {}, release: func() {}, mapErr: func(err error) error { return err },
		}
		if n, err := b.Read(nil); n != 0 || err != nil {
			t.Errorf("Read(nil) = (%d, %v)", n, err)
		}
		got, err := io.ReadAll(b)
		if string(got) != "x" || err != nil {
			t.Errorf("ReadAll = (%q, %v)", got, err)
		}
	})

	t.Run("early close", func(t *testing.T) {
		var calls atomic.Int32
		b := &bodyReader{stream: &fakeClientStream{}, budget: 3, cleanup: func() { calls.Add(1) }, release: func() { calls.Add(1) }, mapErr: func(err error) error { return err }}
		if trail := b.Trailer(); trail.BytesTotal != 0 || trail.Err != nil || trail.Truncated || len(trail.Warnings) != 0 {
			t.Errorf("live Trailer = %+v", trail)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := b.Read(make([]byte, 1)); !errors.Is(err, ErrBodyClosed) {
			t.Errorf("Read after Close = %v", err)
		}
		if err := b.Close(); err != nil || calls.Load() != 2 {
			t.Errorf("second Close = %v, callbacks = %d", err, calls.Load())
		}
	})
}

type fakeSource struct {
	addr      string
	accept    func(context.Context) (net.Conn, tunnel.Identity, error)
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}
}

func (s *fakeSource) Accept(ctx context.Context) (net.Conn, tunnel.Identity, error) {
	return s.accept(ctx)
}
func (s *fakeSource) Addr() string { return s.addr }
func (s *fakeSource) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.closeCh != nil {
			close(s.closeCh)
		}
	})
	return nil
}

func TestListenerConstructionStateAndShutdown(t *testing.T) {
	t.Parallel()

	if _, err := NewSourceListener(nil, ListenerConfig{}); err == nil {
		t.Error("nil source accepted")
	}
	src := &fakeSource{addr: "fixture", accept: func(context.Context) (net.Conn, tunnel.Identity, error) { return nil, tunnel.Identity{}, errFixture }}
	if _, err := NewSourceListener(src, ListenerConfig{MaxSessions: -1}); err == nil {
		t.Error("negative MaxSessions accepted")
	}
	got, err := NewSourceListener(src, ListenerConfig{})
	if err != nil {
		t.Fatalf("NewSourceListener: %v", err)
	}
	l := got.(*listener)
	if l.log == nil || l.hsTO != defaultHandshakeTimeout || l.Addr() != "fixture" {
		t.Errorf("listener defaults = log:%v timeout:%v addr:%q", l.log, l.hsTO, l.Addr())
	}
	if err := l.Serve(context.Background(), nil); err == nil {
		t.Error("Serve accepted nil handler")
	}
	if err := l.Serve(context.Background(), tunnel.SessionHandlerFunc(func(context.Context, tunnel.Session) (func(), error) { return nil, nil })); !errors.Is(err, errFixture) {
		t.Errorf("Serve(source failure) = %v", err)
	}

	state := &listener{cfg: ListenerConfig{MaxSessions: 1}, sessions: make(map[*session]struct{}), stopped: make(chan struct{}), src: src}
	if !state.reserve() || state.reserve() {
		t.Error("session cap was not enforced")
	}
	state.release()
	state.release()
	state.closed = true
	if state.reserve() || !state.isClosed() {
		t.Error("closed listener reserved a slot or reported open")
	}

	blocked := &listener{src: src, sessions: make(map[*session]struct{}), stopped: make(chan struct{})}
	blocked.wg.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := blocked.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want deadline", err)
	}
	blocked.wg.Done()
}

func TestServeConnValidationAndDefaults(t *testing.T) {
	t.Parallel()

	if err := ServeConn(context.Background(), nil, DialerConfig{Endpoint: "hub"}, nil); dialReason(err) != ReasonDial {
		t.Errorf("ServeConn(nil) = %v, want dial failure", err)
	}
	local, peer := net.Pipe()
	if err := ServeConn(context.Background(), local, DialerConfig{Endpoint: "hub"}, nil); dialReason(err) != ReasonDial {
		t.Errorf("ServeConn(nil handler) = %v, want dial failure", err)
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Error("nil-handler ServeConn did not close its connection")
	}
	_ = peer.Close()

	local, peer = net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := handlerFuncs{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{Body: io.NopCloser(strings.NewReader(""))}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}
	err := ServeConn(ctx, local, DialerConfig{Endpoint: "hub", MaxChunkBytes: defaultChunkBytes + 1}, h)
	if dialReason(err) != ReasonContextCancelled || !errors.Is(err, context.Canceled) {
		t.Errorf("ServeConn(cancelled) = %v", err)
	}
}

func dialReason(err error) Reason {
	var de *DialError
	if errors.As(err, &de) {
		return de.Reason
	}
	return ""
}

func TestServeLimitsAndClosedClassification(t *testing.T) {
	t.Parallel()

	t.Run("listener already closed", func(t *testing.T) {
		src := &fakeSource{addr: "fixture", accept: func(context.Context) (net.Conn, tunnel.Identity, error) {
			return nil, tunnel.Identity{}, errFixture
		}}
		l := &listener{src: src, log: discardLogger(), sessions: make(map[*session]struct{}), stopped: make(chan struct{}), closed: true}
		err := l.Serve(context.Background(), tunnel.SessionHandlerFunc(func(context.Context, tunnel.Session) (func(), error) { return nil, nil }))
		if !errors.Is(err, ErrListenerClosed) {
			t.Errorf("Serve = %v, want ErrListenerClosed", err)
		}
	})

	t.Run("session cap closes excess connection", func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		src := &fakeSource{addr: "fixture"}
		src.accept = func(acceptCtx context.Context) (net.Conn, tunnel.Identity, error) {
			if calls.Add(1) == 1 {
				return local, tunnel.Identity{ClusterID: "extra"}, nil
			}
			<-acceptCtx.Done()
			return nil, tunnel.Identity{}, acceptCtx.Err()
		}
		l := &listener{
			cfg: ListenerConfig{MaxSessions: 1}, src: src, log: discardLogger(), hsTO: time.Second,
			sessions: make(map[*session]struct{}), stopped: make(chan struct{}), active: 1,
		}
		done := make(chan error, 1)
		go func() {
			done <- l.Serve(ctx, tunnel.SessionHandlerFunc(func(context.Context, tunnel.Session) (func(), error) { return nil, nil }))
		}()
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Error("excess connection remained open")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Serve = %v, want context.Canceled", err)
		}
	})
}

func TestAttachFailureRejectionAndRelease(t *testing.T) {
	t.Parallel()

	// hsTO is generous on purpose. It bounds the HTTP/2 preface exchange with
	// a ServeConn that the subtests below start in a goroutine and then
	// immediately race, so it is really bounding goroutine scheduling latency.
	// At 100ms this flaked on a loaded machine roughly one run in three: the
	// handshake timed out, attach took its setup-failure path, the session
	// handler was never called, and the release() inside attach's watcher
	// goroutine went unexecuted — which also dropped the package below the
	// 100% coverage floor and failed CI for a reason that had nothing to do
	// with the change under test. Nothing here depends on this expiring:
	// waitReady returns as soon as the connection reaches TransientFailure, so
	// the deliberately-broken subtest below still fails fast rather than
	// waiting this out.
	newListener := func() *listener {
		return &listener{
			log: discardLogger(), hsTO: 30 * time.Second,
			sessions: make(map[*session]struct{}), stopped: make(chan struct{}),
		}
	}

	t.Run("gRPC handshake fails", func(t *testing.T) {
		l := newListener()
		local, peer := net.Pipe()
		_ = peer.Close()
		l.active = 1
		l.attach(context.Background(), local, tunnel.Identity{ClusterID: "prod"}, tunnel.SessionHandlerFunc(func(context.Context, tunnel.Session) (func(), error) {
			t.Fatal("handler called for a failed handshake")
			return nil, nil
		}))
		if l.active != 0 {
			t.Errorf("active = %d after setup failure", l.active)
		}
	})

	for _, tc := range []struct {
		name   string
		reject bool
	}{
		{name: "handler rejects", reject: true},
		{name: "release runs after close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newListener()
			local, peer := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := handlerFuncs{
				do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
					return &tunnel.Response{Body: io.NopCloser(strings.NewReader(""))}, nil
				},
				describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
			}
			spokeDone := make(chan error, 1)
			go func() {
				spokeDone <- ServeConn(ctx, peer, DialerConfig{Endpoint: "fixture", Logger: discardLogger()}, h)
			}()
			var captured tunnel.Session
			released := make(chan struct{})
			l.active = 1
			l.attach(ctx, local, tunnel.Identity{ClusterID: "prod"}, tunnel.SessionHandlerFunc(func(_ context.Context, s tunnel.Session) (func(), error) {
				captured = s
				if tc.reject {
					return nil, errFixture
				}
				return func() { close(released) }, nil
			}))
			if captured == nil {
				t.Fatal("session handler was not called")
			}
			if tc.reject {
				select {
				case <-captured.Done():
				case <-time.After(time.Second):
					t.Fatal("rejected session was not closed")
				}
				if l.active != 0 {
					t.Errorf("active = %d after rejection", l.active)
				}
			} else {
				_ = captured.Close("test complete")
				select {
				case <-released:
				case <-time.After(time.Second):
					t.Fatal("release callback did not run")
				}
			}
			cancel()
			<-spokeDone
		})
	}
}

func TestNewSessionConstructionFailures(t *testing.T) {
	t.Parallel()

	l := &listener{log: discardLogger(), hsTO: 20 * time.Millisecond, sessions: make(map[*session]struct{}), stopped: make(chan struct{})}

	t.Run("invalid target", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		_, err := l.newSession(context.Background(), local, tunnel.Identity{ClusterID: "%zz"})
		if err == nil || !strings.Contains(err.Error(), "build client") {
			t.Errorf("newSession = %v, want invalid-target error", err)
		}
	})

	t.Run("HTTP2 handshake timeout", func(t *testing.T) {
		local, peer := net.Pipe()
		defer local.Close()
		defer peer.Close()
		_, err := l.newSession(context.Background(), local, tunnel.Identity{ClusterID: "prod"})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("newSession = %v, want deadline", err)
		}
	})
}

func TestWatchStoppedAndCloseError(t *testing.T) {
	t.Parallel()

	local, peer := net.Pipe()
	defer peer.Close()
	s := closableBareSession(t, local)
	l := &listener{stopped: make(chan struct{})}
	close(l.stopped)
	l.watch(context.Background(), s)
	if got := s.CloseReason(); got != "hub-shutdown" {
		t.Errorf("CloseReason = %q, want hub-shutdown", got)
	}

	local, peer = net.Pipe()
	defer peer.Close()
	s = closableBareSession(t, local)
	if err := s.cc.Close(); err != nil {
		t.Fatalf("pre-close ClientConn: %v", err)
	}
	// Closing a ClientConn that is already closed reports the deprecated
	// grpc.ErrClientConnClosing (itself a Canceled status), which session.Close
	// now discards unconditionally: a real *grpc.ClientConn has no other error
	// to give it, so surfacing this one would make every ordinary double-close
	// look like a fault.
	if err := s.Close("again"); err != nil {
		t.Errorf("second Close returned %v, want nil for the idempotent case", err)
	}
}

func TestWaitReadyAndWatchers(t *testing.T) {
	t.Parallel()

	closedCC, err := grpc.NewClient("passthrough:///closed", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_ = closedCC.Close()
	if err := waitReady(context.Background(), closedCC); err == nil || !strings.Contains(err.Error(), "shut down") {
		t.Errorf("waitReady(shutdown) = %v", err)
	}

	failCC, err := grpc.NewClient("passthrough:///fail",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return nil, errFixture }))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer failCC.Close()
	failCC.Connect()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReady(ctx, failCC); err == nil {
		t.Error("waitReady(transient failure) returned nil")
	}

	idleCC, err := grpc.NewClient("passthrough:///idle", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer idleCC.Close()
	expired, stop := context.WithCancel(context.Background())
	stop()
	if err := waitReady(expired, idleCC); !errors.Is(err, context.Canceled) {
		t.Errorf("waitReady(cancelled) = %v", err)
	}

	l := &listener{stopped: make(chan struct{})}
	for _, tc := range []struct {
		name string
		fire func(*session, *notifyConn, *oneShotDialer)
		want string
	}{
		{name: "session already done", fire: func(s *session, _ *notifyConn, _ *oneShotDialer) { close(s.done) }},
		{name: "connection dies", fire: func(_ *session, n *notifyConn, _ *oneShotDialer) { n.kill("boom") }, want: "connection closed"},
		{name: "dialer redials", fire: func(_ *session, _ *notifyConn, d *oneShotDialer) { d.once.Do(func() { close(d.redialed) }) }, want: "single-use"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			s := closableBareSession(t, local)
			n := s.conn
			d := newOneShotDialer(n)
			tc.fire(s, n, d)
			l.deathWatch(s, n, d)
			if tc.want != "" && !strings.Contains(s.CloseReason(), tc.want) {
				t.Errorf("CloseReason = %q, want %q", s.CloseReason(), tc.want)
			}
		})
	}
}

func closableBareSession(t *testing.T, conn net.Conn) *session {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &session{identity: tunnel.Identity{ClusterID: "prod"}, cc: cc, conn: newNotifyConn(conn), log: discardLogger(), ctx: ctx, cancel: cancel, done: make(chan struct{})}
}
