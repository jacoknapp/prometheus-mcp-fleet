// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"bytes"
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
	// Time and Timeout are defaulted independently, each on its own <= 0
	// boundary: a caller who only pinned one of the pair must not lose the
	// other to the same fallback.
	timeAtZero := (KeepaliveParams{Time: 0, Timeout: 7 * time.Second, PermitWithoutStream: true}).clientParams()
	if timeAtZero.Time != defaultClientPingTime || timeAtZero.Timeout != 7*time.Second || !timeAtZero.PermitWithoutStream {
		t.Errorf("client parameters with Time at its zero boundary = %+v", timeAtZero)
	}
	timeoutAtZero := (KeepaliveParams{Time: 9 * time.Second, Timeout: 0, PermitWithoutStream: true}).clientParams()
	if timeoutAtZero.Time != 9*time.Second || timeoutAtZero.Timeout != defaultClientPingTimeout || !timeoutAtZero.PermitWithoutStream {
		t.Errorf("client parameters with Timeout at its zero boundary = %+v", timeoutAtZero)
	}
	policy := (KeepaliveParams{Time: -1}).enforcementPolicy()
	if policy.MinTime != defaultServerMinPingTime || policy.PermitWithoutStream {
		t.Errorf("custom enforcement policy = %+v", policy)
	}
	policyAtZero := (KeepaliveParams{Time: 0, Timeout: time.Second, PermitWithoutStream: true}).enforcementPolicy()
	if policyAtZero.MinTime != defaultServerMinPingTime || !policyAtZero.PermitWithoutStream {
		t.Errorf("enforcement policy with Time at its zero boundary = %+v", policyAtZero)
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
	// 1<<62 itself is the documented ceiling and must still convert cleanly;
	// only one bit further overflows.
	if req, err := requestFromProto(&fleetv1.ProxyRequest{Method: http.MethodGet, Path: "/x", MaxResponseBytes: 1 << 62}); err != nil || req.MaxResponseBytes != 1<<62 {
		t.Errorf("requestFromProto(1<<62) = (%+v, %v), want it accepted with MaxResponseBytes 1<<62", req, err)
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

// zeroThenData reports a legal (0, nil) read once before yielding data, then
// io.EOF once the data is exhausted. A reader is allowed to do this per the
// io.Reader contract, and streamBody must not mistake it for a chunk worth
// sending.
type zeroThenData struct {
	calls int
	data  []byte
}

func (r *zeroThenData) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		return 0, nil
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
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

	// A trailer is still owed even when the stream's context happens to have
	// been cancelled by the time the copy finishes cleanly: the early return
	// that skips the trailer is only for a copy that itself failed because the
	// hub cancelled mid-transfer (RST_STREAM already told it everything).
	// copyErr == nil means the copy did not fail, so the cancellation must not
	// swallow the trailer here.
	t.Run("a trailer is still sent when the context is already done but the copy did not fail", func(t *testing.T) {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		stream := &fakeProxyServer{ctx: cancelledCtx}
		err := (&spokeServer{h: baseHandler, chunkBytes: 2}).Proxy(validProtoRequest(), stream)
		if err != nil {
			t.Fatalf("Proxy = %v, want nil: the copy succeeded, so cancellation must not suppress the trailer", err)
		}
		if len(stream.sent) == 0 || stream.sent[len(stream.sent)-1].GetTrail() == nil {
			t.Errorf("sent = %+v, want the last chunk to be a trailer", stream.sent)
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

	// TestBudgetShrinksAcrossMultipleChunks distinguishes `budget - sent` from
	// `budget + sent`: with a single small chunk both arithmetic directions
	// agree (sent starts at 0), so the boundary only shows up once several
	// chunks have actually been sent and the remaining budget must shrink.
	t.Run("the remaining budget shrinks as chunks are sent, across many chunks", func(t *testing.T) {
		stream := &fakeProxyServer{ctx: context.Background()}
		s := &spokeServer{chunkBytes: 2}
		body := bytes.Repeat([]byte("x"), 10)
		sent, truncated, err := s.streamBody(stream, bytes.NewReader(body), 3)
		if sent != 3 || !truncated || err != nil {
			t.Fatalf("streamBody = (%d, %v, %v), want (3, true, nil): "+
				"the budget must shrink with every chunk sent, not grow", sent, truncated, err)
		}
		var got []byte
		for _, c := range stream.sent {
			got = append(got, c.GetData()...)
		}
		if string(got) != "xxx" {
			t.Errorf("bytes actually sent = %q, want exactly the 3-byte budget", got)
		}
	})

	t.Run("a zero-byte, no-error read sends no empty chunk", func(t *testing.T) {
		stream := &fakeProxyServer{ctx: context.Background()}
		s := &spokeServer{chunkBytes: 4}
		sent, truncated, err := s.streamBody(stream, &zeroThenData{data: []byte("abc")}, 16)
		if sent != 3 || truncated || err != nil {
			t.Fatalf("streamBody = (%d, %v, %v), want (3, false, nil)", sent, truncated, err)
		}
		for _, c := range stream.sent {
			if d := c.GetData(); len(d) == 0 && c.GetKind() != nil {
				if _, isData := c.GetKind().(*fleetv1.ProxyChunk_Data); isData {
					t.Errorf("an empty Data chunk was sent: %+v", stream.sent)
				}
			}
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

	// TestBodyReaderProtocolAndTerminalPaths's own "oversized data" case only
	// ever sees b.received == 0: the single chunk it sends already exceeds the
	// budget on its own. That leaves the budget arithmetic untested once
	// received bytes have already accumulated across earlier chunks -- a
	// mutant that swapped the subtraction for addition would still refuse the
	// very first chunk correctly, for the wrong reason, and only misbehave
	// from the second chunk on.
	t.Run("budget spans multiple chunks", func(t *testing.T) {
		b := &bodyReader{
			stream: &fakeClientStream{results: []recvResult{
				{chunk: dataChunk("abc")},  // received 0 -> 3, under the budget of 5
				{chunk: dataChunk("de")},   // received 3 -> 5, lands exactly on the budget
				{chunk: dataChunk("f")},    // one byte past the budget: must truncate now, not before
				{chunk: dataChunk("more")}, // never reached; truncation already latched
			}}, budget: 5, cleanup: func() {}, release: func() {}, mapErr: func(err error) error { return err },
		}
		got, err := io.ReadAll(b)
		if string(got) != "abcde" {
			t.Errorf("body = %q, want abcde", got)
		}
		if !errors.Is(err, tunnel.ErrResponseTooLarge) {
			t.Errorf("terminal error = %v, want tunnel.ErrResponseTooLarge", err)
		}
		if trail := b.Trailer(); trail.BytesTotal != 5 || !trail.Truncated {
			t.Errorf("Trailer() = %+v, want BytesTotal 5 and Truncated true", trail)
		}
	})

	// TestBodyReaderExactBudgetFitIsNotTruncated distinguishes `>` from `>=`
	// at the oversized-chunk check: a chunk that lands exactly on the budget is
	// a complete, untruncated response, not an overflow. The "budget spans
	// multiple chunks" case above cannot tell the two apart, because its
	// exact-fit chunk is immediately followed by a genuinely oversized one, so
	// the final result (a truncated body ending "abcde") is identical whether
	// the cutoff happens one chunk early or right on time.
	t.Run("a chunk landing exactly on the budget is not truncated", func(t *testing.T) {
		b := &bodyReader{
			stream: &fakeClientStream{results: []recvResult{
				{chunk: dataChunk("abcde")}, // received 0 -> 5, lands exactly on the budget
				{chunk: trailChunk(&fleetv1.ResponseTrail{BytesTotal: 5})},
				{err: io.EOF},
			}}, budget: 5, cleanup: func() {}, release: func() {}, mapErr: func(err error) error { return err },
		}
		// io.ReadAll swallows a terminal io.EOF, which is exactly the outcome
		// this test needs to tell apart from tunnel.ErrResponseTooLarge, so the
		// body is drained by hand instead.
		var got []byte
		buf := make([]byte, 8)
		var err error
		for {
			var n int
			n, err = b.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		if string(got) != "abcde" {
			t.Errorf("body = %q, want abcde", got)
		}
		if !errors.Is(err, io.EOF) {
			t.Errorf("terminal error = %v, want io.EOF: an exact fit is not an overflow", err)
		}
		if trail := b.Trailer(); trail.Truncated || trail.BytesTotal != 5 {
			t.Errorf("Trailer() = %+v, want BytesTotal 5 and Truncated false", trail)
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

	// TestBodyReaderCloseBeforeATrailerReportsBytesActuallyDelivered covers
	// finish()'s fallback: closing early, after some data arrived but before
	// any trailer, must still report how much actually reached the caller
	// instead of leaving Trailer().BytesTotal at its zero value.
	t.Run("close before a trailer reports bytes actually delivered", func(t *testing.T) {
		b := &bodyReader{
			stream: &fakeClientStream{results: []recvResult{{chunk: dataChunk("abcde")}}},
			budget: 10, cleanup: func() {}, release: func() {}, mapErr: func(err error) error { return err },
		}
		buf := make([]byte, 5)
		n, err := b.Read(buf)
		if n != 5 || err != nil {
			t.Fatalf("Read = (%d, %v), want (5, nil)", n, err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if trail := b.Trailer(); trail.BytesTotal != 5 {
			t.Errorf("Trailer().BytesTotal = %d, want 5: the fallback must report bytes actually "+
				"delivered when Close happened before any trailer arrived", trail.BytesTotal)
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
	// A release beyond what was ever reserved must not drive the counter
	// negative: that would let reserve() admit an extra session it should
	// have refused, silently exceeding MaxSessions.
	state.release()
	if state.active != 0 {
		t.Errorf("active = %d after releasing more than was reserved, want 0", state.active)
	}
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

// TestServeConnUsesTheConfiguredLogger proves cfg.Logger is not silently
// discarded: ServeConn's own lifecycle line must reach the caller's Logger,
// not a default one built regardless of what was configured. Nothing in this
// package ever read the DialerConfig.Logger a caller supplied, which made a
// configured Logger dead configuration; this pins the fix.
func TestServeConnUsesTheConfiguredLogger(t *testing.T) {
	t.Parallel()

	local, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := handlerFuncs{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{Body: io.NopCloser(strings.NewReader(""))}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}
	if err := ServeConn(ctx, local, DialerConfig{Endpoint: "hub-configured", Logger: logger}, h); dialReason(err) != ReasonContextCancelled {
		t.Fatalf("ServeConn(cancelled) = %v", err)
	}
	if !strings.Contains(buf.String(), "hub-configured") {
		t.Errorf("the configured Logger recorded nothing about this call (got %q); "+
			"ServeConn must not fall back to a default logger when one was supplied", buf.String())
	}
}

// TestServeConnEndsWithConnClosedWhenNotCancelled drives ServeConn's other
// terminal branch: an uncancelled context whose underlying connection simply
// dies. Every other ServeConn test tears down via context cancellation, which
// left this path — and the "spoke tunnel connection closed" log line in it —
// unexercised.
func TestServeConnEndsWithConnClosedWhenNotCancelled(t *testing.T) {
	t.Parallel()

	local, peer := net.Pipe()
	h := handlerFuncs{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{Body: io.NopCloser(strings.NewReader(""))}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	done := make(chan error, 1)
	go func() {
		done <- ServeConn(context.Background(), local, DialerConfig{Endpoint: "hub", Logger: logger}, h)
	}()

	// Give the gRPC server a moment to start reading on the wrapped
	// connection, then kill the peer so the notify wrapper observes the
	// failure instead of a context cancellation.
	time.Sleep(50 * time.Millisecond)
	_ = peer.Close()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ServeConn did not return after the connection died")
	}
	if dialReason(err) != ReasonConnClosed {
		t.Fatalf("ServeConn() = %v, want ReasonConnClosed", err)
	}
	if !strings.Contains(buf.String(), "spoke tunnel connection closed") {
		t.Errorf("the configured Logger did not record the connection closing (got %q)", buf.String())
	}
}

// TestServeConnMaxChunkBytesControlsWireChunking proves the effective chunk
// size ServeConn's config clamp settles on is really what ends up on the
// wire, not just a value that lets ServeConn return without error. It does so
// by reading exactly one wire chunk (a fresh bodyReader's first Read call
// returns precisely one chunk's worth, no more, no less) from a body larger
// than the chunk, over a real gRPC connection.
func TestServeConnMaxChunkBytesControlsWireChunking(t *testing.T) {
	t.Parallel()

	// The <= 0 side of the clamp is deliberately not exercised here: a mutant
	// on that boundary (e.g. chunk < 0, leaving a configured 0 unclamped)
	// turns spokeServer.streamBody's chunk buffer into make([]byte, 0), and
	// every Read into a zero-length slice returns (0, nil) forever per the
	// io.Reader contract -- an unkillable-by-timeout busy loop with nothing to
	// observe. Gremlins itself reports that boundary as TIMED OUT, not LIVED,
	// so it costs nothing to leave it alone. Only the upper bound is tested.
	tests := []struct {
		name       string
		configured int
		wantChunk  int
	}{
		{name: "over the cap is clamped to the default", configured: defaultChunkBytes + 1, wantChunk: defaultChunkBytes},
		{name: "exactly the cap is honoured, not clamped", configured: defaultChunkBytes, wantChunk: defaultChunkBytes},
		{name: "a small valid value is honoured", configured: 4, wantChunk: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := bytes.Repeat([]byte("x"), tc.wantChunk*2+7)
			h := handlerFuncs{
				do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
					return &tunnel.Response{Body: io.NopCloser(bytes.NewReader(body))}, nil
				},
				describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
			}

			local, peer := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			spokeDone := make(chan error, 1)
			go func() {
				spokeDone <- ServeConn(ctx, peer, DialerConfig{
					Endpoint: "fixture", Logger: discardLogger(), MaxChunkBytes: tc.configured,
				}, h)
			}()

			l := &listener{log: discardLogger(), hsTO: 10 * time.Second, sessions: make(map[*session]struct{}), stopped: make(chan struct{})}
			sess, err := l.newSession(ctx, local, tunnel.Identity{ClusterID: "prod"})
			if err != nil {
				t.Fatalf("newSession: %v", err)
			}
			defer func() { _ = sess.Close("test complete") }()

			resp, err := sess.Do(ctx, &tunnel.Request{Method: "GET", Path: "/x", MaxResponseBytes: int64(len(body))})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// A misconfigured chunk size (notably a clamp that leaves it at
			// zero) turns the spoke's streamBody loop into a busy spin that
			// never sends data or terminates, so the read is bounded rather
			// than left to hang the whole test binary.
			type readResult struct {
				n   int
				err error
			}
			buf := make([]byte, len(body))
			readDone := make(chan readResult, 1)
			go func() {
				n, err := resp.Body.Read(buf)
				readDone <- readResult{n, err}
			}()
			select {
			case r := <-readDone:
				if r.err != nil {
					t.Fatalf("first Read: %v", r.err)
				}
				if r.n != tc.wantChunk {
					t.Errorf("first Read returned %d bytes, want exactly one wire chunk of %d", r.n, tc.wantChunk)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("first Read did not return within 5s; the configured chunk size of %d likely produced a zero-length wire chunk", tc.configured)
			}

			cancel()
			<-spokeDone
		})
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

	t.Run("an identity's own RemoteAddr is not overwritten", func(t *testing.T) {
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
		l.active = 1
		// net.Pipe's RemoteAddr() is non-nil ("pipe"), so an identity that
		// already carries an address (e.g. from an X-Forwarded-For header)
		// must win over it, not be replaced by it.
		l.attach(ctx, local, tunnel.Identity{ClusterID: "prod", RemoteAddr: "203.0.113.9"}, tunnel.SessionHandlerFunc(func(_ context.Context, s tunnel.Session) (func(), error) {
			captured = s
			return nil, nil
		}))
		if captured == nil {
			t.Fatal("session handler was not called")
		}
		if got := captured.Identity().RemoteAddr; got != "203.0.113.9" {
			t.Errorf("Identity().RemoteAddr = %q, want the identity's own address preserved", got)
		}
		_ = captured.Close("test complete")
		cancel()
		<-spokeDone
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
			// The identity carried no RemoteAddr of its own, so attach must
			// have filled it in from the connection rather than leaving it
			// empty.
			if got := captured.Identity().RemoteAddr; got == "" {
				t.Error("Identity().RemoteAddr is empty, want it filled in from the connection")
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
