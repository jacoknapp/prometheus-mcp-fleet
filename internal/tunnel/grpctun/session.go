// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// session is the hub's handle on one spoke. It is the gRPC *client* end of the
// reversed-role connection: the socket was accepted, not dialled.
//
// It is safe for concurrent use. Every Do becomes an independent HTTP/2 stream,
// so a 40 MiB range query and a 300 byte label lookup make progress at the same
// time on the same socket.
type session struct {
	identity tunnel.Identity
	client   fleetv1.SpokeServiceClient
	cc       *grpc.ClientConn
	conn     *notifyConn
	log      *slog.Logger

	// ctx is cancelled by Close and aborts every in-flight stream.
	ctx    context.Context
	cancel context.CancelFunc

	gen      atomic.Int64
	inflight atomic.Int64

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	reason    atomic.Pointer[string]
}

// compile-time assertion.
var _ tunnel.Session = (*session)(nil)

// Identity implements tunnel.Session. It is derived purely from the verified
// client certificate; nothing the spoke says at runtime can change it.
func (s *session) Identity() tunnel.Identity { return s.identity }

// Generation implements tunnel.Session.
//
// The value is the spoke's process start time in Unix nanoseconds, as reported
// in ClusterFacts.started_at_unix_nano. The wire protocol only carries it
// inside a full Describe payload, so:
//
//   - before the first successful Describe, Generation returns 0;
//   - a Describe that replies unchanged=true carries no facts and therefore no
//     generation, so the last known value is retained.
//
// The registry uses it to resolve reconnect races: a session whose generation
// is older than the one already registered must never displace it.
func (s *session) Generation() int64 { return s.gen.Load() }

// Done implements tunnel.Session.
func (s *session) Done() <-chan struct{} { return s.done }

// CloseReason reports the reason recorded by Close, or "" while the session is
// still live. It exists for audit logging and tests.
func (s *session) CloseReason() string {
	if r := s.reason.Load(); r != nil {
		return *r
	}
	return ""
}

// InFlight reports how many response bodies are currently open on this session.
// It is exported for leak tests: after every caller has closed its body it must
// settle back to zero.
func (s *session) InFlight() int { return int(s.inflight.Load()) }

// Close implements tunnel.Session. It is idempotent; only the first reason is
// recorded. In-flight requests are aborted with RST_STREAM.
func (s *session) Close(reason string) error {
	s.closeOnce.Do(func() {
		s.reason.Store(&reason)
		s.cancel()
		if err := s.cc.Close(); err != nil && !errors.Is(err, grpc.ErrClientConnClosing) {
			s.closeErr = err
		}
		// The ClientConn owns the transport and normally closes the socket for
		// us; closing again is harmless and covers the case where the
		// connection never reached READY.
		_ = s.conn.Close()
		close(s.done)
		s.log.Info("tunnel session closed",
			slog.String("cluster", s.identity.ClusterID),
			slog.String("reason", reason))
	})
	return s.closeErr
}

// Describe implements tunnel.Session.
func (s *session) Describe(ctx context.Context, knownFingerprint string) (tunnel.Facts, error) {
	select {
	case <-s.done:
		return tunnel.Facts{}, tunnel.ErrSessionClosed
	default:
	}

	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopWatch := context.AfterFunc(s.ctx, cancel)
	defer stopWatch()

	resp, err := s.client.Describe(callCtx, &fleetv1.DescribeRequest{KnownFingerprint: knownFingerprint})
	if err != nil {
		return tunnel.Facts{}, fmt.Errorf("describe %s: %w", s.identity.ClusterID, s.mapErr(ctx, err))
	}
	facts := factsFromProto(resp)
	if facts.Generation != 0 {
		s.gen.Store(facts.Generation)
	} else {
		facts.Generation = s.gen.Load()
	}
	return facts, nil
}

// Do implements tunnel.Session. It returns as soon as the response head has
// arrived; the body is pulled lazily, one ProxyChunk at a time.
//
// The caller must close Response.Body. Closing it early cancels the upstream
// stream (RST_STREAM), which propagates to the spoke's request context and
// aborts the query inside the remote cluster.
func (s *session) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	select {
	case <-s.done:
		return nil, tunnel.ErrSessionClosed
	default:
	}

	streamCtx, cancel := context.WithCancel(ctx)
	// Cancelling the session must abort the stream, but a context tree cannot
	// have two parents. AfterFunc gives us the second edge without a goroutine
	// per request.
	stopWatch := context.AfterFunc(s.ctx, cancel)
	cleanup := func() {
		stopWatch()
		cancel()
	}

	stream, err := s.client.Proxy(streamCtx, requestToProto(req))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("proxy %s %s: %w", req.Method, req.Path, s.mapErr(ctx, err))
	}

	chunk, err := stream.Recv()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("proxy %s %s: %w", req.Method, req.Path, s.mapErr(ctx, err))
	}
	head := chunk.GetHead()
	if head == nil {
		cleanup()
		return nil, fmt.Errorf("proxy %s %s: %w: first chunk is not a head", req.Method, req.Path, ErrProtocol)
	}

	s.inflight.Add(1)
	body := &bodyReader{
		stream:  stream,
		budget:  req.MaxResponseBytes,
		cleanup: cleanup,
		release: func() { s.inflight.Add(-1) },
		mapErr:  func(err error) error { return s.mapErr(ctx, err) },
	}
	return &tunnel.Response{
		StatusCode:      int(head.GetStatusCode()),
		ContentType:     head.GetContentType(),
		ContentEncoding: head.GetContentEncoding(),
		Body:            body,
		Trailer:         body.Trailer,
	}, nil
}

// mapErr turns a gRPC status into the vocabulary the tunnel package defines, so
// hub callers can branch with errors.Is on context.Canceled,
// context.DeadlineExceeded and tunnel.ErrSessionClosed without importing gRPC.
func (s *session) mapErr(callerCtx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if callerCtx != nil && callerCtx.Err() != nil {
		return callerCtx.Err()
	}
	select {
	case <-s.done:
		return fmt.Errorf("%w: %v", tunnel.ErrSessionClosed, err)
	default:
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Canceled:
			return context.Canceled
		case codes.DeadlineExceeded:
			return context.DeadlineExceeded
		case codes.Unavailable:
			return fmt.Errorf("%w: %s", tunnel.ErrSessionClosed, st.Message())
		}
	}
	return err
}

// bodyReader turns a stream of ProxyChunks into an io.ReadCloser.
//
// It is deliberately pull-based and goroutine-free: Read calls Recv directly,
// so there is no per-request goroutine to leak, and the caller's read rate is
// the HTTP/2 flow-control rate. Closing it cancels the stream.
type bodyReader struct {
	stream  grpc.ServerStreamingClient[fleetv1.ProxyChunk]
	budget  int64
	cleanup func()
	release func()
	mapErr  func(error) error

	mu       sync.Mutex
	pending  []byte
	received int64
	finished bool
	term     error
	trail    tunnel.Trailer
	doneOnce sync.Once
}

var _ io.ReadCloser = (*bodyReader)(nil)

// Read implements io.Reader. It returns tunnel.ErrResponseTooLarge once the
// response exceeds the request's MaxResponseBytes, after having delivered
// exactly that many bytes, and the trailer then reports Truncated.
func (b *bodyReader) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if len(b.pending) > 0 {
			n := copy(p, b.pending)
			b.pending = b.pending[n:]
			return n, nil
		}
		if b.finished {
			return 0, b.term
		}
		if len(p) == 0 {
			return 0, nil
		}
		b.pull()
	}
}

// pull receives exactly one chunk and folds it into the reader's state. The
// caller must hold b.mu.
func (b *bodyReader) pull() {
	chunk, err := b.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			b.finish(fmt.Errorf("%w: stream ended before the trailer", ErrProtocol))
			return
		}
		b.finish(b.mapErr(err))
		return
	}
	switch k := chunk.GetKind().(type) {
	case *fleetv1.ProxyChunk_Data:
		data := k.Data
		if len(data) == 0 {
			return
		}
		if remaining := b.budget - b.received; int64(len(data)) > remaining {
			// The spoke sent more than it was allowed to. Hand the caller
			// exactly its budget, then abort: the receiving side enforces the
			// cap, never the sender's good manners.
			b.pending = data[:remaining]
			b.received = b.budget
			b.trail.BytesTotal = b.received
			b.trail.Truncated = true
			b.finish(tunnel.ErrResponseTooLarge)
			return
		}
		b.pending = data
		b.received += int64(len(data))
	case *fleetv1.ProxyChunk_Trail:
		b.absorbTrail(k.Trail)
	case *fleetv1.ProxyChunk_Head:
		b.finish(fmt.Errorf("%w: second head on one stream", ErrProtocol))
	default:
		b.finish(fmt.Errorf("%w: empty chunk", ErrProtocol))
	}
}

// absorbTrail records the trailer and decides how the body terminates. The
// caller must hold b.mu.
func (b *bodyReader) absorbTrail(t *fleetv1.ResponseTrail) {
	b.trail = tunnel.Trailer{
		BytesTotal:      int64(t.GetBytesTotal()),
		UpstreamLatency: time.Duration(t.GetUpstreamDurationMs()) * time.Millisecond,
		Truncated:       t.GetTruncated(),
		Warnings:        t.GetWarnings(),
	}
	term := error(io.EOF)
	switch {
	case t.GetError() != "":
		// The spoke could not finish the upstream call, so the body the caller
		// holds is incomplete. Reporting io.EOF here would let a partial
		// response masquerade as a complete one.
		b.trail.Err = fmt.Errorf("%w: %s", ErrUpstream, t.GetError())
		term = b.trail.Err
	case t.GetTruncated():
		term = tunnel.ErrResponseTooLarge
	}
	// Drain the final status so the RPC ends cleanly instead of with a
	// cancellation the spoke would log as an error.
	if _, err := b.stream.Recv(); err != nil && !errors.Is(err, io.EOF) && term == io.EOF {
		term = b.mapErr(err)
	}
	b.finish(term)
}

// finish latches the terminal error and releases the stream. The caller must
// hold b.mu.
func (b *bodyReader) finish(err error) {
	b.finished = true
	b.term = err
	if b.trail.BytesTotal == 0 && b.received > 0 {
		b.trail.BytesTotal = b.received
	}
	b.doneOnce.Do(func() {
		b.cleanup()
		b.release()
	})
}

// Close implements io.Closer. Closing before the body has been drained cancels
// the upstream stream, which the spoke observes as a cancelled request context.
// It is idempotent.
func (b *bodyReader) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = nil
	if !b.finished {
		b.finish(ErrBodyClosed)
	} else {
		b.doneOnce.Do(func() {
			b.cleanup()
			b.release()
		})
	}
	return nil
}

// Trailer implements the contract in tunnel.Response: it reports the zero value
// until the body has been fully read or closed, and the accumulated accounting
// afterwards. A body closed early yields a partial trailer whose BytesTotal is
// what actually arrived.
func (b *bodyReader) Trailer() tunnel.Trailer {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.finished {
		return tunnel.Trailer{}
	}
	return b.trail
}
