// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package memtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Sentinel errors reported by this package. They mirror the ones grpctun
// reports for the same situations so a test written against memtun keeps
// passing against the real transport.
var (
	// ErrUpstream wraps the failure message a handler reported in its trailer.
	// The real transport carries that failure as a string on the wire, so the
	// handler's original error value is deliberately not recoverable here
	// either.
	ErrUpstream = errors.New("memtun: upstream failure reported by handler")

	// ErrBodyClosed is returned by Response.Body.Read after an early Close.
	ErrBodyClosed = errors.New("memtun: response body closed")

	// ErrInvalidRequest reports a tunnel.Request the transport refuses.
	ErrInvalidRequest = errors.New("memtun: invalid request")
)

// chunkBytes matches the 64 KiB the real transport puts on the wire, so a test
// that depends on chunk boundaries behaves the same on both.
const chunkBytes = 64 << 10

// Pair wires h directly to a tunnel.Session, with no network, no TLS and no
// gRPC in between.
//
// id is the identity the session reports, as though it had been derived from a
// verified client certificate. generation is the spoke process start time the
// session reports once Describe has returned changed facts; before that,
// Generation reports 0, exactly as the real transport does (the wire protocol
// only carries the generation inside a full ClusterFacts payload).
//
// The caller should Close the session when finished; doing so aborts any
// in-flight request.
func Pair(id tunnel.Identity, generation int64, h tunnel.Handler) tunnel.Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		identity:  id,
		gen:       generation,
		h:         h,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		closeChan: make(chan struct{}),
	}
}

// session is the in-process tunnel.Session.
type session struct {
	identity tunnel.Identity
	gen      int64
	h        tunnel.Handler

	ctx    context.Context
	cancel context.CancelFunc

	reported atomic.Int64
	inflight atomic.Int64

	done      chan struct{}
	closeChan chan struct{}
	closeOnce sync.Once
	reason    atomic.Pointer[string]
}

var _ tunnel.Session = (*session)(nil)

// Identity implements tunnel.Session.
func (s *session) Identity() tunnel.Identity { return s.identity }

// Generation implements tunnel.Session. It reports 0 until the first Describe
// call has returned changed facts.
func (s *session) Generation() int64 { return s.reported.Load() }

// Done implements tunnel.Session.
func (s *session) Done() <-chan struct{} { return s.done }

// CloseReason reports the reason recorded by Close, or "" while the session is
// live.
func (s *session) CloseReason() string {
	if r := s.reason.Load(); r != nil {
		return *r
	}
	return ""
}

// InFlight reports how many response bodies are currently open. Leak tests
// assert it settles back to zero.
func (s *session) InFlight() int { return int(s.inflight.Load()) }

// Close implements tunnel.Session. It is idempotent and aborts in-flight
// requests, as dropping the socket would.
func (s *session) Close(reason string) error {
	s.closeOnce.Do(func() {
		s.reason.Store(&reason)
		s.cancel()
		close(s.done)
	})
	return nil
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
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()

	facts, err := s.h.Describe(callCtx, knownFingerprint)
	if err != nil {
		return tunnel.Facts{}, fmt.Errorf("describe %s: %w", s.identity.ClusterID, s.mapErr(ctx, err))
	}
	if !facts.Changed {
		// An unchanged reply carries no facts on the wire, and therefore no
		// generation. Mirror that exactly.
		return tunnel.Facts{Fingerprint: facts.Fingerprint, Changed: false, Generation: s.reported.Load()}, nil
	}
	s.reported.Store(s.gen)
	facts.Generation = s.gen
	return facts, nil
}

// Do implements tunnel.Session. It returns once the handler has produced a
// head; the body is streamed lazily.
func (s *session) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	select {
	case <-s.done:
		return nil, tunnel.ErrSessionClosed
	default:
	}

	reqCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	cleanup := func() {
		stop()
		cancel()
	}

	// The handler runs on its own goroutine so that cancelling ctx aborts Do
	// even when the handler is blocked, which is what RST_STREAM buys on the
	// real transport.
	type result struct {
		resp *tunnel.Response
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		r, err := s.h.Do(reqCtx, cloneRequest(req))
		resCh <- result{r, err}
	}()

	var res result
	select {
	case res = <-resCh:
	case <-reqCtx.Done():
		cleanup()
		go func() {
			// Do not leak the handler's response if it arrives after we gave up.
			if r := <-resCh; r.resp != nil && r.resp.Body != nil {
				_ = r.resp.Body.Close()
			}
		}()
		return nil, fmt.Errorf("proxy %s %s: %w", req.Method, req.Path, s.mapErr(ctx, reqCtx.Err()))
	}
	if res.err != nil {
		cleanup()
		return nil, fmt.Errorf("proxy %s %s: %w", req.Method, req.Path, s.mapErr(ctx, res.err))
	}
	if res.resp == nil || res.resp.Body == nil {
		cleanup()
		return nil, fmt.Errorf("proxy %s %s: handler returned a nil body", req.Method, req.Path)
	}

	s.inflight.Add(1)
	pr, pw := io.Pipe()
	body := &bodyReader{
		pr:      pr,
		cleanup: cleanup,
		release: func() { s.inflight.Add(-1) },
	}
	go pump(reqCtx, pw, res.resp, req.MaxResponseBytes, body)

	return &tunnel.Response{
		StatusCode:      res.resp.StatusCode,
		ContentType:     res.resp.ContentType,
		ContentEncoding: res.resp.ContentEncoding,
		Body:            body,
		Trailer:         body.Trailer,
	}, nil
}

// mapErr normalises errors into the vocabulary hub callers branch on.
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
	return err
}

// validateRequest applies the same structural checks the real transport does
// before putting a request on the wire.
func validateRequest(req *tunnel.Request) error {
	switch {
	case req == nil:
		return fmt.Errorf("%w: nil request", ErrInvalidRequest)
	case req.Method != "GET" && req.Method != "POST":
		return fmt.Errorf("%w: method %q is not GET or POST", ErrInvalidRequest, req.Method)
	case !strings.HasPrefix(req.Path, "/"):
		return fmt.Errorf("%w: path %q is not absolute", ErrInvalidRequest, req.Path)
	case req.MaxResponseBytes <= 0:
		return fmt.Errorf("%w: MaxResponseBytes must be > 0, got %d", ErrInvalidRequest, req.MaxResponseBytes)
	default:
		return nil
	}
}

// cloneRequest hands the handler its own copy, because the real transport
// re-materialises the request from protobuf and a handler that mutated it could
// not affect the caller.
func cloneRequest(req *tunnel.Request) *tunnel.Request {
	out := *req
	if req.Form != nil {
		out.Form = make([]byte, len(req.Form))
		copy(out.Form, req.Form)
	}
	return &out
}

// pump copies the handler's body into the pipe, enforcing the byte budget and
// publishing the trailer when it finishes. It is the memtun analogue of the
// spoke's streaming Proxy handler.
func pump(ctx context.Context, pw *io.PipeWriter, resp *tunnel.Response, budget int64, body *bodyReader) {
	defer func() { _ = resp.Body.Close() }()

	started := time.Now()
	sent, truncated, copyErr := copyBudgeted(pw, resp.Body, budget)

	trail := tunnel.Trailer{
		BytesTotal:      sent,
		UpstreamLatency: time.Since(started),
		Truncated:       truncated,
	}
	if resp.Trailer != nil {
		t := resp.Trailer()
		if t.UpstreamLatency > 0 {
			trail.UpstreamLatency = t.UpstreamLatency
		}
		trail.Truncated = trail.Truncated || t.Truncated
		trail.Warnings = t.Warnings
		if t.Err != nil {
			// Stringify, exactly as the wire would: the caller must not be able
			// to errors.Is its way back to the handler's own sentinel.
			trail.Err = fmt.Errorf("%w: %s", ErrUpstream, t.Err.Error())
		}
	}

	term := error(io.EOF)
	switch {
	case ctx.Err() != nil:
		term = ctx.Err()
	case copyErr != nil && trail.Err == nil:
		trail.Err = fmt.Errorf("%w: %s", ErrUpstream, copyErr.Error())
		term = trail.Err
	case trail.Err != nil:
		term = trail.Err
	case trail.Truncated:
		term = tunnel.ErrResponseTooLarge
	}

	body.publish(trail)
	_ = pw.CloseWithError(term)
}

// copyBudgeted copies at most budget bytes and then probes for one more, so
// truncation lands on exactly the budget rather than on a chunk boundary.
func copyBudgeted(w io.Writer, r io.Reader, budget int64) (sent int64, truncated bool, err error) {
	buf := make([]byte, chunkBytes)
	for {
		remaining := budget - sent
		if remaining <= 0 {
			n, rerr := r.Read(buf[:1])
			if n > 0 {
				truncated = true
			}
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return sent, truncated, rerr
			}
			return sent, truncated, nil
		}
		lim := int64(len(buf))
		if remaining < lim {
			lim = remaining
		}
		n, rerr := r.Read(buf[:lim])
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				// The reader went away; it already knows why.
				return sent, truncated, nil
			}
			sent += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return sent, truncated, nil
			}
			return sent, truncated, rerr
		}
	}
}

// bodyReader adapts the pipe to the tunnel.Response contract: the trailer stays
// invisible until the body is drained or closed, and an early Close cancels the
// producing side instead of leaking it.
type bodyReader struct {
	pr      *io.PipeReader
	cleanup func()
	release func()

	mu        sync.Mutex
	finished  bool
	term      error
	delivered int64
	trail     tunnel.Trailer
	published bool
	closed    bool
	doneOnce  sync.Once
}

var _ io.ReadCloser = (*bodyReader)(nil)

// Read implements io.Reader. Once a terminal error has been reported it is
// reported again on every subsequent call, so tunnel.ErrResponseTooLarge is not
// something a caller can read past.
func (b *bodyReader) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.term != nil {
		term := b.term
		b.mu.Unlock()
		return 0, term
	}
	b.mu.Unlock()

	n, err := b.pr.Read(p)

	b.mu.Lock()
	b.delivered += int64(n)
	if err != nil {
		b.finished = true
		if b.term == nil {
			if b.closed && !b.published {
				b.term = ErrBodyClosed
			} else {
				b.term = err
			}
		}
		err = b.term
	}
	b.mu.Unlock()

	if err != nil {
		b.finishOnce()
	}
	return n, err
}

// Close implements io.Closer. An early Close cancels the handler, which is what
// closing a body does on the real transport. It is idempotent.
func (b *bodyReader) Close() error {
	b.mu.Lock()
	b.closed = true
	b.finished = true
	if b.term == nil {
		b.term = ErrBodyClosed
		b.trail.BytesTotal = b.delivered
	}
	b.mu.Unlock()
	_ = b.pr.CloseWithError(ErrBodyClosed)
	b.finishOnce()
	return nil
}

// Trailer implements the tunnel.Response contract: the zero value until the
// body is fully read or closed.
func (b *bodyReader) Trailer() tunnel.Trailer {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.finished {
		return tunnel.Trailer{}
	}
	return b.trail
}

// publish records the trailer produced by the pump. A body the caller already
// abandoned keeps its partial trailer.
func (b *bodyReader) publish(t tunnel.Trailer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.trail = t
	b.published = true
}

func (b *bodyReader) finishOnce() {
	b.doneOnce.Do(func() {
		b.cleanup()
		b.release()
	})
}
