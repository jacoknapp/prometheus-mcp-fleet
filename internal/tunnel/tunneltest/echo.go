// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package tunneltest

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Call is one observation of a request that reached the handler. Tests use it
// to assert that a request crossed the transport intact and that the deadline
// travelled with it.
type Call struct {
	// Method, Path, Form, RequestID and MaxResponseBytes are copied from the
	// request the handler received.
	Method           string
	Path             string
	Form             []byte
	RequestID        string
	MaxResponseBytes int64
	// Deadline is the handler context's deadline, and HasDeadline says whether
	// there was one at all.
	Deadline    time.Time
	HasDeadline bool
}

// EchoHandler is a configurable tunnel.Handler for tests. Its zero value is
// usable: it answers 200 with the request's own form bytes as the body, which
// makes round-trip assertions trivial.
//
// All fields must be set before the handler is first used. Every method is safe
// for concurrent use afterwards.
type EchoHandler struct {
	// StatusCode is the reported status. Default 200.
	StatusCode int
	// ContentType is the reported content type. Default "application/json".
	ContentType string
	// ContentEncoding is reported verbatim, e.g. "gzip".
	ContentEncoding string

	// Body, when non-nil, is the response body.
	Body []byte
	// BodySize, when > 0 and Body is nil, makes the body DeterministicBody of
	// that many bytes.
	BodySize int
	// BodyFor, when non-nil, chooses the body per request and takes precedence
	// over Body and BodySize. It is how a test gives two concurrent streams
	// distinguishable payloads.
	BodyFor func(req *tunnel.Request) []byte

	// Warnings and UpstreamLatency are reported in the trailer.
	Warnings        []string
	UpstreamLatency time.Duration

	// DoErr, when non-nil, is returned by Do instead of a response, which the
	// transport must surface as an error from Session.Do.
	DoErr error
	// TrailerErr, when non-nil, is reported as Trailer.Err: the tunnel worked
	// and the upstream call did not.
	TrailerErr error

	// DelayBeforeHead stalls Do before it returns the head. It is cancellable.
	DelayBeforeHead time.Duration

	// Gate, when non-nil, is consulted per request. If it returns a non-nil
	// channel, the body stalls once at least after bytes have been produced and
	// resumes when the channel is closed. A gate that is never closed stalls
	// until the request context is cancelled, which is how the suite proves
	// cancellation reaches the handler.
	Gate func(req *tunnel.Request) (after int, release <-chan struct{})

	// Fingerprint is the facts fingerprint Describe reports.
	Fingerprint string
	// Facts is the cluster payload Describe reports when the caller's
	// fingerprint does not match.
	Facts fleet.Cluster
	// DescribeErr, when non-nil, is returned by Describe.
	DescribeErr error

	mu            sync.Mutex
	calls         []Call
	describeCalls []string

	abortOnce sync.Once
	abortInit sync.Once
	aborted   chan struct{}
}

var _ tunnel.Handler = (*EchoHandler)(nil)

// Do implements tunnel.Handler.
func (h *EchoHandler) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	dl, hasDL := ctx.Deadline()
	h.mu.Lock()
	h.calls = append(h.calls, Call{
		Method:           req.Method,
		Path:             req.Path,
		Form:             append([]byte(nil), req.Form...),
		RequestID:        req.RequestID,
		MaxResponseBytes: req.MaxResponseBytes,
		Deadline:         dl,
		HasDeadline:      hasDL,
	})
	h.mu.Unlock()

	if h.DelayBeforeHead > 0 {
		timer := time.NewTimer(h.DelayBeforeHead)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			h.markAborted()
			return nil, ctx.Err()
		}
	}
	if h.DoErr != nil {
		return nil, h.DoErr
	}

	body := h.bodyFor(req)
	var after int
	var release <-chan struct{}
	if h.Gate != nil {
		after, release = h.Gate(req)
	}

	status := h.StatusCode
	if status == 0 {
		status = 200
	}
	ctype := h.ContentType
	if ctype == "" {
		ctype = "application/json"
	}

	r := &gatedReader{ctx: ctx, data: body, after: after, release: release, h: h}
	trailer := tunnel.Trailer{
		BytesTotal:      int64(len(body)),
		UpstreamLatency: h.UpstreamLatency,
		Warnings:        h.Warnings,
		Err:             h.TrailerErr,
	}
	return &tunnel.Response{
		StatusCode:      status,
		ContentType:     ctype,
		ContentEncoding: h.ContentEncoding,
		Body:            r,
		Trailer:         func() tunnel.Trailer { return trailer },
	}, nil
}

// Describe implements tunnel.Handler. It reports Changed=false when the
// caller's fingerprint already matches.
func (h *EchoHandler) Describe(_ context.Context, knownFingerprint string) (tunnel.Facts, error) {
	h.mu.Lock()
	h.describeCalls = append(h.describeCalls, knownFingerprint)
	h.mu.Unlock()

	if h.DescribeErr != nil {
		return tunnel.Facts{}, h.DescribeErr
	}
	if knownFingerprint != "" && knownFingerprint == h.Fingerprint {
		return tunnel.Facts{Fingerprint: h.Fingerprint, Changed: false}, nil
	}
	return tunnel.Facts{Fingerprint: h.Fingerprint, Changed: true, Cluster: h.Facts}, nil
}

// Calls returns a copy of every request the handler has seen, in order.
func (h *EchoHandler) Calls() []Call {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Call(nil), h.calls...)
}

// DescribeCalls returns the known-fingerprint argument of every Describe call.
func (h *EchoHandler) DescribeCalls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.describeCalls...)
}

// Aborted is closed the first time a handler observes its request context being
// cancelled. It is the suite's proof that a client-side cancellation really
// reached the far end rather than merely being swallowed locally.
func (h *EchoHandler) Aborted() <-chan struct{} {
	h.initAborted()
	return h.aborted
}

func (h *EchoHandler) initAborted() {
	h.abortInit.Do(func() { h.aborted = make(chan struct{}) })
}

func (h *EchoHandler) markAborted() {
	h.initAborted()
	h.abortOnce.Do(func() { close(h.aborted) })
}

// bodyFor picks the response body for one request.
func (h *EchoHandler) bodyFor(req *tunnel.Request) []byte {
	switch {
	case h.BodyFor != nil:
		return h.BodyFor(req)
	case h.Body != nil:
		return h.Body
	case h.BodySize > 0:
		return DeterministicBody(h.BodySize)
	default:
		return append([]byte(nil), req.Form...)
	}
}

// gatedReader serves a fixed byte slice, optionally stalling partway through
// until a channel closes or the context is cancelled.
type gatedReader struct {
	ctx     context.Context
	data    []byte
	off     int
	after   int
	release <-chan struct{}
	passed  bool
	h       *EchoHandler
}

// Read implements io.Reader.
func (r *gatedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		r.h.markAborted()
		return 0, err
	}
	if r.release != nil && !r.passed && r.off >= r.after {
		select {
		case <-r.release:
			r.passed = true
		case <-r.ctx.Done():
			r.h.markAborted()
			return 0, r.ctx.Err()
		}
	}
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// Close implements io.Closer.
func (r *gatedReader) Close() error { return nil }

// DeterministicBody returns n pseudo-random but reproducible bytes. Using a
// varied payload rather than a repeated byte means a reassembly bug that
// duplicates or drops a chunk cannot hide.
func DeterministicBody(n int) []byte {
	out := make([]byte, n)
	// xorshift64*, chosen because it is four lines and needs no imports.
	state := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		// The mask says what the byte conversion already did: take the low
		// eight bits. Truncation is the point -- this is a PRNG byte, not a length.
		out[i] = byte(((state * 0x2545F4914F6CDD1D) >> 33) & 0xFF)
	}
	return out
}
