// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package memtun

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// TestCloneRequestIsIndependentOfTheOriginal proves the handler gets its own
// copy of Form, matching the real transport: a handler that mutated the bytes
// it was handed must not be able to affect the caller's own request, because
// the real transport re-materialises the request from protobuf and could never
// share memory with the caller's copy either.
func TestCloneRequestIsIndependentOfTheOriginal(t *testing.T) {
	t.Parallel()

	t.Run("form bytes are copied, not aliased", func(t *testing.T) {
		t.Parallel()
		req := &tunnel.Request{Method: http.MethodGet, Path: "/x", Form: []byte("query=up"), MaxResponseBytes: 1}
		clone := cloneRequest(req)
		if diff := cmp.Diff(req.Form, clone.Form); diff != "" {
			t.Fatalf("clone.Form mismatch (-want +got):\n%s", diff)
		}
		clone.Form[0] = 'Q'
		if req.Form[0] == 'Q' {
			t.Fatal("mutating the clone's Form also mutated the original request")
		}
	})

	t.Run("a nil Form clones to nil, not an empty slice", func(t *testing.T) {
		t.Parallel()
		req := &tunnel.Request{Method: http.MethodGet, Path: "/x", MaxResponseBytes: 1}
		clone := cloneRequest(req)
		if clone.Form != nil {
			t.Fatalf("clone.Form = %#v, want nil", clone.Form)
		}
	})
}

type testHandler struct {
	do       func(context.Context, *tunnel.Request) (*tunnel.Response, error)
	describe func(context.Context, string) (tunnel.Facts, error)
}

func (h testHandler) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	return h.do(ctx, req)
}

func (h testHandler) Describe(ctx context.Context, fingerprint string) (tunnel.Facts, error) {
	return h.describe(ctx, fingerprint)
}

func validRequest() *tunnel.Request {
	return &tunnel.Request{Method: http.MethodGet, Path: "/api/v1/query", MaxResponseBytes: 1024}
}

func TestSessionErrorAndLifecyclePaths(t *testing.T) {
	t.Parallel()

	upstreamErr := errors.New("facts unavailable")
	h := testHandler{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) {
			return tunnel.Facts{}, upstreamErr
		},
	}
	s := Pair(tunnel.Identity{ClusterID: "prod"}, 42, h).(*session)

	if got := s.CloseReason(); got != "" {
		t.Errorf("CloseReason() while live = %q, want empty", got)
	}
	if _, err := s.Describe(context.Background(), "old"); !errors.Is(err, upstreamErr) {
		t.Errorf("Describe() = %v, want upstream error", err)
	}
	if _, err := s.Do(context.Background(), validRequest()); err == nil || !strings.Contains(err.Error(), "nil body") {
		t.Errorf("Do() = %v, want a nil-body error", err)
	}
	if err := s.Close("maintenance"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.CloseReason(); got != "maintenance" {
		t.Errorf("CloseReason() = %q, want maintenance", got)
	}
	if got := s.mapErr(context.Background(), nil); got != nil {
		t.Errorf("mapErr(nil error) = %v, want nil", got)
	}
	if got := s.mapErr(context.Background(), upstreamErr); !errors.Is(got, tunnel.ErrSessionClosed) || !errors.Is(got, upstreamErr) {
		t.Errorf("mapErr() = %v, want session-closed wrapping upstream", got)
	}
	if _, err := s.Do(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Do(nil) = %v, want ErrInvalidRequest", err)
	}
}

// TestMapErrPrefersACancelledCallerContextOverTheHandlersOwnError proves that a
// caller context which has already expired takes priority over whatever error
// the handler itself produced, on a session that is not otherwise closed. A
// caller asking "did my own deadline or cancellation cause this" must see its
// own context.Canceled, not an unrelated handler failure that happened to race
// it.
func TestMapErrPrefersACancelledCallerContextOverTheHandlersOwnError(t *testing.T) {
	t.Parallel()

	h := testHandler{
		do:       func(context.Context, *tunnel.Request) (*tunnel.Response, error) { return &tunnel.Response{}, nil },
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}
	s := Pair(tunnel.Identity{ClusterID: "prod"}, 1, h).(*session)
	t.Cleanup(func() { _ = s.Close("cleanup") })

	callerCtx, cancel := context.WithCancel(context.Background())
	cancel()
	handlerErr := errors.New("unrelated handler failure")

	got := s.mapErr(callerCtx, handlerErr)
	if !errors.Is(got, context.Canceled) {
		t.Fatalf("mapErr(cancelled ctx, handlerErr) = %v, want context.Canceled", got)
	}
	if errors.Is(got, handlerErr) {
		t.Errorf("mapErr(cancelled ctx, handlerErr) = %v, must not still be the handler's error", got)
	}
	if errors.Is(got, tunnel.ErrSessionClosed) {
		t.Errorf("mapErr(cancelled ctx, handlerErr) = %v, the session itself is not closed", got)
	}
}

type observedBody struct {
	closed atomic.Bool
}

func (*observedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *observedBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestCancelledDoClosesALateHandlerResponse(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	body := &observedBody{}
	h := testHandler{
		do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
			close(started)
			<-release
			return &tunnel.Response{Body: body}, nil
		},
		describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
	}
	s := Pair(tunnel.Identity{ClusterID: "prod"}, 1, h).(*session)
	t.Cleanup(func() { _ = s.Close("cleanup") })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.Do(ctx, validRequest())
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Do() = %v, want context.Canceled", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for !body.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !body.closed.Load() {
		t.Error("late handler response body was not closed")
	}
}

// writerFunc adapts a function to io.Writer.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// zeroThenData reports a legal (0, nil) read once before yielding data, then
// io.EOF once the data is exhausted.
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

type dataThenError struct {
	data []byte
	err  error
}

func (r *dataThenError) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestCopyAndPumpReportReaderFailures(t *testing.T) {
	t.Parallel()

	readErr := errors.New("source vanished")
	t.Run("failure while probing beyond budget", func(t *testing.T) {
		var out strings.Builder
		sent, truncated, err := copyBudgeted(&out, &dataThenError{data: []byte("abc"), err: readErr}, 3)
		if sent != 3 || truncated || !errors.Is(err, readErr) || out.String() != "abc" {
			t.Errorf("copyBudgeted = (%d, %v, %v, %q), want (3, false, readErr, abc)", sent, truncated, err, out.String())
		}
	})

	// A reader is allowed by the io.Reader contract to return (0, nil), and
	// copyBudgeted must not mistake that for a chunk worth writing out.
	t.Run("a zero-byte, no-error read produces no empty write", func(t *testing.T) {
		var writes [][]byte
		w := writerFunc(func(p []byte) (int, error) {
			writes = append(writes, append([]byte(nil), p...))
			return len(p), nil
		})
		sent, truncated, err := copyBudgeted(w, &zeroThenData{data: []byte("abc")}, 16)
		if sent != 3 || truncated || err != nil {
			t.Fatalf("copyBudgeted = (%d, %v, %v), want (3, false, nil)", sent, truncated, err)
		}
		for _, p := range writes {
			if len(p) == 0 {
				t.Errorf("an empty Write occurred: %v", writes)
			}
		}
	})

	t.Run("pump exposes an incomplete response", func(t *testing.T) {
		h := testHandler{
			do: func(context.Context, *tunnel.Request) (*tunnel.Response, error) {
				return &tunnel.Response{Body: io.NopCloser(&dataThenError{data: []byte("abc"), err: readErr})}, nil
			},
			describe: func(context.Context, string) (tunnel.Facts, error) { return tunnel.Facts{}, nil },
		}
		s := Pair(tunnel.Identity{ClusterID: "prod"}, 1, h).(*session)
		t.Cleanup(func() { _ = s.Close("cleanup") })
		resp, err := s.Do(context.Background(), validRequest())
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		got, err := io.ReadAll(resp.Body)
		if string(got) != "abc" || !errors.Is(err, ErrUpstream) {
			t.Errorf("ReadAll = (%q, %v), want abc and ErrUpstream", got, err)
		}
		if trail := resp.Trailer(); !errors.Is(trail.Err, ErrUpstream) || trail.BytesTotal != 3 {
			t.Errorf("Trailer = %+v, want 3 bytes and ErrUpstream", trail)
		}
	})
}

// TestBodyReaderDoesNotFinishOnASuccessfulRead proves a Read that reports no
// error leaves the body live: Trailer's zero-value contract holds only while
// finished is false, so latching it early on an ordinary in-progress read
// would let a caller observe a "done" trailer for a response that is not.
func TestBodyReaderDoesNotFinishOnASuccessfulRead(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	b := &bodyReader{pr: pr, cleanup: func() {}, release: func() {}}
	t.Cleanup(func() { _ = pw.Close() })

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = pw.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	n, err := b.Read(buf)
	if n != 5 || err != nil {
		t.Fatalf("Read = (%d, %v), want (5, nil)", n, err)
	}
	if b.finished {
		t.Error("finished = true after a successful read that reported no error")
	}
	if trail := b.Trailer(); trail.BytesTotal != 0 || trail.Truncated || trail.Err != nil || len(trail.Warnings) != 0 {
		t.Errorf("Trailer() = %+v, want the zero value while the body is still live", trail)
	}
	<-writeDone
}
