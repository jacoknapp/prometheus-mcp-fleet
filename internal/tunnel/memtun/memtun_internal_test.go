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

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

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
