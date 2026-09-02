// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

func TestLimitedBodyRepeatsTerminalErrors(t *testing.T) {
	t.Parallel()

	t.Run("too large", func(t *testing.T) {
		t.Parallel()
		b := newLimitedBody(io.NopCloser(strings.NewReader("abcd")), 2, 0, nil, false)
		buf := make([]byte, 8)
		if n, err := b.Read(buf); n != 2 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("first Read = %d, %v; want 2, ErrTooLarge", n, err)
		}
		if n, err := b.Read(buf); n != 0 || !errors.Is(err, ErrTooLarge) {
			t.Errorf("second Read = %d, %v; want 0, ErrTooLarge", n, err)
		}
	})

	t.Run("source failure", func(t *testing.T) {
		t.Parallel()
		want := errors.New("source failed")
		b := newLimitedBody(&failingBody{err: want}, 8, 0, nil, false)
		buf := make([]byte, 1)
		if _, err := b.Read(buf); !errors.Is(err, want) {
			t.Fatalf("first Read = %v, want source failure", err)
		}
		if _, err := b.Read(buf); !errors.Is(err, want) {
			t.Errorf("second Read = %v, want cached source failure", err)
		}
	})
}

// recordingReader records the length of the buffer it is asked to fill on
// each call and always fills it completely, so a test can inspect exactly
// how much a caller requested regardless of how the underlying source would
// otherwise be limited.
type recordingReader struct {
	reqLens []int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	r.reqLens = append(r.reqLens, len(p))
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (r *recordingReader) Close() error { return nil }

// Note on body.go:74 ("if n > 0"): a mutant widening this to "n >= 0" only
// changes behaviour when a Read from the upstream source returns (0, nil or
// err) — io.Reader permits n == 0. Entering that block with n == 0 adds 0 to
// b.n, evaluates an "over" that was already <= 0 one line above unless b.n
// already equals b.limit (in which case over stays exactly 0 either way, so
// truncated is not newly set), and — when peeking — writes p[:0] to the
// warnings buffer, which is a no-op. Every statement in the block is either
// a no-op or reproduces a value already true before the block ran, so no
// input makes original and mutant produce different bytes, error, or
// truncated state. Left alive with this as its proof.

// TestLimitedBodyClipsRequestToRemainingCap pins the exact arithmetic of the
// pre-read clip in limitedBody.Read: once some bytes have already been
// consumed, the next request must be sized to precisely the bytes still
// remaining under the cap (b.limit - b.n), clipped to remaining+1 only when
// the caller's buffer is strictly larger than that. It also pins the
// boundary itself: a caller buffer exactly the size of the remaining
// allowance must not be clipped at all.
func TestLimitedBodyClipsRequestToRemainingCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		limit         int64
		warmup        int
		bufSize       int
		wantReqLen    int
		wantN         int
		wantTruncated bool
	}{
		{
			name:          "buffer exactly at remaining is not clipped",
			limit:         10,
			warmup:        4,
			bufSize:       6, // == limit - warmup
			wantReqLen:    6,
			wantN:         6,
			wantTruncated: false,
		},
		{
			name:          "buffer past remaining is clipped to remaining+1",
			limit:         10,
			warmup:        4,
			bufSize:       20,
			wantReqLen:    7, // (limit-warmup)+1, the deliberate one-byte-past peek
			wantN:         6, // the 7th byte is discarded as the over-cap detector
			wantTruncated: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recordingReader{}
			b := newLimitedBody(rec, tc.limit, 0, nil, false)

			warmupBuf := make([]byte, tc.warmup)
			if n, err := b.Read(warmupBuf); n != tc.warmup || err != nil {
				t.Fatalf("warmup Read = %d, %v; want %d, nil", n, err, tc.warmup)
			}

			buf := make([]byte, tc.bufSize)
			n, err := b.Read(buf)

			if got := rec.reqLens[1]; got != tc.wantReqLen {
				t.Errorf("source asked for %d bytes, want %d", got, tc.wantReqLen)
			}
			if n != tc.wantN {
				t.Errorf("Read n = %d, want %d", n, tc.wantN)
			}
			if tc.wantTruncated {
				if !errors.Is(err, ErrTooLarge) {
					t.Errorf("Read err = %v, want ErrTooLarge", err)
				}
			} else if err != nil {
				t.Errorf("Read err = %v, want nil", err)
			}
		})
	}
}

// TestLimitedBodyCloseCancelsDerivedContext pins both directions of the
// b.cancel != nil guard in Close: a non-nil cancel must actually be invoked,
// and a nil cancel must never be called (which would panic).
func TestLimitedBodyCloseCancelsDerivedContext(t *testing.T) {
	t.Parallel()

	t.Run("non-nil cancel is invoked", func(t *testing.T) {
		t.Parallel()
		called := false
		b := newLimitedBody(io.NopCloser(strings.NewReader("x")), 8, 0, func() { called = true }, false)
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !called {
			t.Error("Close did not invoke the derived cancel func")
		}
	})

	t.Run("nil cancel is never called", func(t *testing.T) {
		t.Parallel()
		b := newLimitedBody(io.NopCloser(strings.NewReader("x")), 8, 0, nil, false)
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

func TestRoundTripInternalFailures(t *testing.T) {
	t.Parallel()
	c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})

	badLabelRoute, err := promapi.Get(promapi.EndpointLabelValues)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.roundTrip(t.Context(), badLabelRoute, "bad/label", nil, false, ""); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("roundTrip invalid label = %v, want ErrNotAllowed", err)
	}

	queryRoute, err := promapi.Get(promapi.EndpointQuery)
	if err != nil {
		t.Fatal(err)
	}
	queryRoute.Method = "bad method"
	if _, _, _, err := c.roundTrip(t.Context(), queryRoute, "", url.Values{"query": {"up"}}, false, ""); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Errorf("roundTrip invalid method = %v, want build request failure", err)
	}
}

func TestProbeInternalFailures(t *testing.T) {
	t.Parallel()

	t.Run("request construction", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.base = &url.URL{Scheme: "http", Host: "[::1"}
		if err := c.probe(t.Context(), EndpointHealthy, "/-/healthy"); err == nil || !strings.Contains(err.Error(), "/-/healthy") {
			t.Errorf("probe malformed URL = %v, want path-named construction error", err)
		}
	})

	t.Run("bearer token read", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example", BearerTokenFile: "/missing/token"})
		if err := c.probe(t.Context(), EndpointHealthy, "/-/healthy"); err == nil || !strings.Contains(err.Error(), "read bearer token") {
			t.Errorf("probe missing bearer token = %v, want token read error", err)
		}
	})
}

// Note on json.go:189 ("if c.maxResponseBytes < limit") and client.go:255
// ("if req.MaxResponseBytes > 0 && req.MaxResponseBytes < limit"): both pick
// the smaller of two values via "if a < b { b = a }". Widening the
// comparison to "<=" only changes what happens when a == b, and in that case
// the assignment b = a is a no-op — a and b already hold the same value, so
// the resulting limit is identical whichever branch runs. No downstream code
// can observe which branch was taken, only the resulting number. Left alive
// with this as their proof.
//
// client.go:374 ("if remaining < budget { budget = remaining }") is the same
// min-assignment shape and is equivalent at the boundary for the same
// reason; TestUpstreamContextDeadlineBudget below instead kills the
// CONDITIONALS_NEGATION mutant at that line, which does not collapse to a
// no-op (it flips which of the two values wins).

func TestJSONHelpersPropagateTransportAndReadFailures(t *testing.T) {
	t.Parallel()

	t.Run("label values transport", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})
		if _, err := c.LabelValues(t.Context(), "job"); !errors.Is(err, ErrUpstream) {
			t.Errorf("LabelValues = %v, want ErrUpstream", err)
		}
	})

	t.Run("instant query transport", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})
		if _, err := c.InstantQuery(t.Context(), "up"); !errors.Is(err, ErrUpstream) {
			t.Errorf("InstantQuery = %v, want ErrUpstream", err)
		}
	})

	t.Run("response read", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &failingBody{err: io.ErrUnexpectedEOF},
			}, nil
		})
		route, _ := promapi.Get(promapi.EndpointLabels)
		if _, err := c.fetch(t.Context(), route, "", nil, &struct{}{}); !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "read body") {
			t.Errorf("fetch = %v, want upstream read failure", err)
		}
	})

	t.Run("bad scalar value", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(bytes.NewBufferString(
					`{"status":"success","data":{"resultType":"scalar","result":[1,"not-a-number"]}}`)),
			}, nil
		})
		if _, err := c.InstantQuery(t.Context(), "up"); !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "not-a-number") {
			t.Errorf("InstantQuery = %v, want invalid scalar value error", err)
		}
	})
}

// TestSnippetBoundaries pins the exact edges of snippet's length cap and its
// control-character sweep.
func TestSnippetBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("length boundary", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			n    int
			want string
		}{
			{"exactly at max is not clipped", 256, strings.Repeat("A", 256)},
			{"one over max is clipped", 257, strings.Repeat("A", 256) + "...[clipped]"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got := snippet(bytes.Repeat([]byte("A"), tc.n))
				if got != tc.want {
					t.Errorf("snippet(%d bytes) = %q, want %q", tc.n, got, tc.want)
				}
			})
		}
	})

	// Note on r < 0x20 (the low control-character bound): the boundary value
	// 0x20 itself is the space character, and the replacement snippet emits
	// for a control character is also a space. Whether 0x20 falls inside or
	// outside that range is therefore not observable in the output — a test
	// at r == 0x20 cannot tell "replaced with a space" from "passed through
	// as a space". This is not tested below for that reason; the equivalent
	// mutant at json.go:221:8 is left alive with this as its proof.
	t.Run("high control-character range", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			r    rune
			want rune
		}{
			{"0x1f is replaced (ordinary low control char)", 0x1f, ' '},
			{"0x7e just below the DEL boundary is kept", 0x7e, 0x7e},
			{"0x7f at the DEL boundary is replaced", 0x7f, ' '},
			{"0x85 mid-range is replaced", 0x85, ' '},
			{"0x9f at the upper boundary is replaced", 0x9f, ' '},
			{"0xa0 just past the upper boundary is kept", 0xa0, 0xa0},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				got := snippet([]byte(string(tc.r)))
				gotRunes := []rune(got)
				if len(gotRunes) != 1 || gotRunes[0] != tc.want {
					t.Errorf("snippet(%q) = %q, want %q", tc.r, got, string(tc.want))
				}
			})
		}
	})
}

// TestNewConfiguresTransportTimeouts pins the exact duration values wired
// into the transport that http.Transport keeps as plain struct fields (and
// so can be inspected directly, unlike the net.Dialer.Timeout and
// net.Dialer.KeepAlive values a few lines above them in New: those are
// captured inside the opaque net.Dialer.DialContext method value, which
// Go's reflect package has no supported way to open back up, and observing
// their effect behaviourally would require either a multi-second real dial
// against an unreachable address or an unreliable network fixture — neither
// consistent with the rest of this suite's fast, deterministic style. Those
// two are left alive with this comment as their proof.
func TestNewConfiguresTransportTimeouts(t *testing.T) {
	t.Parallel()
	c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
	tr, ok := c.httpc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.httpc.Transport)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %s, want 90s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %s, want 10s", tr.TLSHandshakeTimeout)
	}
}

// TestUpstreamContextDeadlineBudget pins the two boundaries in
// upstreamContext that decide how much of a caller's deadline is spent.
//
// Both use a frozen Config.Clock so "remaining" is deterministic rather than
// dependent on how fast the test happens to run.
func TestUpstreamContextDeadlineBudget(t *testing.T) {
	t.Parallel()

	t.Run("remaining exactly at the hop margin is refused", func(t *testing.T) {
		t.Parallel()
		frozen := time.Now()
		c := mustInternalClient(t, Config{
			BaseURL: "http://prom.example",
			Timeout: time.Hour,
			Clock:   func() time.Time { return frozen },
		})
		// deadline.Sub(clock()) - HopMargin == 0 exactly.
		ctx, cancel := context.WithDeadline(t.Context(), frozen.Add(HopMargin))
		defer cancel()

		_, _, err := c.upstreamContext(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("upstreamContext() error = %v, want it to wrap context.DeadlineExceeded", err)
		}
	})

	t.Run("remaining one tick past the hop margin is accepted", func(t *testing.T) {
		t.Parallel()
		frozen := time.Now()
		c := mustInternalClient(t, Config{
			BaseURL: "http://prom.example",
			Timeout: time.Hour,
			Clock:   func() time.Time { return frozen },
		})
		ctx, cancel := context.WithDeadline(t.Context(), frozen.Add(HopMargin+time.Nanosecond))
		defer cancel()

		callCtx, cancelCall, err := c.upstreamContext(ctx)
		if err != nil {
			t.Fatalf("upstreamContext(): %v, want it to succeed with 1ns of budget left", err)
		}
		defer cancelCall()
		if _, ok := callCtx.Deadline(); !ok {
			t.Fatal("callCtx has no deadline")
		}
	})

	// This proves the tighter of Config.Timeout and the caller's remaining
	// deadline wins when the caller's deadline is the looser one: if the
	// comparison that picks the tighter budget were inverted, the derived
	// context would live for ~10s instead of the configured 200ms.
	t.Run("remaining well past the timeout: the timeout wins", func(t *testing.T) {
		t.Parallel()
		frozen := time.Now()
		const budget = 200 * time.Millisecond
		c := mustInternalClient(t, Config{
			BaseURL: "http://prom.example",
			Timeout: budget,
			Clock:   func() time.Time { return frozen },
		})
		ctx, cancel := context.WithDeadline(t.Context(), frozen.Add(HopMargin+10*time.Second))
		defer cancel()

		before := time.Now()
		callCtx, cancelCall, err := c.upstreamContext(ctx)
		after := time.Now()
		if err != nil {
			t.Fatalf("upstreamContext(): %v", err)
		}
		defer cancelCall()

		deadline, ok := callCtx.Deadline()
		if !ok {
			t.Fatal("callCtx has no deadline")
		}
		const slack = 500 * time.Millisecond
		if deadline.After(after.Add(budget + slack)) {
			t.Fatalf("deadline is %s after the call, want it bounded by the %s timeout, not the 10s remaining",
				deadline.Sub(before), budget)
		}
		if deadline.Before(before.Add(budget - slack)) {
			t.Fatalf("deadline is only %s after the call, want it close to the %s timeout",
				deadline.Sub(after), budget)
		}
	})
}

func mustInternalClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingBody struct{ err error }

func (b *failingBody) Read([]byte) (int, error) { return 0, b.err }
func (*failingBody) Close() error               { return nil }

// fakeNetError is a transport error that reports itself as a timeout without
// the context having expired, which is what a ResponseHeaderTimeout or a dial
// timeout looks like from the caller's side.
type fakeNetError struct{ timeout bool }

func (e fakeNetError) Error() string   { return "fake net error" }
func (e fakeNetError) Timeout() bool   { return e.timeout }
func (e fakeNetError) Temporary() bool { return false }

// TestErrorCode pins the mapping from transport failures onto the closed code
// set: a context that ended is a timeout whatever the transport said, a
// net.Error that timed out on its own is a timeout, everything else is
// CodeError.
func TestErrorCode(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{"context ended", cancelled, errors.New("connection reset"), CodeTimeout},
		{"transport timeout", context.Background(), fakeNetError{timeout: true}, CodeTimeout},
		{"transport failure", context.Background(), fakeNetError{timeout: false}, CodeError},
		{"plain error", context.Background(), errors.New("EOF"), CodeError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := errorCode(tc.ctx, tc.err); got != tc.want {
				t.Errorf("errorCode() = %q, want %q", got, tc.want)
			}
		})
	}
}
