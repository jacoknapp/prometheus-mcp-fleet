// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestChainOrder(t *testing.T) {
	t.Parallel()

	var order []string
	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, "enter:"+name)
				next.ServeHTTP(w, r)
				order = append(order, "exit:"+name)
			})
		}
	}

	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), mark("first"), nil, mark("second"))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"enter:first", "enter:second", "handler", "exit:second", "exit:first"}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("middleware order (-want +got):\n%s", diff)
	}
}

func TestChainNilHandler(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	Chain(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestRecoverBeforeWrite(t *testing.T) {
	t.Parallel()

	const secret = "pmf_agt_SUPERSECRETVALUE"

	tests := []struct {
		name  string
		panic any
	}{
		{name: "string value", panic: "boom " + secret},
		{name: "error value", panic: errors.New("boom " + secret)},
		{name: "nil map dereference", panic: (map[string]string)(nil)},
		{name: "integer value", panic: 42},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logger, buf := newTestLogger()
			var panics atomic.Int64

			h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				panic(tc.panic)
			}), RequestID, Recover(logger, func() { panics.Add(1) }))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/query", nil))

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
			if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
				t.Errorf("content type = %q, want %q", got, ContentTypeJSON)
			}
			if n := panics.Load(); n != 1 {
				t.Errorf("onPanic called %d times, want 1", n)
			}

			var body ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if body.Error.Code != CodeInternal {
				t.Errorf("code = %q, want %q", body.Error.Code, CodeInternal)
			}
			if body.Error.RequestID == "" {
				t.Error("error body is missing the request id")
			}

			// The client must learn nothing about the failure beyond "500".
			// The random request id is scrubbed first so its hex digits cannot
			// masquerade as a leak of a numeric panic value.
			raw := rec.Body.String()
			scrubbed := strings.ReplaceAll(raw, body.Error.RequestID, "")
			for _, leak := range []string{secret, "boom", "goroutine", ".go:", "httpx", "panic", "42"} {
				if strings.Contains(scrubbed, leak) {
					t.Errorf("response body leaks %q: %s", leak, raw)
				}
			}
			if body.Error.Message != "internal error" {
				t.Errorf("message = %q, want a generic one", body.Error.Message)
			}

			// The operator, by contrast, must get everything.
			rec2 := lastLine(t, buf)
			if rec2["msg"] != "panic recovered" {
				t.Errorf("log msg = %v, want %q", rec2["msg"], "panic recovered")
			}
			if rec2["level"] != "ERROR" {
				t.Errorf("log level = %v, want ERROR", rec2["level"])
			}
			if stack, _ := rec2["stack"].(string); !strings.Contains(stack, "httpx") {
				t.Errorf("log is missing a usable stack: %v", rec2["stack"])
			}
		})
	}
}

func TestRecoverNilCallbackAndLogger(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()

	// A nil onPanic must not itself panic.
	rec := httptest.NewRecorder()
	Recover(logger, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	// A nil logger falls back to slog.Default rather than dereferencing nil.
	rec = httptest.NewRecorder()
	Recover(nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestNilLoggerFallback proves neither constructor dereferences a nil logger.
// The handlers are built but not served, so nothing reaches slog.Default and
// the test output stays clean.
func TestNilLoggerFallback(t *testing.T) {
	t.Parallel()

	if AccessLog(nil) == nil {
		t.Error("AccessLog(nil) returned a nil middleware")
	}
	if Recover(nil, nil) == nil {
		t.Error("Recover(nil, nil) returned a nil middleware")
	}
}

func TestRecoverPassesThroughAbortHandler(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	var panics atomic.Int64

	h := Recover(logger, func() { panics.Add(1) })(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	got := catchPanic(t, func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
	if err, ok := got.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
		t.Fatalf("recovered %#v, want http.ErrAbortHandler re-panicked", got)
	}
	if n := panics.Load(); n != 0 {
		t.Errorf("onPanic called %d times for a deliberate abort, want 0", n)
	}
	if out := buf.String(); out != "" {
		t.Errorf("a deliberate abort must not be logged as a panic: %s", out)
	}
}

func TestRecoverAfterWriteAbortsInsteadOfCorrupting(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	var panics atomic.Int64

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"partial":`)
		panic("late boom")
	}), RequestID, Recover(logger, func() { panics.Add(1) }), AccessLog(logger))

	rec := httptest.NewRecorder()
	got := catchPanic(t, func() { h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil)) })

	if err, ok := got.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
		t.Fatalf("recovered %#v, want http.ErrAbortHandler so net/http drops the connection", got)
	}
	if n := panics.Load(); n != 1 {
		t.Errorf("onPanic called %d times, want 1", n)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the already-sent %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != `{"partial":` {
		t.Errorf("body = %q, want the partial write left untouched", got)
	}
	if !strings.Contains(buf.String(), "panic recovered") {
		t.Error("the late panic was not logged")
	}
}

// TestRecoverAfterWriteOverTheWire proves the abort reaches the client as a
// truncated response rather than as spliced-in error JSON.
func TestRecoverAfterWriteOverTheWire(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	srv := httptest.NewServer(Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush() //nolint:errcheck,forcetypeassert // the chain guarantees a flusher
		panic("late boom")
	}), RequestID, Recover(logger, nil)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL) //nolint:noctx // the default test client is fine here
	if err != nil {
		// The connection was dropped before the head reached the client. That
		// is an acceptable outcome: the caller sees a transport failure and
		// never a body it might mistake for a complete answer.
		if strings.Contains(err.Error(), CodeInternal) {
			t.Errorf("error JSON reached the client after a partial write: %v", err)
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("read succeeded with %q, want a truncated body error", body)
	}
	if strings.Contains(string(body), CodeInternal) {
		t.Errorf("error JSON was spliced onto a partial body: %q", body)
	}
}

// catchPanic runs f and returns the value it panicked with, failing when it
// did not panic at all.
func catchPanic(t *testing.T, f func()) (recovered any) {
	t.Helper()
	defer func() { recovered = recover() }()
	f()
	t.Fatal("function did not panic")
	return nil
}

func TestAccessLogLevelByStatusClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		wantLevel string
		wantBytes float64
	}{
		{name: "200 is debug", status: http.StatusOK, wantLevel: "DEBUG", wantBytes: 5},
		{name: "204 is debug", status: http.StatusNoContent, wantLevel: "DEBUG", wantBytes: 0},
		{name: "301 is debug", status: http.StatusMovedPermanently, wantLevel: "DEBUG", wantBytes: 5},
		{name: "399 is debug", status: 399, wantLevel: "DEBUG", wantBytes: 5},
		{name: "400 is warn", status: http.StatusBadRequest, wantLevel: "WARN", wantBytes: 5},
		{name: "401 is warn", status: http.StatusUnauthorized, wantLevel: "WARN", wantBytes: 5},
		{name: "404 is warn", status: http.StatusNotFound, wantLevel: "WARN", wantBytes: 5},
		{name: "499 is warn", status: 499, wantLevel: "WARN", wantBytes: 5},
		{name: "500 is error", status: http.StatusInternalServerError, wantLevel: "ERROR", wantBytes: 5},
		{name: "503 is error", status: http.StatusServiceUnavailable, wantLevel: "ERROR", wantBytes: 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logger, buf := newTestLogger()
			h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status != http.StatusNoContent {
					_, _ = io.WriteString(w, "hello")
				}
			}), RequestID, AccessLog(logger))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/query", nil)
			req.RemoteAddr = "10.1.2.3:54321"
			h.ServeHTTP(httptest.NewRecorder(), req)

			rec := lastLine(t, buf)
			if rec["level"] != tc.wantLevel {
				t.Errorf("level = %v, want %v", rec["level"], tc.wantLevel)
			}
			if rec["method"] != http.MethodPost {
				t.Errorf("method = %v, want POST", rec["method"])
			}
			if rec["path"] != "/api/v1/query" {
				t.Errorf("path = %v, want /api/v1/query", rec["path"])
			}
			if got, want := rec["status"].(float64), float64(tc.status); got != want {
				t.Errorf("status = %v, want %v", got, want)
			}
			if got := rec["bytes"].(float64); got != tc.wantBytes {
				t.Errorf("bytes = %v, want %v", got, tc.wantBytes)
			}
			if _, ok := rec["duration_ms"].(float64); !ok {
				t.Errorf("duration_ms = %v, want a number", rec["duration_ms"])
			}
			if id, _ := rec["request_id"].(string); !generatedID.MatchString(id) {
				t.Errorf("request_id = %q, want a generated id", id)
			}
			if rec["remote_addr"] != "10.1.2.3:54321" {
				t.Errorf("remote_addr = %v, want 10.1.2.3:54321", rec["remote_addr"])
			}
		})
	}
}

// TestAccessLogNeverLeaksSecrets is the assertion that matters most in this
// package: a bearer token, a session cookie and a PromQL expression carrying a
// customer identifier must not reach the log aggregator.
func TestAccessLogNeverLeaksSecrets(t *testing.T) {
	t.Parallel()

	const (
		token       = "pmf_agt_01J8ZZTOPSECRETTOKENVALUE"
		cookieValue = "sessionSECRETCOOKIE"
		customer    = "acme-corp-tenant-42"
		bodySecret  = "BODYSECRETPAYLOAD"
	)
	query := `up{customer="` + customer + `",job="api"}`

	logger, buf := newTestLogger()
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
	}), RequestID, Recover(logger, nil), AccessLog(logger), SecurityHeaders)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/query?query="+query+"&token=QUERYSECRET",
		strings.NewReader(bodySecret))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Cookie", "session="+cookieValue)
	req.Header.Set("X-Api-Key", "HEADERSECRET")
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if out == "" {
		t.Fatal("expected an access log line")
	}
	for _, leak := range []string{token, cookieValue, customer, bodySecret, "Bearer", "QUERYSECRET", "HEADERSECRET", "query=", "up{"} {
		if strings.Contains(out, leak) {
			t.Errorf("access log leaks %q:\n%s", leak, out)
		}
	}

	rec := lastLine(t, buf)
	if rec["path"] != "/api/v1/query" {
		t.Errorf("path = %v, want the bare path with no query string", rec["path"])
	}
}

// TestAccessLogPanicLineHasNoQueryString guards the same property on the
// recovery path, which formats a request as well.
func TestAccessLogPanicLineHasNoQueryString(t *testing.T) {
	t.Parallel()

	logger, buf := newTestLogger()
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), RequestID, Recover(logger, nil))

	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up%7Bcustomer%3D%22acme%22%7D", nil))

	if out := buf.String(); strings.Contains(out, "acme") || strings.Contains(out, "query=") {
		t.Errorf("panic log leaks the query string:\n%s", out)
	}
}

func TestPathOf(t *testing.T) {
	t.Parallel()

	patterned := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/prod?x=1", nil)
	patterned.Pattern = "GET /api/v1/clusters/{id}"

	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "route pattern wins when matched",
			req:  patterned,
			want: "GET /api/v1/clusters/{id}",
		},
		{
			name: "falls back to the escaped path",
			req:  httptest.NewRequest(http.MethodGet, "/a%20b/c?secret=1", nil),
			want: "/a%20b/c",
		},
		{
			name: "tolerates a nil URL",
			req:  &http.Request{Method: http.MethodGet},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := pathOf(tc.req); got != tc.want {
				t.Errorf("pathOf = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tlsState *tls.ConnectionState
		wantHSTS bool
	}{
		{name: "plaintext gets no hsts", tlsState: nil, wantHSTS: false},
		{name: "tls gets hsts", tlsState: &tls.ConnectionState{}, wantHSTS: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.TLS = tc.tlsState

			SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)

			want := map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"Referrer-Policy":         "no-referrer",
				"X-Frame-Options":         "DENY",
				"Cache-Control":           "no-store",
				"Content-Security-Policy": contentSecurityPolicy,
			}
			for k, v := range want {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}

			got := rec.Header().Get("Strict-Transport-Security")
			switch {
			case tc.wantHSTS && got != hstsValue:
				t.Errorf("Strict-Transport-Security = %q, want %q", got, hstsValue)
			case !tc.wantHSTS && got != "":
				t.Errorf("Strict-Transport-Security = %q over plaintext, want it absent", got)
			}
		})
	}
}

func TestMaxBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		limit         int64
		body          string
		declareLength bool
		wantStatus    int
		wantReadErr   bool
	}{
		{name: "under the limit passes", limit: 64, body: "small", declareLength: true, wantStatus: http.StatusOK},
		{name: "declared oversize is refused up front", limit: 4, body: "far too long", declareLength: true, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "undeclared oversize fails on read", limit: 4, body: "far too long", declareLength: false, wantStatus: http.StatusOK, wantReadErr: true},
		{name: "zero limit is a pass-through", limit: 0, body: "anything at all", declareLength: true, wantStatus: http.StatusOK},
		{name: "negative limit is a pass-through", limit: -1, body: "anything at all", declareLength: true, wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var readErr error
			h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, readErr = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}), RequestID, MaxBody(tc.limit))

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			if !tc.declareLength {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusRequestEntityTooLarge {
				var body ErrorBody
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if body.Error.Code != CodeRequestTooLarge {
					t.Errorf("code = %q, want %q", body.Error.Code, CodeRequestTooLarge)
				}
				return
			}
			if tc.wantReadErr && readErr == nil {
				t.Error("handler read the whole oversized body, want an error at the cap")
			}
			if !tc.wantReadErr && readErr != nil {
				t.Errorf("read error = %v, want nil", readErr)
			}
		})
	}
}

// TestFlusherSurvivesTheChain is the SSE regression guard: a handler that
// streams asks for an http.Flusher with a type assertion, and a wrapper that
// does not satisfy it turns a live stream into a buffered one with no error
// anywhere.
func TestFlusherSurvivesTheChain(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()

	var gotFlusher, gotHijacker bool
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		gotFlusher = ok
		_, gotHijacker = w.(http.Hijacker)
		if ok {
			_, _ = io.WriteString(w, "event: ping\n\n")
			f.Flush()
		}
	}),
		RequestID,
		Recover(logger, nil),
		AccessLog(logger),
		SecurityHeaders,
		MaxBody(1<<20),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))

	if !gotFlusher {
		t.Error("handler did not receive an http.Flusher through the chain")
	}
	if !gotHijacker {
		t.Error("handler did not receive an http.Hijacker through the chain")
	}
	if !rec.Flushed {
		t.Error("Flush did not reach the underlying writer")
	}
	if got := rec.Body.String(); got != "event: ping\n\n" {
		t.Errorf("body = %q", got)
	}
}

// TestHijackSurvivesTheChain takes a real connection over the chain, which a
// recorder cannot prove.
func TestHijackSurvivesTheChain(t *testing.T) {
	t.Parallel()

	logger, _ := newTestLogger()
	hijacked := make(chan error, 1)

	srv := httptest.NewServer(Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			hijacked <- errors.New("no http.Hijacker through the chain")
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			hijacked <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
		hijacked <- brw.Flush()
	}), RequestID, Recover(logger, nil), AccessLog(logger)))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := <-hijacked; err != nil {
		t.Fatalf("hijack: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "hi" {
		t.Errorf("body = %q, want %q", body, "hi")
	}
}

// TestResponseWriterBehaviour covers the wrapper's own edge cases.
func TestResponseWriterBehaviour(t *testing.T) {
	t.Parallel()

	t.Run("wrapping is idempotent", func(t *testing.T) {
		t.Parallel()
		rw := wrapResponseWriter(httptest.NewRecorder())
		if again := wrapResponseWriter(rw); again != rw {
			t.Error("wrapResponseWriter nested a second wrapper")
		}
	})

	t.Run("defaults to 200 and counts bytes", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		rw := wrapResponseWriter(rec)
		if rw.Wrote() {
			t.Error("Wrote reported true before anything was written")
		}
		n, err := rw.Write([]byte("hello"))
		if err != nil || n != 5 {
			t.Fatalf("Write = %d, %v", n, err)
		}
		if rw.Status() != http.StatusOK || rw.BytesWritten() != 5 || !rw.Wrote() {
			t.Errorf("status %d bytes %d wrote %t", rw.Status(), rw.BytesWritten(), rw.Wrote())
		}
	})

	t.Run("repeat WriteHeader is ignored", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		rw := wrapResponseWriter(rec)
		rw.WriteHeader(http.StatusTeapot)
		rw.WriteHeader(http.StatusInternalServerError)
		if rw.Status() != http.StatusTeapot {
			t.Errorf("status = %d, want %d", rw.Status(), http.StatusTeapot)
		}
		if rec.Code != http.StatusTeapot {
			t.Errorf("underlying status = %d, want %d", rec.Code, http.StatusTeapot)
		}
	})

	t.Run("Flush implies 200", func(t *testing.T) {
		t.Parallel()
		rw := wrapResponseWriter(httptest.NewRecorder())
		rw.Flush()
		if !rw.Wrote() || rw.Status() != http.StatusOK {
			t.Errorf("after Flush: wrote %t status %d", rw.Wrote(), rw.Status())
		}
	})

	t.Run("Unwrap exposes the underlying writer", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		if got := wrapResponseWriter(rec).Unwrap(); got != http.ResponseWriter(rec) {
			t.Error("Unwrap did not return the wrapped writer")
		}
	})

	t.Run("Hijack reports the unsupported case", func(t *testing.T) {
		t.Parallel()
		conn, brw, err := wrapResponseWriter(httptest.NewRecorder()).Hijack()
		if err == nil {
			t.Fatal("Hijack on a recorder succeeded, want an error")
		}
		if conn != nil || brw != nil {
			t.Errorf("Hijack returned %v, %v alongside an error", conn, brw)
		}
	})

	t.Run("wroteResponse tolerates a bare writer", func(t *testing.T) {
		t.Parallel()
		if wroteResponse(httptest.NewRecorder()) {
			t.Error("wroteResponse on an unwrapped writer = true, want false")
		}
	})
}

// bareWriter is an http.ResponseWriter with no Flusher or Hijacker beneath it,
// used to prove the wrapper degrades quietly instead of panicking.
type bareWriter struct{ header http.Header }

func (b *bareWriter) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}
func (b *bareWriter) Write(p []byte) (int, error) { return len(p), nil }
func (b *bareWriter) WriteHeader(int)             {}

func TestFlushWithoutUnderlyingFlusher(t *testing.T) {
	t.Parallel()

	rw := wrapResponseWriter(&bareWriter{})
	rw.Flush() // must not panic
	if rw.Status() != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Status())
	}
	if _, _, err := rw.Hijack(); err == nil {
		t.Error("Hijack on a non-hijackable writer succeeded, want an error")
	}
}
