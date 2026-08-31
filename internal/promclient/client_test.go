// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient_test

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// newClient builds a client against fake, applying opt to the config first.
func newClient(t *testing.T, baseURL string, opt func(*promclient.Config)) *promclient.Client {
	t.Helper()
	cfg := promclient.Config{BaseURL: baseURL, Timeout: 5 * time.Second}
	if opt != nil {
		opt(&cfg)
	}
	c, err := promclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// drain reads a response body to completion and returns the bytes, the
// trailer and the read error.
func drain(t *testing.T, resp *tunnel.Response) ([]byte, tunnel.Trailer, error) {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	trailer := resp.Trailer()
	if cerr := resp.Body.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	return b, trailer, err
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     promclient.Config
		wantErr string
	}{
		{"empty base url", promclient.Config{}, "BaseURL is required"},
		{"unparseable base url", promclient.Config{BaseURL: "http://[::1"}, "parse BaseURL"},
		{"bad scheme", promclient.Config{BaseURL: "ftp://h:9090"}, "must be http or https"},
		{"no host", promclient.Config{BaseURL: "http:///api"}, "has no host"},
		{"negative bytes", promclient.Config{BaseURL: "http://h", MaxResponseBytes: -1}, "must not be negative"},
		{"negative timeout", promclient.Config{BaseURL: "http://h", Timeout: -time.Second}, "must not be negative"},
		{"missing ca file", promclient.Config{BaseURL: "http://h", TLSCAFile: filepath.Join(dir, "nope.pem")}, "read TLSCAFile"},
		{"empty ca bundle", promclient.Config{BaseURL: "http://h", TLSCAFile: badPEM}, "contains no certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := promclient.New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()
	c := newClient(t, "http://prom:9090/prom#frag", func(cfg *promclient.Config) { cfg.Timeout = 0 })
	if got := c.MaxResponseBytes(); got != promclient.DefaultMaxResponseBytes {
		t.Fatalf("MaxResponseBytes = %d, want %d", got, promclient.DefaultMaxResponseBytes)
	}
	if got, want := c.BaseURL(), "http://prom:9090/prom"; got != want {
		t.Fatalf("BaseURL = %q, want %q (fragment must be dropped)", got, want)
	}
}

// TestDoRefusesPathsOutsideAllowList is the security regression test for
// BUILD_SPEC section 9: the spoke re-validates, so a hub that asks for an
// admin or debug path is refused even though it "asked" politely.
func TestDoRefusesPathsOutsideAllowList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		form   string
	}{
		{"admin delete series", "POST", "/api/v1/admin/tsdb/delete_series", "match[]=up"},
		{"admin clean tombstones", "POST", "/api/v1/admin/tsdb/clean_tombstones", ""},
		{"traversal to admin", "POST", "/api/v1/query/../../admin", "query=up"},
		{"encoded traversal", "GET", "/api/v1/label/%2e%2e%2f%2e%2e/values", ""},
		{"remote write", "POST", "/api/v1/write", ""},
		{"remote read", "POST", "/api/v1/read", ""},
		{"reload", "POST", "/-/reload", ""},
		{"quit", "POST", "/-/quit", ""},
		{"pprof", "GET", "/debug/pprof/heap", ""},
		{"double slash", "GET", "/api/v1//status/flags", ""},
		{"backslash", "GET", "/api/v1\\status/flags", ""},
		{"relative path", "GET", "api/v1/status/flags", ""},
		{"empty path", "GET", "", ""},
		{"wrong method for route", "GET", "/api/v1/query", "query=up"},
		{"unknown path", "GET", "/api/v2/query", ""},
		{"label name not a label", "GET", "/api/v1/label/9bad/values", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
			c := newClient(t, fake.URL, nil)

			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method:           tc.method,
				Path:             tc.path,
				Form:             []byte(tc.form),
				MaxResponseBytes: 1 << 20,
			})
			if !errors.Is(err, promclient.ErrNotAllowed) {
				t.Fatalf("Do() error = %v, want ErrNotAllowed", err)
			}
			if resp != nil {
				t.Fatalf("Do() returned a response for a refused request")
			}
			if got := fake.Requests(); len(got) != 0 {
				t.Fatalf("refused request still reached upstream: %+v", got)
			}
		})
	}
}

func TestDoRefusesInvalidForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		form   string
		gated  bool
	}{
		{name: "unparseable form", method: "POST", path: "/api/v1/query", form: "query=%zz"},
		{name: "unknown parameter", method: "POST", path: "/api/v1/query", form: "query=up&evil=1"},
		{name: "missing required parameter", method: "POST", path: "/api/v1/query", form: ""},
		{name: "range missing step", method: "POST", path: "/api/v1/query_range", form: "query=up&start=1&end=2"},
		{name: "bad enum", method: "GET", path: "/api/v1/targets", form: "state=everything"},
		{name: "control character", method: "POST", path: "/api/v1/query", form: "query=up%00"},
		{name: "gated status config", method: "GET", path: "/api/v1/status/config", form: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
			c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.AllowStatusConfig = tc.gated })

			_, err := c.Do(t.Context(), &tunnel.Request{
				Method: tc.method, Path: tc.path, Form: []byte(tc.form), MaxResponseBytes: 1 << 20,
			})
			if !errors.Is(err, promclient.ErrNotAllowed) {
				t.Fatalf("Do() error = %v, want ErrNotAllowed", err)
			}
			if got := fake.Requests(); len(got) != 0 {
				t.Fatalf("refused request still reached upstream: %+v", got)
			}
		})
	}
}

func TestDoRejectsNilRequest(t *testing.T) {
	t.Parallel()
	c := newClient(t, "http://127.0.0.1:1", nil)
	if _, err := c.Do(t.Context(), nil); !errors.Is(err, promclient.ErrNotAllowed) {
		t.Fatalf("Do(nil) error = %v, want ErrNotAllowed", err)
	}
}

func TestDoSendsFormOnTheRightSideOfTheRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        tunnel.Request
		wantPath   string
		wantForm   url.Values
		wantInBody bool
	}{
		{
			name:       "post route carries the form in the body",
			req:        tunnel.Request{Method: "POST", Path: "/api/v1/query", Form: []byte("query=up%7Bjob%3D%22api%22%7D&time=1787047200")},
			wantPath:   "/api/v1/query",
			wantForm:   url.Values{"query": {`up{job="api"}`}, "time": {"1787047200"}},
			wantInBody: true,
		},
		{
			name:     "get route carries the form in the query string",
			req:      tunnel.Request{Method: "GET", Path: "/api/v1/label/job/values", Form: []byte("limit=10")},
			wantPath: "/api/v1/label/job/values",
			wantForm: url.Values{"limit": {"10"}},
		},
		{
			name:     "get route with no form",
			req:      tunnel.Request{Method: "GET", Path: "/api/v1/status/flags"},
			wantPath: "/api/v1/status/flags",
			wantForm: url.Values{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
			c := newClient(t, fake.URL, nil)

			req := tc.req
			req.MaxResponseBytes = 1 << 20
			resp, err := c.Do(t.Context(), &req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, trailer, readErr := drain(t, resp)
			if readErr != nil {
				t.Fatalf("read body: %v", readErr)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if trailer.BytesTotal != int64(len(body)) {
				t.Fatalf("trailer.BytesTotal = %d, want %d", trailer.BytesTotal, len(body))
			}
			if trailer.Truncated {
				t.Fatal("trailer reports truncation for a small body")
			}

			got := fake.Requests()
			if len(got) != 1 {
				t.Fatalf("recorded %d requests, want 1", len(got))
			}
			if got[0].Path != tc.wantPath {
				t.Fatalf("path = %q, want %q", got[0].Path, tc.wantPath)
			}
			if diff := cmp.Diff(tc.wantForm, got[0].Form); diff != "" {
				t.Fatalf("form mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDoPreservesBaseURLPrefix(t *testing.T) {
	t.Parallel()

	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name    string
		base    string
		method  string
		path    string
		form    string
		wantURL string
	}{
		{"path prefix", srv.URL + "/prom", "POST", "/api/v1/query", "query=up", "/prom/api/v1/query"},
		{"path prefix with trailing slash", srv.URL + "/prom/", "POST", "/api/v1/query", "query=up", "/prom/api/v1/query"},
		{"no prefix", srv.URL, "POST", "/api/v1/query", "query=up", "/api/v1/query"},
		{"query prefix kept on get", srv.URL + "/prom?tenant=acme", "GET", "/api/v1/status/flags", "", "/prom/api/v1/status/flags?tenant=acme"},
		{"query prefix merged with form", srv.URL + "/prom?tenant=acme", "GET", "/api/v1/label/job/values", "limit=5", "/prom/api/v1/label/job/values?tenant=acme&limit=5"},
		{"query prefix kept on post", srv.URL + "?tenant=acme", "POST", "/api/v1/query", "query=up", "/api/v1/query?tenant=acme"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, tc.base, nil)
			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method: tc.method, Path: tc.path, Form: []byte(tc.form), MaxResponseBytes: 1 << 20,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if _, _, _ = drain(t, resp); gotURL != tc.wantURL {
				t.Fatalf("upstream URL = %q, want %q", gotURL, tc.wantURL)
			}
		})
	}
}

func TestDoGzipPassthrough(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c := newClient(t, fake.URL, nil)

	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"),
		MaxResponseBytes: 1 << 20, AcceptGzip: true,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, trailer, readErr := drain(t, resp)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if resp.ContentEncoding != "gzip" {
		t.Fatalf("ContentEncoding = %q, want gzip", resp.ContentEncoding)
	}
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body is not gzip: %q", body[:min(8, len(body))])
	}
	zr, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if !strings.Contains(string(plain), `"resultType":"vector"`) {
		t.Fatalf("inflated body is not the fixture: %s", plain)
	}
	if len(trailer.Warnings) != 0 {
		t.Fatalf("warnings must not be peeked from a compressed body, got %v", trailer.Warnings)
	}
}

func TestDoWithoutGzipIsNotSilentlyInflated(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c := newClient(t, fake.URL, nil)

	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _, _ := drain(t, resp)
	if resp.ContentEncoding != "" {
		t.Fatalf("ContentEncoding = %q, want empty", resp.ContentEncoding)
	}
	if !strings.HasPrefix(string(body), "{") {
		t.Fatalf("body is not plain JSON: %q", body[:min(16, len(body))])
	}
}

func TestDoEnforcesByteCapDuringRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		bodySize      int
		cap           int64
		wantTruncated bool
	}{
		{"under the cap", 2048, 1 << 20, false},
		{"exactly at the cap", 4096, 4096, false},
		{"over the cap", 200_000, 4096, true},
		{"tiny cap", 200_000, 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: tc.bodySize})
			c := newClient(t, fake.URL, nil)

			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"),
				MaxResponseBytes: tc.cap,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, trailer, readErr := drain(t, resp)

			if !tc.wantTruncated {
				if readErr != nil {
					t.Fatalf("read: %v", readErr)
				}
				if trailer.Truncated {
					t.Fatal("trailer reports truncation below the cap")
				}
				if int64(len(body)) != int64(tc.bodySize) {
					t.Fatalf("delivered %d bytes, want the full %d byte body", len(body), tc.bodySize)
				}
				if trailer.BytesTotal != int64(tc.bodySize) {
					t.Fatalf("trailer.BytesTotal = %d, want %d", trailer.BytesTotal, tc.bodySize)
				}
				return
			}
			if !errors.Is(readErr, promclient.ErrTooLarge) {
				t.Fatalf("read error = %v, want ErrTooLarge", readErr)
			}
			if !errors.Is(readErr, tunnel.ErrResponseTooLarge) {
				t.Fatalf("read error = %v, want it to wrap tunnel.ErrResponseTooLarge", readErr)
			}
			if !trailer.Truncated {
				t.Fatal("trailer.Truncated = false, want true")
			}
			if !errors.Is(trailer.Err, promclient.ErrTooLarge) {
				t.Fatalf("trailer.Err = %v, want ErrTooLarge", trailer.Err)
			}
			if int64(len(body)) > tc.cap {
				t.Fatalf("delivered %d bytes, cap is %d", len(body), tc.cap)
			}
			if trailer.BytesTotal != int64(len(body)) {
				t.Fatalf("trailer.BytesTotal = %d, delivered %d", trailer.BytesTotal, len(body))
			}
		})
	}
}

// TestDoDoesNotTrustContentLength proves the cap is enforced from the bytes
// actually delivered rather than from the Content-Length header.
//
// Two properties matter, and they pull in opposite directions. A response that
// declares no length at all — chunked, or streamed forever — must still be
// capped, which a Content-Length-based check would miss entirely. And a
// response that declares a length over the cap must not be rejected from its
// header: the prefix that fits is genuinely useful to an agent, so the transfer
// is streamed and aborted exactly at the cap.
func TestDoDoesNotTrustContentLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		cap     int64
	}{
		{
			name: "no content length at all",
			cap:  1024,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// Flushing before the body is complete forces chunked
				// encoding, so no Content-Length reaches the client.
				w.WriteHeader(http.StatusOK)
				http.NewResponseController(w).Flush() //nolint:errcheck // best effort
				for range 50 {
					_, _ = io.WriteString(w, strings.Repeat("A", 1000))
					http.NewResponseController(w).Flush() //nolint:errcheck // best effort
				}
			},
		},
		{
			name: "content length far over the cap",
			cap:  4096,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				body := strings.Repeat("A", 200_000)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				_, _ = io.WriteString(w, body)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)

			c := newClient(t, srv.URL, nil)
			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: tc.cap,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, trailer, readErr := drain(t, resp)
			if !errors.Is(readErr, promclient.ErrTooLarge) {
				t.Fatalf("read error = %v, want ErrTooLarge", readErr)
			}
			if int64(len(body)) != tc.cap {
				t.Fatalf("delivered %d bytes, want exactly the cap of %d", len(body), tc.cap)
			}
			if !trailer.Truncated {
				t.Fatal("trailer.Truncated = false")
			}
			if trailer.BytesTotal != tc.cap {
				t.Fatalf("trailer.BytesTotal = %d, want %d", trailer.BytesTotal, tc.cap)
			}
		})
	}
}

func TestDoClientCapWinsOverRequestCap(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: 100_000})
	c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.MaxResponseBytes = 2048 })

	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"),
		MaxResponseBytes: 1 << 30, // the hub asked for more than the spoke permits
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _, readErr := drain(t, resp)
	if !errors.Is(readErr, promclient.ErrTooLarge) {
		t.Fatalf("read error = %v, want ErrTooLarge", readErr)
	}
	if len(body) > 2048 {
		t.Fatalf("delivered %d bytes, spoke cap is 2048", len(body))
	}
}

// TestDoZeroRequestCapUsesClientDefault proves a zero MaxResponseBytes on the
// request is treated as "no request-side preference", not as a zero-byte
// budget: the clamp in Do only tightens the client's own cap when the hub
// asked for something smaller than it, and zero must not be read as smaller.
func TestDoZeroRequestCapUsesClientDefault(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: 2048})
	c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.MaxResponseBytes = 4096 })

	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"),
		MaxResponseBytes: 0,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, trailer, readErr := drain(t, resp)
	if readErr != nil {
		t.Fatalf("read: %v, want the client's 4096 byte default to cover a 2048 byte body", readErr)
	}
	if trailer.Truncated {
		t.Fatal("trailer.Truncated = true; a zero request cap must not collapse the effective limit to zero")
	}
	if len(body) != 2048 {
		t.Fatalf("delivered %d bytes, want the full 2048 byte body", len(body))
	}
}

func TestDoReportsWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     testutil.FakeOptions
		wantWarn []string
	}{
		{
			name:     "small json body is peeked",
			opts:     testutil.FakeOptions{Warnings: []string{"some series have been dropped", "evaluation is partial"}},
			wantWarn: []string{"some series have been dropped", "evaluation is partial"},
		},
		{
			name: "no warnings",
			opts: testutil.FakeOptions{},
		},
		{
			name: "large body is not peeked",
			opts: testutil.FakeOptions{Warnings: []string{"dropped"}, BodySize: 200_000},
		},
		{
			// 128 KiB is exactly promclient's unexported warningsPeekLimit. A
			// body sitting exactly on it must still be peeked; only a body
			// larger than the limit is skipped.
			name:     "a body exactly at the peek limit is still peeked",
			opts:     testutil.FakeOptions{Warnings: []string{"dropped"}, BodySize: 128 << 10},
			wantWarn: []string{"dropped"},
		},
		{
			name: "a body one byte over the peek limit is not peeked",
			opts: testutil.FakeOptions{Warnings: []string{"dropped"}, BodySize: 128<<10 + 1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, tc.opts)
			c := newClient(t, fake.URL, nil)
			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_, trailer, readErr := drain(t, resp)
			if readErr != nil {
				t.Fatalf("read: %v", readErr)
			}
			if diff := cmp.Diff(tc.wantWarn, trailer.Warnings); diff != "" {
				t.Fatalf("warnings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDoPassesUpstreamErrorsThrough proves a non-2xx is data, not an error:
// Prometheus' own 400 body is the most useful thing an agent can be handed.
func TestDoPassesUpstreamErrorsThrough(t *testing.T) {
	t.Parallel()

	for _, code := range []int{400, 422, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
				FailEndpoints: map[string]int{"query": code},
			})
			c := newClient(t, fake.URL, nil)
			resp, err := c.Do(t.Context(), &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
			})
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, _, readErr := drain(t, resp)
			if readErr != nil {
				t.Fatalf("read: %v", readErr)
			}
			if resp.StatusCode != code {
				t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, code)
			}
			if !strings.Contains(string(body), `"status":"error"`) {
				t.Fatalf("upstream error body was not passed through: %s", body)
			}
		})
	}
}

func TestDoUpstreamUnreachable(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	base := fake.URL
	fake.Close()

	c := newClient(t, base, nil)
	_, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, promclient.ErrUpstream) {
		t.Fatalf("Do() error = %v, want ErrUpstream", err)
	}
}

// TestDoReservesHopMargin proves the spoke refuses to start a call it cannot
// finish inside the hub's deadline, so the hub sees a structured error rather
// than a truncated stream.
func TestDoReservesHopMargin(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c := newClient(t, fake.URL, nil)

	ctx, cancel := context.WithTimeout(t.Context(), promclient.HopMargin/2)
	defer cancel()

	_, err := c.Do(ctx, &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, promclient.ErrUpstream) {
		t.Fatalf("Do() error = %v, want ErrUpstream", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Do() error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if got := fake.Requests(); len(got) != 0 {
		t.Fatalf("call was made despite an exhausted budget: %+v", got)
	}
}

func TestDoCancellationAbortsBody(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: 500_000, SlowBody: 20 * time.Millisecond})
	c := newClient(t, fake.URL, nil)

	ctx, cancel := context.WithCancel(t.Context())
	resp, err := c.Do(ctx, &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	cancel()
	_, readErr := io.ReadAll(resp.Body)
	if readErr == nil {
		t.Fatal("read after cancel succeeded, want an error")
	}
	trailer := resp.Trailer()
	if trailer.Err == nil {
		t.Fatal("trailer.Err = nil after a cancelled read")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent.
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDoSendsBearerTokenReReadEveryRequest(t *testing.T) {
	t.Parallel()

	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	t.Cleanup(srv.Close)

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv.URL, func(cfg *promclient.Config) { cfg.BearerTokenFile = tokenFile })

	call := func() {
		t.Helper()
		resp, err := c.Do(t.Context(), &tunnel.Request{
			Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
		})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		drain(t, resp)
	}
	call()
	// Kubernetes rotates the projected token in place; the next request must
	// pick the new value up without a restart.
	if err := os.WriteFile(tokenFile, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	call()

	want := []string{"Bearer first-token", "Bearer second-token"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Authorization headers (-want +got):\n%s", diff)
	}
}

func TestDoBearerTokenFileProblems(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct{ name, file, want string }{
		{"missing", filepath.Join(dir, "absent"), "read bearer token file"},
		{"empty", empty, "is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
			c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.BearerTokenFile = tc.file })
			_, err := c.Do(t.Context(), &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
			})
			if !errors.Is(err, promclient.ErrUpstream) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Do() error = %v, want ErrUpstream containing %q", err, tc.want)
			}
		})
	}
}

func TestDoSetsRequestHeaders(t *testing.T) {
	t.Parallel()

	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	t.Cleanup(srv.Close)

	c := newClient(t, srv.URL, func(cfg *promclient.Config) { cfg.UserAgent = "spoke/1.2.3" })
	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"),
		MaxResponseBytes: 1 << 20, RequestID: "req-42",
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	drain(t, resp)

	for k, want := range map[string]string{
		"User-Agent":   "spoke/1.2.3",
		"Accept":       "application/json",
		"Content-Type": "application/x-www-form-urlencoded",
		"X-Request-Id": "req-42",
	} {
		if got := hdr.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	if got := hdr.Get("Accept-Encoding"); got != "" {
		t.Errorf("Accept-Encoding = %q, want empty when AcceptGzip is false", got)
	}
	if got := hdr.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty when no token file is configured", got)
	}
}

func TestDoDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	c := newClient(t, srv.URL, nil)
	resp, err := c.Do(t.Context(), &tunnel.Request{
		Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	drain(t, resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("StatusCode = %d, want 302 returned rather than followed", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("upstream hit %d times, want 1 (redirect must not be followed)", hits)
	}
}

func TestPing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    testutil.FakeOptions
		wantErr bool
	}{
		{name: "healthy", opts: testutil.FakeOptions{}},
		{
			name: "falls back to buildinfo",
			opts: testutil.FakeOptions{FailEndpoints: map[string]int{"/-/healthy": http.StatusNotFound}},
		},
		{
			name: "both probes fail",
			opts: testutil.FakeOptions{FailEndpoints: map[string]int{
				"/-/healthy": http.StatusNotFound,
				"build_info": http.StatusServiceUnavailable,
			}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, tc.opts)
			c := newClient(t, fake.URL, nil)
			err := c.Ping(t.Context())
			if tc.wantErr {
				if !errors.Is(err, promclient.ErrUpstream) {
					t.Fatalf("Ping() error = %v, want ErrUpstream", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ping: %v", err)
			}
		})
	}
}

func TestPingUnreachableAndDeadlineExhausted(t *testing.T) {
	t.Parallel()

	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	base := fake.URL
	fake.Close()
	c := newClient(t, base, nil)
	if err := c.Ping(t.Context()); !errors.Is(err, promclient.ErrUpstream) {
		t.Fatalf("Ping() error = %v, want ErrUpstream", err)
	}

	live := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
	c2 := newClient(t, live.URL, nil)
	ctx, cancel := context.WithTimeout(t.Context(), promclient.HopMargin/2)
	defer cancel()
	if err := c2.Ping(ctx); !errors.Is(err, promclient.ErrUpstream) {
		t.Fatalf("Ping() error = %v, want ErrUpstream", err)
	}
}

func TestInstantQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		expr    string
		results map[string]string
		want    promclient.Vector
		wantErr string
	}{
		{
			name: "vector",
			expr: "up",
			want: promclient.Vector{
				{Labels: map[string]string{"__name__": "up", "instance": "10.42.0.11:9100", "job": "node-exporter", "namespace": "monitoring"}, Value: 1},
				{Labels: map[string]string{"__name__": "up", "instance": "10.42.0.12:9100", "job": "node-exporter", "namespace": "monitoring"}, Value: 0},
			},
		},
		{
			name:    "scalar",
			expr:    "scalar_expr",
			results: map[string]string{"scalar_expr": `{"status":"success","data":{"resultType":"scalar","result":[1787047200.412,"42"]}}`},
			want:    promclient.Vector{{Labels: map[string]string{}, Value: 42}},
		},
		{
			name:    "matrix is refused",
			expr:    "matrix_expr",
			results: map[string]string{"matrix_expr": `{"status":"success","data":{"resultType":"matrix","result":[]}}`},
			wantErr: "not an instant vector",
		},
		{
			name:    "error envelope",
			expr:    "bad_expr",
			results: map[string]string{"bad_expr": `{"status":"error","errorType":"bad_data","error":"invalid parameter"}`},
			wantErr: "bad_data",
		},
		{
			name:    "non string sample value",
			expr:    "numeric_value",
			results: map[string]string{"numeric_value": `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,1]}]}}`},
			wantErr: "not a string",
		},
		{
			name:    "unparseable sample value",
			expr:    "junk_value",
			results: map[string]string{"junk_value": `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"abc"]}]}}`},
			wantErr: "sample value",
		},
		{
			name:    "malformed vector result",
			expr:    "junk_result",
			results: map[string]string{"junk_result": `{"status":"success","data":{"resultType":"vector","result":{}}}`},
			wantErr: "decode vector",
		},
		{
			name:    "malformed scalar result",
			expr:    "junk_scalar",
			results: map[string]string{"junk_scalar": `{"status":"success","data":{"resultType":"scalar","result":{}}}`},
			wantErr: "decode scalar",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{QueryResults: tc.results})
			c := newClient(t, fake.URL, nil)

			got, err := c.InstantQuery(t.Context(), tc.expr)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("InstantQuery() error = %v, want containing %q", err, tc.wantErr)
				}
				if !errors.Is(err, promclient.ErrUpstream) {
					t.Fatalf("InstantQuery() error = %v, want ErrUpstream", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("InstantQuery: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("vector mismatch (-want +got):\n%s", diff)
			}
			// The query must have been POSTed, as the route declares.
			reqs := fake.Requests()
			if len(reqs) != 1 || reqs[0].Method != http.MethodPost {
				t.Fatalf("recorded %+v, want a single POST", reqs)
			}
		})
	}
}

func TestInstantQueryNaN(t *testing.T) {
	t.Parallel()
	fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{QueryResults: map[string]string{
		"nan_expr": `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"NaN"]}]}}`,
	}})
	c := newClient(t, fake.URL, nil)
	got, err := c.InstantQuery(t.Context(), "nan_expr")
	if err != nil {
		t.Fatalf("InstantQuery: %v", err)
	}
	if len(got) != 1 || !isNaN(got[0].Value) {
		t.Fatalf("got %+v, want a single NaN sample", got)
	}
}

// isNaN avoids importing math for one comparison.
func isNaN(f float64) bool { return f != f }

func TestLabelValues(t *testing.T) {
	t.Parallel()

	t.Run("known label", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c := newClient(t, fake.URL, nil)
		got, err := c.LabelValues(t.Context(), "job")
		if err != nil {
			t.Fatalf("LabelValues: %v", err)
		}
		want := []string{"apiserver", "cadvisor", "coredns", "kube-state-metrics", "kubelet", "node-exporter", "prometheus"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("values mismatch (-want +got):\n%s", diff)
		}
		if reqs := fake.Requests(); len(reqs) != 1 || reqs[0].Path != "/api/v1/label/job/values" {
			t.Fatalf("recorded %+v", reqs)
		}
	})

	t.Run("invalid label name is refused before any I/O", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c := newClient(t, fake.URL, nil)
		for _, bad := range []string{"", "9nope", "a/b", "../../admin", "a b"} {
			if _, err := c.LabelValues(t.Context(), bad); !errors.Is(err, promclient.ErrNotAllowed) {
				t.Fatalf("LabelValues(%q) error = %v, want ErrNotAllowed", bad, err)
			}
		}
		if got := fake.Requests(); len(got) != 0 {
			t.Fatalf("refused label name still reached upstream: %+v", got)
		}
	})

	t.Run("error envelope inside a 200", func(t *testing.T) {
		t.Parallel()
		// A 200 carrying an error envelope is what a Prometheus behind a
		// gateway routinely produces. Trusting the status code alone would hand
		// an agent an empty label list and call it success.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"error","errorType":"bad_data","error":"label name is required"}`)
		}))
		t.Cleanup(srv.Close)

		c := newClient(t, srv.URL, nil)
		got, err := c.LabelValues(t.Context(), "job")
		if !errors.Is(err, promclient.ErrUpstream) {
			t.Fatalf("LabelValues() error = %v, want ErrUpstream", err)
		}
		if !strings.Contains(err.Error(), "bad_data") {
			t.Fatalf("LabelValues() error = %v, want the upstream errorType", err)
		}
		if got != nil {
			t.Fatalf("LabelValues returned %v alongside an error", got)
		}
	})
}

// TestFetchClipsUpstreamErrorBodies proves an upstream error body cannot
// dominate an error string or smuggle control characters into a log line. The
// body is attacker-influenceable: a scrape target's error text reaches it.
func TestFetchClipsUpstreamErrorBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantClip   bool
		wantAbsent string
	}{
		{
			name:     "long body is clipped",
			body:     strings.Repeat("A", 4000),
			wantClip: true,
		},
		{
			name:       "control characters are neutralised",
			body:       "line one\n\u001b[31mred\u0000",
			wantAbsent: "\u001b",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := tc.body
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, body)
			}))
			t.Cleanup(srv.Close)

			c := newClient(t, srv.URL, nil)
			err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil)
			if !errors.Is(err, promclient.ErrUpstream) {
				t.Fatalf("GetJSON() error = %v, want ErrUpstream", err)
			}
			msg := err.Error()
			if tc.wantClip && !strings.Contains(msg, "...[clipped]") {
				t.Fatalf("a %d byte body was not clipped: %d chars of error", len(body), len(msg))
			}
			if len(msg) > 1024 {
				t.Fatalf("error message is %d chars, want it bounded", len(msg))
			}
			for _, r := range msg {
				if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
					t.Fatalf("error message carries control character %q: %q", r, msg)
				}
			}
		})
	}
}

// TestUpstreamBudgetIsTheSmallerOfTimeoutAndDeadline proves the call is bounded
// by whichever of Config.Timeout and the caller's deadline is tighter. The hub
// propagates its deadline down the tunnel, and a spoke that ignored it in
// favour of its own generous timeout would leave the hub waiting on a request
// it had already given up on.
func TestUpstreamBudgetIsTheSmallerOfTimeoutAndDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		clientTimeo time.Duration
		ctxTimeo    time.Duration // zero means no caller deadline
	}{
		{name: "caller deadline is tighter", clientTimeo: time.Hour, ctxTimeo: 300 * time.Millisecond},
		{name: "client timeout is tighter", clientTimeo: 300 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// A server that never answers within the budget.
			fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{Latency: 3 * time.Second})
			c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.Timeout = tc.clientTimeo })

			ctx := t.Context()
			if tc.ctxTimeo > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.ctxTimeo)
				defer cancel()
			}

			start := time.Now()
			_, err := c.Do(ctx, &tunnel.Request{
				Method: "POST", Path: "/api/v1/query", Form: []byte("query=up"), MaxResponseBytes: 1 << 20,
			})
			elapsed := time.Since(start)

			if !errors.Is(err, promclient.ErrUpstream) {
				t.Fatalf("Do() error = %v, want ErrUpstream", err)
			}
			if elapsed > 10*time.Second {
				t.Fatalf("call took %s, want it bounded by the ~300ms budget", elapsed)
			}
		})
	}
}

func TestGetJSON(t *testing.T) {
	t.Parallel()

	t.Run("decodes flags", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c := newClient(t, fake.URL, nil)
		var env struct {
			Status string            `json:"status"`
			Data   map[string]string `json:"data"`
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, &env); err != nil {
			t.Fatalf("GetJSON: %v", err)
		}
		if env.Status != "success" || env.Data["storage.tsdb.retention.time"] != "15d" {
			t.Fatalf("decoded %+v", env)
		}
	})

	t.Run("returns the server header", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{ServerHeader: "Thanos/0.39.2"})
		c := newClient(t, fake.URL, nil)
		hdr, err := c.GetJSONHeaders(t.Context(), promapi.EndpointBuildInfo, nil, nil)
		if err != nil {
			t.Fatalf("GetJSONHeaders: %v", err)
		}
		if got := hdr.Get("Server"); got != "Thanos/0.39.2" {
			t.Fatalf("Server = %q", got)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c := newClient(t, fake.URL, nil)

		if err := c.GetJSON(t.Context(), promapi.Endpoint("nope"), nil, nil); !errors.Is(err, promclient.ErrNotAllowed) {
			t.Fatalf("unknown endpoint error = %v, want ErrNotAllowed", err)
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointLabelValues, nil, nil); !errors.Is(err, promclient.ErrNotAllowed) {
			t.Fatalf("path-param endpoint error = %v, want ErrNotAllowed", err)
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointConfig, nil, nil); !errors.Is(err, promapi.ErrEndpointGated) {
			t.Fatalf("gated endpoint error = %v, want promapi.ErrEndpointGated", err)
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointTargets, url.Values{"state": {"bogus"}}, nil); !errors.Is(err, promclient.ErrNotAllowed) {
			t.Fatalf("invalid param error = %v, want ErrNotAllowed", err)
		}
	})

	t.Run("gated endpoint when enabled", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{})
		c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.AllowStatusConfig = true })
		var env struct {
			Data struct {
				YAML string `json:"yaml"`
			} `json:"data"`
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointConfig, nil, &env); err != nil {
			t.Fatalf("GetJSON: %v", err)
		}
		if !strings.Contains(env.Data.YAML, "external_labels") {
			t.Fatalf("config yaml = %q", env.Data.YAML)
		}
	})

	t.Run("upstream failures", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{
			FailEndpoints: map[string]int{"flags": http.StatusInternalServerError},
		})
		c := newClient(t, fake.URL, nil)
		err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil)
		if !errors.Is(err, promclient.ErrUpstream) || !strings.Contains(err.Error(), "status 500") {
			t.Fatalf("GetJSON() error = %v, want ErrUpstream with the status", err)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "this is not json")
		}))
		t.Cleanup(srv.Close)
		c := newClient(t, srv.URL, nil)
		var out map[string]any
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, &out); !errors.Is(err, promclient.ErrUpstream) {
			t.Fatalf("GetJSON() error = %v, want ErrUpstream", err)
		}
	})

	t.Run("oversize body", func(t *testing.T) {
		t.Parallel()
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: 100_000})
		c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.MaxResponseBytes = 4096 })
		err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil)
		if !errors.Is(err, promclient.ErrTooLarge) {
			t.Fatalf("GetJSON() error = %v, want ErrTooLarge", err)
		}
	})

	// "exactly at the cap" pins the boundary of fetch's byte-cap check from
	// the accepting side: a body padded to precisely MaxResponseBytes must
	// decode cleanly, not be refused as too large. The "oversize body" case
	// above already proves one-over-cap is refused; together they bound the
	// comparison on both sides.
	t.Run("exactly at the cap", func(t *testing.T) {
		t.Parallel()
		const cap = 2048
		fake := testutil.NewFakePrometheus(t, testutil.FakeOptions{BodySize: cap})
		c := newClient(t, fake.URL, func(cfg *promclient.Config) { cfg.MaxResponseBytes = cap })
		var env struct {
			Status string `json:"status"`
		}
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, &env); err != nil {
			t.Fatalf("GetJSON() error = %v, want a body padded to exactly the cap to decode cleanly", err)
		}
		if env.Status != "success" {
			t.Fatalf("decoded status = %q, want success", env.Status)
		}
	})
}

func TestTLSConfiguration(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{}}`)
	}))
	t.Cleanup(srv.Close)

	t.Run("verification failure is an upstream error", func(t *testing.T) {
		t.Parallel()
		c := newClient(t, srv.URL, nil)
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil); !errors.Is(err, promclient.ErrUpstream) {
			t.Fatalf("GetJSON() error = %v, want ErrUpstream", err)
		}
	})

	t.Run("skip verify", func(t *testing.T) {
		t.Parallel()
		c := newClient(t, srv.URL, func(cfg *promclient.Config) { cfg.TLSInsecure = true })
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil); err != nil {
			t.Fatalf("GetJSON: %v", err)
		}
	})

	t.Run("ca file", func(t *testing.T) {
		t.Parallel()
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(caFile, pemEncodeCert(t, srv), 0o600); err != nil {
			t.Fatal(err)
		}
		c := newClient(t, srv.URL, func(cfg *promclient.Config) { cfg.TLSCAFile = caFile })
		if err := c.GetJSON(t.Context(), promapi.EndpointFlags, nil, nil); err != nil {
			t.Fatalf("GetJSON: %v", err)
		}
	})
}
