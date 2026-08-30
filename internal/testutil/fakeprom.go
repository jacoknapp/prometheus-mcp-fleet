// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtures holds the recorded Prometheus API responses. They are real
// envelopes (status/data/resultType) rather than minimal stubs, because the
// shape of the envelope is exactly what the code under test has to cope with.
//
//go:embed testdata/*.json
var fixtures embed.FS

// FakeOptions configures the faults and shapes a [FakePrometheus] exhibits.
// The zero value is a healthy, fast server.
type FakeOptions struct {
	// Latency is slept before the response headers are written.
	Latency time.Duration
	// FailEndpoints forces an HTTP status for selected endpoints instead of
	// serving the fixture. A key is either a full request path
	// ("/api/v1/query") or the short endpoint id used by internal/promapi
	// ("query", "build_info", "tsdb_status", ...).
	FailEndpoints map[string]int
	// BodySize pads every fixture response to at least this many bytes. The
	// padding is added as an extra JSON member, so the body stays parseable.
	BodySize int
	// SlowBody is slept between body chunks, which lets a test starve a reader
	// without closing the connection.
	SlowBody time.Duration
	// Warnings is injected as the envelope's "warnings" member.
	Warnings []string
	// DisableTSDBStatus makes /api/v1/status/tsdb answer 404, emulating the
	// Prometheus-compatible servers that do not implement it.
	DisableTSDBStatus bool

	// ServerHeader sets the Server response header. It defaults to
	// "Prometheus/3.6.0"; set it to "Thanos/0.39.2" or similar to exercise
	// flavor detection. (Extension beyond the base fault set.)
	ServerHeader string
	// QueryResults overrides the response body for an exact PromQL
	// expression, keyed by the "query" form value. The value is the raw JSON
	// body to return. (Extension beyond the base fault set.)
	QueryResults map[string]string
	// LabelValues overrides /api/v1/label/<name>/values for one label. It
	// exists so a test can describe a cluster far larger than a fixture file
	// should be — forty thousand jobs, say — without shipping the bytes.
	// (Extension beyond the base fault set.)
	LabelValues map[string][]string
}

// RecordedRequest is one request the fake observed.
type RecordedRequest struct {
	// Method is the HTTP method as received.
	Method string
	// Path is the request path as received.
	Path string
	// Form is the merged query string and, for form-encoded POSTs, body
	// parameters.
	Form url.Values
}

// FakePrometheus is an httptest.Server that answers the Prometheus HTTP API
// from fixtures, with injectable latency, failure, oversize and slow-body
// faults.
type FakePrometheus struct {
	// URL is the server's base URL, suitable for a promclient Config.BaseURL.
	URL string

	opts FakeOptions
	srv  *httptest.Server

	mu       sync.Mutex
	requests []RecordedRequest
}

// fixtureByPath maps a fixed API path to its fixture file and to the short
// endpoint id that FakeOptions.FailEndpoints also accepts.
var fixtureByPath = map[string]struct{ file, endpoint string }{
	"/api/v1/query":              {"query.json", "query"},
	"/api/v1/query_range":        {"query_range.json", "query_range"},
	"/api/v1/series":             {"series.json", "series"},
	"/api/v1/labels":             {"labels.json", "labels"},
	"/api/v1/metadata":           {"metadata.json", "metadata"},
	"/api/v1/targets":            {"targets.json", "targets"},
	"/api/v1/rules":              {"rules.json", "rules"},
	"/api/v1/alerts":             {"alerts.json", "alerts"},
	"/api/v1/alertmanagers":      {"alertmanagers.json", "alertmanagers"},
	"/api/v1/status/tsdb":        {"status_tsdb.json", "tsdb_status"},
	"/api/v1/status/runtimeinfo": {"status_runtimeinfo.json", "runtime_info"},
	"/api/v1/status/buildinfo":   {"status_buildinfo.json", "build_info"},
	"/api/v1/status/flags":       {"status_flags.json", "flags"},
	"/api/v1/status/config":      {"status_config.json", "config"},
}

// NewFakePrometheus starts a fake Prometheus and registers its shutdown with
// t.Cleanup.
func NewFakePrometheus(t *testing.T, opts FakeOptions) *FakePrometheus {
	t.Helper()
	if opts.ServerHeader == "" {
		opts.ServerHeader = "Prometheus/3.6.0"
	}
	f := &FakePrometheus{opts: opts}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	f.URL = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

// Close stops the server. It is safe to call more than once and is called
// automatically at the end of the test that created the fake.
func (f *FakePrometheus) Close() { f.srv.Close() }

// Requests returns a copy of every request the fake has served, in order.
func (f *FakePrometheus) Requests() []RecordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]RecordedRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

// Reset discards the recorded request log.
func (f *FakePrometheus) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

// serve is the whole fake. It records the request, resolves a fixture, applies
// the configured faults and writes the body.
func (f *FakePrometheus) serve(w http.ResponseWriter, r *http.Request) {
	rec := RecordedRequest{Method: r.Method, Path: r.URL.Path, Form: url.Values{}}
	_ = r.ParseForm()
	for k, v := range r.Form {
		rec.Form[k] = append([]string(nil), v...)
	}
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()

	if f.opts.Latency > 0 {
		time.Sleep(f.opts.Latency)
	}
	w.Header().Set("Server", f.opts.ServerHeader)

	body, endpoint, status := f.resolve(r, rec.Form)
	if code, ok := f.opts.FailEndpoints[r.URL.Path]; ok && code != 0 {
		status, body = code, errorBody(code)
	} else if code, ok := f.opts.FailEndpoints[endpoint]; ok && endpoint != "" && code != 0 {
		status, body = code, errorBody(code)
	}

	if isJSON(body) {
		body = f.decorate(body)
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		body = buf.Bytes()
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	f.writeBody(w, body)
}

// resolve picks the response body for a request, returning the short endpoint
// id so FailEndpoints can be keyed either way.
func (f *FakePrometheus) resolve(r *http.Request, form url.Values) (body []byte, endpoint string, status int) {
	p := path.Clean(r.URL.Path)
	switch {
	case p == "/-/healthy":
		return []byte("Prometheus Server is Healthy.\n"), "healthy", http.StatusOK
	case p == "/-/ready":
		return []byte("Prometheus Server is Ready.\n"), "ready", http.StatusOK
	case p == "/api/v1/status/tsdb" && f.opts.DisableTSDBStatus:
		return []byte("404 page not found\n"), "tsdb_status", http.StatusNotFound
	case p == "/api/v1/query" || p == "/api/v1/query_range":
		return f.queryFixture(p, form), fixtureByPath[p].endpoint, http.StatusOK
	case strings.HasPrefix(p, "/api/v1/label/") && strings.HasSuffix(p, "/values"):
		label := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/label/"), "/values")
		if vals, ok := f.opts.LabelValues[label]; ok {
			body, _ := json.Marshal(map[string]any{"status": "success", "data": vals})
			return body, "label_values", http.StatusOK
		}
		return labelValuesFixture(label), "label_values", http.StatusOK
	}
	if fx, ok := fixtureByPath[p]; ok {
		return mustFixture(fx.file), fx.endpoint, http.StatusOK
	}
	return []byte("404 page not found\n"), "", http.StatusNotFound
}

// queryFixture returns the body for an instant or range query. Instant queries
// are matched against QueryResults first and then against a small set of
// expressions the facts collector is known to issue, so a test can assert on
// distinct results without wiring a handler.
func (f *FakePrometheus) queryFixture(p string, form url.Values) []byte {
	if p == "/api/v1/query_range" {
		return mustFixture("query_range.json")
	}
	expr := form.Get("query")
	if b, ok := f.opts.QueryResults[expr]; ok {
		return []byte(b)
	}
	switch {
	case strings.Contains(expr, "kubernetes_build_info"):
		return mustFixture("query_kubernetes_build_info.json")
	case strings.Contains(expr, "kube_node_info"):
		return mustFixture("query_kube_node_count.json")
	case strings.Contains(expr, "prometheus_build_info"):
		return mustFixture("query_prometheus_build_info.json")
	case strings.Contains(expr, "prometheus_target_interval_length_seconds"):
		return mustFixture("query_target_interval.json")
	}
	return mustFixture("query.json")
}

// labelValuesFixture returns the per-label fixture when one exists, so that
// label_values(job) and label_values(__name__) differ as they would upstream.
func labelValuesFixture(label string) []byte {
	name := "label_values_" + label + ".json"
	if _, err := fixtures.ReadFile("testdata/" + name); err == nil {
		return mustFixture(name)
	}
	return mustFixture("label_values.json")
}

// mustFixture reads an embedded fixture and compacts it. A missing fixture is
// a programming error in the fake itself, never a test outcome.
//
// The files on disk are indented so they stay reviewable, but Prometheus emits
// compact JSON, and a test that asserts on the bytes on the wire must see what
// the real server would send.
func mustFixture(name string) []byte {
	b, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		panic("testutil: missing fixture " + name + ": " + err.Error())
	}
	var buf bytes.Buffer
	_ = json.Compact(&buf, b) // Embedded fixtures are validated by the package tests.
	return buf.Bytes()
}

// errorBody renders the JSON error envelope Prometheus returns for a status.
func errorBody(code int) []byte {
	kind := "internal"
	switch code {
	case http.StatusBadRequest:
		kind = "bad_data"
	case http.StatusUnprocessableEntity:
		kind = "execution"
	case http.StatusServiceUnavailable:
		kind = "unavailable"
	case http.StatusNotFound:
		kind = "not_found"
	}
	b, _ := json.Marshal(map[string]string{
		"status":    "error",
		"errorType": kind,
		"error":     fmt.Sprintf("injected fault: HTTP %d", code),
	})
	return b
}

// isJSON reports whether body looks like a JSON object.
func isJSON(body []byte) bool {
	return len(body) > 0 && body[0] == '{'
}

// decorate injects the configured warnings and padding into a JSON envelope.
func (f *FakePrometheus) decorate(body []byte) []byte {
	if len(f.opts.Warnings) > 0 {
		w, _ := json.Marshal(f.opts.Warnings)
		body = injectMember(body, `"warnings":`+string(w))
	}
	if pad := f.opts.BodySize - len(body); pad > 0 {
		const overhead = len(`,"_padding":""`)
		if pad > overhead {
			body = injectMember(body, `"_padding":"`+strings.Repeat("p", pad-overhead)+`"`)
		}
	}
	return body
}

// injectMember appends a member to a top-level JSON object.
func injectMember(body []byte, member string) []byte {
	i := bytes.LastIndexByte(body, '}')
	if i < 0 {
		return body
	}
	out := make([]byte, 0, len(body)+len(member)+1)
	out = append(out, body[:i]...)
	out = append(out, ',')
	out = append(out, member...)
	out = append(out, body[i:]...)
	return out
}

// writeBody writes the body, in chunks with a pause between them when SlowBody
// is set.
func (f *FakePrometheus) writeBody(w http.ResponseWriter, body []byte) {
	if f.opts.SlowBody <= 0 {
		_, _ = w.Write(body)
		return
	}
	const chunk = 4096
	for off := 0; off < len(body); off += chunk {
		end := min(off+chunk, len(body))
		if _, err := w.Write(body[off:end]); err != nil {
			return
		}
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		time.Sleep(f.opts.SlowBody)
	}
}
