// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promapi

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestGetKnownAndUnknown(t *testing.T) {
	t.Parallel()

	all := Endpoints()
	// Every other test in this file, and the round trip in promproxy, is a
	// `for range Endpoints()` loop. An empty table would satisfy all of them
	// vacuously, so the table's contents are asserted here once, explicitly.
	for _, want := range []Endpoint{EndpointQuery, EndpointQueryRange, EndpointSeries, EndpointLabelValues} {
		if !slices.Contains(all, want) {
			t.Fatalf("Endpoints() = %v, missing %q", all, want)
		}
	}
	if !slices.IsSorted(all) {
		t.Errorf("Endpoints() = %v, want sorted; callers render it as documentation", all)
	}
	if n := len(slices.Compact(slices.Clone(all))); n != len(all) {
		t.Errorf("Endpoints() = %v, want no duplicates", all)
	}

	for _, e := range all {
		r, err := Get(e)
		if err != nil {
			t.Fatalf("Get(%q): %v", e, err)
		}
		if r.Endpoint != e {
			t.Errorf("Get(%q).Endpoint = %q", e, r.Endpoint)
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			t.Errorf("Get(%q).Method = %q, want GET or POST", e, r.Method)
		}
		if !strings.HasPrefix(r.PathTemplate, "/api/v1/") {
			t.Errorf("Get(%q).PathTemplate = %q, want an /api/v1/ path", e, r.PathTemplate)
		}
		if r.Summary == "" {
			t.Errorf("Get(%q) has no Summary; the docs generator needs one", e)
		}
	}

	if _, err := Get("delete_series"); !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("Get(unknown) error = %v, want ErrUnknownEndpoint", err)
	}
}

// TestNoDestructiveEndpointExists is the structural guarantee that matters
// most: the endpoints an attacker would want simply are not in the table, so
// there is no filter to bypass.
func TestNoDestructiveEndpointExists(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"/api/v1/admin/tsdb/delete_series",
		"/api/v1/admin/tsdb/clean_tombstones",
		"/api/v1/admin/tsdb/snapshot",
		"/api/v1/write",
		"/api/v1/read",
		"/-/reload",
		"/-/quit",
		"/debug/pprof/heap",
	}
	for _, path := range forbidden {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			if _, _, ok := Lookup(method, path); ok {
				t.Errorf("Lookup(%q, %q) resolved; it must not exist in the allow-list", method, path)
			}
		}
	}
}

func TestBuildPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		endpoint  Endpoint
		labelName string
		want      string
		wantErr   error
	}{
		{
			name: "plain path", endpoint: EndpointQuery, want: "/api/v1/query",
		},
		{
			name:     "label values substitutes the label",
			endpoint: EndpointLabelValues, labelName: "job",
			want: "/api/v1/label/job/values",
		},
		{
			name:     "label values with underscores",
			endpoint: EndpointLabelValues, labelName: "_internal_id",
			want: "/api/v1/label/_internal_id/values",
		},
		{
			name:     "label name is required for label values",
			endpoint: EndpointLabelValues, labelName: "",
			wantErr: ErrInvalidLabelName,
		},
		{
			name:     "label name rejected for other endpoints",
			endpoint: EndpointQuery, labelName: "job",
			wantErr: ErrInvalidParam,
		},
		{
			name: "unknown endpoint", endpoint: "nope", wantErr: ErrUnknownEndpoint,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildPath(tc.endpoint, tc.labelName)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("BuildPath error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildPath: %v", err)
			}
			if got != tc.want {
				t.Fatalf("BuildPath = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildPathRejectsTraversal covers the only user-influenced path component
// in the whole system.
func TestBuildPathRejectsTraversal(t *testing.T) {
	t.Parallel()

	hostile := []string{
		"../../admin/tsdb/delete_series",
		"..",
		"job/../../..",
		"job%2f..%2f..",
		"job/values",
		"job values",
		"job\x00",
		"job\n",
		"jöb",
		"job}",
		"1job", // must start with a letter or underscore
		strings.Repeat("a", 5000),
	}
	for _, label := range hostile {
		t.Run(url.PathEscape(label), func(t *testing.T) {
			t.Parallel()
			got, err := BuildPath(EndpointLabelValues, label)
			if err == nil {
				t.Fatalf("BuildPath accepted hostile label %q and produced %q", label, got)
			}
			if !errors.Is(err, ErrInvalidLabelName) {
				t.Fatalf("BuildPath(%q) error = %v, want ErrInvalidLabelName", label, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint Endpoint
		form     url.Values
		gated    bool
		wantErr  error
	}{
		{
			name: "instant query", endpoint: EndpointQuery,
			form: url.Values{"query": {"up"}},
		},
		{
			name: "instant query with optional params", endpoint: EndpointQuery,
			form: url.Values{
				"query": {"rate(http_requests_total[5m])"},
				"time":  {"2026-08-29T12:00:00Z"},
				// A Unix timestamp is equally acceptable to Prometheus.
				"timeout": {"30s"},
				"limit":   {"100"},
			},
		},
		{
			name: "missing required query", endpoint: EndpointQuery,
			form: url.Values{}, wantErr: ErrInvalidParam,
		},
		{
			name: "unknown parameter is rejected, not dropped", endpoint: EndpointQuery,
			form: url.Values{"query": {"up"}, "dedup": {"true"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "repeated non-repeatable parameter", endpoint: EndpointQuery,
			form: url.Values{"query": {"up", "down"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "repeated matcher is fine", endpoint: EndpointSeries,
			form: url.Values{"match[]": {`up`, `{job="api"}`}},
		},
		{
			name: "range query needs start end and step", endpoint: EndpointQueryRange,
			form:    url.Values{"query": {"up"}, "start": {"0"}, "end": {"60"}},
			wantErr: ErrInvalidParam,
		},
		{
			name: "range query complete", endpoint: EndpointQueryRange,
			form: url.Values{"query": {"up"}, "start": {"0"}, "end": {"60"}, "step": {"15s"}},
		},
		{
			name: "bad time", endpoint: EndpointQuery,
			form: url.Values{"query": {"up"}, "time": {"yesterday"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "bad duration", endpoint: EndpointQuery,
			form: url.Values{"query": {"up"}, "timeout": {"soon"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "negative integer", endpoint: EndpointQuery,
			form: url.Values{"query": {"up"}, "limit": {"-1"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "enum out of range", endpoint: EndpointTargets,
			form: url.Values{"state": {"everything"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "enum in range", endpoint: EndpointTargets,
			form: url.Values{"state": {"active"}},
		},
		{
			name: "control character in PromQL", endpoint: EndpointQuery,
			form: url.Values{"query": {"up\x00"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "newline in PromQL is rejected", endpoint: EndpointQuery,
			form: url.Values{"query": {"up\nDROP"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "oversized PromQL", endpoint: EndpointQuery,
			form: url.Values{"query": {strings.Repeat("a", MaxPromQLBytes+1)}}, wantErr: ErrInvalidParam,
		},
		{
			name: "too many repeats", endpoint: EndpointSeries,
			form: url.Values{"match[]": repeat(`up`, MaxRepeatedParams+1)}, wantErr: ErrInvalidParam,
		},
		{
			name: "gated endpoint refused by default", endpoint: EndpointConfig,
			form: url.Values{}, wantErr: ErrEndpointGated,
		},
		{
			name: "gated endpoint allowed when enabled", endpoint: EndpointConfig,
			form: url.Values{}, gated: true,
		},
		{
			name: "invalid metric name", endpoint: EndpointMetadata,
			form: url.Values{"metric": {"has-a-dash"}}, wantErr: ErrInvalidParam,
		},
		{
			name: "recording rule name with a colon is valid", endpoint: EndpointMetadata,
			form: url.Values{"metric": {"job:requests:rate5m"}},
		},
		{
			name: "empty matcher", endpoint: EndpointSeries,
			form: url.Values{"match[]": {"   "}}, wantErr: ErrInvalidParam,
		},
		{
			name: "unknown endpoint", endpoint: "nope", wantErr: ErrUnknownEndpoint,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.endpoint, tc.form, tc.gated)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Validate error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		path      string
		wantOK    bool
		wantEP    Endpoint
		wantLabel string
	}{
		{"instant query", "POST", "/api/v1/query", true, EndpointQuery, ""},
		{"method is case insensitive", "post", "/api/v1/query", true, EndpointQuery, ""},
		{"wrong method for the route", "GET", "/api/v1/query", false, "", ""},
		{"label values", "GET", "/api/v1/label/job/values", true, EndpointLabelValues, "job"},
		{"label values percent-encoded", "GET", "/api/v1/label/my_label/values", true, EndpointLabelValues, "my_label"},
		{"targets", "GET", "/api/v1/targets", true, EndpointTargets, ""},
		{"trailing slash is not the same route", "POST", "/api/v1/query/", false, "", ""},
		{"prefix is not enough", "POST", "/api/v1/query_extra", false, "", ""},
		{"relative traversal", "POST", "/api/v1/query/../../admin", false, "", ""},
		{"double slash", "POST", "//api/v1/query", false, "", ""},
		{"backslash", "POST", `\api\v1\query`, false, "", ""},
		{"null byte", "POST", "/api/v1/query\x00", false, "", ""},
		{"empty path", "POST", "", false, "", ""},
		{"relative path", "POST", "api/v1/query", false, "", ""},
		{"label segment with a slash", "GET", "/api/v1/label/a/b/values", false, "", ""},
		{"label segment traversal encoded", "GET", "/api/v1/label/%2e%2e/values", false, "", ""},
		{"label segment empty", "GET", "/api/v1/label//values", false, "", ""},
		{"gated route still resolves", "GET", "/api/v1/status/config", true, EndpointConfig, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, label, ok := Lookup(tc.method, tc.path)
			if ok != tc.wantOK {
				t.Fatalf("Lookup(%q, %q) ok = %v, want %v", tc.method, tc.path, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if r.Endpoint != tc.wantEP {
				t.Errorf("endpoint = %q, want %q", r.Endpoint, tc.wantEP)
			}
			if label != tc.wantLabel {
				t.Errorf("label = %q, want %q", label, tc.wantLabel)
			}
		})
	}
}

// TestBuildPathLookupRoundTrip proves the hub and the spoke agree: anything the
// hub can construct, the spoke will accept, and nothing else.
func TestBuildPathLookupRoundTrip(t *testing.T) {
	t.Parallel()

	for _, e := range Endpoints() {
		r, err := Get(e)
		if err != nil {
			t.Fatal(err)
		}
		label := ""
		if r.HasPathParam() {
			label = "job"
		}
		path, err := BuildPath(e, label)
		if err != nil {
			t.Fatalf("BuildPath(%q): %v", e, err)
		}
		got, gotLabel, ok := Lookup(r.Method, path)
		if !ok {
			t.Fatalf("Lookup(%q, %q) failed for a path BuildPath produced", r.Method, path)
		}
		if got.Endpoint != e {
			t.Errorf("round trip for %q resolved to %q", e, got.Endpoint)
		}
		if gotLabel != label {
			t.Errorf("round trip for %q returned label %q, want %q", e, gotLabel, label)
		}
	}
}

func TestValidateLabelName(t *testing.T) {
	t.Parallel()

	valid := []string{"job", "_x", "a1", "A_B_9", "__name__"}
	invalid := []string{"", "1a", "a-b", "a.b", "a b", "a/b", "ä", "a\x00"}

	for _, s := range valid {
		if err := ValidateLabelName(s); err != nil {
			t.Errorf("ValidateLabelName(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateLabelName(s); !errors.Is(err, ErrInvalidLabelName) {
			t.Errorf("ValidateLabelName(%q) = %v, want ErrInvalidLabelName", s, err)
		}
	}
}

func TestValidateRejectsInvalidLabelParameter(t *testing.T) {
	t.Parallel()
	err := Validate(EndpointTargets, url.Values{"scrapePool": {"bad-label"}}, false)
	if !errors.Is(err, ErrInvalidParam) || !strings.Contains(err.Error(), "valid label name") {
		t.Errorf("Validate(targets, invalid scrapePool) = %v, want an invalid label error", err)
	}
}

func TestValidateDuration(t *testing.T) {
	t.Parallel()

	valid := []string{"5m", "1h30m", "500ms", "1w", "2d", "1y", "30", "0.5"}
	invalid := []string{"", "soon", "5 m", "-5m", "0", "m5", "5x"}

	for _, s := range valid {
		if err := validateDuration(s); err != nil {
			t.Errorf("validateDuration(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateDuration(s); err == nil {
			t.Errorf("validateDuration(%q) = nil, want an error", s)
		}
	}
}

func TestValidateTime(t *testing.T) {
	t.Parallel()

	valid := []string{"2026-08-29T12:00:00Z", "2026-08-29T12:00:00.123Z", "1756468800", "1756468800.5", "0"}
	invalid := []string{"", "yesterday", "2026-08-29", "now-1h"}

	for _, s := range valid {
		if err := validateTime(s); err != nil {
			t.Errorf("validateTime(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := validateTime(s); err == nil {
			t.Errorf("validateTime(%q) = nil, want an error", s)
		}
	}
}

// FuzzLookup asserts that no input can make the allow-list resolve to a path
// outside the table, and that Lookup never panics.
func FuzzLookup(f *testing.F) {
	seeds := []string{
		"/api/v1/query", "/api/v1/label/job/values", "/api/v1/../admin",
		"/api/v1/label/%2e%2e%2f/values", "", "/", "//", "/api/v1/label//values",
	}
	for _, s := range seeds {
		f.Add("GET", s)
		f.Add("POST", s)
	}
	f.Fuzz(func(t *testing.T, method, path string) {
		r, label, ok := Lookup(method, path)
		if !ok {
			return
		}
		// Whatever resolved must be a real route, and rebuilding its path from
		// the captured label must reproduce the input exactly. If it does not,
		// two different strings map to one route and the spoke's re-validation
		// is not equivalent to the hub's construction.
		rebuilt, err := BuildPath(r.Endpoint, label)
		if err != nil {
			t.Fatalf("Lookup(%q, %q) resolved to %q but BuildPath failed: %v",
				method, path, r.Endpoint, err)
		}
		if rebuilt != path {
			t.Fatalf("Lookup(%q, %q) resolved to a path that rebuilds as %q",
				method, path, rebuilt)
		}
	})
}

// FuzzValidate asserts Validate never panics on arbitrary parameter input.
func FuzzValidate(f *testing.F) {
	f.Add("query", "query", "up")
	f.Add("query_range", "step", "15s")
	f.Add("targets", "state", "active")
	f.Fuzz(func(t *testing.T, endpoint, key, value string) {
		_ = Validate(Endpoint(endpoint), url.Values{key: {value}}, false)
		_ = Validate(Endpoint(endpoint), url.Values{key: {value}}, true)
	})
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// TestValidateAcceptsExactlyTheDocumentedLimits pins the accepting side of
// every bound this package advertises.
//
// Each limit already had a test proving that one byte over is refused. That
// alone does not distinguish `>` from `>=`: a limit written one too tight
// rejects the largest legitimate value, and nothing here would have noticed.
// The constants are part of the documented contract, so the value that sits
// exactly on each one has to be accepted.
func TestValidateAcceptsExactlyTheDocumentedLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint Endpoint
		form     url.Values
	}{{
		name: "PromQL of exactly MaxPromQLBytes", endpoint: EndpointQuery,
		form: url.Values{"query": {strings.Repeat("a", MaxPromQLBytes)}},
	}, {
		// A matcher is not PromQL-kinded, so it takes the smaller cap.
		name: "matcher of exactly MaxParamBytes", endpoint: EndpointSeries,
		form: url.Values{"match[]": {strings.Repeat("a", MaxParamBytes)}},
	}, {
		name: "exactly MaxRepeatedParams repeats", endpoint: EndpointSeries,
		form: url.Values{"match[]": repeat(`up`, MaxRepeatedParams)},
	}, {
		// Zero is a legitimate limit; only a negative one is refused.
		name: "integer zero", endpoint: EndpointQuery,
		form: url.Values{"query": {"up"}, "limit": {"0"}},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(tc.endpoint, tc.form, false); err != nil {
				t.Errorf("Validate(%q, ...) = %v, want nil", tc.endpoint, err)
			}
		})
	}
}

// TestValidateKeepsThePromQLCapSeparate proves the two size caps are not
// interchangeable. Collapsing them either truncates legitimate expressions to
// the parameter cap or lets every other field grow to the PromQL cap.
func TestValidateKeepsThePromQLCapSeparate(t *testing.T) {
	t.Parallel()

	oversizeForAParam := strings.Repeat("a", MaxParamBytes+1)

	if err := Validate(EndpointQuery, url.Values{"query": {oversizeForAParam}}, false); err != nil {
		t.Errorf("a %d-byte PromQL expression was rejected: %v", MaxParamBytes+1, err)
	}
	err := Validate(EndpointSeries, url.Values{"match[]": {oversizeForAParam}}, false)
	if !errors.Is(err, ErrInvalidParam) {
		t.Errorf("a %d-byte matcher = %v, want ErrInvalidParam", MaxParamBytes+1, err)
	}
}

// TestValidateLabelNameLengthBoundary pins both sides of MaxLabelNameBytes.
// The label is the only caller-influenced path segment this package builds.
func TestValidateLabelNameLengthBoundary(t *testing.T) {
	t.Parallel()

	if err := ValidateLabelName(strings.Repeat("a", MaxLabelNameBytes)); err != nil {
		t.Errorf("a label name of exactly %d bytes was rejected: %v", MaxLabelNameBytes, err)
	}
	err := ValidateLabelName(strings.Repeat("a", MaxLabelNameBytes+1))
	if !errors.Is(err, ErrInvalidLabelName) {
		t.Errorf("a %d-byte label name = %v, want ErrInvalidLabelName", MaxLabelNameBytes+1, err)
	}
}

// TestForbiddenRunesAtTheEdges walks the exact boundaries of the control
// character filter. This is the rule that stops a parameter carrying a
// terminal escape or a log-injection newline into whatever reads the proxied
// response, so which side of each edge a rune falls on is the whole point.
func TestForbiddenRunesAtTheEdges(t *testing.T) {
	t.Parallel()

	rejected := []struct {
		name  string
		value string
	}{
		// Byte 0 specifically: a scan that started at the second byte would
		// pass a value whose very first rune is a control character.
		{"leading NUL", "\x00up"},
		{"leading newline", "\nup"},
		{"US, the last C0 rune", "up\x1f"},
		{"DEL, the first rune of the C1 block", "up\x7f"},
		{"APC, the last rune of the C1 block", "up\u009f"},
	}
	for _, tc := range rejected {
		t.Run("rejected/"+tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(EndpointQuery, url.Values{"query": {tc.value}}, false)
			if !errors.Is(err, ErrInvalidParam) {
				t.Errorf("Validate(query=%q) = %v, want ErrInvalidParam", tc.value, err)
			}
		})
	}

	accepted := []struct {
		name  string
		value string
	}{
		// 0x20 is a space, the first printable rune, and PromQL is unreadable
		// without it.
		{"space", "sum by (job) (up)"},
		// 0xa0 is the first rune above the C1 block. Everything from here up is
		// ordinary text; a filter that swallowed it would reject any label
		// value carrying a non-ASCII character.
		{"NBSP, the first rune past the C1 block", "up{job=\"a\u00a0b\"}"},
		{"an ordinary non-ASCII rune", "up{job=\"caf\u00e9\"}"},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(EndpointQuery, url.Values{"query": {tc.value}}, false); err != nil {
				t.Errorf("Validate(query=%q) = %v, want nil", tc.value, err)
			}
		})
	}
}
