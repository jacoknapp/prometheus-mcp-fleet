// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofHandler(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", PprofHandler())

	tests := []struct {
		name, path string
		wantCode   int
		wantBody   string
	}{
		{name: "index", path: "/debug/pprof/", wantCode: http.StatusOK, wantBody: "goroutine"},
		{name: "named profile", path: "/debug/pprof/heap?debug=1", wantCode: http.StatusOK, wantBody: "heap profile"},
		{name: "cmdline", path: "/debug/pprof/cmdline", wantCode: http.StatusOK},
		{name: "symbol", path: "/debug/pprof/symbol", wantCode: http.StatusOK, wantBody: "num_symbols"},
		{name: "unknown profile", path: "/debug/pprof/nope", wantCode: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body does not contain %q:\n%s", tc.wantBody, rec.Body.String())
			}
		})
	}
}
