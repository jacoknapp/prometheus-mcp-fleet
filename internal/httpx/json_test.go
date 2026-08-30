// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// withRequestID returns a request carrying id in its context.
func withRequestID(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if id == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		req        *http.Request
		status     int
		value      any
		wantStatus int
		wantBody   string
		wantReqID  string
	}{
		{
			name:       "object",
			req:        withRequestID("req-1"),
			status:     http.StatusOK,
			value:      map[string]int{"n": 1},
			wantStatus: http.StatusOK,
			wantBody:   "{\"n\":1}\n",
			wantReqID:  "req-1",
		},
		{
			name:       "created without a request id",
			req:        withRequestID(""),
			status:     http.StatusCreated,
			value:      []string{"a"},
			wantStatus: http.StatusCreated,
			wantBody:   "[\"a\"]\n",
		},
		{
			name:       "nil request is tolerated",
			req:        nil,
			status:     http.StatusOK,
			value:      struct{}{},
			wantStatus: http.StatusOK,
			wantBody:   "{}\n",
		},
		{
			name:       "unencodable value yields a complete error body",
			req:        withRequestID("req-2"),
			status:     http.StatusOK,
			value:      make(chan int),
			wantStatus: http.StatusInternalServerError,
			wantReqID:  "req-2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			WriteJSON(rec, tc.req, tc.status, tc.value)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Content-Type"); got != ContentTypeJSON {
				t.Errorf("content type = %q, want %q", got, ContentTypeJSON)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("nosniff header = %q", got)
			}
			if got := rec.Header().Get(HeaderRequestID); got != tc.wantReqID {
				t.Errorf("%s = %q, want %q", HeaderRequestID, got, tc.wantReqID)
			}

			// Whatever happened, the body must be one complete JSON document.
			if !json.Valid(rec.Body.Bytes()) {
				t.Fatalf("body is not valid JSON: %q", rec.Body.String())
			}
			if tc.wantBody != "" {
				if diff := cmp.Diff(tc.wantBody, rec.Body.String()); diff != "" {
					t.Errorf("body (-want +got):\n%s", diff)
				}
				return
			}

			var body ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body.Error.Code != CodeInternal {
				t.Errorf("code = %q, want %q", body.Error.Code, CodeInternal)
			}
			if body.Error.RequestID != tc.wantReqID {
				t.Errorf("request id = %q, want %q", body.Error.RequestID, tc.wantReqID)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *http.Request
		status  int
		code    string
		message string
		want    ErrorDetail
	}{
		{
			name:    "with a request id",
			req:     withRequestID("abc123"),
			status:  http.StatusNotFound,
			code:    "unknown_cluster",
			message: "no such cluster",
			want:    ErrorDetail{Code: "unknown_cluster", Message: "no such cluster", RequestID: "abc123"},
		},
		{
			name:    "without a request id",
			req:     withRequestID(""),
			status:  http.StatusUnauthorized,
			code:    "unauthorized",
			message: "credential rejected",
			want:    ErrorDetail{Code: "unauthorized", Message: "credential rejected"},
		},
		{
			name:    "nil request",
			req:     nil,
			status:  http.StatusBadRequest,
			code:    "bad_request",
			message: "malformed",
			want:    ErrorDetail{Code: "bad_request", Message: "malformed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			WriteError(rec, tc.req, tc.status, tc.code, tc.message)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			var body ErrorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if diff := cmp.Diff(tc.want, body.Error); diff != "" {
				t.Errorf("error detail (-want +got):\n%s", diff)
			}
			if !strings.HasSuffix(rec.Body.String(), "\n") {
				t.Error("body is not newline-terminated")
			}
		})
	}
}

// TestWriteJSONDoesNotOverwriteAnExistingRequestIDHeader proves the middleware
// stays authoritative over the header it set.
func TestWriteJSONDoesNotOverwriteAnExistingRequestIDHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rec.Header().Set(HeaderRequestID, "set-by-middleware")
	WriteJSON(rec, withRequestID("from-context"), http.StatusOK, map[string]string{"ok": "yes"})

	if got := rec.Header().Get(HeaderRequestID); got != "set-by-middleware" {
		t.Errorf("%s = %q, want the middleware value preserved", HeaderRequestID, got)
	}
}

func TestErrorJSONIsAlwaysValid(t *testing.T) {
	t.Parallel()

	b := errorJSON("id", CodeInternal, `a "quoted" <message> with \ backslash`)
	if !json.Valid(b) {
		t.Fatalf("errorJSON produced invalid JSON: %q", b)
	}
	var body ErrorBody
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Message != `a "quoted" <message> with \ backslash` {
		t.Errorf("message = %q", body.Error.Message)
	}
}
