// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// generatedID matches the shape of a freshly minted identifier: 16 random
// bytes, hex-encoded.
var generatedID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		inbound  string
		wantEcho bool
		why      string
	}{
		{name: "absent header is generated", inbound: "", wantEcho: false, why: "nothing to echo"},
		{name: "simple alphanumeric is echoed", inbound: "abc123", wantEcho: true},
		{name: "hyphen and underscore are echoed", inbound: "trace-id_42", wantEcho: true},
		{name: "uuid shape is echoed", inbound: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", wantEcho: true},
		{name: "exactly 64 characters is echoed", inbound: strings.Repeat("a", 64), wantEcho: true},
		{name: "65 characters is rejected", inbound: strings.Repeat("a", 65), wantEcho: false, why: "over the length cap"},
		{name: "space is rejected", inbound: "has space", wantEcho: false},
		{name: "crlf header injection is rejected", inbound: "ok\r\nX-Evil: 1", wantEcho: false},
		{name: "newline is rejected", inbound: "ok\ninjected", wantEcho: false},
		{name: "html is rejected", inbound: "<script>alert(1)</script>", wantEcho: false},
		{name: "dot is rejected", inbound: "../../etc/passwd", wantEcho: false},
		{name: "nul byte is rejected", inbound: "ab\x00cd", wantEcho: false},
		{name: "non-ascii is rejected", inbound: "id-é", wantEcho: false},
		{name: "colon is rejected", inbound: "a:b", wantEcho: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fromCtx string
			h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				fromCtx = RequestIDFrom(r.Context())
			}))

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.inbound != "" {
				req.Header.Set(HeaderRequestID, tc.inbound)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			gotHeader := rec.Header().Get(HeaderRequestID)
			if gotHeader == "" {
				t.Fatal("response is missing the request id header")
			}
			if gotHeader != fromCtx {
				t.Errorf("header %q and context %q disagree", gotHeader, fromCtx)
			}
			if tc.wantEcho {
				if gotHeader != tc.inbound {
					t.Errorf("id = %q, want the inbound %q echoed", gotHeader, tc.inbound)
				}
				return
			}
			if gotHeader == tc.inbound {
				t.Errorf("id %q was echoed but should have been replaced (%s)", gotHeader, tc.why)
			}
			if !generatedID.MatchString(gotHeader) {
				t.Errorf("generated id = %q, want 32 hex characters", gotHeader)
			}
		})
	}
}

func TestRequestIDFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context //nolint:containedctx // a table of contexts is the point
		want string
	}{
		{name: "background has none", ctx: context.Background(), want: ""},
		{name: "nil context has none", ctx: nil, want: ""},
		{name: "wrong value type has none", ctx: context.WithValue(context.Background(), requestIDKey, 42), want: ""},
		{name: "populated", ctx: context.WithValue(context.Background(), requestIDKey, "abc"), want: "abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RequestIDFrom(tc.ctx); got != tc.want {
				t.Errorf("RequestIDFrom = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewRequestIDIsUnique(t *testing.T) {
	t.Parallel()

	const n = 512
	seen := make(map[string]struct{}, n)
	for range n {
		id := newRequestID()
		if !generatedID.MatchString(id) {
			t.Fatalf("id = %q, want 32 hex characters", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
}
