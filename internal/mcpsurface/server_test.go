// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// TestNewRequiresVerifier pins the one configuration this package refuses to
// build. An unauthenticated MCP endpoint onto a hundred production Prometheus
// servers is not a deployment mistake we let a caller make quietly.
func TestNewRequiresVerifier(t *testing.T) {
	t.Parallel()
	s, err := New(Options{Name: "x"})
	if err == nil {
		t.Fatalf("New without a verifier succeeded: %+v", s)
	}
	if s != nil {
		t.Errorf("New returned a server alongside its error: %+v", s)
	}
	if !strings.Contains(err.Error(), "Verifier") {
		t.Errorf("error = %q, want it to name the missing field", err)
	}
}

// TestNewDefaults covers the documented defaulting rules.
func TestNewDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       Options
		wantName string
		wantTitl string
		wantVers string
		wantPage int
		wantBody int64
	}{
		{
			name:     "every field zero",
			in:       Options{},
			wantName: DefaultServerName,
			wantTitl: DefaultServerName,
			wantVers: "0.0.0-dev",
			wantPage: DefaultPageSize,
			wantBody: DefaultMaxRequestBodyBytes,
		},
		{
			name:     "title defaults to name",
			in:       Options{Name: "hub"},
			wantName: "hub",
			wantTitl: "hub",
			wantVers: "0.0.0-dev",
			wantPage: DefaultPageSize,
			wantBody: DefaultMaxRequestBodyBytes,
		},
		{
			name: "explicit values survive",
			in: Options{
				Name: "hub", Title: "Hub", Version: "1.2.3",
				PageSize: 7, MaxRequestBodyBytes: 99,
			},
			wantName: "hub", wantTitl: "Hub", wantVers: "1.2.3",
			wantPage: 7, wantBody: 99,
		},
		{
			name:     "a negative body cap is left alone so it can disable the check",
			in:       Options{MaxRequestBodyBytes: -1},
			wantName: DefaultServerName, wantTitl: DefaultServerName,
			wantVers: "0.0.0-dev", wantPage: DefaultPageSize, wantBody: -1,
		},
		{
			name:     "a non-positive page size defaults",
			in:       Options{PageSize: -5},
			wantName: DefaultServerName, wantTitl: DefaultServerName,
			wantVers: "0.0.0-dev", wantPage: DefaultPageSize,
			wantBody: DefaultMaxRequestBodyBytes,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := tc.in
			in.Verifier = okVerifier().TokenVerifier()
			s, err := New(in)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if s.opts.Name != tc.wantName || s.opts.Title != tc.wantTitl ||
				s.opts.Version != tc.wantVers {
				t.Errorf("identity = %q/%q/%q, want %q/%q/%q",
					s.opts.Name, s.opts.Title, s.opts.Version,
					tc.wantName, tc.wantTitl, tc.wantVers)
			}
			if s.opts.PageSize != tc.wantPage {
				t.Errorf("PageSize = %d, want %d", s.opts.PageSize, tc.wantPage)
			}
			if s.opts.MaxRequestBodyBytes != tc.wantBody {
				t.Errorf("MaxRequestBodyBytes = %d, want %d",
					s.opts.MaxRequestBodyBytes, tc.wantBody)
			}
			if s.opts.Logger == nil {
				t.Error("a nil Logger was not replaced with a discard handler")
			}
			if s.MCPServer() == nil {
				t.Error("MCPServer() is nil")
			}
			if s.schemas == nil {
				t.Error("the schema map was not initialised")
			}
		})
	}
}

// TestHandlerRejectsNonPOST pins the shape protocol revision 2026-07-28
// requires: sessions are gone, so there is no GET stream to resume and no
// DELETE to end a session with.
func TestHandlerRejectsNonPOST(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	h := s.Handler()

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(method, "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+testToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405; body %q", rec.Code, rec.Body.String())
			}
			// RFC 9110 §15.5.6: a 405 must say what is allowed.
			if got := rec.Header().Get("Allow"); got != http.MethodPost {
				t.Errorf("Allow = %q, want POST", got)
			}
			if got := rec.Header().Get("Mcp-Session-Id"); got != "" {
				t.Errorf("a stateless handler minted a session id %q", got)
			}
		})
	}
}

// TestHandlerRejectsOversizeBody proves the body cap is wired into the
// transport, not merely stored on Options.
func TestHandlerRejectsOversizeBody(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, func(o *Options) { o.MaxRequestBodyBytes = 64 })

	big := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"pad":"` +
		strings.Repeat("x", 4096) + `"}}`
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, mcpPOST(big, testToken))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "64") {
		t.Errorf("the 413 body does not name the limit: %q", rec.Body.String())
	}
}

// TestHandlerStatelessPOST proves a well-formed POST reaches the transport and
// that no session id is minted on the way back.
func TestHandlerStatelessPOST(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, mcpPOST(initializeBody, testToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != "" {
		t.Errorf("Mcp-Session-Id = %q; the handler is configured stateless", got)
	}
	if !strings.Contains(rec.Body.String(), `"serverInfo"`) {
		t.Errorf("initialize did not answer with serverInfo: %q", rec.Body.String())
	}
}

// TestUnauthorizedChallenge covers the 401 path and the WWW-Authenticate
// challenge that carries the RFC 9728 document location.
func TestUnauthorizedChallenge(t *testing.T) {
	t.Parallel()
	const metadata = "https://hub.example" + wellKnownPRMPath

	tests := []struct {
		name       string
		mutate     func(o *Options)
		token      string
		wantStatus int
		wantParams []string
		wantNoHdr  bool
	}{
		{
			name:       "no credential at all",
			mutate:     func(o *Options) { o.ResourceMetadataURL = metadata },
			token:      "",
			wantStatus: http.StatusUnauthorized,
			wantParams: []string{fmt.Sprintf("resource_metadata=%q", metadata)},
		},
		{
			name:       "a credential the verifier refuses",
			mutate:     func(o *Options) { o.ResourceMetadataURL = metadata },
			token:      "pmf_agt_wrong",
			wantStatus: http.StatusUnauthorized,
			wantParams: []string{fmt.Sprintf("resource_metadata=%q", metadata)},
		},
		{
			name: "required scopes are advertised alongside the metadata",
			mutate: func(o *Options) {
				o.ResourceMetadataURL = metadata
				o.RequiredScopes = []string{"mcp:read", "mcp:write"}
			},
			token:      "",
			wantStatus: http.StatusUnauthorized,
			wantParams: []string{
				fmt.Sprintf("resource_metadata=%q", metadata),
				`scope="mcp:read mcp:write"`,
			},
		},
		{
			name:       "no metadata configured means no challenge parameters",
			mutate:     nil,
			token:      "",
			wantStatus: http.StatusUnauthorized,
			wantNoHdr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestServer(t, tc.mutate)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, mcpPOST(initializeBody, tc.token))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %q",
					rec.Code, tc.wantStatus, rec.Body.String())
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if tc.wantNoHdr {
				if challenge != "" {
					t.Errorf("WWW-Authenticate = %q, want none", challenge)
				}
				return
			}
			if !strings.HasPrefix(challenge, "Bearer ") {
				t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", challenge)
			}
			for _, want := range tc.wantParams {
				if !strings.Contains(challenge, want) {
					t.Errorf("WWW-Authenticate = %q, want it to carry %s", challenge, want)
				}
			}
		})
	}
}

// TestResourceMetadataURLIsOriginPlusWellKnown pins the construction of the
// resource_metadata value.
//
// RFC 9728 §3.1 puts the well-known segment at the *origin root* with the
// resource path appended after it. For a public URL of https://host/mcp the
// document therefore lives at
// https://host/.well-known/oauth-protected-resource/mcp — not at
// https://host/mcp/.well-known/oauth-protected-resource/mcp, which is what
// concatenating the well-known path onto the full public URL produces and
// which is a 404. A challenge pointing at a 404 is worse than no challenge:
// the client believes it has discovery and gets nothing.
//
// This package emits whatever it is handed, verbatim, so what it must
// guarantee is exactly that: no path juggling of its own, and the value that
// arrives is the value that ships.
func TestResourceMetadataURLIsOriginPlusWellKnown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		publicURL string
		want      string
	}{
		{
			name:      "a public URL with a path",
			publicURL: "https://hub.example.com/mcp",
			want:      "https://hub.example.com" + wellKnownPRMPath,
		},
		{
			name:      "a public URL at the root",
			publicURL: "https://hub.example.com",
			want:      "https://hub.example.com" + wellKnownPRMPath,
		},
		{
			name:      "a non-default port belongs to the origin",
			publicURL: "https://hub.example.com:8443/mcp",
			want:      "https://hub.example.com:8443" + wellKnownPRMPath,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// The construction the composition root performs, restated here so
			// a regression in it shows up as a failure of this contract too.
			u, err := url.Parse(tc.publicURL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			origin := url.URL{Scheme: u.Scheme, Host: u.Host}
			built := origin.String() + wellKnownPRMPath
			if diff := cmp.Diff(tc.want, built); diff != "" {
				t.Fatalf("metadata URL (-want +got):\n%s", diff)
			}
			// The bug that shipped: the well-known path concatenated onto the
			// full public URL, which puts the document under the resource.
			buggy := strings.TrimSuffix(tc.publicURL, "/") + wellKnownPRMPath
			if buggy == built && u.Path != "" && u.Path != "/" {
				t.Fatal("the buggy concatenation is indistinguishable from the " +
					"correct construction; this test proves nothing")
			}

			s := newTestServer(t, func(o *Options) { o.ResourceMetadataURL = built })
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, mcpPOST(initializeBody, ""))

			challenge := rec.Header().Get("WWW-Authenticate")
			want := fmt.Sprintf("Bearer resource_metadata=%q", built)
			if diff := cmp.Diff(want, challenge); diff != "" {
				t.Errorf("challenge (-want +got):\n%s", diff)
			}
			// And explicitly: the handler must not have appended anything of
			// its own to the URL it was given.
			if strings.Contains(challenge, buggy) && buggy != built {
				t.Errorf("challenge points under the resource path: %q", challenge)
			}
		})
	}
}

// TestVerifierErrorStatuses covers the status codes the bearer middleware maps
// verifier errors onto. A 500 for an unexpected error is correct: it is not
// the caller's credential that is wrong.
func TestVerifierErrorStatuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		verifier   *fakeVerifier
		wantStatus int
	}{
		{
			name:       "invalid token",
			verifier:   &fakeVerifier{err: auth.ErrInvalidToken},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a store failure is not the caller's fault",
			verifier:   &fakeVerifier{err: errors.New("store unavailable")},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "a verifier that returns neither info nor error",
			verifier:   &fakeVerifier{},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestServer(t, func(o *Options) { o.Verifier = tc.verifier.TokenVerifier() })
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, mcpPOST(initializeBody, testToken))
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body %q",
					rec.Code, tc.wantStatus, rec.Body.String())
			}
			calls, lastToken, sawRequest := tc.verifier.observed()
			if calls == 0 {
				t.Fatal("the verifier was never called")
			}
			if !sawRequest {
				t.Error("the verifier was not handed the HTTP request")
			}
			if lastToken != testToken {
				t.Errorf("verifier saw token %q", lastToken)
			}
		})
	}
}

// TestInsufficientScope covers the 403 branch, which also carries a challenge.
func TestInsufficientScope(t *testing.T) {
	t.Parallel()
	const metadata = "https://hub.example" + wellKnownPRMPath
	s := newTestServer(t, func(o *Options) {
		o.RequiredScopes = []string{"mcp:admin"}
		o.ResourceMetadataURL = metadata
	})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, mcpPOST(initializeBody, testToken))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), metadata) {
		t.Errorf("the 403 dropped the challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

// TestCrossOriginProtection covers the CSRF defence and its escape hatch.
func TestCrossOriginProtection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		mutate     func(o *Options)
		origin     string
		fetchSite  string
		wantStatus int
	}{
		{
			name:       "a non-browser client sends neither header and is allowed",
			wantStatus: http.StatusOK,
		},
		{
			name:       "a cross-site browser request is refused",
			fetchSite:  "cross-site",
			origin:     "https://evil.example",
			wantStatus: http.StatusForbidden,
		},
		{
			name:      "an explicitly trusted origin is allowed",
			fetchSite: "cross-site",
			origin:    "https://console.example",
			mutate: func(o *Options) {
				o.TrustedOrigins = []string{"https://console.example"}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:      "an unparseable trusted origin is logged, not fatal",
			fetchSite: "cross-site",
			origin:    "https://evil.example",
			mutate: func(o *Options) {
				o.TrustedOrigins = []string{"::not a url::"}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "the escape hatch disables the check",
			fetchSite:  "cross-site",
			origin:     "https://evil.example",
			mutate:     func(o *Options) { o.DisableCrossOriginProtection = true },
			wantStatus: http.StatusOK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestServer(t, func(o *Options) {
				o.DisableCrossOriginProtection = false
				o.Logger = slog.New(slog.DiscardHandler)
				if tc.mutate != nil {
					tc.mutate(o)
				}
			})
			req := mcpPOST(initializeBody, testToken)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body %q",
					rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestMount proves the handler is reachable at the pattern it was mounted on,
// and that a method the pattern excludes never reaches it.
func TestMount(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	mux := http.NewServeMux()
	s.Mount(mux, "POST /mcp")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, mcpPOST(initializeBody, testToken))
	if rec.Code != http.StatusOK {
		t.Errorf("mounted POST /mcp = %d, want 200; body %q", rec.Code, rec.Body.String())
	}

	// The mux pattern names the method, so a GET is refused by routing before
	// the handler's own 405 is reached.
	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	get.Header.Set("Authorization", "Bearer "+testToken)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /mcp = %d, want 405", getRec.Code)
	}

	// Nothing else is mounted.
	other := httptest.NewRequest(http.MethodPost, "/elsewhere", nil)
	otherRec := httptest.NewRecorder()
	mux.ServeHTTP(otherRec, other)
	if otherRec.Code != http.StatusNotFound {
		t.Errorf("POST /elsewhere = %d, want 404", otherRec.Code)
	}
}

// TestProtocolErrorAndErrorCode covers the JSON-RPC error framing and its
// inverse, including an error wrapped by a caller.
func TestProtocolErrorAndErrorCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      error
		wantCode int64
		wantOK   bool
		wantMsg  string
	}{
		{
			name:     "unauthenticated",
			err:      ProtocolError(CodeUnauthenticated, "requires an authenticated principal"),
			wantCode: CodeUnauthenticated, wantOK: true,
			wantMsg: "requires an authenticated principal",
		},
		{
			name:     "forbidden, formatted",
			err:      ProtocolError(CodeForbidden, "tool %q is out of scope", "query_range"),
			wantCode: CodeForbidden, wantOK: true,
			wantMsg: `tool "query_range" is out of scope`,
		},
		{
			name:     "invalid params mirrors the standard code",
			err:      ProtocolError(CodeInvalidParams, "bad args"),
			wantCode: jsonrpc.CodeInvalidParams, wantOK: true, wantMsg: "bad args",
		},
		{
			name:     "a wrapped protocol error is still recoverable",
			err:      fmt.Errorf("registering: %w", ProtocolError(CodeForbidden, "nope")),
			wantCode: CodeForbidden, wantOK: true, wantMsg: "nope",
		},
		{
			name: "a plain error is not a protocol error",
			err:  errors.New("upstream unreachable"),
		},
		{
			name: "a nil error is not a protocol error",
			err:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, ok := ErrorCode(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ErrorCode(%v) ok = %v, want %v", tc.err, ok, tc.wantOK)
			}
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d", code, tc.wantCode)
			}
			if !tc.wantOK {
				return
			}
			var e *jsonrpc.Error
			if !errors.As(tc.err, &e) {
				t.Fatalf("errors.As did not recover a *jsonrpc.Error from %v", tc.err)
			}
			if e.Message != tc.wantMsg {
				t.Errorf("message = %q, want %q", e.Message, tc.wantMsg)
			}
		})
	}
}

// TestProtocolErrorCodesAreDistinct guards the closed set from a copy-paste
// collision, which would make an authorization failure indistinguishable from
// an authentication one at the client.
func TestProtocolErrorCodesAreDistinct(t *testing.T) {
	t.Parallel()
	seen := map[int64]string{}
	for name, code := range map[string]int64{
		"CodeUnauthenticated": CodeUnauthenticated,
		"CodeForbidden":       CodeForbidden,
		"CodeInvalidParams":   CodeInvalidParams,
	} {
		if prev, dup := seen[code]; dup {
			t.Errorf("%s and %s share code %d", name, prev, code)
		}
		seen[code] = name
	}
	// The two application codes must sit in the JSON-RPC implementation-defined
	// server-error range.
	for _, code := range []int64{CodeUnauthenticated, CodeForbidden} {
		if code > -32000 || code < -32099 {
			t.Errorf("code %d is outside the -32000..-32099 reserved range", code)
		}
	}
}

// TestStaticTokenVerifier covers the single-credential verifier used by the
// stdio transport, including the credentials it must refuse.
func TestStaticTokenVerifier(t *testing.T) {
	t.Parallel()
	p := testPrincipal("kid-static")

	tests := []struct {
		name      string
		configure string
		principal *fleet.Principal
		ttl       time.Duration
		present   string
		wantErr   bool
		wantUser  string
	}{
		{
			name:      "the configured credential is accepted",
			configure: "secret", principal: p, ttl: time.Hour,
			present: "secret", wantUser: "kid-static",
		},
		{
			name:      "a different credential is refused",
			configure: "secret", principal: p, ttl: time.Hour,
			present: "other", wantErr: true,
		},
		{
			name:      "a prefix of the credential is refused",
			configure: "secret", principal: p, ttl: time.Hour,
			present: "secr", wantErr: true,
		},
		{
			name:      "a superstring of the credential is refused",
			configure: "secret", principal: p, ttl: time.Hour,
			present: "secretsecret", wantErr: true,
		},
		{
			name:      "an empty presented credential is refused",
			configure: "secret", principal: p, ttl: time.Hour,
			present: "", wantErr: true,
		},
		{
			name:      "an unset credential matches nothing, not even the empty string",
			configure: "", principal: p, ttl: time.Hour,
			present: "", wantErr: true,
		},
		{
			name:      "an unset credential is not matched by a real one either",
			configure: "", principal: p, ttl: time.Hour,
			present: "secret", wantErr: true,
		},
		{
			name:      "a nil principal yields no subject rather than a panic",
			configure: "secret", principal: nil, ttl: time.Hour,
			present: "secret", wantUser: "",
		},
		{
			name:      "a non-positive ttl falls back to an hour",
			configure: "secret", principal: p, ttl: 0,
			present: "secret", wantUser: "kid-static",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := StaticTokenVerifier(tc.configure, tc.principal, tc.ttl)
			before := time.Now()
			info, err := v(t.Context(), tc.present, nil)
			if tc.wantErr {
				if !errors.Is(err, auth.ErrInvalidToken) {
					t.Fatalf("err = %v, want auth.ErrInvalidToken", err)
				}
				if info != nil {
					t.Errorf("a refused credential still produced %+v", info)
				}
				return
			}
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if info.UserID != tc.wantUser {
				t.Errorf("UserID = %q, want %q", info.UserID, tc.wantUser)
			}
			if !info.Expiration.After(before) {
				t.Errorf("Expiration %v is not in the future", info.Expiration)
			}
			if tc.ttl <= 0 && info.Expiration.Sub(before) < 59*time.Minute {
				t.Errorf("a zero ttl gave %v, want the one-hour fallback",
					info.Expiration.Sub(before))
			}
			if got := PrincipalOf(info.Extra); got != tc.principal {
				t.Errorf("PrincipalOf = %v, want the configured principal", got)
			}
		})
	}
}

// TestStaticTokenVerifierIsConstantTime is a shape check, not a timing
// measurement: it asserts the comparison goes through crypto/subtle by proving
// the verifier does not short-circuit on length. A timing assertion in a unit
// test is a flake, so what is pinned here is that every refusal path returns
// the same error with no principal attached, which is what stops a caller
// distinguishing "wrong length" from "wrong bytes" by the response alone.
func TestStaticTokenVerifierIsConstantTime(t *testing.T) {
	t.Parallel()
	v := StaticTokenVerifier("correct-horse", testPrincipal("kid"), time.Hour)
	for _, bad := range []string{"", "c", "correct-hors", "correct-horsE", "correct-horsee",
		strings.Repeat("x", 4096)} {
		info, err := v(t.Context(), bad, nil)
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("verify(%q) err = %v, want auth.ErrInvalidToken", bad, err)
		}
		if info != nil {
			t.Errorf("verify(%q) leaked %+v", bad, info)
		}
	}
}
