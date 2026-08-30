// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// testToken is the single credential every fake verifier in this file accepts.
const testToken = "pmf_agt_test_credential"

// wellKnownPRMPath mirrors internal/hubapi.PRMPath. It is duplicated rather
// than imported because hubapi sits above this package in the layering and the
// architecture test forbids the edge; the duplication is the point of the test
// that uses it.
const wellKnownPRMPath = "/.well-known/oauth-protected-resource/mcp"

// testPrincipal builds a principal with no secret material in it.
func testPrincipal(kid string) *fleet.Principal {
	return &fleet.Principal{
		KID:   kid,
		Name:  "test-agent",
		Class: fleet.ClassAgent,
		Role:  fleet.RoleViewer,
		Scope: &fleet.Scope{Role: fleet.RoleViewer},
	}
}

// fakeVerifier is a hand-written [TokenVerifier] that records what it was
// asked and answers from a fixed script. It stands in for authn.Verifier,
// which this package deliberately does not import.
type fakeVerifier struct {
	// info is returned for a matching token. A nil info with a nil err
	// reproduces an SDK-hostile verifier that reports neither.
	info *auth.TokenInfo
	// err is returned instead of info, for any token.
	err error

	// mu guards the recorded observations. The SDK's transport and a parallel
	// subtest can both be inside the verifier at once, so a plain field would
	// be a race in the fake rather than in the code under test.
	mu sync.Mutex
	// calls counts invocations.
	calls int
	// lastToken is the credential of the most recent call.
	lastToken string
	// sawRequest records whether an HTTP request reached the verifier.
	sawRequest bool
}

// TokenVerifier returns the verifier function.
func (f *fakeVerifier) TokenVerifier() TokenVerifier {
	return func(_ context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		f.mu.Lock()
		f.calls++
		f.lastToken = token
		f.sawRequest = f.sawRequest || req != nil
		f.mu.Unlock()
		if f.err != nil {
			return nil, f.err
		}
		if token != testToken {
			return nil, auth.ErrInvalidToken
		}
		return f.info, nil
	}
}

// observed returns the recorded call count, most recent token and whether an
// HTTP request was ever seen.
func (f *fakeVerifier) observed() (calls int, lastToken string, sawRequest bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastToken, f.sawRequest
}

// okVerifier is the fake every happy-path test uses: it accepts [testToken]
// and returns a TokenInfo with no Extra map at all, which is what an
// unwrapped authn.Verifier produces.
func okVerifier() *fakeVerifier {
	return &fakeVerifier{info: &auth.TokenInfo{
		UserID:     "kid-1",
		Scopes:     []string{"mcp"},
		Expiration: time.Now().Add(time.Hour),
	}}
}

// newTestServer builds a Server with cross-origin protection off and the
// supplied option overrides applied.
func newTestServer(t *testing.T, mutate func(o *Options)) *Server {
	t.Helper()
	opts := Options{
		Name:                         "test-hub",
		Version:                      "0.0.0-test",
		Verifier:                     okVerifier().TokenVerifier(),
		DisableCrossOriginProtection: true,
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// mcpPOST builds a well-formed Streamable HTTP POST carrying body.
func mcpPOST(body, token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// initializeBody is a minimal, valid initialize request.
const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
	`{"protocolVersion":"2025-06-18","capabilities":{},` +
	`"clientInfo":{"name":"test","version":"0"}}}`

// bearerRoundTripper attaches a bearer credential to every request an SDK
// client makes, which is the only hook the transport offers.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	base := b.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

// connect serves s over httptest and returns a connected SDK client session.
// Both are torn down by t.Cleanup.
func connect(t *testing.T, s *Server) *mcp.ClientSession {
	t.Helper()
	httpSrv := httptest.NewServer(s.Handler())
	t.Cleanup(httpSrv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   httpSrv.URL,
		HTTPClient: &http.Client{Transport: bearerRoundTripper{token: testToken}},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// echoIn and echoOut are the argument and result types of the test tool. Every
// output field is omitempty, as AddTool documents it must be.
type echoIn struct {
	Text string `json:"text" jsonschema:"the text to echo"`
	Fail bool   `json:"fail,omitempty" jsonschema:"return a tool error"`
}

type echoOut struct {
	Text      string `json:"text,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Principal string `json:"principal,omitempty"`
	SawHeader bool   `json:"sawHeader,omitempty"`
	ToolName  string `json:"toolName,omitempty"`
}

// decodeStructured re-decodes a tool result's structured content into v. The
// SDK hands the client an any holding whatever JSON decoded to, so a round
// trip is the honest way to read it back as the tool's own type.
func decodeStructured(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("result carries no structured content: %+v", res)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode structured content %s: %v", b, err)
	}
}
