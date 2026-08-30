// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// TestPrincipalVerifierStoresPrincipal covers the wrapper's whole contract:
// the base verifier's TokenInfo survives, and the resolved principal is
// reachable through [PrincipalOf].
func TestPrincipalVerifierStoresPrincipal(t *testing.T) {
	t.Parallel()
	want := testPrincipal("kid-wrapped")
	expiry := time.Now().Add(30 * time.Minute)

	tests := []struct {
		name string
		base *auth.TokenInfo
	}{
		{
			name: "the base leaves Extra nil",
			base: &auth.TokenInfo{UserID: "kid-wrapped", Expiration: expiry},
		},
		{
			name: "the base already populated Extra",
			base: &auth.TokenInfo{
				UserID: "kid-wrapped", Expiration: expiry,
				Extra: map[string]any{"issuer": "hub"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var sawToken string
			v := PrincipalVerifier(
				func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
					sawToken = token
					return tc.base, nil
				},
				func(_ context.Context, token string) (*fleet.Principal, error) {
					if token != testToken {
						t.Errorf("resolve saw token %q", token)
					}
					return want, nil
				},
			)
			info, err := v(t.Context(), testToken, nil)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if sawToken != testToken {
				t.Errorf("base saw token %q", sawToken)
			}
			if info.UserID != "kid-wrapped" || !info.Expiration.Equal(expiry) {
				t.Errorf("the base TokenInfo did not survive: %+v", info)
			}
			got := PrincipalOf(info.Extra)
			if got != want {
				t.Fatalf("PrincipalOf = %v, want the resolved principal", got)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("principal (-want +got):\n%s", diff)
			}
			// Pre-existing Extra entries must not be clobbered.
			if _, had := tc.base.Extra["issuer"]; len(tc.base.Extra) > 1 && !had {
				t.Error("the wrapper dropped an existing Extra entry")
			}
		})
	}
}

// errResolve is a sentinel the resolve failure test asserts on.
var errResolve = errors.New("revoked")

// TestPrincipalVerifierErrors covers both failure paths. A resolve failure
// must present as an invalid token so the middleware answers 401 with a
// challenge, not 500.
func TestPrincipalVerifierErrors(t *testing.T) {
	t.Parallel()
	baseErr := errors.New("store unavailable")

	tests := []struct {
		name        string
		base        TokenVerifier
		resolve     func(context.Context, string) (*fleet.Principal, error)
		wantIs      error
		wantNotIs   error
		wantMessage string
	}{
		{
			name: "the base verifier's error is returned unchanged",
			base: func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
				return nil, baseErr
			},
			resolve: func(context.Context, string) (*fleet.Principal, error) {
				t.Error("resolve ran after the base verifier failed")
				return nil, nil
			},
			wantIs:    baseErr,
			wantNotIs: auth.ErrInvalidToken,
		},
		{
			name: "a resolve failure becomes an invalid token",
			base: func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
				return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
			},
			resolve: func(context.Context, string) (*fleet.Principal, error) {
				return nil, errResolve
			},
			wantIs:      auth.ErrInvalidToken,
			wantMessage: "revoked",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := PrincipalVerifier(tc.base, tc.resolve)
			info, err := v(t.Context(), testToken, nil)
			if info != nil {
				t.Errorf("a failed verification produced %+v", info)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.wantIs)
			}
			if tc.wantNotIs != nil && errors.Is(err, tc.wantNotIs) {
				t.Errorf("err = %v, must not be %v", err, tc.wantNotIs)
			}
			// The cause must stay reachable: an operator debugging a 401 needs
			// to know it was a revocation and not a bad signature.
			if tc.name == "a resolve failure becomes an invalid token" &&
				!errors.Is(err, errResolve) {
				t.Errorf("err = %v lost the underlying cause", err)
			}
		})
	}
}

// TestPrincipalOf covers every way the Extra map can fail to carry a
// principal. Each must give nil rather than panic: PrincipalOf is what stands
// between a wiring mistake and a crash in a tool handler.
func TestPrincipalOf(t *testing.T) {
	t.Parallel()
	p := testPrincipal("kid-1")
	tests := []struct {
		name  string
		extra map[string]any
		want  *fleet.Principal
	}{
		{name: "nil map", extra: nil},
		{name: "empty map", extra: map[string]any{}},
		{name: "key absent", extra: map[string]any{"other": p}},
		{name: "wrong type under the key", extra: map[string]any{PrincipalExtraKey: "not-a-principal"}},
		{name: "a value principal rather than a pointer",
			extra: map[string]any{PrincipalExtraKey: *p}},
		{name: "an explicit nil under the key",
			extra: map[string]any{PrincipalExtraKey: (*fleet.Principal)(nil)}},
		{name: "the real thing", extra: map[string]any{PrincipalExtraKey: p}, want: p},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := PrincipalOf(tc.extra); got != tc.want {
				t.Errorf("PrincipalOf = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrincipalExtraKeyIsNamespaced guards the key against a collision with an
// SDK or middleware key, which would let something else's value be read back
// as a principal.
func TestPrincipalExtraKeyIsNamespaced(t *testing.T) {
	t.Parallel()
	const want = "github.com/jacoknapp/prometheus-mcp-fleet/principal"
	if PrincipalExtraKey != want {
		t.Errorf("PrincipalExtraKey = %q, want %q; changing it silently drops "+
			"every principal a running hub already issued", PrincipalExtraKey, want)
	}
}

// TestUnwrappedVerifierDeniesCleanly is the regression test for a bug that
// shipped: the raw authn verifier was passed to Options.Verifier without
// [PrincipalVerifier] around it. Authentication then succeeded — the HTTP
// layer happily returned 200 on the auth check — while every tool call failed
// with "requires an authenticated principal", because TokenInfo.Extra carried
// no principal for [PrincipalOf] to find.
//
// The behaviour under test is that this misconfiguration degrades to a clean,
// diagnosable authorization denial and never to a nil-pointer panic in a tool
// handler. Both halves are asserted: the HTTP request is authenticated, and
// the tool sees a nil principal.
func TestUnwrappedVerifierDeniesCleanly(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil) // okVerifier returns a TokenInfo with no Extra.

	var sawPrincipal *fleet.Principal
	var handlerRan bool
	AddTool(s, Tool{Name: "needs_principal", Description: "d"},
		func(_ context.Context, req *Request, _ echoIn) (echoOut, Result, error) {
			handlerRan = true
			sawPrincipal = req.Principal()
			if sawPrincipal == nil {
				return echoOut{}, ErrorResult, ProtocolError(
					CodeUnauthenticated, "this tool requires an authenticated principal")
			}
			return echoOut{Text: "ok"}, OKResult, nil
		})

	sess := connect(t, s)
	_, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "needs_principal",
		Arguments: map[string]any{"text": "hello"},
	})
	if err == nil {
		t.Fatal("the call succeeded; the tool should have refused a nil principal")
	}
	if !handlerRan {
		t.Fatal("the handler never ran, so the HTTP layer refused the request; " +
			"the bug being pinned is that it does not")
	}
	if sawPrincipal != nil {
		t.Errorf("PrincipalOf recovered %v from an unwrapped verifier", sawPrincipal)
	}
	code, ok := ErrorCode(err)
	if !ok || code != CodeUnauthenticated {
		t.Errorf("error = %v (code %d, ok %v), want a CodeUnauthenticated "+
			"protocol error", err, code, ok)
	}
}

// TestWrappedVerifierReachesTheTool is the other half: with the verifier
// wrapped as intended, the principal arrives in the handler intact.
func TestWrappedVerifierReachesTheTool(t *testing.T) {
	t.Parallel()
	want := testPrincipal("kid-e2e")
	base := okVerifier()
	s := newTestServer(t, func(o *Options) {
		o.Verifier = PrincipalVerifier(
			base.TokenVerifier(),
			func(context.Context, string) (*fleet.Principal, error) { return want, nil },
		)
	})

	AddTool(s, Tool{Name: "whoami", Description: "d"},
		func(_ context.Context, req *Request, in echoIn) (echoOut, Result, error) {
			p := req.Principal()
			if p == nil {
				return echoOut{}, ErrorResult, ProtocolError(
					CodeUnauthenticated, "no principal")
			}
			return echoOut{
				Text:      in.Text,
				Subject:   req.Token.Subject,
				Principal: p.KID,
				SawHeader: req.Header != nil,
				ToolName:  req.ToolName,
			}, OKResult, nil
		})

	sess := connect(t, s)
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "whoami",
		Arguments: map[string]any{"text": "hi"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool reported an error: %+v", res.Content)
	}
	var got echoOut
	decodeStructured(t, res, &got)
	want2 := echoOut{
		Text: "hi", Subject: "kid-1", Principal: "kid-e2e",
		SawHeader: true, ToolName: "whoami",
	}
	if diff := cmp.Diff(want2, got); diff != "" {
		t.Errorf("tool output (-want +got):\n%s", diff)
	}
}
