// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// RequestIDHeader is the header the middleware copies into its error envelope
// so a 401 can be correlated with the hub's own log line. It is read from the
// response first, because the request-id middleware stamps it there before the
// handler chain runs.
const RequestIDHeader = "X-Request-Id"

// Middleware returns HTTP middleware that authenticates the request's bearer
// credential and, on success, calls the next handler with the principal in the
// request context.
//
// On failure it writes 401 (or 429 when the source address is in failure
// backoff) with the project's JSON error envelope and a WWW-Authenticate
// challenge. The challenge is RFC 6750-shaped -- realm, scope and an
// error/error_description pair -- so a spec-compliant MCP client produces a
// coherent diagnostic even though this hub issues static bearer keys rather
// than OAuth access tokens; see the protected-resource document served by
// internal/hubapi.
//
// Neither the response body, the challenge nor any log line ever contains the
// offending credential, or any part of it.
func (v *Verifier) Middleware(want fleet.KeyClass) func(http.Handler) http.Handler {
	scope := ScopeName(want)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := BearerToken(r)
			if !ok {
				v.metrics.AuthFailure(ReasonMissing)
				v.deny(w, r, scope, http.StatusUnauthorized, "unauthenticated", "a bearer credential is required")
				return
			}
			ctx := ContextWithSourceIP(r.Context(), SourceAddr(r))
			p, err := v.Verify(ctx, raw, want)
			if err != nil {
				v.log.LogAttrs(ctx, slog.LevelInfo, "request denied",
					slog.String("path", r.URL.Path),
					slog.String("method", r.Method),
					slog.String("error", err.Error()))
				if errors.Is(err, ErrRateLimited) {
					v.deny(w, r, scope, http.StatusTooManyRequests, "rate_limited",
						"too many authentication failures from this source")
					return
				}
				// Every other outcome answers 401 with one message. Telling a
				// caller apart from "unknown key", "wrong secret", "expired",
				// "revoked" and "wrong class" would hand an attacker a probe
				// for which credentials exist and which are still live.
				v.deny(w, r, scope, http.StatusUnauthorized, "unauthenticated", "the presented credential is not valid")
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithPrincipal(ctx, p)))
		})
	}
}

// TokenVerifier adapts [Verifier.Verify] to the MCP SDK's auth.TokenVerifier
// signature, for use with auth.RequireBearerToken and the streamable HTTP
// handler.
//
// Failures are returned wrapped in auth.ErrInvalidToken so the SDK middleware
// answers 401 rather than 500; the wrapped sentinel from this package is
// preserved alongside it, so a caller of this function directly can still use
// errors.Is to tell an expired credential from a revoked one. The error text
// never contains the token.
//
// The returned auth.TokenInfo carries the key identifier as UserID -- it is
// public by design -- the credential's own expiry, and a scope list derived
// from the key's [fleet.Scope]. The scope list is advisory metadata for the
// client: authorization is enforced by internal/promproxy and internal/mcptools
// against the [fleet.Scope] on the principal, never against these strings.
func (v *Verifier) TokenVerifier(want fleet.KeyClass) func(ctx context.Context, tok string, r *http.Request) (*auth.TokenInfo, error) {
	return func(ctx context.Context, tok string, r *http.Request) (*auth.TokenInfo, error) {
		if r != nil {
			ctx = ContextWithSourceIP(ctx, SourceAddr(r))
		}
		p, expiry, err := v.verify(ctx, tok, want)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
		}
		if expiry.IsZero() {
			// The SDK middleware rejects a TokenInfo with no expiration. A
			// stored key without one is re-verified against the store every
			// CacheTTL anyway, so that is the honest horizon to advertise.
			expiry = v.clock().Add(v.cacheTTL)
		}
		return &auth.TokenInfo{
			Scopes:     ScopesOf(p),
			Expiration: expiry,
			UserID:     p.KID,
			Extra: map[string]any{
				"class": string(p.Class),
				"role":  string(p.Role),
				"name":  p.Name,
			},
		}, nil
	}
}

// ScopeName returns the WWW-Authenticate scope token advertised for a
// credential class. It is a closed mapping: no caller input reaches it.
func ScopeName(class fleet.KeyClass) string {
	switch class {
	case fleet.ClassAdmin:
		return "admin"
	case fleet.ClassEnrollment:
		return "enroll"
	default:
		return "mcp"
	}
}

// ScopesOf renders a principal's authorization as the flat scope strings the
// MCP protocol expects. It emits the role and the tool allow-list, never a
// cluster identifier, so the list cannot be used to enumerate the fleet.
func ScopesOf(p *fleet.Principal) []string {
	if p == nil {
		return nil
	}
	scopes := make([]string, 0, 2)
	scopes = append(scopes, "class:"+string(p.Class))
	if p.Role != "" {
		scopes = append(scopes, "role:"+string(p.Role))
	}
	if p.Scope != nil {
		for _, t := range p.Scope.Tools.Allow {
			scopes = append(scopes, "tool:"+t)
		}
	}
	return scopes
}

// BearerToken extracts the credential from an Authorization header. It reports
// false when the header is absent or is not exactly two whitespace-separated
// fields whose first field is "bearer", case-insensitively per RFC 7235.
func BearerToken(r *http.Request) (string, bool) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bearer") {
		return "", false
	}
	return fields[1], true
}

// SourceAddr returns the host portion of the request's remote address, for
// per-source failure accounting. Forwarded-for headers are ignored on purpose:
// they are set by the client, so honouring them would let one caller mint an
// unlimited number of rate-limit buckets.
func SourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// deny writes the challenge and the JSON error envelope for a rejected
// request.
func (v *Verifier) deny(w http.ResponseWriter, r *http.Request, scope string, status int, code, message string) {
	params := []string{fmt.Sprintf("realm=%q", v.realm), fmt.Sprintf("scope=%q", scope)}
	if v.resourceMD != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", v.resourceMD))
	}
	if status == http.StatusUnauthorized {
		params = append(params,
			fmt.Sprintf("error=%q", "invalid_token"),
			fmt.Sprintf("error_description=%q", message))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId,omitempty"`
		} `json:"error"`
	}{}
	body.Error.Code = code
	body.Error.Message = message
	body.Error.RequestID = requestID(w, r)
	_ = json.NewEncoder(w).Encode(body)
}

// requestID returns the correlation id stamped on the response or, failing
// that, the one the client supplied.
func requestID(w http.ResponseWriter, r *http.Request) string {
	if id := w.Header().Get(RequestIDHeader); id != "" {
		return id
	}
	return r.Header.Get(RequestIDHeader)
}
