// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// principalKey is the unexported context key for the authenticated principal.
// Using a private zero-size struct type makes the value unreachable from any
// other package except through [PrincipalFrom], so no handler can inject a
// principal it did not earn.
type principalKey struct{}

// sourceIPKey is the unexported context key for the caller's source address.
type sourceIPKey struct{}

// ContextWithPrincipal returns a copy of ctx carrying p as the authenticated
// principal. It is called by [Verifier.Middleware]; handlers should only ever
// read the principal back out with [PrincipalFrom].
func ContextWithPrincipal(ctx context.Context, p *fleet.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated principal stored in ctx, or nil when
// the request was not authenticated. A nil return is always safe to use with
// [fleet.Principal.String] and with the Scope helpers, both of which are
// nil-tolerant and deny by default.
func PrincipalFrom(ctx context.Context) *fleet.Principal {
	p, _ := ctx.Value(principalKey{}).(*fleet.Principal)
	return p
}

// ContextWithSourceIP returns a copy of ctx carrying the caller's source
// address, which [Verifier.Verify] uses for per-source failure rate limiting.
//
// [Verifier.Middleware] and [Verifier.TokenVerifier] set it from
// http.Request.RemoteAddr. Forwarded-for headers are deliberately not
// consulted: they are attacker-controlled, and honouring them would let a
// single client mint an unlimited number of rate-limit buckets. A composition
// root running behind a trusted proxy may set the value itself.
func ContextWithSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, ip)
}

// SourceIPFrom returns the source address stored in ctx, or the empty string.
func SourceIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(sourceIPKey{}).(string)
	return ip
}
