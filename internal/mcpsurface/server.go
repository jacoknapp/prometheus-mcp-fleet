// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// Defaults applied by [New] when the corresponding [Options] field is zero.
const (
	// DefaultMaxRequestBodyBytes caps an inbound MCP request body. Tool
	// arguments are a few kilobytes at most; the ceiling exists so an
	// authenticated caller cannot spend the hub's memory.
	DefaultMaxRequestBodyBytes = 1 << 20
	// DefaultPageSize is the list-method page size. It is set well above the
	// tool count so a client sees the whole catalogue in one round trip.
	DefaultPageSize = 250
	// DefaultServerName is the implementation name advertised to clients.
	DefaultServerName = "prometheus-mcp-fleet"
)

// TokenVerifier is the credential check the HTTP layer applies before any tool
// runs. It mirrors the SDK's own signature so [authn.Verifier.TokenVerifier]
// can be passed straight in, and is declared here so callers do not have to
// name an SDK type.
type TokenVerifier = func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error)

// Options configures a [Server]. Every field has a documented default except
// Verifier, which is required: an unauthenticated MCP endpoint onto a hundred
// production Prometheus servers is not a configuration this package will
// build.
type Options struct {
	// Name is the implementation name advertised to clients. Empty means
	// [DefaultServerName].
	Name string
	// Title is the human-facing name. Empty means Name.
	Title string
	// Version is the implementation version. Empty means "0.0.0-dev".
	Version string
	// Instructions is the server-level guidance sent to clients. It is
	// operator-authored: nothing reported by a spoke ever reaches it.
	Instructions string
	// Logger receives SDK and transport events. Nil discards them.
	Logger *slog.Logger
	// PageSize bounds list-method pages. Zero means [DefaultPageSize].
	PageSize int
	// MaxRequestBodyBytes caps an inbound request body. Zero means
	// [DefaultMaxRequestBodyBytes]; negative disables the cap and must not be
	// used on an exposed listener.
	MaxRequestBodyBytes int64
	// Verifier authenticates the bearer credential. Required.
	Verifier TokenVerifier
	// ResourceMetadataURL is advertised as resource_metadata in the
	// WWW-Authenticate challenge on a 401. The document itself is served by
	// internal/hubapi's public mux, which owns the RFC 9728 route; this
	// package only points at it.
	ResourceMetadataURL string
	// RequiredScopes, when set, are enforced by the bearer middleware in
	// addition to the per-tool scope check. It is normally left empty:
	// authorization in this project is a [fleet.Scope] decision, and a flat
	// scope string is a second, weaker copy of it.
	RequiredScopes []string
	// TrustedOrigins are additional origins permitted to make cross-site
	// requests to the MCP endpoint. Same-origin requests and requests with no
	// Origin or Sec-Fetch-Site header — which is every non-browser client —
	// are always permitted.
	TrustedOrigins []string
	// DisableCrossOriginProtection turns off Origin validation. It exists for
	// tests and for a deployment that terminates its own CSRF defence in
	// front of the hub; the spec requires the check otherwise.
	DisableCrossOriginProtection bool
	// KeepAlive sets the SDK's ping interval. Zero disables it, which is
	// correct for a stateless POST-only transport where there is no session
	// to keep alive.
	KeepAlive time.Duration
}

// Server is the hub's MCP surface: an SDK server plus the HTTP plumbing that
// authenticates callers and speaks Streamable HTTP to them.
type Server struct {
	mcp  *mcp.Server
	opts Options

	mu        sync.Mutex
	tools     []string
	resources []string
	templates []string
	prompts   []string
	schemas   map[string][]byte
}

// New returns a Server configured by opts. It reports an error only for a
// configuration mistake, never for a runtime condition.
func New(opts Options) (*Server, error) {
	if opts.Verifier == nil {
		return nil, errors.New("mcpsurface: Options.Verifier is required")
	}
	if opts.Name == "" {
		opts.Name = DefaultServerName
	}
	if opts.Title == "" {
		opts.Title = opts.Name
	}
	if opts.Version == "" {
		opts.Version = "0.0.0-dev"
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.PageSize <= 0 {
		opts.PageSize = DefaultPageSize
	}
	if opts.MaxRequestBodyBytes == 0 {
		opts.MaxRequestBodyBytes = DefaultMaxRequestBodyBytes
	}
	impl := &mcp.Implementation{
		Name:    opts.Name,
		Title:   opts.Title,
		Version: opts.Version,
	}
	srv := mcp.NewServer(impl, &mcp.ServerOptions{
		Instructions: opts.Instructions,
		Logger:       opts.Logger,
		PageSize:     opts.PageSize,
		KeepAlive:    opts.KeepAlive,
	})
	return &Server{mcp: srv, opts: opts, schemas: map[string][]byte{}}, nil
}

// MCPServer exposes the underlying SDK server. It is the one deliberate hole
// in this package's firewall, for a composition root that must run the server
// over a transport this package does not wrap — notably stdio. Tool code must
// not use it.
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// ToolNames returns the registered tool names in registration order.
func (s *Server) ToolNames() []string { return s.snapshot(&s.tools) }

// ResourceURIs returns the registered resource URIs in registration order.
func (s *Server) ResourceURIs() []string { return s.snapshot(&s.resources) }

// ResourceTemplateURIs returns the registered resource template URI patterns.
func (s *Server) ResourceTemplateURIs() []string { return s.snapshot(&s.templates) }

// PromptNames returns the registered prompt names in registration order.
func (s *Server) PromptNames() []string { return s.snapshot(&s.prompts) }

func (s *Server) snapshot(p *[]string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(*p)
}

// record adds name to a registration list, replacing an existing entry rather
// than appending a second one.
//
// The SDK replaces a tool registered twice under the same name, so appending
// here would make ToolNames report a catalogue larger than the one that
// actually exists. The hub logs that count on startup, so the discrepancy would
// be a number an operator reads and trusts while it quietly disagrees with the
// server.
func (s *Server) record(p *[]string, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(*p, name) {
		return
	}
	*p = append(*p, name)
}

// InputSchema returns the advertised JSON Schema of a registered tool's
// arguments, indented, or false when no such tool is registered.
//
// It exists so the schema can be checked into the repository as a golden file.
// An MCP tool's input schema is a compatibility contract with every client
// that has ever called it, and a contract that can change without a reviewable
// diff is not a contract.
func (s *Server) InputSchema(tool string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.schemas[tool]
	if !ok {
		return nil, false
	}
	return slices.Clone(b), true
}

// recordSchema stores a tool's advertised input schema.
func (s *Server) recordSchema(tool string, schema []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.schemas[tool] = schema
}

// Handler returns the authenticated Streamable HTTP handler for the MCP
// endpoint.
//
// The chain, outermost first, is: cross-origin protection, bearer
// authentication, then the stateless streamable transport. Authentication is
// outside the transport on purpose — a caller with no credential must be
// refused before any JSON-RPC framing is parsed on its behalf.
func (s *Server) Handler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{
			// Revision 2026-07-28 removed protocol sessions. Stateless means
			// the handler neither reads nor sets Mcp-Session-Id and answers
			// GET and DELETE with 405, which is exactly the spec's shape.
			Stateless:           true,
			Logger:              s.opts.Logger,
			MaxRequestBodyBytes: s.opts.MaxRequestBodyBytes,
			// The POST is the whole request lifecycle now, so a client that
			// hangs up should cancel the fan-out it started rather than leave
			// a hundred spoke queries running.
			PropagateRequestCancellation: true,
		})

	var h http.Handler = streamable
	h = auth.RequireBearerToken(auth.TokenVerifier(s.opts.Verifier), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.opts.ResourceMetadataURL,
		Scopes:              s.opts.RequiredScopes,
	})(h)
	if !s.opts.DisableCrossOriginProtection {
		cop := http.NewCrossOriginProtection()
		for _, o := range s.opts.TrustedOrigins {
			// An unparseable origin is a configuration mistake, and refusing
			// to start on it would take the hub down for a typo. Log and skip.
			if err := cop.AddTrustedOrigin(o); err != nil {
				s.opts.Logger.Warn("mcpsurface: ignoring untrusted origin", "origin", o, "error", err)
			}
		}
		h = cop.Handler(h)
	}
	return h
}

// Mount registers the MCP endpoint on mux. pattern is a Go 1.22 ServeMux
// pattern and should name the method explicitly, for example "POST /mcp".
func (s *Server) Mount(mux *http.ServeMux, pattern string) {
	mux.Handle(pattern, s.Handler())
}

// Application-defined JSON-RPC error codes, drawn from the -32000..-32099
// range the JSON-RPC 2.0 specification reserves for implementation-defined
// server errors.
const (
	// CodeUnauthenticated reports a request that carried no usable principal.
	// It should be unreachable behind the bearer middleware and exists so a
	// tool never has to guess.
	CodeUnauthenticated int64 = -32001
	// CodeForbidden reports that the authenticated principal's scope does not
	// permit the tool. It is a protocol error rather than a tool result
	// because an authorization failure is not a fact about the monitored
	// world, and a model that sees one as tool output will try to fix it by
	// editing its query.
	CodeForbidden int64 = -32003
	// CodeInvalidParams mirrors the standard JSON-RPC code for arguments that
	// could not be interpreted at all.
	CodeInvalidParams int64 = jsonrpc.CodeInvalidParams
)

// ProtocolError returns an error that the SDK reports as a JSON-RPC error
// rather than packing into a tool result. Use it only for conditions the model
// must not attempt to work around: authentication, authorization, and
// arguments so malformed that no tool semantics apply.
func ProtocolError(code int64, format string, args ...any) error {
	return &jsonrpc.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// PrincipalExtraKey is the key under which [PrincipalVerifier] stores the
// verified principal in auth.TokenInfo.Extra.
const PrincipalExtraKey = "github.com/jacoknapp/prometheus-mcp-fleet/principal"

// PrincipalVerifier adapts an [authn.Verifier] into a [TokenVerifier] that
// additionally carries the verified [fleet.Principal] to the tool layer.
//
// base should be authn.Verifier.TokenVerifier(class): it produces the
// auth.TokenInfo the SDK middleware requires, including the expiry the
// middleware refuses to run without. resolve should be authn.Verifier.Verify
// for the same class; it runs immediately afterwards and is served from that
// verifier's positive cache, so the second call is a map lookup rather than a
// second HMAC and a second store read.
//
// The principal travels in TokenInfo.Extra rather than in the request context
// because the SDK hands a tool handler its request, not the HTTP request the
// context belongs to. [fleet.Principal] carries no secret material, which is
// what makes that safe.
func PrincipalVerifier(
	base TokenVerifier,
	resolve func(ctx context.Context, token string) (*fleet.Principal, error),
) TokenVerifier {
	return func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		info, err := base(ctx, token, req)
		if err != nil {
			return nil, err
		}
		p, err := resolve(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
		}
		if info.Extra == nil {
			info.Extra = make(map[string]any, 1)
		}
		info.Extra[PrincipalExtraKey] = p
		return info, nil
	}
}

// StaticTokenVerifier returns a [TokenVerifier] that accepts exactly one
// credential and resolves it to one principal.
//
// It exists for the stdio transport, where the MCP specification says
// credentials come from the environment rather than from an authorization
// server, and for tests. It is not appropriate for the HTTP listener: a single
// shared secret cannot be revoked without restarting the process and gives
// every caller the same scope. Use [PrincipalVerifier] over an authn.Verifier
// there.
//
// The comparison is constant time. An empty token is refused outright rather
// than matching an unset credential.
func StaticTokenVerifier(token string, p *fleet.Principal, ttl time.Duration) TokenVerifier {
	want := []byte(token)
	return func(_ context.Context, presented string, _ *http.Request) (*auth.TokenInfo, error) {
		got := []byte(presented)
		if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
			return nil, auth.ErrInvalidToken
		}
		if ttl <= 0 {
			ttl = time.Hour
		}
		info := &auth.TokenInfo{
			Expiration: time.Now().Add(ttl),
			Extra:      map[string]any{PrincipalExtraKey: p},
		}
		if p != nil {
			info.UserID = p.KID
		}
		return info, nil
	}
}

// ErrorCode recovers the JSON-RPC code from an error built by [ProtocolError],
// reporting false for any other error.
//
// It exists so a caller — chiefly a test in internal/mcptools — can assert that
// a failure was framed as a protocol error rather than a tool result, without
// naming an SDK type of its own.
func ErrorCode(err error) (int64, bool) {
	var e *jsonrpc.Error
	if errors.As(err, &e) {
		return e.Code, true
	}
	return 0, false
}
