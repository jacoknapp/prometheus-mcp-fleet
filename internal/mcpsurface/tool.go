// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// Tool is the operator-authored description of one MCP tool.
//
// Every field is written by this project. Nothing a spoke reports ever becomes
// a tool name or a tool description: the trusted layer of the surface is a
// hundred percent our own text, so a monitored cluster cannot influence what
// the model is told its instruments do.
//
// Tools registered through this package are always advertised with
// readOnlyHint true. The hub reaches Prometheus through an allow-list that
// contains no write endpoint, so there is no honest way to register anything
// else here.
type Tool struct {
	// Name is the wire name, e.g. "query_range".
	Name string
	// Title is the human-facing display name.
	Title string
	// Description is what the model reads to decide whether to call this. It
	// should state the token cost of the result and name the tool to call
	// instead when this one is the expensive choice.
	Description string
	// Idempotent advertises idempotentHint. It is meaningful to a client only
	// alongside a non-read-only tool, and is carried for completeness.
	Idempotent bool
	// OpenWorld advertises openWorldHint. It defaults to true, matching the
	// protocol default, because the fleet is an open world: clusters appear
	// and disappear as spokes connect.
	OpenWorld *bool
	// Meta is protocol _meta for the tool. It is where the x-mcp-header
	// parameter mirroring is declared.
	Meta map[string]any
	// Constraints narrow the input schema inferred from the In type. The key
	// is the property's JSON name. See [Constraint].
	Constraints map[string]Constraint
}

// TokenInfo is the authenticated caller, as a tool sees it.
type TokenInfo struct {
	// Subject is the credential's public key identifier.
	Subject string
	// Scopes are the advisory scope strings advertised to the client.
	// Authorization is never decided from them.
	Scopes []string
	// Expiration is when the credential stops being valid.
	Expiration time.Time
	// Principal is the verified principal, or nil when the request carried
	// none. Its [fleet.Scope] is the authorization document.
	Principal *fleet.Principal
}

// Request is the subset of an MCP tool call a tool implementation may see. It
// exists so a tool never names an SDK type.
type Request struct {
	// ToolName is the tool being called, which is also the name checked
	// against the principal's tool scope.
	ToolName string
	// Token is the authenticated caller, or nil.
	Token *TokenInfo
	// Header is the inbound HTTP header, or nil for a non-HTTP transport. It
	// is read-only; a tool must not mutate it.
	Header http.Header
}

// Principal returns the verified principal, or nil. It is nil-safe.
func (r *Request) Principal() *fleet.Principal {
	if r == nil || r.Token == nil {
		return nil
	}
	return r.Token.Principal
}

// Result tells the adapter how to frame a handler's output.
type Result struct {
	// IsError marks the output as a tool error: the call reached the tool and
	// the tool has something to say about the world. The model sees the
	// structured output and can self-correct. It is never used for
	// authentication or authorization failures — those are [ProtocolError].
	IsError bool
}

// ErrorResult is the [Result] for a tool error.
var ErrorResult = Result{IsError: true}

// OKResult is the [Result] for a successful call.
var OKResult = Result{}

// ToolFunc is a typed tool implementation. In and Out are Go structs; their
// JSON Schemas are inferred from `json` and `jsonschema` struct tags, so the
// schema an MCP client sees and the struct the handler receives cannot drift
// apart.
//
// Returning a non-nil error makes the call a protocol error when the error is
// one from [ProtocolError], and a tool error otherwise. Returning
// [ErrorResult] with a nil error is the normal way to report a tool error,
// because it lets the handler put a machine-readable code into Out where the
// model can act on it.
type ToolFunc[In, Out any] func(ctx context.Context, req *Request, in In) (Out, Result, error)

// AddTool registers a typed tool.
//
// Out must be a type every field of which is optional — `omitempty` or
// `omitzero` — because a tool error returns a mostly-zero Out and the SDK
// validates it against the inferred output schema before it goes on the wire.
//
// AddTool panics if the SDK cannot infer a schema for In or Out, or if a
// [Constraint] names a property that does not exist. Those are programming
// errors discovered at registration, which is to say at process start and in
// every test, rather than on the first call.
func AddTool[In, Out any](s *Server, t Tool, h ToolFunc[In, Out]) {
	openWorld := true
	if t.OpenWorld != nil {
		openWorld = *t.OpenWorld
	}
	schema, err := inputSchema[In](t)
	if err != nil {
		panic(fmt.Sprintf("mcpsurface: tool %q: %v", t.Name, err))
	}
	tool := &mcp.Tool{
		Name:        t.Name,
		Title:       t.Title,
		Description: t.Description,
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{
			Title:          t.Title,
			ReadOnlyHint:   true,
			IdempotentHint: t.Idempotent,
			OpenWorldHint:  &openWorld,
		},
	}
	if len(t.Meta) > 0 {
		tool.Meta = mcp.Meta(t.Meta)
	}
	encoded, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("mcpsurface: tool %q: encode input schema: %v", t.Name, err))
	}
	mcp.AddTool(s.mcp, tool, func(
		ctx context.Context, req *mcp.CallToolRequest, in In,
	) (*mcp.CallToolResult, Out, error) {
		out, res, err := h(ctx, adaptRequest(t.Name, req), in)
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		return &mcp.CallToolResult{IsError: res.IsError}, out, nil
	})
	s.record(&s.tools, t.Name)
	s.recordSchema(t.Name, encoded)
}

// adaptRequest projects an SDK request onto the narrow [Request] a tool sees.
func adaptRequest(name string, req *mcp.CallToolRequest) *Request {
	r := &Request{ToolName: name}
	if req == nil || req.Extra == nil {
		return r
	}
	r.Header = req.Extra.Header
	if ti := req.Extra.TokenInfo; ti != nil {
		r.Token = &TokenInfo{
			Subject:    ti.UserID,
			Scopes:     ti.Scopes,
			Expiration: ti.Expiration,
			Principal:  PrincipalOf(ti.Extra),
		}
	}
	return r
}

// PrincipalOf recovers the principal [PrincipalVerifier] stored in an
// auth.TokenInfo Extra map. It returns nil when the map is absent or carries
// something else, so a caller that forgot to wire [PrincipalVerifier] gets a
// clean authorization denial rather than a panic.
func PrincipalOf(extra map[string]any) *fleet.Principal {
	p, _ := extra[PrincipalExtraKey].(*fleet.Principal)
	return p
}
