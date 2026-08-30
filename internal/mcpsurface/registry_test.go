// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// noopTool is a handler that ignores its input; registration tests do not call
// through to it.
func noopTool(context.Context, *Request, echoIn) (echoOut, Result, error) {
	return echoOut{}, OKResult, nil
}

// TestAddToolRecordsNameAndSchema covers the registry bookkeeping and the
// schema an MCP client is shown.
func TestAddToolRecordsNameAndSchema(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	AddTool(s, Tool{
		Name:        "query_range",
		Title:       "Range query",
		Description: "Runs a PromQL range query.",
		Constraints: map[string]Constraint{
			"text": {
				Description: "the PromQL expression",
				MaxLength:   Ptr(2048),
				Examples:    []any{"up"},
			},
		},
	}, noopTool)

	if diff := cmp.Diff([]string{"query_range"}, s.ToolNames()); diff != "" {
		t.Errorf("ToolNames (-want +got):\n%s", diff)
	}

	raw, ok := s.InputSchema("query_range")
	if !ok {
		t.Fatal("InputSchema reported no schema for a registered tool")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	want := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"text": map[string]any{
				"type":        "string",
				"description": "the PromQL expression",
				"maxLength":   float64(2048),
				"examples":    []any{"up"},
			},
			"fail": map[string]any{
				"type":        "boolean",
				"description": "return a tool error",
			},
		},
		"required":             []any{"text"},
		"additionalProperties": false,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("input schema (-want +got):\n%s", diff)
	}
}

// TestInputSchemaIsACopy proves a caller cannot mutate the registry through
// the slice it is handed. The schema is a compatibility contract; handing out
// the live bytes would let a golden-file test rewrite the thing it checks.
func TestInputSchemaIsACopy(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	AddTool(s, Tool{Name: "t", Description: "d"}, noopTool)

	first, ok := s.InputSchema("t")
	if !ok {
		t.Fatal("no schema recorded")
	}
	for i := range first {
		first[i] = 'x'
	}
	second, _ := s.InputSchema("t")
	if string(second) == string(first) {
		t.Error("InputSchema returned the live buffer; mutating it corrupted the registry")
	}

	if _, ok := s.InputSchema("no_such_tool"); ok {
		t.Error("InputSchema reported a schema for an unregistered tool")
	}
}

// TestAddToolPanicsOnUnknownConstraint pins the registration-time failure. A
// constraint naming a renamed field is a guardrail that quietly stopped being
// enforced, which is why it is a panic at process start rather than a warning.
func TestAddToolPanicsOnUnknownConstraint(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("AddTool accepted a constraint on a property that does not exist")
		}
		msg, isStr := r.(string)
		if !isStr {
			t.Fatalf("panic value = %T(%v), want a string", r, r)
		}
		for _, want := range []string{"bad_tool", "no_such_property"} {
			if !strings.Contains(msg, want) {
				t.Errorf("panic message %q does not name %q", msg, want)
			}
		}
	}()
	AddTool(s, Tool{
		Name:        "bad_tool",
		Description: "d",
		Constraints: map[string]Constraint{"no_such_property": {Pattern: "^x$"}},
	}, noopTool)
}

// TestAddToolDuplicateName documents what a repeated registration does.
//
// The SDK replaces the tool with the same name, so the catalogue a client
// lists holds one entry and the *second* handler is the one that runs. This
// package's own bookkeeping appends, so ToolNames and the schema map report
// the name twice and hold the last schema. Neither is a condition production
// code reaches — registration is a compile-time-shaped list — but a test that
// did not say which one wins would leave the next reader guessing.
func TestAddToolDuplicateName(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)

	AddTool(s, Tool{Name: "dup", Description: "first"},
		func(context.Context, *Request, echoIn) (echoOut, Result, error) {
			return echoOut{Text: "first"}, OKResult, nil
		})
	AddTool(s, Tool{Name: "dup", Description: "second"},
		func(context.Context, *Request, echoIn) (echoOut, Result, error) {
			return echoOut{Text: "second"}, OKResult, nil
		})

	// The SDK replaces the tool, and this package's bookkeeping now matches:
	// a catalogue of one tool reports one name. Reporting two would make the
	// count the hub logs on startup disagree with the server it describes.
	if diff := cmp.Diff([]string{"dup"}, s.ToolNames()); diff != "" {
		t.Errorf("ToolNames (-want +got):\n%s", diff)
	}

	sess := connect(t, s)
	tools, err := sess.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	// The SDK replaces, so the catalogue holds one.
	if len(tools.Tools) != 1 {
		t.Fatalf("the catalogue holds %d tools, want 1: %+v", len(tools.Tools), tools.Tools)
	}
	if tools.Tools[0].Description != "second" {
		t.Errorf("description = %q, want the second registration to win",
			tools.Tools[0].Description)
	}

	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "dup", Arguments: map[string]any{"text": "x"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var got echoOut
	decodeStructured(t, res, &got)
	if got.Text != "second" {
		t.Errorf("handler returned %q, want the second registration to win", got.Text)
	}
}

// TestToolAnnotations pins the hints every tool registered through this
// package advertises. Read-only is not a preference here: the hub reaches
// Prometheus through an allow-list with no write endpoint in it, so there is
// no honest way to advertise anything else.
func TestToolAnnotations(t *testing.T) {
	t.Parallel()
	closedWorld := false
	s := newTestServer(t, nil)
	AddTool(s, Tool{
		Name: "default_hints", Title: "Defaults", Description: "d",
	}, noopTool)
	AddTool(s, Tool{
		Name: "closed_world", Description: "d",
		Idempotent: true, OpenWorld: &closedWorld,
		Meta: map[string]any{"x-mcp-header": "X-Cluster"},
	}, noopTool)

	sess := connect(t, s)
	tools, err := sess.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}

	def := byName["default_hints"]
	if def == nil {
		t.Fatal("default_hints was not advertised")
	}
	if !def.Annotations.ReadOnlyHint {
		t.Error("readOnlyHint is not set; every tool here is read-only by construction")
	}
	if def.Annotations.IdempotentHint {
		t.Error("idempotentHint defaulted to true")
	}
	if def.Annotations.OpenWorldHint == nil || !*def.Annotations.OpenWorldHint {
		t.Errorf("openWorldHint = %v, want true: clusters appear and disappear",
			def.Annotations.OpenWorldHint)
	}
	if def.Annotations.Title != "Defaults" {
		t.Errorf("annotation title = %q", def.Annotations.Title)
	}

	closed := byName["closed_world"]
	if closed == nil {
		t.Fatal("closed_world was not advertised")
	}
	if !closed.Annotations.IdempotentHint {
		t.Error("idempotentHint was not carried through")
	}
	if closed.Annotations.OpenWorldHint == nil || *closed.Annotations.OpenWorldHint {
		t.Error("an explicit false OpenWorld was not honoured")
	}
	if got := closed.Meta["x-mcp-header"]; got != "X-Cluster" {
		t.Errorf("_meta = %v, want the header mirroring declaration", closed.Meta)
	}
}

// TestToolErrorResult proves a tool error is framed as a result the model can
// read and correct, not as a protocol error.
func TestToolErrorResult(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	AddTool(s, Tool{Name: "maybe_fails", Description: "d"},
		func(_ context.Context, _ *Request, in echoIn) (echoOut, Result, error) {
			if in.Fail {
				return echoOut{Text: "UNKNOWN_CLUSTER"}, ErrorResult, nil
			}
			return echoOut{Text: in.Text}, OKResult, nil
		})

	sess := connect(t, s)
	for _, tc := range []struct {
		name    string
		fail    bool
		wantErr bool
		wantOut string
	}{
		{name: "success", fail: false, wantOut: "hello"},
		{name: "tool error", fail: true, wantErr: true, wantOut: "UNKNOWN_CLUSTER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "maybe_fails",
				Arguments: map[string]any{"text": "hello", "fail": tc.fail},
			})
			if err != nil {
				t.Fatalf("CallTool returned a protocol error: %v", err)
			}
			if res.IsError != tc.wantErr {
				t.Errorf("IsError = %v, want %v", res.IsError, tc.wantErr)
			}
			var got echoOut
			decodeStructured(t, res, &got)
			if got.Text != tc.wantOut {
				t.Errorf("text = %q, want %q", got.Text, tc.wantOut)
			}
		})
	}
}

// TestToolProtocolErrorIsNotAResult proves an error from [ProtocolError]
// leaves the tool-result path entirely.
func TestToolProtocolErrorIsNotAResult(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	AddTool(s, Tool{Name: "forbidden", Description: "d"},
		func(context.Context, *Request, echoIn) (echoOut, Result, error) {
			return echoOut{}, ErrorResult, ProtocolError(CodeForbidden, "out of scope")
		})

	sess := connect(t, s)
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "forbidden", Arguments: map[string]any{"text": "x"},
	})
	if err == nil {
		t.Fatalf("CallTool succeeded with %+v; a protocol error must not be a result", res)
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("error = %v, want it to carry the message", err)
	}
}

// TestAddResource covers fixed-URI registration, the MIME default, and the
// per-content override.
func TestAddResource(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	s.AddResource(Resource{
		URI: "fleet://clusters", Name: "clusters", Title: "Clusters",
		Description: "Every cluster the hub can reach.",
	}, func(_ context.Context, req *ResourceRequest) (ResourceContent, error) {
		return ResourceContent{Text: `{"uri":"` + req.URI + `"}`}, nil
	})
	s.AddResource(Resource{
		URI: "fleet://readme", Name: "readme", MIMEType: MIMETypeMarkdown,
	}, func(context.Context, *ResourceRequest) (ResourceContent, error) {
		return ResourceContent{Text: "# hi"}, nil
	})
	s.AddResource(Resource{
		URI: "fleet://override", Name: "override",
	}, func(context.Context, *ResourceRequest) (ResourceContent, error) {
		return ResourceContent{MIMEType: "text/plain", Text: "plain"}, nil
	})

	want := []string{"fleet://clusters", "fleet://readme", "fleet://override"}
	if diff := cmp.Diff(want, s.ResourceURIs()); diff != "" {
		t.Errorf("ResourceURIs (-want +got):\n%s", diff)
	}

	sess := connect(t, s)
	for _, tc := range []struct {
		uri      string
		wantMIME string
		wantText string
	}{
		{uri: "fleet://clusters", wantMIME: MIMETypeJSON, wantText: `{"uri":"fleet://clusters"}`},
		{uri: "fleet://readme", wantMIME: MIMETypeMarkdown, wantText: "# hi"},
		{uri: "fleet://override", wantMIME: "text/plain", wantText: "plain"},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			t.Parallel()
			res, err := sess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: tc.uri})
			if err != nil {
				t.Fatalf("ReadResource: %v", err)
			}
			if len(res.Contents) != 1 {
				t.Fatalf("got %d contents, want 1", len(res.Contents))
			}
			c := res.Contents[0]
			if c.URI != tc.uri || c.MIMEType != tc.wantMIME || c.Text != tc.wantText {
				t.Errorf("content = %+v, want uri %q mime %q text %q",
					c, tc.uri, tc.wantMIME, tc.wantText)
			}
		})
	}
}

// TestAddResourceTemplate covers parameterised registration and the URI
// substitution a handler sees.
func TestAddResourceTemplate(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	s.AddResourceTemplate(ResourceTemplate{
		URITemplate: "fleet://clusters/{name}", Name: "cluster",
		Title: "Cluster", Description: "One cluster's facts.",
	}, func(_ context.Context, req *ResourceRequest) (ResourceContent, error) {
		return ResourceContent{Text: req.URI}, nil
	})

	if diff := cmp.Diff([]string{"fleet://clusters/{name}"}, s.ResourceTemplateURIs()); diff != "" {
		t.Errorf("ResourceTemplateURIs (-want +got):\n%s", diff)
	}
	if len(s.ResourceURIs()) != 0 {
		t.Errorf("a template was recorded as a fixed resource: %v", s.ResourceURIs())
	}

	sess := connect(t, s)
	templates, err := sess.ListResourceTemplates(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	if len(templates.ResourceTemplates) != 1 ||
		templates.ResourceTemplates[0].URITemplate != "fleet://clusters/{name}" {
		t.Fatalf("templates = %+v", templates.ResourceTemplates)
	}
	if templates.ResourceTemplates[0].MIMEType != MIMETypeJSON {
		t.Errorf("MIMEType = %q, want the JSON default",
			templates.ResourceTemplates[0].MIMEType)
	}

	res, err := sess.ReadResource(t.Context(),
		&mcp.ReadResourceParams{URI: "fleet://clusters/prod-eu-1"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if got := res.Contents[0].Text; got != "fleet://clusters/prod-eu-1" {
		t.Errorf("the handler saw URI %q, want the substituted one", got)
	}
}

// TestResourceHandlerError proves a resource read failure is a protocol error.
func TestResourceHandlerError(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	s.AddResource(Resource{URI: "fleet://broken", Name: "broken"},
		func(context.Context, *ResourceRequest) (ResourceContent, error) {
			return ResourceContent{}, ProtocolError(CodeInvalidParams, "no such cluster")
		})

	sess := connect(t, s)
	if _, err := sess.ReadResource(t.Context(),
		&mcp.ReadResourceParams{URI: "fleet://broken"}); err == nil {
		t.Fatal("a failing resource read succeeded")
	} else if !strings.Contains(err.Error(), "no such cluster") {
		t.Errorf("error = %v, want it to carry the message", err)
	}
}

// TestResourceSeesPrincipal proves the authenticated caller reaches a resource
// handler by the same route it reaches a tool.
func TestResourceSeesPrincipal(t *testing.T) {
	t.Parallel()
	want := testPrincipal("kid-res")
	s := newTestServer(t, func(o *Options) {
		o.Verifier = PrincipalVerifier(
			okVerifier().TokenVerifier(),
			func(context.Context, string) (*fleet.Principal, error) { return want, nil },
		)
	})
	s.AddResource(Resource{URI: "fleet://me", Name: "me"},
		func(_ context.Context, req *ResourceRequest) (ResourceContent, error) {
			p := req.Principal()
			if p == nil {
				return ResourceContent{Text: "anonymous"}, nil
			}
			return ResourceContent{Text: p.KID + "/" + req.Token.Subject}, nil
		})

	sess := connect(t, s)
	res, err := sess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "fleet://me"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if got := res.Contents[0].Text; got != "kid-res/kid-1" {
		t.Errorf("resource saw %q, want kid-res/kid-1", got)
	}
}

// TestAddPrompt covers prompt registration, the argument list and the role
// default.
func TestAddPrompt(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	s.AddPrompt(Prompt{
		Name: "investigate_alert", Title: "Investigate an alert",
		Description: "Walks an incident from alert to root cause.",
		Arguments: []PromptArgument{
			{Name: "alert", Title: "Alert", Description: "the alert name", Required: true},
			{Name: "cluster", Description: "optional cluster"},
		},
	}, func(_ context.Context, args map[string]string) (PromptResult, error) {
		return PromptResult{
			Description: "investigating " + args["alert"],
			Messages: []PromptMessage{
				{Text: "start with " + args["alert"]}, // no Role: defaults to user
				{Role: RoleAssistant, Text: "acknowledged"},
			},
		}, nil
	})

	if diff := cmp.Diff([]string{"investigate_alert"}, s.PromptNames()); diff != "" {
		t.Errorf("PromptNames (-want +got):\n%s", diff)
	}

	sess := connect(t, s)
	list, err := sess.ListPrompts(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(list.Prompts) != 1 {
		t.Fatalf("got %d prompts", len(list.Prompts))
	}
	args := list.Prompts[0].Arguments
	if len(args) != 2 || args[0].Name != "alert" || !args[0].Required || args[1].Required {
		t.Errorf("arguments = %+v", args)
	}

	got, err := sess.GetPrompt(t.Context(), &mcp.GetPromptParams{
		Name: "investigate_alert", Arguments: map[string]string{"alert": "HighLatency"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if got.Description != "investigating HighLatency" {
		t.Errorf("description = %q", got.Description)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("got %d messages", len(got.Messages))
	}
	if got.Messages[0].Role != mcp.Role(RoleUser) {
		t.Errorf("role = %q, want the user default", got.Messages[0].Role)
	}
	if got.Messages[1].Role != mcp.Role(RoleAssistant) {
		t.Errorf("role = %q, want assistant", got.Messages[1].Role)
	}
	text, ok := got.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("content = %T, want *mcp.TextContent", got.Messages[0].Content)
	}
	if text.Text != "start with HighLatency" {
		t.Errorf("text = %q", text.Text)
	}
}

// TestPromptHandlerError proves a prompt failure is a protocol error.
func TestPromptHandlerError(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	s.AddPrompt(Prompt{Name: "broken"},
		func(context.Context, map[string]string) (PromptResult, error) {
			return PromptResult{}, ProtocolError(CodeInvalidParams, "missing alert")
		})

	sess := connect(t, s)
	if _, err := sess.GetPrompt(t.Context(),
		&mcp.GetPromptParams{Name: "broken"}); err == nil {
		t.Fatal("a failing prompt succeeded")
	} else if !strings.Contains(err.Error(), "missing alert") {
		t.Errorf("error = %v", err)
	}
}

// TestRegistrationIsConcurrencySafe exercises the mutex the snapshot and
// record helpers share. It exists for the race detector rather than for its
// assertions.
func TestRegistrationIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 50 {
			s.AddResource(Resource{
				URI:  "fleet://r" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
				Name: "r",
			}, func(context.Context, *ResourceRequest) (ResourceContent, error) {
				return ResourceContent{}, nil
			})
		}
	}()
	for range 50 {
		_ = s.ResourceURIs()
		_ = s.ToolNames()
		_, _ = s.InputSchema("nope")
	}
	<-done
	if len(s.ResourceURIs()) != 50 {
		t.Errorf("recorded %d resources, want 50", len(s.ResourceURIs()))
	}
}

// TestAdaptRequest covers every nil the SDK can hand the adapter. A tool call
// that arrives over stdio has no HTTP request behind it, so none of these is
// hypothetical.
func TestAdaptRequest(t *testing.T) {
	t.Parallel()
	p := testPrincipal("kid-adapt")
	expiry := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	header := http.Header{"X-Cluster": []string{"prod-eu-1"}}

	tests := []struct {
		name string
		req  *mcp.CallToolRequest
		want *Request
	}{
		{
			name: "a nil request",
			req:  nil,
			want: &Request{ToolName: "query"},
		},
		{
			name: "a request with no Extra",
			req:  &mcp.CallToolRequest{},
			want: &Request{ToolName: "query"},
		},
		{
			name: "Extra with no TokenInfo",
			req:  &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: header}},
			want: &Request{ToolName: "query", Header: header},
		},
		{
			name: "TokenInfo with no Extra map",
			req: &mcp.CallToolRequest{Extra: &mcp.RequestExtra{
				Header:    header,
				TokenInfo: &auth.TokenInfo{UserID: "kid-1", Expiration: expiry},
			}},
			want: &Request{
				ToolName: "query", Header: header,
				Token: &TokenInfo{Subject: "kid-1", Expiration: expiry},
			},
		},
		{
			name: "the fully wired case",
			req: &mcp.CallToolRequest{Extra: &mcp.RequestExtra{
				Header: header,
				TokenInfo: &auth.TokenInfo{
					UserID: "kid-1", Scopes: []string{"mcp"}, Expiration: expiry,
					Extra: map[string]any{PrincipalExtraKey: p},
				},
			}},
			want: &Request{
				ToolName: "query", Header: header,
				Token: &TokenInfo{
					Subject: "kid-1", Scopes: []string{"mcp"},
					Expiration: expiry, Principal: p,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := adaptRequest("query", tc.req)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("adaptRequest (-want +got):\n%s", diff)
			}
			// Whatever arrived, reading the principal must not panic.
			if got.Principal() != tc.want.Principal() {
				t.Errorf("Principal() = %v", got.Principal())
			}
		})
	}
}

// TestNilSafeAccessors covers the nil receivers a handler can legitimately
// hold.
func TestNilSafeAccessors(t *testing.T) {
	t.Parallel()
	var nilReq *Request
	if got := nilReq.Principal(); got != nil {
		t.Errorf("(*Request)(nil).Principal() = %v", got)
	}
	if got := (&Request{}).Principal(); got != nil {
		t.Errorf("Request{}.Principal() = %v", got)
	}
	if got := (&Request{Token: &TokenInfo{}}).Principal(); got != nil {
		t.Errorf("Request with an empty token returned %v", got)
	}

	var nilRes *ResourceRequest
	if got := nilRes.Principal(); got != nil {
		t.Errorf("(*ResourceRequest)(nil).Principal() = %v", got)
	}
	if got := (&ResourceRequest{}).Principal(); got != nil {
		t.Errorf("ResourceRequest{}.Principal() = %v", got)
	}
	p := testPrincipal("kid")
	if got := (&ResourceRequest{Token: &TokenInfo{Principal: p}}).Principal(); got != p {
		t.Errorf("ResourceRequest.Principal() = %v, want %v", got, p)
	}
}

// TestPtr covers the pointer helper Constraint literals are written with.
func TestPtr(t *testing.T) {
	t.Parallel()
	if got := Ptr(42); got == nil || *got != 42 {
		t.Errorf("Ptr(42) = %v", got)
	}
	if got := Ptr(1.5); got == nil || *got != 1.5 {
		t.Errorf("Ptr(1.5) = %v", got)
	}
	if got := Ptr("s"); got == nil || *got != "s" {
		t.Errorf("Ptr(\"s\") = %v", got)
	}
	a, b := Ptr(1), Ptr(1)
	if a == b {
		t.Error("Ptr returned the same address twice")
	}
}
