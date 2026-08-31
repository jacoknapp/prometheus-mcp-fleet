// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// e2eBearerTransport attaches the fixed test bearer credential to every
// outbound request, mirroring mcpsurface's own test transport: it is the
// only hook the SDK's HTTP client offers for authenticating a session.
type e2eBearerTransport struct{ token string }

func (b e2eBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(clone)
}

// connectRegistered serves a fully registered server over httptest and
// returns a connected SDK client session. This is the only way to exercise
// the exact ToolFunc closures [Register] installs: calling t.tools.query
// directly, or rebuilding the wrapper with [run] in a test file, executes a
// different closure at a different source line and cannot cover register.go
// itself. Both the server and the session are torn down by t.Cleanup.
func connectRegistered(t *testing.T) (*mcp.ClientSession, *harness) {
	t.Helper()
	s, h := newRegisteredServer(t)
	httpSrv := httptest.NewServer(s.Handler())
	t.Cleanup(httpSrv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   httpSrv.URL,
		HTTPClient: &http.Client{Transport: e2eBearerTransport{token: "test-token"}},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess, h
}

// toolStructuredError decodes the "error" object every ToolError-carrying
// envelope embeds when a call fails.
type toolStructuredError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type toolStructuredResult struct {
	Error *toolStructuredError `json:"error"`
}

// TestRegisteredToolsProduceBusinessErrors calls each tool that can fail for
// a reason the input schema does not already foreclose, through the exact
// server [Register] builds. This is what makes run's zero-result factory
// closures in register.go execute: they run only on the path where fn
// returns a non-nil *ToolError, and a schema-guarded argument (an enum, a
// bound) never reaches the Go handler at all — the SDK rejects it first (see
// TestSchemaGuardedArgumentsNeverReachTheHandler). An unrecognised cluster
// name is not schema-guarded, because a cluster identity is an open string
// the registry resolves at call time, so it is the one input that legitimately
// drives every cluster-scoped tool's error path end to end.
func TestRegisteredToolsProduceBusinessErrors(t *testing.T) {
	t.Parallel()
	const badCluster = "does-not-exist-xyz"

	tests := []struct {
		tool string
		args map[string]any
		want string
	}{
		{ToolDescribeCluster, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolQuery, map[string]any{"cluster": badCluster, "query": "up"}, CodeUnknownCluster},
		{ToolQueryRange, map[string]any{"cluster": badCluster, "query": "up"}, CodeUnknownCluster},
		{ToolSearchMetrics, map[string]any{"cluster": badCluster, "pattern": "up"}, CodeUnknownCluster},
		{ToolMetricMetadata, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolSeries, map[string]any{"cluster": badCluster, "matchers": []string{"up"}}, CodeUnknownCluster},
		{ToolLabelNames, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolLabelValues, map[string]any{"cluster": badCluster, "label": "job"}, CodeUnknownCluster},
		{ToolTargets, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolRules, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolAlerts, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolTSDBStats, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		{ToolRuntimeInfo, map[string]any{"cluster": badCluster}, CodeUnknownCluster},
		// fanout_query has no single "cluster" field; its query is validated
		// centrally before any cluster is contacted, and an unparsable
		// expression is exactly as open-ended as a bad cluster name.
		{ToolFanoutQuery, map[string]any{"query": "sum(((("}, CodePromQLParse},
	}

	sess, _ := connectRegistered(t)
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
				Name: tc.tool, Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !res.IsError {
				t.Fatalf("tool %q succeeded, want a business error", tc.tool)
			}
			var got toolStructuredResult
			decodeCallToolResult(t, res, &got)
			if got.Error == nil {
				t.Fatalf("tool %q result carried no error envelope: %+v", tc.tool, res.StructuredContent)
			}
			if got.Error.Code != tc.want {
				t.Errorf("tool %q error code = %q, want %q", tc.tool, got.Error.Code, tc.want)
			}
		})
	}
}

// TestSchemaGuardedArgumentsNeverReachTheHandler documents, as an executable
// fact rather than a comment, why list_clusters and explain_promql cannot be
// driven to a *ToolError through this server: every argument that could make
// them fail is a closed enum the input schema already carries, so the SDK
// refuses the call before mcptools sees it, and explain_promql's own
// business logic never returns a *ToolError at all — an invalid expression
// is a successful, documented answer, not a failure.
func TestSchemaGuardedArgumentsNeverReachTheHandler(t *testing.T) {
	t.Parallel()
	sess, _ := connectRegistered(t)

	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: ToolListClusters, Arguments: map[string]any{"status": "not-a-real-status"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("an out-of-enum status was not rejected")
	}
	// The rejection is the SDK's own schema-validation error, not a
	// mcptools envelope: StructuredContent is unset because the typed
	// handler in register.go never ran, and with it the zero-result
	// closure list_clusters would otherwise need to build an error around.
	if res.StructuredContent != nil {
		t.Errorf("expected no structured content from a schema rejection, got %#v",
			res.StructuredContent)
	}

	res2, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name: ToolExplainPromQL, Arguments: map[string]any{"query": "sum(((("},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res2.IsError {
		t.Error("explain_promql must never report isError, even for an invalid expression")
	}
}

// decodeCallToolResult re-decodes a tool result's structured content into v.
func decodeCallToolResult(t *testing.T, res *mcp.CallToolResult, v any) {
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
