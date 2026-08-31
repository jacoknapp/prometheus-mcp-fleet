// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
)

// bearer adds an Authorization header to every request, which is how an MCP
// client presents an agent key.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(clone)
}

func TestBuildMCPExposesTheToolSurfaceAndSaysWhatItRegistered(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t))

	names := h.mcp.ToolNames()
	for _, want := range []string{"list_clusters", "describe_cluster", "query"} {
		if !slices.Contains(names, want) {
			t.Fatalf("tool %q is missing from %v", want, names)
		}
	}
	rec := sink.mustFind(t, "mcp surface ready")
	if got, want := rec["tools"], float64(len(names)); got != want {
		t.Fatalf("logged tools = %v, want %v", got, want)
	}
	if len(h.mcp.ResourceURIs()) == 0 || len(h.mcp.PromptNames()) == 0 {
		t.Fatalf("resources=%d prompts=%d, want both registered",
			len(h.mcp.ResourceURIs()), len(h.mcp.PromptNames()))
	}
}

func TestMCPHandlerReflectsWhetherASurfaceWasBuilt(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	if h.mcpHandler() == nil {
		t.Fatal("a built surface produced no handler")
	}
	h.mcp = nil
	if h.mcpHandler() != nil {
		t.Fatal("a hub with no surface produced a handler")
	}
}

func TestBuildMCPRefusesMissingToolDependencies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		drop func(*hub)
	}{
		{name: "prometheus proxy", drop: func(h *hub) { h.proxy = nil }},
		{name: "cluster registry", drop: func(h *hub) { h.registry = nil }},
		{name: "credential verifier", drop: func(h *hub) { h.verifier = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _ := newWiredHub(t, newHubConfig(t))
			tc.drop(h)
			if _, err := h.buildMCP(); err == nil || !strings.Contains(err.Error(), "build") {
				t.Fatalf("buildMCP = %v, want a tool dependency error", err)
			}
		})
	}
}

// TestAToolCallReceivesTheVerifiedPrincipal is the regression test for the
// failure this composition root has had before: a verifier passed to the MCP
// server unwrapped authenticates the token at the transport but never carries
// the principal to the tool layer, so HTTP answers 200 and every tool call
// fails authorization.
func TestAToolCallReceivesTheVerifiedPrincipal(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	srv := mustStartPublic(t, h)

	raw := mintScopedAgentKey(t, h)
	client := mcp.NewClient(&mcp.Implementation{Name: "hub-test", Version: "0"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   "http://" + srv.Addr() + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token: raw}},
		MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "list_clusters",
		Arguments: map[string]any{},
	})
	// An unwrapped verifier surfaces here, and only here: as a protocol-level
	// "requires an authenticated principal" on a request that authenticated.
	if err != nil {
		t.Fatalf("list_clusters: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_clusters returned a tool error: %+v", res.Content)
	}
}

func TestTheMCPEndpointRefusesACallWithNoCredential(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--public-url", "http://hub.example.test/mcp")
	h, _ := newWiredHub(t, cfg)
	h.tunnel = mustTunnelServer(t, h)
	srv := mustStartPublic(t, h)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+srv.Addr()+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /mcp = %d, want 401", resp.StatusCode)
	}
	// The challenge has to point at the document the public mux actually
	// serves, or a client discovers a 404 instead of an authorization server.
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "http://hub.example.test"+hubapi.PRMPath) {
		t.Fatalf("WWW-Authenticate = %q, want it to name %q",
			challenge, "http://hub.example.test"+hubapi.PRMPath)
	}
}

func TestTheMCPEndpointRefusesAnAdminCredential(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	srv := mustStartPublic(t, h)

	// Offering an admin key at the agent endpoint must be a rejection rather
	// than a silent promotion to elevated rights.
	admin := mintKey(t, h, fleet.ClassAdmin, nil)
	client := mcp.NewClient(&mcp.Implementation{Name: "hub-test", Version: "0"}, nil)
	_, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   "http://" + srv.Addr() + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token: admin}},
		MaxRetries: -1,
	}, nil)
	if err == nil {
		t.Fatal("an admin credential was accepted at the agent endpoint")
	}
}

// mintScopedAgentKey stores an agent credential permitted to call every tool.
func mintScopedAgentKey(t *testing.T, h *hub) string {
	t.Helper()
	return mintKey(t, h, fleet.ClassAgent, &fleet.Scope{
		Clusters: fleet.ClusterScope{Allow: []string{"*"}},
		Tools:    fleet.ToolScope{Allow: []string{"*"}},
	})
}
