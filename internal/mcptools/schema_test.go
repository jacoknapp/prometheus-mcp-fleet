// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
)

// update rewrites the golden schema files instead of comparing against them.
var update = flag.Bool("update", false, "rewrite the golden tool input schemas in testdata/schemas")

// schemaDir holds one golden file per tool.
const schemaDir = "testdata/schemas"

// newRegisteredServer builds a server with every tool registered on it.
func newRegisteredServer(t *testing.T) (*mcpsurface.Server, *harness) {
	t.Helper()
	h := newHarness(t)
	s, err := mcpsurface.New(mcpsurface.Options{
		Name:                         "prometheus-mcp-fleet-test",
		Version:                      "0.0.0-test",
		Verifier:                     testVerifier,
		DisableCrossOriginProtection: true,
	})
	if err != nil {
		t.Fatalf("mcpsurface.New: %v", err)
	}
	if err := Register(s, h.tools); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return s, h
}

// TestToolInputSchemasGolden is the MCP compatibility guard.
//
// An input schema is a contract with every client that has ever called the
// tool: a tightened bound, a renamed property or a removed enum value breaks
// callers silently at run time. Checking the schemas in means any such change
// arrives as a reviewable diff in a pull request instead of as a support
// ticket. Run with -update to accept an intentional change.
func TestToolInputSchemasGolden(t *testing.T) {
	t.Parallel()
	s, _ := newRegisteredServer(t)

	for _, name := range ToolNames() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, ok := s.InputSchema(name)
			if !ok {
				t.Fatalf("tool %q registered no input schema", name)
			}
			// Round-trip so the golden file is canonical regardless of how the
			// schema encoder orders its own output.
			var canonical any
			if err := json.Unmarshal(got, &canonical); err != nil {
				t.Fatalf("schema is not valid JSON: %v", err)
			}
			pretty, err := json.MarshalIndent(canonical, "", "  ")
			if err != nil {
				t.Fatalf("re-encode schema: %v", err)
			}
			pretty = append(pretty, '\n')

			path := filepath.Join(schemaDir, name+".json")
			if *update {
				if err := os.MkdirAll(schemaDir, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(path, pretty, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (run go test ./internal/mcptools -update)", path, err)
			}
			if diff := cmp.Diff(string(want), string(pretty)); diff != "" {
				t.Errorf("input schema for %q drifted (-golden +got):\n%s\n"+
					"If this change is intended, re-run with -update and review the diff.",
					name, diff)
			}
		})
	}
}

// TestRegisteredSurface pins the tool, resource and prompt names. The catalogue
// is part of the contract just as much as the schemas are.
func TestRegisteredSurface(t *testing.T) {
	t.Parallel()
	s, _ := newRegisteredServer(t)

	wantTools := []string{
		"list_clusters", "describe_cluster",
		"query", "query_range", "explain_promql", "query_exemplars",
		"search_metrics", "metric_metadata", "target_metadata",
		"series", "label_names", "label_values",
		"targets", "rules", "alerts", "alertmanagers", "tsdb_stats", "runtime_info",
		"fanout_query",
	}
	if diff := cmp.Diff(wantTools, s.ToolNames()); diff != "" {
		t.Errorf("registered tools (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantTools, ToolNames()); diff != "" {
		t.Errorf("ToolNames (-want +got):\n%s", diff)
	}
	if got := len(wantTools); got != 19 {
		t.Errorf("tool count = %d, want 19", got)
	}
	wantResources := []string{
		"fleet://clusters", "fleet://alerts/firing", "fleet://promql/cheatsheet",
	}
	if diff := cmp.Diff(wantResources, s.ResourceURIs()); diff != "" {
		t.Errorf("registered resources (-want +got):\n%s", diff)
	}
	wantTemplates := []string{"fleet://clusters/{name}"}
	if diff := cmp.Diff(wantTemplates, s.ResourceTemplateURIs()); diff != "" {
		t.Errorf("registered resource templates (-want +got):\n%s", diff)
	}
	wantPrompts := []string{
		"investigate_alert", "cardinality_hotspot", "compare_clusters",
		"capacity_check", "fleet_health_sweep",
	}
	if diff := cmp.Diff(wantPrompts, s.PromptNames()); diff != "" {
		t.Errorf("registered prompts (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantPrompts, PromptNames()); diff != "" {
		t.Errorf("PromptNames (-want +got):\n%s", diff)
	}
}

// TestEveryToolSchemaIsConstrained checks the properties a model is most
// likely to misuse actually carry bounds. A schema that infers "integer" for
// limit and stops there is a schema that lets an agent ask for 2,000,000 rows.
func TestEveryToolSchemaIsConstrained(t *testing.T) {
	t.Parallel()
	s, _ := newRegisteredServer(t)

	for _, name := range ToolNames() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, _ := s.InputSchema(name)
			var doc struct {
				Properties map[string]struct {
					Type        any             `json:"type"`
					Description string          `json:"description"`
					Enum        []any           `json:"enum"`
					Minimum     *float64        `json:"minimum"`
					Maximum     *float64        `json:"maximum"`
					Default     json.RawMessage `json:"default"`
				} `json:"properties"`
				AdditionalProperties *bool `json:"additionalProperties"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("decode schema: %v", err)
			}
			if doc.AdditionalProperties == nil || *doc.AdditionalProperties {
				t.Error("schema accepts additional properties; a misspelled argument " +
					"would be silently ignored")
			}
			for prop, p := range doc.Properties {
				if p.Description == "" {
					t.Errorf("property %q has no description", prop)
				}
				switch prop {
				case "limit", "topN", "maxPoints", "maxSeries", "maxClusters",
					"maxSeriesPerCluster", "concurrency":
					if p.Minimum == nil || p.Maximum == nil {
						t.Errorf("property %q is unbounded", prop)
					}
					if len(p.Default) == 0 {
						t.Errorf("property %q advertises no default", prop)
					}
				case "format", "mode", "status", "state", "health", "type",
					"dimension", "onError":
					if len(p.Enum) == 0 {
						t.Errorf("property %q is a closed set but advertises no enum", prop)
					}
				}
			}
		})
	}
}

// testVerifier is the credential these tests' servers are built with. The
// servers are exercised through the tool functions rather than over HTTP, but
// mcpsurface refuses to build an unauthenticated surface and is right to.
var testVerifier = mcpsurface.StaticTokenVerifier(
	"test-token", principal(fullScope()), time.Hour)
