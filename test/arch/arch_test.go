// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package arch enforces the dependency direction described in
// docs/architecture.md. It shells out to `go list` rather than importing a
// graph library, so it adds no dependency to the module.
//
// The rules exist to stop the codebase becoming a ball of mud one convenient
// import at a time. A violation is not a style complaint: every rule below
// corresponds to something that would break if the edge existed — a test that
// could no longer run without a network, a transport that could no longer be
// swapped, or an import cycle.
package arch

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// modulePath is the module under test.
const modulePath = "github.com/jacoknapp/prometheus-mcp-fleet"

// layer assigns each internal package a level. A package may import another
// package in the same layer or any lower layer, and nothing higher.
//
// Packages absent from this map are unclassified, which the test reports as a
// failure: a new package must state where it belongs, so that layering is a
// decision rather than an accident.
var layer = map[string]int{
	// L0 — domain and pure logic. No I/O, no clients, no config parsing.
	"fleet":   0,
	"version": 0,
	"config":  0,
	"tunnel":  0,
	"promapi": 0,
	// mtls builds the client side of the tunnel's TLS config. It sits at L0 so
	// the spoke can present a certificate without linking internal/ca, which is
	// the code that issues identities for the whole fleet.
	"mtls": 0,

	// L1 — infrastructure. May touch the network, the filesystem and the clock.
	"obs":               1,
	"httpx":             1,
	"token":             1,
	"kube":              1,
	"store":             1,
	"store/filestore":   1,
	"store/secretstore": 1,
	"store/storetest":   1,
	"ca":                1,
	"authn":             1,
	"promclient":        1,
	"tunnel/grpctun":    1,
	"tunnel/memtun":     1,
	// wstun carries the tunnel over a WebSocket on the hub's HTTP listener
	// (ADR-0014). It sits beside grpctun rather than above it: it supplies an
	// authenticated net.Conn and grpctun does everything after that.
	"tunnel/wstun":      1,
	"tunnel/tunneltest": 1,
	"gen/fleet/v1":      1,

	// L2 — services composed from L1.
	"registry":     2,
	"promproxy":    2,
	"clusterfacts": 2,
	"hubapi":       2,
	"mcpsurface":   2,
	"render":       2,

	// L3 — the agent-facing surface.
	"mcptools": 3,

	// L4 — composition roots. These may import anything.
	"hub":   4,
	"spoke": 4,

	// Test helpers are importable from anywhere; they are excluded from the
	// layer check but not from the forbidden-edge check.
	"testutil": 99,
}

// forbidden lists specific edges that the layer rule alone would permit but
// which must not exist, each with the reason it is banned. The reason is part
// of the test: a rule whose justification has been forgotten should be deleted,
// not silently kept.
var forbidden = []struct {
	from, to string
	because  string
}{
	{
		from: "tunnel", to: "google.golang.org/grpc",
		because: "tunnel defines the transport contract; if it names gRPC, the " +
			"transport can no longer be swapped and memtun cannot exist",
	},
	{
		from: "promapi", to: "net/http",
		because: "promapi is a pure allow-list; giving it an HTTP client would " +
			"put request construction in two places",
	},
	{
		from: "fleet", to: modulePath,
		because: "fleet is the root of the dependency graph and must import " +
			"nothing from this module",
	},
	{
		from: "mcpsurface", to: modulePath + "/internal/promproxy",
		because: "the MCP transport adapter must stay ignorant of the Prometheus " +
			"domain, so SDK churn cannot reach the query path",
	},
	{
		from: "registry", to: modulePath + "/internal/mcptools",
		because: "the registry must not know what a tool is",
	},
	{
		from: "spoke", to: modulePath + "/internal/registry",
		because: "the spoke has no fleet view; importing the registry means " +
			"hub logic has leaked into the spoke binary",
	},
	{
		from: "spoke", to: modulePath + "/internal/ca",
		because: "the spoke must never be able to issue a certificate",
	},
	{
		from: "spoke", to: modulePath + "/internal/store",
		because: "the spoke holds no credential store",
	},
	{
		from: "spoke", to: modulePath + "/internal/mcptools",
		because: "the spoke serves no MCP surface; this edge would ship the whole " +
			"tool catalogue into 100 clusters",
	},
	{
		from: "clusterfacts", to: "k8s.io/client-go",
		because: "ADR-0009: the spoke gathers facts from config and PromQL, and " +
			"stays free of client-go",
	},
}

// allowedDirectRequires is the closed dependency budget of ADR-0010. Anything
// in go.mod's direct require block that is not listed here needs an ADR.
var allowedDirectRequires = []string{
	// ADR-0014: the WebSocket tunnel needs RFC 6455 framing and a net.Conn
	// adapter. It has zero transitive dependencies, which is the only reason
	// it clears the budget.
	"github.com/coder/websocket",
	"github.com/google/go-cmp",
	// jsonschema-go is the MCP SDK's own schema type: mcp.Tool.InputSchema is
	// a *jsonschema.Schema, so any code that inspects or emits a tool schema
	// must name the type. It adds no new dependency tree — it arrives with the
	// SDK either way — and only internal/mcpsurface imports it.
	"github.com/google/jsonschema-go",
	"github.com/modelcontextprotocol/go-sdk",
	"github.com/prometheus/client_golang",
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
	"go.opentelemetry.io/otel",
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc",
	"go.opentelemetry.io/otel/sdk",
	"go.opentelemetry.io/otel/trace",
	"golang.org/x/sync",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
}

// bannedModules must not be imported *directly* by any package in this module.
//
// The check is on direct imports, not the whole build graph: an allowed
// dependency may legitimately pull one of these in transitively (OpenTelemetry's
// resource detector uses github.com/google/uuid, for example). What matters is
// that our own code does not reach for them, because that is what a
// hand-rolled alternative is protecting.
var bannedModules = []string{
	"github.com/spf13/viper",
	"github.com/spf13/cobra",
	"github.com/sirupsen/logrus",
	"go.uber.org/zap",
	"github.com/rs/zerolog",
	"github.com/gin-gonic/gin",
	"github.com/gorilla/mux",
	"github.com/stretchr/testify",
	"github.com/golang/mock",
	"github.com/google/uuid",
	"github.com/prometheus/prometheus",
	"k8s.io/client-go",
	"k8s.io/apimachinery",
	"go.etcd.io/bbolt",
	"gorm.io/gorm",
}

// pkg is the subset of `go list -json` output this test needs.
type pkg struct {
	ImportPath string
	Deps       []string
	Imports    []string
}

// listPackages returns every package in the module with its transitive
// dependencies.
func listPackages(t *testing.T) []pkg {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps=false", "-json", "./...")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			t.Fatalf("go list: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}

	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}
	return pkgs
}

// asExitError reports whether err is an *exec.ExitError, assigning it to target.
func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// internalName strips the module and internal prefix, or returns "" for a
// package outside internal/.
func internalName(importPath string) string {
	const prefix = modulePath + "/internal/"
	if !strings.HasPrefix(importPath, prefix) {
		return ""
	}
	return strings.TrimPrefix(importPath, prefix)
}

func TestEveryInternalPackageIsClassified(t *testing.T) {
	t.Parallel()

	for _, p := range listPackages(t) {
		name := internalName(p.ImportPath)
		if name == "" {
			continue
		}
		if _, ok := layer[name]; !ok {
			t.Errorf("internal/%s has no layer assigned.\n"+
				"Add it to the layer map in test/arch/arch_test.go and say where it "+
				"belongs. An unclassified package is one nobody decided the shape of.",
				name)
		}
	}
}

func TestDependencyDirection(t *testing.T) {
	t.Parallel()

	for _, p := range listPackages(t) {
		from := internalName(p.ImportPath)
		if from == "" {
			continue
		}
		fromLayer, ok := layer[from]
		if !ok || fromLayer == 99 {
			continue // reported by TestEveryInternalPackageIsClassified
		}
		for _, imp := range p.Imports {
			to := internalName(imp)
			if to == "" {
				continue
			}
			toLayer, ok := layer[to]
			if !ok || toLayer == 99 {
				continue
			}
			if toLayer > fromLayer {
				t.Errorf("layering violation: internal/%s (L%d) imports internal/%s (L%d).\n"+
					"A package may only import its own layer or lower. Either move the "+
					"shared type down, or invert the dependency with an interface "+
					"declared at the point of use.",
					from, fromLayer, to, toLayer)
			}
		}
	}
}

func TestForbiddenEdges(t *testing.T) {
	t.Parallel()

	byName := map[string]pkg{}
	for _, p := range listPackages(t) {
		if name := internalName(p.ImportPath); name != "" {
			byName[name] = p
		}
	}

	for _, rule := range forbidden {
		p, ok := byName[rule.from]
		if !ok {
			// The package may not exist yet; that is not a failure.
			continue
		}
		for _, dep := range p.Deps {
			if dep == rule.to || strings.HasPrefix(dep, rule.to+"/") {
				t.Errorf("forbidden edge: internal/%s imports %s.\n  reason: %s",
					rule.from, rule.to, rule.because)
			}
		}
	}
}

// TestNoBannedDirectImports asserts that no package in this module reaches for
// a dependency the budget replaced with the standard library. See ADR-0010.
func TestNoBannedDirectImports(t *testing.T) {
	t.Parallel()

	for _, p := range listPackages(t) {
		if !strings.HasPrefix(p.ImportPath, modulePath) {
			continue
		}
		for _, imp := range p.Imports {
			for _, banned := range bannedModules {
				if imp == banned || strings.HasPrefix(imp, banned+"/") {
					t.Errorf("%s imports the banned dependency %s.\n"+
						"See docs/adr/0010-dependency-budget.md. Adding one of these "+
						"requires an ADR stating what it does that the standard "+
						"library cannot.", p.ImportPath, imp)
				}
			}
		}
	}
}

// TestDirectRequiresMatchBudget asserts go.mod's direct require block has not
// grown without an ADR. Dependency growth is never a decision anyone makes; it
// is a hundred small conveniences that each looked free, so it needs a gate.
func TestDirectRequiresMatchBudget(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("go", "list", "-m", "-f", "{{if not .Indirect}}{{.Path}}{{end}}", "all")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}

	var unexpected []string
	for line := range strings.SplitSeq(string(out), "\n") {
		mod := strings.TrimSpace(line)
		if mod == "" || mod == modulePath {
			continue
		}
		if !slices.Contains(allowedDirectRequires, mod) {
			unexpected = append(unexpected, mod)
		}
	}
	if len(unexpected) > 0 {
		slices.Sort(unexpected)
		t.Errorf("go.mod has direct requires outside the budget: %s\n"+
			"Either remove them, or add an ADR and extend allowedDirectRequires "+
			"in this test. See docs/adr/0010-dependency-budget.md.",
			strings.Join(unexpected, ", "))
	}
}

// TestSpokeBinaryStaysSmall asserts the spoke's transitive package count stays
// well under the hub's. The spoke ships into ~100 clusters run by people who
// did not write it, so its surface is a product property, not an implementation
// detail.
func TestSpokeBinaryStaysSmall(t *testing.T) {
	t.Parallel()

	count := func(target string) int {
		cmd := exec.Command("go", "list", "-deps", target)
		cmd.Dir = "../.."
		out, err := cmd.Output()
		if err != nil {
			t.Skipf("%s does not build yet: %v", target, err)
		}
		return len(strings.Fields(string(out)))
	}

	spoke := count("./cmd/spoke")
	hub := count("./cmd/hub")
	if spoke == 0 || hub == 0 {
		t.Skip("binaries not present yet")
	}
	if spoke >= hub {
		t.Errorf("the spoke pulls in %d packages and the hub %d.\n"+
			"The spoke must stay the smaller of the two; check whether hub-only "+
			"code has leaked into it.", spoke, hub)
	}
	t.Logf("transitive packages: spoke=%d hub=%d", spoke, hub)
}

// ensure fmt stays used if the file is edited down.
var _ = fmt.Sprintf
