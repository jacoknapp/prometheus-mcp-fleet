// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e drives the whole system on a real Kubernetes cluster.
//
// It exists because the unit tests cannot catch the things that actually break
// in this design: enrollment against a real API server, a mutually
// authenticated tunnel across a real network, RBAC that is one verb short, and
// a chart whose environment variable name has a typo in it. Every one of those
// passes every unit test and fails on install.
//
// Run with:
//
//	make e2e
//
// It needs kind, docker, kubectl and helm on PATH. It creates and destroys its
// own cluster unless PMF_E2E_KEEP is set, which is useful when a step fails and
// you want to look around.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	clusterName = "pmf-e2e"
	// The hub and the spoke get separate namespaces on purpose. In production
	// they are in separate *clusters*, installed from separate charts as
	// separate releases; a single kind cluster cannot reproduce that, but
	// sharing a namespace would quietly let a co-location assumption creep
	// into the charts. Separate namespaces keep the spoke's view of the hub
	// purely "some address I was configured with".
	hubNamespace   = "prometheus-mcp-hub"
	spokeNamespace = "prometheus-mcp-spoke"
	promNamespace  = "monitoring"
	clusterID      = "e2e-cluster"

	hubImage   = "ghcr.io/jacoknapp/prometheus-mcp-fleet/hub:e2e"
	spokeImage = "ghcr.io/jacoknapp/prometheus-mcp-fleet/spoke:e2e"

	// installTimeout bounds each helm install. A slow image load on a cold
	// runner is the usual reason this needs to be generous.
	installTimeout = 5 * time.Minute
	// settleTimeout bounds waiting for the spoke to enrol and connect. The
	// spoke jitters its first dial by up to 5s and backs off from there.
	settleTimeout = 3 * time.Minute
)

// TestFleetEndToEnd is the whole product in one test: install the hub, mint
// credentials, enrol a spoke, and drive a real MCP tool call that reaches a
// real Prometheus and comes back with a real answer.
func TestFleetEndToEnd(t *testing.T) {
	requireTools(t, "kind", "docker", "kubectl", "helm")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	kubeconfig := setupCluster(ctx, t)
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)

	t.Log("building and loading images")
	buildImages(ctx, t)
	loadImages(ctx, t, kubeconfig)

	t.Log("installing Prometheus")
	installPrometheus(ctx, t, env)

	t.Log("installing the hub")
	installHub(ctx, t, env)

	adminToken := bootstrapAdminToken(ctx, t, env)

	t.Log("minting an agent key and an enrollment token")
	agentKey := mintAgentKey(ctx, t, env, adminToken)
	enrollToken := mintEnrollmentToken(ctx, t, env, adminToken)

	t.Log("installing the spoke")
	installSpoke(ctx, t, env, enrollToken)

	t.Log("waiting for the spoke to enrol and connect")
	waitForConnectedCluster(ctx, t, env, agentKey)

	t.Run("list_clusters", func(t *testing.T) {
		out := callTool(ctx, t, env, agentKey, "list_clusters", map[string]any{})
		if !strings.Contains(out, clusterID) {
			t.Fatalf("list_clusters did not report %q:\n%s", clusterID, out)
		}
	})

	t.Run("query returns up==1", func(t *testing.T) {
		out := callTool(ctx, t, env, agentKey, "query", map[string]any{
			"cluster": clusterID,
			"query":   "up",
		})
		// The assertion that matters: a value came back through the tunnel
		// from a real Prometheus, not a fixture.
		if !strings.Contains(out, `"1"`) && !strings.Contains(out, ":1") {
			t.Fatalf("query for up did not return a 1 value:\n%s", out)
		}
	})

	t.Run("destructive endpoints are unreachable", func(t *testing.T) {
		// There is no tool that maps to them, so the failure must be
		// "unknown tool", not "forbidden" — the point is that the capability
		// does not exist rather than that it is filtered.
		out, err := callToolErr(ctx, t, env, agentKey, "delete_series", map[string]any{
			"cluster": clusterID,
		})
		if err == nil && !strings.Contains(strings.ToLower(out), "unknown") &&
			!strings.Contains(strings.ToLower(out), "not found") {
			t.Fatalf("a delete_series tool appears to exist:\n%s", out)
		}
	})

	t.Run("an unscoped key is refused", func(t *testing.T) {
		out, _ := callToolErr(ctx, t, env, "pmf_agt_"+strings.Repeat("0", 60), "list_clusters", map[string]any{})
		if !strings.Contains(out, "401") && !strings.Contains(strings.ToLower(out), "unauth") {
			t.Fatalf("an invalid key was not rejected:\n%s", out)
		}
	})

	t.Run("spoke reconnects after a hub restart", func(t *testing.T) {
		run(ctx, t, env, "kubectl", "-n", hubNamespace, "rollout", "restart", "deployment/pmf-hub")
		run(ctx, t, env, "kubectl", "-n", hubNamespace, "rollout", "status",
			"deployment/pmf-hub", "--timeout=3m")
		// The registry is in memory and self-registering, so this proves the
		// rebuild-from-reconnect path that replaced the database.
		waitForConnectedCluster(ctx, t, env, agentKey)
	})
}

// setupCluster creates a kind cluster and returns the path to its kubeconfig.
func setupCluster(ctx context.Context, t *testing.T) string {
	t.Helper()

	kubeconfig := t.TempDir() + "/kubeconfig"
	if out, err := exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", clusterName, "--kubeconfig", kubeconfig, "--wait", "120s").CombinedOutput(); err != nil {
		t.Fatalf("kind create cluster: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		if os.Getenv("PMF_E2E_KEEP") != "" {
			t.Logf("PMF_E2E_KEEP is set; leaving cluster %q up. "+
				"Inspect with: kubectl --kubeconfig %s get all -A", clusterName, kubeconfig)
			return
		}
		if t.Failed() {
			dumpDiagnostics(t, kubeconfig)
		}
		_ = exec.Command("kind", "delete", "cluster", "--name", clusterName).Run()
	})

	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	for _, ns := range []string{hubNamespace, spokeNamespace, promNamespace} {
		run(ctx, t, env, "kubectl", "create", "namespace", ns)
	}
	return kubeconfig
}

// buildImages builds both component images from the repository root.
func buildImages(ctx context.Context, t *testing.T) {
	t.Helper()
	for _, c := range []struct{ component, image string }{
		{"hub", hubImage}, {"spoke", spokeImage},
	} {
		cmd := exec.CommandContext(ctx, "docker", "build",
			"--build-arg", "COMPONENT="+c.component,
			"--build-arg", "VERSION=e2e",
			"-t", c.image, "-f", "Dockerfile", ".")
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("docker build %s: %v\n%s", c.component, err, tail(out, 40))
		}
	}
}

// loadImages side-loads the images so the cluster never pulls from a registry.
func loadImages(ctx context.Context, t *testing.T, kubeconfig string) {
	t.Helper()
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	for _, image := range []string{hubImage, spokeImage} {
		run(ctx, t, env, "kind", "load", "docker-image", image, "--name", clusterName)
	}
}

// installPrometheus brings up a minimal Prometheus for the spoke to proxy.
func installPrometheus(ctx context.Context, t *testing.T, env []string) {
	t.Helper()
	run(ctx, t, env, "helm", "repo", "add", "prometheus-community",
		"https://prometheus-community.github.io/helm-charts")
	run(ctx, t, env, "helm", "repo", "update")
	run(ctx, t, env, "helm", "install", "prom", "prometheus-community/prometheus",
		"-n", promNamespace,
		"--set", "alertmanager.enabled=false",
		"--set", "prometheus-pushgateway.enabled=false",
		"--set", "prometheus-node-exporter.enabled=false",
		"--wait", "--timeout", installTimeout.String())
}

// installHub installs the hub chart with the locally built image.
func installHub(ctx context.Context, t *testing.T, env []string) {
	t.Helper()
	run(ctx, t, env, "helm", "install", "pmf-hub", "../../charts/prometheus-mcp-hub",
		"-n", hubNamespace,
		"--set", "image.repository=ghcr.io/jacoknapp/prometheus-mcp-fleet/hub",
		"--set", "image.tag=e2e",
		"--set", "image.pullPolicy=Never",
		"--set", "image.digest=",
		// No tunnel Service and no tunnel serverNames since ADR-0014: the tunnel
		// is a WebSocket on the hub's MCP listener, so the default chart values
		// already expose everything the spoke needs.
		"--wait", "--timeout", installTimeout.String())
}

// installSpoke installs the spoke chart pointed at the in-cluster hub.
func installSpoke(ctx context.Context, t *testing.T, env []string, enrollToken string) {
	t.Helper()

	run(ctx, t, env, "kubectl", "-n", spokeNamespace, "create", "secret", "generic",
		"pmf-enrollment", "--from-literal=token="+enrollToken)

	run(ctx, t, env, "helm", "install", "pmf-spoke", "../../charts/prometheus-mcp-spoke",
		"-n", spokeNamespace,
		"--set", "image.repository=ghcr.io/jacoknapp/prometheus-mcp-fleet/spoke",
		"--set", "image.tag=e2e",
		"--set", "image.pullPolicy=Never",
		"--set", "image.digest=",
		"--set", "cluster.id="+clusterID,
		"--set", "cluster.labels.env=e2e",
		// The tunnel URL, not host:port. There is no Ingress in this suite, so the
		// spoke dials the hub's ClusterIP Service directly on the MCP port and
		// ws:// (plaintext) is what that listener actually speaks.
		"--set", "hub.endpoints[0]=ws://pmf-hub."+hubNamespace+".svc:8080/tunnel",
		// Enrollment is served on that same plaintext MCP listener, so http://.
		// No Ingress means no TLS to terminate and nothing to skip verifying,
		// which is why hub.tlsInsecure is not set here.
		"--set", "hub.apiUrl=http://pmf-hub."+hubNamespace+".svc:8080",
		"--set", "enrollment.existingSecret=pmf-enrollment",
		"--set", "prometheus.url=http://prom-prometheus-server."+promNamespace+".svc:80",
		"--wait", "--timeout", installTimeout.String())
}

// bootstrapAdminToken reads the admin token the hub prints on first start.
func bootstrapAdminToken(ctx context.Context, t *testing.T, env []string) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		out, err := output(ctx, env, "kubectl", "-n", hubNamespace, "logs",
			"deployment/pmf-hub", "--tail=200")
		if err == nil {
			if tok := extractToken(out, "pmf_adm_"); tok != "" {
				return tok
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatal("the hub never printed a bootstrap admin token")
	return ""
}

// mintAgentKey creates a scoped agent key through the admin API.
func mintAgentKey(ctx context.Context, t *testing.T, env []string, adminToken string) string {
	t.Helper()
	body := `{"class":"agt","name":"e2e","scope":{"role":"viewer",` +
		`"clusters":{"allow":["*"]},"tools":{"allow":["*"]}}}`
	out := hubCurl(ctx, t, env, adminToken, "POST", "http://127.0.0.1:9090/admin/v1/keys", body)
	if tok := extractToken(out, "pmf_agt_"); tok != "" {
		return tok
	}
	t.Fatalf("no agent key in the response:\n%s", out)
	return ""
}

// mintEnrollmentToken creates a single-use enrollment token for the test cluster.
func mintEnrollmentToken(ctx context.Context, t *testing.T, env []string, adminToken string) string {
	t.Helper()
	body := fmt.Sprintf(`{"clusterId":%q,"labels":{"env":"e2e"}}`, clusterID)
	out := hubCurl(ctx, t, env, adminToken, "POST", "http://127.0.0.1:9090/admin/v1/enrollments", body)
	if tok := extractToken(out, "pmf_enr_"); tok != "" {
		return tok
	}
	t.Fatalf("no enrollment token in the response:\n%s", out)
	return ""
}

// waitForConnectedCluster polls list_clusters until the spoke reports connected.
func waitForConnectedCluster(ctx context.Context, t *testing.T, env []string, agentKey string) {
	t.Helper()

	deadline := time.Now().Add(settleTimeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := callToolErr(ctx, t, env, agentKey, "list_clusters", map[string]any{})
		last = out
		if err == nil && strings.Contains(out, clusterID) && strings.Contains(out, "connected") {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("cluster %q never reached the connected state within %s.\nlast response:\n%s",
		clusterID, settleTimeout, last)
}

// callTool drives one MCP tool call and fails the test on error.
func callTool(ctx context.Context, t *testing.T, env []string, key, tool string, args map[string]any) string {
	t.Helper()
	out, err := callToolErr(ctx, t, env, key, tool, args)
	if err != nil {
		t.Fatalf("tools/call %s: %v\n%s", tool, err, out)
	}
	return out
}

// callToolErr drives one MCP tool call, returning the raw response.
func callToolErr(ctx context.Context, t *testing.T, env []string, key, tool string, args map[string]any) (string, error) {
	t.Helper()

	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`,
		tool, argsJSON)

	return output(ctx, env, "kubectl", "-n", hubNamespace, "exec", "deployment/pmf-hub", "--",
		"/usr/local/bin/app", "mcp-call", "--token", key, "--body", body)
}

// hubCurl runs an admin API request from inside the hub pod, because the admin
// listener is bound to loopback and is deliberately not reachable otherwise.
func hubCurl(ctx context.Context, t *testing.T, env []string, token, method, url, body string) string {
	t.Helper()
	out, err := output(ctx, env, "kubectl", "-n", hubNamespace, "exec", "deployment/pmf-hub", "--",
		"/usr/local/bin/app", "admin", "--token", token, "--method", method,
		"--url", url, "--body", body)
	if err != nil {
		t.Fatalf("admin %s %s: %v\n%s", method, url, err, out)
	}
	return out
}

// extractToken finds the first token with the given prefix in text.
func extractToken(text, prefix string) string {
	i := strings.Index(text, prefix)
	if i < 0 {
		return ""
	}
	rest := text[i:]
	end := strings.IndexFunc(rest, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' || r == '_')
	})
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// run executes a command and fails the test on error.
func run(ctx context.Context, t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	if out, err := output(ctx, env, name, args...); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// output executes a command and returns its combined output.
func output(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// requireTools skips the suite when a prerequisite is missing, naming it.
func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	var missing []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		t.Skipf("missing required tools: %s", strings.Join(missing, ", "))
	}
}

// dumpDiagnostics prints enough state to diagnose a failure from a CI log.
func dumpDiagnostics(t *testing.T, kubeconfig string) {
	t.Helper()
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	ctx := context.Background()

	for _, args := range [][]string{
		{"get", "pods", "-A", "-o", "wide"},
		{"get", "events", "-n", hubNamespace, "--sort-by=.lastTimestamp"},
		{"get", "events", "-n", spokeNamespace, "--sort-by=.lastTimestamp"},
		{"logs", "-n", hubNamespace, "deployment/pmf-hub", "--tail=200"},
		{"logs", "-n", spokeNamespace, "deployment/pmf-spoke", "--tail=200"},
		{"describe", "deployment", "-n", hubNamespace},
		{"describe", "deployment", "-n", spokeNamespace},
	} {
		out, _ := output(ctx, env, "kubectl", args...)
		t.Logf("=== kubectl %s ===\n%s", strings.Join(args, " "), tail([]byte(out), 60))
	}
}

// tail returns the last n lines of out, so a failure log stays readable.
func tail(out []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
