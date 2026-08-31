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
//
// There are two entry paths and deliberately only one set of assertions.
// [TestFleetEndToEnd] provisions everything itself; setting PMF_E2E instead
// points the suite at a fleet somebody else provisioned. Both converge on
// [fleetAssertions], because the previous arrangement — a provisioned path that
// spoke MCP over a port-forward and a standalone path that shelled into the hub
// pod — let the two drift until the standalone path was invoking `mcp-call` and
// `admin` subcommands that this repository has never had.
//
// Both paths install from the same committed values files under .github/e2e/,
// for the same reason: those files are the chart value contract, and a second
// copy of that contract expressed as --set flags is a second thing to forget to
// update.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	clusterName = "pmf-e2e"
	// The hub and the spoke get separate namespaces on purpose. In production
	// they are in separate *clusters*, installed from separate charts as
	// separate releases; a single kind cluster cannot reproduce that, but
	// sharing a namespace would quietly let a co-location assumption creep
	// into the charts. Separate namespaces keep the spoke's view of the hub
	// purely "some address I was configured with".
	//
	// These names, the release names and the cluster ID are duplicated in
	// .github/workflows/e2e.yml and, more importantly, baked into the
	// endpoints in .github/e2e/spoke-values.yaml. Change one, change all three.
	hubNamespace   = "pmf-hub"
	spokeNamespace = "pmf-spoke"
	promNamespace  = "monitoring"

	hubRelease   = "prometheus-mcp-hub"
	spokeRelease = "prometheus-mcp-spoke"
	promRelease  = "kube-prometheus-stack"

	clusterID = "e2e-kind"

	// imagePrefix and imageTag must agree with .github/e2e/{hub,spoke}-values.yaml,
	// which pin image.registry/image.repository/image.tag to exactly this.
	imagePrefix = "localhost/prometheus-mcp-fleet"
	imageTag    = "e2e"

	// kubePrometheusStackVersion is pinned so a chart release upstream cannot
	// turn a green suite red overnight. Keep it in step with the same pin in
	// .github/workflows/e2e.yml.
	kubePrometheusStackVersion = "88.6.1"

	// installTimeout bounds each helm install. A slow image load on a cold
	// runner is the usual reason this needs to be generous.
	installTimeout = 10 * time.Minute
	// settleTimeout bounds waiting for the spoke to enrol and connect. The
	// spoke jitters its first dial by up to 5s and backs off from there.
	settleTimeout = 3 * time.Minute
)

// repoRoot is where the charts, the Makefile and .github/e2e live, relative to
// this package.
const repoRoot = "../.."

// TestFleetEndToEnd is the whole product in one test: install the hub, mint
// credentials, enrol a spoke, and drive a real MCP tool call that reaches a
// real Prometheus and comes back with a real answer.
func TestFleetEndToEnd(t *testing.T) {
	if os.Getenv("PMF_E2E") != "" {
		testProvisionedFleet(t)
		return
	}
	requireTools(t, "kind", "docker", "kubectl", "helm")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	kubeconfig := setupCluster(ctx, t)
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)

	t.Log("building and loading images")
	buildImages(ctx, t)
	loadImages(ctx, t, env)

	t.Log("installing Prometheus")
	installPrometheus(ctx, t, env)

	t.Log("installing the hub")
	installHub(ctx, t, env)

	// The admin listener binds to loopback inside the pod and is deliberately
	// reachable no other way. kubectl port-forward opens the socket inside the
	// pod's network namespace and dials 127.0.0.1 there, so it reaches a
	// loopback-bound listener without the chart having to expose it.
	adminURL := portForward(t, env, hubNamespace, "deployment/"+hubRelease, 9090)
	waitForHTTP(ctx, t, adminURL+"/healthz")

	adminToken := bootstrapAdminToken(ctx, t, env)

	t.Log("minting an agent key and an enrollment token")
	agentKey := mintAgentKey(ctx, t, adminURL, adminToken)
	enrollToken := mintEnrollmentToken(ctx, t, adminURL, adminToken)

	t.Log("installing the spoke")
	installSpoke(ctx, t, env, enrollToken)

	mcpURL := portForward(t, env, hubNamespace, "deployment/"+hubRelease, 8080) + "/mcp"

	fleetAssertions(ctx, t, env, provisionedConfig{
		mcpURL:         mcpURL,
		adminURL:       adminURL,
		agentToken:     agentKey,
		clusterID:      clusterID,
		hubNamespace:   hubNamespace,
		hubRelease:     hubRelease,
		spokeNamespace: spokeNamespace,
		spokeRelease:   spokeRelease,
	})
}

// testProvisionedFleet is the mode used by .github/workflows/e2e.yml when the
// workflow owns the cluster. The workflow supplies stable port-forwards plus
// the credentials it minted; this test owns the MCP protocol assertions.
func testProvisionedFleet(t *testing.T) {
	t.Helper()
	requireTools(t, "kubectl")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fleetAssertions(ctx, t, os.Environ(), provisionedConfig{
		mcpURL:         requiredEnv(t, "PMF_E2E_MCP_URL"),
		adminURL:       requiredEnv(t, "PMF_E2E_HUB_ADMIN_URL"),
		agentToken:     requiredEnv(t, "PMF_E2E_AGENT_TOKEN"),
		clusterID:      requiredEnv(t, "PMF_E2E_CLUSTER_ID"),
		hubNamespace:   requiredEnv(t, "PMF_E2E_HUB_NAMESPACE"),
		hubRelease:     requiredEnv(t, "PMF_E2E_HUB_RELEASE"),
		spokeNamespace: requiredEnv(t, "PMF_E2E_SPOKE_NAMESPACE"),
		spokeRelease:   requiredEnv(t, "PMF_E2E_SPOKE_RELEASE"),
	})
}

// fleetAssertions is every claim this suite makes about a running fleet. It is
// the single body both entry paths run, so neither can quietly assert less than
// the other.
func fleetAssertions(ctx context.Context, t *testing.T, env []string, cfg provisionedConfig) {
	t.Helper()

	t.Log("waiting for the spoke to enrol and connect")
	waitProvisionedConnected(ctx, t, cfg)

	sess := connectMCP(ctx, t, cfg.mcpURL, cfg.agentToken)
	t.Cleanup(func() { _ = sess.Close() })

	t.Run("list_clusters", func(t *testing.T) {
		out, err := provisionedCall(ctx, sess, "list_clusters", map[string]any{})
		if err != nil {
			t.Fatalf("list_clusters: %v\n%s", err, out)
		}
		// "healthy", not "connected". list_clusters renders a STATUS column
		// that collapses registry state and Prometheus reachability into the
		// one word an agent routes on — healthy, degraded or unreachable — and
		// never prints the registry's own "connected". Asserting the word the
		// tool actually emits is also the stronger claim: "healthy" requires
		// the spoke's Prometheus to have answered, where "connected" would
		// only have meant a tunnel was attached.
		if !strings.Contains(out, cfg.clusterID) || !strings.Contains(out, "healthy") {
			t.Fatalf("list_clusters did not report %q healthy:\n%s", cfg.clusterID, out)
		}
	})

	t.Run("query returns up==1", func(t *testing.T) {
		out, err := provisionedCall(ctx, sess, "query", map[string]any{
			"cluster": cfg.clusterID,
			"query":   "up",
		})
		if err != nil {
			t.Fatalf("query: %v\n%s", err, out)
		}
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
		out, err := provisionedCall(ctx, sess, "delete_series", map[string]any{"cluster": cfg.clusterID})
		lower := strings.ToLower(out + " " + errText(err))
		if err == nil && !strings.Contains(lower, "unknown") && !strings.Contains(lower, "not found") {
			t.Fatalf("a delete_series tool appears to exist:\n%s", out)
		}
	})

	t.Run("an invalid key is refused", func(t *testing.T) {
		client := mcp.NewClient(&mcp.Implementation{Name: "pmf-e2e-invalid", Version: "0"}, nil)
		bad := "pmf_agt_" + strings.Repeat("0", 64)
		badCtx, badCancel := context.WithTimeout(ctx, 30*time.Second)
		defer badCancel()
		badSession, err := client.Connect(badCtx, &mcp.StreamableClientTransport{
			Endpoint:   cfg.mcpURL,
			HTTPClient: &http.Client{Transport: bearerTransport{token: bad}},
			MaxRetries: -1,
		}, nil)
		if badSession != nil {
			_ = badSession.Close()
		}
		if err == nil {
			t.Fatal("an invalid agent key established an MCP session")
		}
	})

	t.Run("spoke reconnects after a hub restart", func(t *testing.T) {
		run(ctx, t, env, "kubectl", "-n", cfg.hubNamespace, "rollout", "restart",
			"deployment/"+cfg.hubRelease)
		run(ctx, t, env, "kubectl", "-n", cfg.hubNamespace, "rollout", "status",
			"deployment/"+cfg.hubRelease, "--timeout=5m")
		// The registry is in memory and self-registering, so this proves the
		// rebuild-from-reconnect path that replaced the database.
		waitProvisionedConnected(ctx, t, cfg)

		// A restart invalidates any transport state held by the prior session.
		// Reconnecting also proves the public endpoint came back, not only metrics.
		reconnected := connectMCP(ctx, t, cfg.mcpURL, cfg.agentToken)
		defer reconnected.Close()
		out, err := provisionedCall(ctx, reconnected, "list_clusters", map[string]any{})
		if err != nil || !strings.Contains(out, cfg.clusterID) {
			t.Fatalf("list_clusters after restart = %v\n%s", err, out)
		}
	})
}

type provisionedConfig struct {
	mcpURL, adminURL, agentToken, clusterID string
	hubNamespace, hubRelease                string
	spokeNamespace, spokeRelease            string
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(clone)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// connectMCP opens an MCP session, retrying while the endpoint refuses.
//
// The retry is not politeness about a slow server. The endpoint is a
// port-forward, and this suite restarts the hub: the forward dies with the pod
// and its supervisor needs a moment to rebind to the replacement. A single
// attempt lands in that window and reports "connection refused" for the
// reconnect assertion, which then measures kubectl rather than whether the
// spoke came back.
func connectMCP(ctx context.Context, t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "prometheus-mcp-fleet-e2e", Version: "0"}, nil)

	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   endpoint,
			HTTPClient: &http.Client{Transport: bearerTransport{token: token}},
			MaxRetries: -1,
		}, nil)
		if err == nil {
			return sess
		}
		lastErr = err
		select {
		case <-ctx.Done():
			t.Fatalf("connect to MCP endpoint %s: %v", endpoint, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatalf("connect to MCP endpoint %s: %v", endpoint, lastErr)
	return nil
}

func provisionedCall(ctx context.Context, sess *mcp.ClientSession, tool string, args map[string]any) (string, error) {
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if res == nil {
		return "", err
	}
	out, marshalErr := json.Marshal(res)
	if marshalErr != nil {
		return "", marshalErr
	}
	if err != nil {
		return string(out), err
	}
	if res.IsError {
		return string(out), fmt.Errorf("tool %s returned an error", tool)
	}
	return string(out), nil
}

func waitProvisionedConnected(ctx context.Context, t *testing.T, cfg provisionedConfig) {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	var last string
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(cfg.adminURL, "/")+"/metrics", nil)
		if err != nil {
			t.Fatalf("build metrics request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			last = string(body)
			if readErr == nil && resp.StatusCode == http.StatusOK && connectedMetric(last) > 0 {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for connected spoke: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatalf("hub never reported a connected spoke within %s; last metrics tail:\n%s",
		settleTimeout, tail([]byte(last), 30))
}

func connectedMetric(metrics string) float64 {
	for line := range strings.SplitSeq(metrics, "\n") {
		if !strings.HasPrefix(line, "promfleet_hub_spokes_connected ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0
		}
		value, _ := strconv.ParseFloat(fields[1], 64)
		return value
	}
	return 0
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required when PMF_E2E is set", name)
	}
	return value
}

// setupCluster creates a kind cluster and returns the path to its kubeconfig.
func setupCluster(ctx context.Context, t *testing.T) string {
	t.Helper()

	// PMF_E2E_KIND_CONFIG replaces the committed cluster config. CI leaves it
	// unset and gets .github/e2e/kind.yaml, which is the configuration this
	// suite is specified against; the override exists for hosts where a stock
	// kind node cannot boot at all and the difference is in the host, not in
	// the product. An unprivileged LXC container is the case in hand: it has no
	// /dev/kmsg and cannot mknod one, and its /proc/sys/kernel is read-only, so
	// kubelet dies first on the oomWatcher and then on ContainerManager. A
	// config that pins a node image whose entrypoint links /dev/kmsg to
	// /dev/console and sets the KubeletInUserNamespace feature gate boots there.
	// A kind config can carry both, which is why this is one knob and not two.
	kindConfig := strings.TrimSpace(os.Getenv("PMF_E2E_KIND_CONFIG"))
	if kindConfig == "" {
		kindConfig = filepath.Join(repoRoot, ".github/e2e/kind.yaml")
	}

	// Delete any cluster left behind by a previous run before creating ours.
	// kind refuses to create over an existing cluster of the same name, so
	// without this an interrupted run — or a deliberate PMF_E2E_KEEP=1 run —
	// makes every subsequent run fail in 0.2s on "node(s) already exist",
	// which reads like a broken suite rather than a stale cluster.
	_ = exec.CommandContext(ctx, "kind", "delete", "cluster", "--name", clusterName).Run()

	kubeconfig := t.TempDir() + "/kubeconfig"
	if out, err := exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", clusterName, "--kubeconfig", kubeconfig,
		"--config", kindConfig,
		"--wait", "300s").CombinedOutput(); err != nil {
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

// buildImages builds both component images through the same make target CI
// uses, so a Dockerfile or build-arg change cannot pass here and fail there.
func buildImages(ctx context.Context, t *testing.T) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "make", "images",
		"REGISTRY="+imagePrefix, "VERSION="+imageTag)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make images: %v\n%s", err, tail(out, 40))
	}
}

// loadImages side-loads the images so the cluster never pulls from a registry.
func loadImages(ctx context.Context, t *testing.T, env []string) {
	t.Helper()
	for _, component := range []string{"hub", "spoke"} {
		run(ctx, t, env, "kind", "load", "docker-image",
			fmt.Sprintf("%s/%s:%s", imagePrefix, component, imageTag), "--name", clusterName)
	}
}

// installPrometheus brings up a real Prometheus for the spoke to proxy. It is
// kube-prometheus-stack rather than the bare prometheus chart because the spoke
// chart's default and .github/e2e/spoke-values.yaml both point at the
// `prometheus-operated` Service, which only the operator creates.
func installPrometheus(ctx context.Context, t *testing.T, env []string) {
	t.Helper()
	run(ctx, t, env, "helm", "repo", "add", "prometheus-community",
		"https://prometheus-community.github.io/helm-charts")
	run(ctx, t, env, "helm", "repo", "update")
	run(ctx, t, env, "helm", "upgrade", "--install", promRelease,
		"prometheus-community/kube-prometheus-stack",
		"--version", kubePrometheusStackVersion,
		"-n", promNamespace, "--create-namespace",
		"--values", filepath.Join(repoRoot, ".github/e2e/prometheus-values.yaml"),
		"--wait", "--timeout", installTimeout.String())
	waitForRollout(ctx, t, env, promNamespace,
		"statefulset/prometheus-"+promRelease+"-prometheus", 5*time.Minute)
}

// waitForRollout waits for a workload to exist and then to finish rolling out.
//
// Plain `kubectl rollout status` is not enough for anything an operator
// creates. `helm install --wait` waits for the objects the chart itself
// rendered; the Prometheus StatefulSet is not one of them — the Prometheus
// Operator materialises it by reconciling the Prometheus custom resource, some
// time after helm has returned. Calling rollout status straight afterwards
// races that reconcile and dies with "statefulsets.apps ... not found"
// whenever the operator is a moment behind, which is most of the time on a
// loaded machine and occasionally everywhere else.
func waitForRollout(ctx context.Context, t *testing.T, env []string, namespace, target string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := output(ctx, env, "kubectl", "-n", namespace,
			"rollout", "status", target, "--timeout=30s")
		if err == nil {
			return
		}
		last = out
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s in %s: %v", target, namespace, ctx.Err())
		case <-time.After(3 * time.Second):
		}
	}
	t.Fatalf("%s in %s never finished rolling out within %s:\n%s",
		target, namespace, timeout, last)
}

// installHub installs the hub chart from the committed e2e values.
func installHub(ctx context.Context, t *testing.T, env []string) {
	t.Helper()
	run(ctx, t, env, "helm", "upgrade", "--install", hubRelease,
		filepath.Join(repoRoot, "charts/prometheus-mcp-hub"),
		"-n", hubNamespace, "--create-namespace",
		"--values", filepath.Join(repoRoot, ".github/e2e/hub-values.yaml"),
		"--wait", "--timeout", installTimeout.String())
	waitForRollout(ctx, t, env, hubNamespace, "deployment/"+hubRelease, 5*time.Minute)
}

// installSpoke installs the spoke chart pointed at the in-cluster hub.
//
// The enrollment token goes into a Secret this test creates rather than through
// enrollment.token, because enrollment.token lands in the Helm release values
// and `helm get values` would then print a live credential.
//
// No hub.caBundle is set: there is no Ingress in this cluster, so the hub's MCP
// listener is plaintext ws:// and http:// and there is no server certificate to
// verify. That is the one thing this suite deliberately does not exercise.
func installSpoke(ctx context.Context, t *testing.T, env []string, enrollToken string) {
	t.Helper()

	run(ctx, t, env, "kubectl", "-n", spokeNamespace, "create", "secret", "generic",
		"pmf-enrollment", "--from-literal=token="+enrollToken)

	run(ctx, t, env, "helm", "upgrade", "--install", spokeRelease,
		filepath.Join(repoRoot, "charts/prometheus-mcp-spoke"),
		"-n", spokeNamespace, "--create-namespace",
		"--values", filepath.Join(repoRoot, ".github/e2e/spoke-values.yaml"),
		"--set", "enrollment.existingSecret=pmf-enrollment",
		"--wait", "--timeout", installTimeout.String())
}

// bootstrapAdminToken reads the admin token the hub prints on first start.
func bootstrapAdminToken(ctx context.Context, t *testing.T, env []string) string {
	t.Helper()

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		out, err := output(ctx, env, "kubectl", "-n", hubNamespace, "logs",
			"deployment/"+hubRelease, "--tail=-1")
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
func mintAgentKey(ctx context.Context, t *testing.T, adminURL, adminToken string) string {
	t.Helper()
	body := `{"class":"agt","name":"e2e","scope":{"role":"viewer",` +
		`"clusters":{"allow":["*"]},"tools":{"allow":["*"]}}}`
	return mintedToken(ctx, t, adminURL+"/admin/v1/keys", adminToken, body)
}

// mintEnrollmentToken creates a single-use enrollment token for the test cluster.
func mintEnrollmentToken(ctx context.Context, t *testing.T, adminURL, adminToken string) string {
	t.Helper()
	body := fmt.Sprintf(`{"clusterId":%q,"labels":{"env":"ci"}}`, clusterID)
	return mintedToken(ctx, t, adminURL+"/admin/v1/enrollments", adminToken, body)
}

// mintedToken POSTs to a credential-minting admin route and returns the token
// out of the MintedKeyResponse.
func mintedToken(ctx context.Context, t *testing.T, url, adminToken, body string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response from %s: %v", url, err)
	}
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST %s returned %d:\n%s", url, resp.StatusCode, raw)
	}
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatalf("decode response from %s: %v\n%s", url, err, raw)
	}
	if minted.Token == "" {
		t.Fatalf("no token in the response from %s:\n%s", url, raw)
	}
	return minted.Token
}

// forwardingLine is what kubectl prints once a port-forward is listening.
var forwardingLine = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward starts a supervised `kubectl port-forward` and returns a stable
// base URL for it.
//
// The local port is chosen by kubectl on first launch and read back off its
// stdout rather than picked by this process. Binding a probe socket to find a
// free port and then closing it leaves a window in which something else takes
// it, and a suite that fails once every few dozen runs on a port collision is
// worse than no suite.
//
// It is supervised because a port-forward is bound to one pod and this suite
// deliberately restarts the hub. `kubectl rollout restart` deletes the pod the
// forward is attached to, kubectl exits, and every later request through this
// URL would fail on a closed socket — including the ones the reconnect
// assertion makes, which would then be measuring kubectl rather than the
// product. The supervisor relaunches kubectl against whatever pod now backs
// the workload, pinned to the same local port so the URL stays valid.
func portForward(t *testing.T, env []string, namespace, target string, remotePort int) string {
	t.Helper()

	// launch starts one kubectl and returns it with the local port it bound.
	// An empty localPort asks kubectl to choose.
	launch := func(localPort string) (*exec.Cmd, string, error) {
		spec := fmt.Sprintf(":%d", remotePort)
		if localPort != "" {
			spec = fmt.Sprintf("%s:%d", localPort, remotePort)
		}
		// Deliberately not CommandContext: the supervisor owns this process's
		// lifetime and t.Cleanup ends it.
		cmd := exec.Command("kubectl", "-n", namespace, "port-forward", target, spec) //nolint:noctx // supervised below
		cmd.Env = env
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, "", err
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return nil, "", err
		}

		ports := make(chan string, 1)
		go func() {
			defer close(ports)
			scanner := bufio.NewScanner(stdout)
			reported := false
			for scanner.Scan() {
				if reported {
					// Keep draining: kubectl blocks writing to a full pipe,
					// and a blocked port-forward stops forwarding.
					continue
				}
				if m := forwardingLine.FindStringSubmatch(scanner.Text()); m != nil {
					ports <- m[1]
					reported = true
				}
			}
		}()

		select {
		case p, ok := <-ports:
			if !ok {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return nil, "", fmt.Errorf("port-forward to %s/%s exited without listening", namespace, target)
			}
			return cmd, p, nil
		case <-time.After(90 * time.Second):
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, "", fmt.Errorf("port-forward to %s/%s never reported a local port", namespace, target)
		}
	}

	cmd, port, err := launch("")
	if err != nil {
		t.Fatalf("port-forward to %s/%s port %d: %v", namespace, target, remotePort, err)
	}

	var (
		mu      sync.Mutex
		current = cmd
		stopped bool
	)
	stop := make(chan struct{})
	t.Cleanup(func() {
		mu.Lock()
		stopped = true
		proc := current
		mu.Unlock()
		close(stop)
		if proc != nil && proc.Process != nil {
			_ = proc.Process.Kill()
		}
	})

	go func() {
		running := cmd
		for {
			if running != nil {
				// Blocks until this kubectl exits, which is what a deleted pod
				// looks like from here.
				_ = running.Wait()
				running = nil
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
			// A failed launch leaves running nil, so the next iteration waits
			// out the tick and tries again: the replacement pod may not be
			// accepting connections yet.
			next, _, err := launch(port)
			if err != nil {
				continue
			}
			mu.Lock()
			if stopped {
				mu.Unlock()
				_ = next.Process.Kill()
				_ = next.Wait()
				return
			}
			current = next
			mu.Unlock()
			running = next
		}
	}()

	return "http://127.0.0.1:" + port
}

// waitForHTTP blocks until url answers 2xx, so the first real request is not
// racing the port-forward's first connection.
func waitForHTTP(ctx context.Context, t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request for %s: %v", url, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", url, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatalf("%s never became healthy: %v", url, lastErr)
}

// extractToken finds the first token with the given prefix in text.
func extractToken(text, prefix string) string {
	i := strings.Index(text, prefix)
	if i < 0 {
		return ""
	}
	rest := text[i:]
	end := strings.IndexFunc(rest, func(r rune) bool { return !tokenRune(r) })
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// tokenRune reports whether r can appear inside a credential: base62 plus the
// underscore that separates a token's fields.
func tokenRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' || r == '_'
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
		{"logs", "-n", hubNamespace, "deployment/" + hubRelease, "--tail=200"},
		{"logs", "-n", spokeNamespace, "deployment/" + spokeRelease, "--tail=200"},
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
