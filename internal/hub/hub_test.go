// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/httpx"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// notInCluster is what kube.InCluster reports outside a pod.
func notInCluster() (*kube.Client, error) {
	return nil, fmt.Errorf("kube: no service account: %w", kube.ErrNotInCluster)
}

// --- resourceMetadataURL ----------------------------------------------

func TestResourceMetadataURLPointsAtTheDocumentThatIsActuallyServed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		publicURL string
		want      string
	}{
		{"origin plus the well-known path", "https://hub.example.test/mcp", "https://hub.example.test" + hubapi.PRMPath},
		{"the resource path is not appended twice", "https://hub.example.test/mcp/", "https://hub.example.test" + hubapi.PRMPath},
		{"a port is part of the origin", "http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080" + hubapi.PRMPath},
		{"unset means no challenge hint", "", ""},
		{"an unparseable URL means no challenge hint", "://nonsense", ""},
		{"a URL with no host means no challenge hint", "/mcp", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := &hub{cfg: &config.Hub{PublicURL: tc.publicURL}}
			// A challenge that points at a 404 is worse than no challenge, so
			// the only two acceptable answers are the served location and "".
			if got := h.resourceMetadataURL(); got != tc.want {
				t.Fatalf("resourceMetadataURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResourceMetadataURLIsWhereThePublicMuxServesIt(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t, "--public-url", "http://hub.example.test/mcp"))
	h.tunnel = mustTunnelServer(t, h)
	srv := mustStartPublic(t, h)

	// The advertised document must resolve on this listener, which is the
	// whole point of computing it from the origin rather than the resource.
	path := strings.TrimPrefix(h.resourceMetadataURL(), "http://hub.example.test")
	status, body := httpGet(t, "http://"+srv.Addr()+path)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body %s", path, status, body)
	}
}

// --- openState --------------------------------------------------------

func TestOpenStateFallsBackToTheFileBackendOutsideACluster(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendAuto)
	h, sink := newBareHub(t, cfg)
	h.inCluster = notInCluster

	if err := h.openState(context.Background()); err != nil {
		t.Fatalf("openState: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })

	if h.kube != nil {
		t.Fatal("a Kubernetes client was built outside a cluster")
	}
	rec := sink.mustFind(t, "resolved state backend")
	if rec["backend"] != config.StateBackendFile {
		t.Fatalf("backend = %v, want %q", rec["backend"], config.StateBackendFile)
	}
	// The CA paths must come from --data-dir. Getting this wrong produces a
	// hub that generates a fresh CA on every restart.
	if want := filepath.Join(cfg.DataDir, config.CACertFileName); cfg.CACertFile != want {
		t.Fatalf("ca cert file = %q, want %q", cfg.CACertFile, want)
	}
	for _, path := range []string{cfg.CACertFile, cfg.CAKeyFile, cfg.PepperFile, cfg.StateFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s under the data dir: %v", path, err)
		}
	}
	if ready, blockers := h.health.Ready(); !ready {
		t.Fatalf("not ready after openState: %v", blockers)
	}
	sink.mustFind(t, "certificate authority ready")
}

func TestOpenStateUsesTheSecretBackendInsideACluster(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendAuto)
	api := newFakeAPI(t)
	h, sink := newBareHub(t, cfg)
	h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }

	if err := h.openState(context.Background()); err != nil {
		t.Fatalf("openState: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })

	if rec := sink.mustFind(t, "resolved state backend"); rec["backend"] != config.StateBackendSecret {
		t.Fatalf("backend = %v, want %q", rec["backend"], config.StateBackendSecret)
	}
	// The CA went into its own Secret, and credential records go into a
	// second one -- separate blast radii, separate RBAC (ADR-0005).
	if api.get(cfg.CASecretName) == nil {
		t.Fatal("the CA secret was not created")
	}
	if err := h.store.RevokeCert(context.Background(), store.RevokedCert{
		Serial: "01", RevokedAt: time.Now(),
	}); err != nil {
		t.Fatalf("write through the store: %v", err)
	}
	if api.get(cfg.StateSecretName) == nil {
		t.Fatal("the credential store did not write to the state secret")
	}
}

func TestOpenStateAppliesTheConfiguredNamespaceToTheInClusterClient(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret, "--namespace", "prometheus-mcp-hub")
	api := newFakeAPI(t)
	h, _ := newBareHub(t, cfg)
	// The chart always sets PMF_NAMESPACE from the downward API, so this is
	// the ordinary in-cluster path, not an exotic one.
	h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }

	if err := h.openState(context.Background()); err != nil {
		t.Fatalf("openState: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })

	seen := api.namespaces()
	if seen["prometheus-mcp-hub"] == 0 {
		t.Fatalf("no request addressed the configured namespace; saw %v", seen)
	}
	if seen[testNamespace] != 0 {
		t.Fatalf("a request still addressed the projected namespace; saw %v", seen)
	}
}

func TestOpenStateRejectsAnUnusableNamespace(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret, "--namespace", "Not A Namespace")
	api := newFakeAPI(t)
	h, _ := newBareHub(t, cfg)
	h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }

	err := h.openState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "configure the Kubernetes client") {
		t.Fatalf("error = %v, want a rejected namespace", err)
	}
}

func TestOpenStateRefusesTheSecretBackendWithoutAServiceAccount(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret)
	h, _ := newBareHub(t, cfg)
	h.inCluster = notInCluster

	err := h.openState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "needs an in-cluster service account") {
		t.Fatalf("error = %v, want an explicit refusal", err)
	}
}

func TestOpenStateReportsABootstrapFailure(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cfg.CACertFile, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(cfg.CAKeyFile, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	h, _ := newBareHub(t, cfg)
	h.health.Set("ca", false, "not loaded yet")

	if err := h.openState(context.Background()); err == nil {
		t.Fatal("expected an unloadable CA to fail startup")
	}
	// Nothing may claim readiness when the CA never loaded.
	if ready, _ := h.health.Ready(); ready {
		t.Fatal("the hub reported ready with no CA")
	}
}

func TestOpenStateReportsACredentialStoreFailure(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret,
		"--state-secret-name", "Not A Name")
	api := newFakeAPI(t)
	h, _ := newBareHub(t, cfg)
	h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }

	err := h.openState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "open the credential store") {
		t.Fatalf("error = %v, want a store open failure", err)
	}
}

// --- buildRequestPath -------------------------------------------------

func TestBuildRequestPathWiresEveryLayerOfTheRequestPath(t *testing.T) {
	t.Parallel()

	h, _ := newTestHub(t, newHubConfig(t))
	if err := h.buildRequestPath(); err != nil {
		t.Fatalf("buildRequestPath: %v", err)
	}
	built := h.verifier
	t.Cleanup(built.Close)

	if h.verifier == nil || h.registry == nil || h.proxy == nil || h.mcp == nil {
		t.Fatalf("request path is incomplete: verifier=%v registry=%v proxy=%v mcp=%v",
			h.verifier != nil, h.registry != nil, h.proxy != nil, h.mcp != nil)
	}
	if len(h.mcp.ToolNames()) == 0 {
		t.Fatal("the MCP surface exposes no tools")
	}
}

func TestBuildRequestPathReportsWhichLayerFailed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		spoil func(*hub)
		want  string
	}{
		{"authentication", func(h *hub) { h.store = nil }, "configure authentication"},
		{"registry", func(h *hub) { h.cfg.FactsPollInterval = -time.Second }, "configure the registry"},
		{"proxy", func(h *hub) { h.cfg.QueryTimeout = -time.Second }, "promproxy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _ := newTestHub(t, newHubConfig(t))
			tc.spoil(h)
			err := h.buildRequestPath()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewProxyRefusesABudgetSmallerThanOneResponse(t *testing.T) {
	t.Parallel()

	h, _ := newTestHub(t, newHubConfig(t))
	h.cfg.MaxResponseBudgetBytes = 1024
	h.cfg.MaxResponseBytes = 1 << 20

	if _, err := h.newProxy(); err == nil {
		t.Fatal("expected a budget below the per-response cap to be refused")
	}
}

// --- apiOptions -------------------------------------------------------

func TestAPIOptionsClassifyStoreErrorsAndTrackDraining(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	opts := h.apiOptions()

	// Without these the API turns an unknown key into a 500 and a replayed
	// enrollment token -- a security event -- into a generic failure.
	if !opts.IsNotFound(fmt.Errorf("wrapped: %w", store.ErrNotFound)) {
		t.Fatal("a store miss is not classified as not-found")
	}
	if opts.IsNotFound(errors.New("the store is down")) {
		t.Fatal("a store outage is classified as not-found")
	}
	for _, err := range []error{store.ErrEnrollmentUsed, store.ErrAlreadyExists} {
		if !opts.IsConflict(fmt.Errorf("wrapped: %w", err)) {
			t.Fatalf("%v is not classified as a conflict", err)
		}
	}
	if opts.IsConflict(store.ErrNotFound) {
		t.Fatal("a miss is classified as a conflict")
	}
	if !opts.EnrollmentEnabled {
		t.Fatal("enrollment is disabled, so no spoke could ever join")
	}
	if opts.PublicURL != h.cfg.PublicURL {
		t.Fatalf("public url = %q, want %q", opts.PublicURL, h.cfg.PublicURL)
	}
	if opts.Draining() {
		t.Fatal("draining before shutdown began")
	}
	h.health.StartDraining()
	if !opts.Draining() {
		t.Fatal("the API was not told the hub is draining")
	}
}

// --- listeners --------------------------------------------------------

// mustStartAdmin starts the admin listener and stops it when the test ends.
func mustStartAdmin(t *testing.T, h *hub) *httpx.Server {
	t.Helper()
	srv, err := h.startAdmin(context.Background())
	if err != nil {
		t.Fatalf("startAdmin: %v", err)
	}
	t.Cleanup(func() { h.shutdown(srv, "admin") })
	return srv
}

// mustStartPublic starts the agent-facing listener and stops it afterwards.
func mustStartPublic(t *testing.T, h *hub) *httpx.Server {
	t.Helper()
	srv, err := h.startPublic(context.Background())
	if err != nil {
		t.Fatalf("startPublic: %v", err)
	}
	t.Cleanup(func() { h.shutdown(srv, "mcp") })
	return srv
}

// mustTunnelServer builds the tunnel server the public listener mounts.
func mustTunnelServer(t *testing.T, h *hub) *wstun.Server {
	t.Helper()
	srv, err := h.newTunnelServer(context.Background())
	if err != nil {
		t.Fatalf("newTunnelServer: %v", err)
	}
	return srv
}

func TestStartAdminServesHealthMetricsAndTheKeyAPI(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t))
	srv := mustStartAdmin(t, h)
	base := "http://" + srv.Addr()

	if status, _ := httpGet(t, base+"/healthz"); status != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", status)
	}
	status, body := httpGet(t, base+"/metrics")
	if status != http.StatusOK || !strings.Contains(body, "promfleet_hub_") {
		t.Fatalf("/metrics = %d, body missing hub metrics:\n%s", status, body)
	}
	// The admin surface is the credential-issuing surface: it must never be
	// reachable without an admin credential.
	if status, _ := httpGet(t, base+"/admin/v1/keys"); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /admin/v1/keys = %d, want 401", status)
	}
	// pprof is off unless asked for.
	if status, _ := httpGet(t, base+"/debug/pprof/"); status == http.StatusOK {
		t.Fatal("pprof is served although it was not enabled")
	}
	sink.mustNotFind(t, "pprof is enabled; keep this listener off the network")
	sink.mustFind(t, "admin listener ready")
}

func TestStartAdminServesPprofOnlyWhenAskedAndSaysSo(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t, "--pprof-enabled=true"))
	srv := mustStartAdmin(t, h)

	if status, _ := httpGet(t, "http://"+srv.Addr()+"/debug/pprof/"); status != http.StatusOK {
		t.Fatalf("/debug/pprof/ = %d, want 200", status)
	}
	sink.mustFind(t, "pprof is enabled; keep this listener off the network")
}

func TestAdminReadinessNamesEveryComponentThatIsNotUp(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	// The same three components Run seeds before anything is served.
	h.health.Set("store", false, "not opened yet")
	h.health.Set("ca", false, "not loaded yet")
	h.health.Set("tunnel", false, "handler not mounted yet")
	srv := mustStartAdmin(t, h)
	url := "http://" + srv.Addr() + "/readyz"

	status, body := httpGet(t, url)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want 503 while starting up", status)
	}
	var got struct {
		Status   string            `json:"status"`
		Draining bool              `json:"draining"`
		Blockers map[string]string `json:"blockers"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode /readyz body %q: %v", body, err)
	}
	for _, name := range []string{"store", "ca", "tunnel"} {
		if got.Blockers[name] == "" {
			t.Fatalf("/readyz does not name %q as a blocker: %v", name, got.Blockers)
		}
	}

	h.health.Set("store", true, "")
	h.health.Set("ca", true, "")
	h.health.Set("tunnel", true, "")
	if status, body := httpGet(t, url); status != http.StatusOK {
		t.Fatalf("/readyz = %d once everything is up, want 200; body %s", status, body)
	}

	// Draining takes it back out of rotation without touching liveness, so a
	// load balancer stops sending work but nothing restarts the pod.
	h.health.StartDraining()
	status, body = httpGet(t, url)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d while draining, want 503", status)
	}
	if !strings.Contains(body, `"draining":true`) {
		t.Fatalf("/readyz body does not report draining: %s", body)
	}
	if status, _ := httpGet(t, "http://"+srv.Addr()+"/healthz"); status != http.StatusOK {
		t.Fatalf("/healthz = %d while draining, want 200", status)
	}
}

func TestStartAdminReportsABindFailure(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.cfg.AdminAddr = "127.0.0.1:999999"

	_, err := h.startAdmin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start the admin listener") {
		t.Fatalf("error = %v, want a bind failure", err)
	}
}

func TestStartAdminReportsAnUnbuildableAPI(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.store = nil

	_, err := h.startAdmin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "build the admin API") {
		t.Fatalf("error = %v, want an admin API construction failure", err)
	}
}

func TestStartPublicServesEnrollmentPKIAndTheTunnelOnOneListener(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	srv := mustStartPublic(t, h)
	base := "http://" + srv.Addr()

	status, body := httpGet(t, base+"/pki/bundle")
	if status != http.StatusOK || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Fatalf("/pki/bundle = %d, body %q", status, body)
	}
	if status, _ := httpGet(t, base+hubapi.PRMPath); status != http.StatusOK {
		t.Fatalf("%s = %d, want 200", hubapi.PRMPath, status)
	}
	// One port, one Ingress rule: the tunnel path is on this listener too,
	// and refuses a request that is not an upgrade (ADR-0014).
	status, _ = httpGet(t, base+h.cfg.TunnelPath)
	if status == http.StatusNotFound {
		t.Fatalf("the tunnel path is not mounted on the MCP listener (got %d)", status)
	}
	sink.mustFind(t, "mcp listener ready")
}

func TestStartPublicOmitsTheMCPRouteWhenThereIsNoSurface(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	h.mcp = nil
	srv := mustStartPublic(t, h)

	// Not 401: a hub with no tool surface has nothing to authenticate for, so
	// the route must simply not exist.
	if status, _ := httpGet(t, "http://"+srv.Addr()+"/mcp"); status != http.StatusNotFound {
		t.Fatalf("/mcp = %d with no surface, want 404", status)
	}
	if h.mcpHandler() != nil {
		t.Fatal("mcpHandler returned a handler for a hub with no surface")
	}
}

func TestStartPublicReportsABindFailure(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	h.cfg.MCPAddr = "127.0.0.1:999999"

	_, err := h.startPublic(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start the MCP listener") {
		t.Fatalf("error = %v, want a bind failure", err)
	}
}

func TestStartPublicReportsAnUnbuildableAPI(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.store = nil

	_, err := h.startPublic(context.Background())
	if err == nil || !strings.Contains(err.Error(), "build the public API") {
		t.Fatalf("error = %v, want a public API construction failure", err)
	}
}

// --- shutdown ---------------------------------------------------------

func TestShutdownReportsAListenerThatWouldNotStopInTime(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := httpx.NewServer(httpx.ServerConfig{
		Name: "stuck", Addr: "127.0.0.1:0", Logger: h.logger,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }),
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = http.Get("http://" + srv.Addr() + "/") //nolint:bodyclose // the handler never answers
	}()
	<-started
	// Give the request time to reach the wedged handler.
	time.Sleep(50 * time.Millisecond)

	h.cfg.ShutdownGrace = 20 * time.Millisecond
	h.shutdown(srv, "stuck")

	// A listener that cannot be drained is reported, not hidden, and not
	// allowed to hang the process.
	rec := sink.mustFind(t, "listener did not shut down cleanly")
	if rec["listener"] != "stuck" {
		t.Fatalf("listener = %v, want %q", rec["listener"], "stuck")
	}
}

// --- run --------------------------------------------------------------

func TestRunStopsAtTheFirstStartupStageThatFails(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		build func(t *testing.T) *hub
		want  string
	}{
		{
			name: "the credential store cannot be read",
			build: func(t *testing.T) *hub {
				cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret)
				api := newFakeAPI(t)
				// Only the state Secret fails, so the CA comes up and the
				// failure is unambiguously the credential lookup.
				api.onGet = func(name string, _ int) *fault {
					if name != cfg.StateSecretName {
						return nil
					}
					return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
				}
				h, _ := newBareHub(t, cfg)
				h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }
				return h
			},
			want: "list admin keys",
		},
		{
			name: "the request path cannot be wired",
			build: func(t *testing.T) *hub {
				h, _ := newBareHub(t, newHubConfig(t))
				h.cfg.FactsPollInterval = -time.Second
				return h
			},
			want: "configure the registry",
		},
		{
			name: "the revocation enforcer refuses its options",
			build: func(t *testing.T) *hub {
				h, _ := newBareHub(t, newHubConfig(t))
				// The only invalid input run can hand the enforcer: every
				// other option is wired from fields that always exist.
				h.revocationInterval = -time.Second
				return h
			},
			want: "configure the revocation enforcer",
		},
		{
			name: "the admin listener cannot bind",
			build: func(t *testing.T) *hub {
				h, _ := newBareHub(t, newHubConfig(t))
				h.cfg.AdminAddr = "127.0.0.1:999999"
				return h
			},
			want: "start the admin listener",
		},
		{
			name: "the tunnel server cannot be built",
			build: func(t *testing.T) *hub {
				h, _ := newBareHub(t, newHubConfig(t))
				h.cfg.MaxSpokes = -1
				return h
			},
			want: "build the tunnel server",
		},
		{
			name: "the mcp listener cannot bind",
			build: func(t *testing.T) *hub {
				h, _ := newBareHub(t, newHubConfig(t))
				h.cfg.MCPAddr = "127.0.0.1:999999"
				return h
			},
			want: "start the MCP listener",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := tc.build(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			err := h.run(ctx)
			// Nothing half-built is served: the failure is returned rather
			// than logged and stepped over.
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAnUnknownKeyIsCountedAsAMissRatherThanAStoreFailure(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	// Well formed, correctly checksummed, and never stored.
	minted, err := token.Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := h.verifier.Verify(context.Background(), minted.Raw.Reveal(), fleet.ClassAgent); err == nil {
		t.Fatal("an unstored credential authenticated")
	}

	// Both outcomes deny the request, but telling them apart is the difference
	// between "someone is guessing key ids" and "persistence is broken".
	text := metricsText(t, h.promReg)
	if !strings.Contains(text, `promfleet_hub_authn_failures_total{reason="`+authn.ReasonUnknownKey+`"} 1`) {
		t.Fatalf("the miss was not counted as %s:\n%s", authn.ReasonUnknownKey, text)
	}
	if strings.Contains(text, `reason="`+authn.ReasonStoreError+`"`) {
		t.Fatalf("a miss was recorded as a store failure:\n%s", text)
	}
}

func TestCloseStoreReportsPersistenceFailure(t *testing.T) {
	t.Parallel()

	h, sink := newBareHub(t, newHubConfig(t))
	h.store = &faultyStore{
		Store:    newFileStore(t),
		closeErr: errors.New("flush failed"),
	}
	h.closeStore(t.Context())

	rec := sink.mustFind(t, "closing the credential store failed")
	if got := rec["error"]; got != "flush failed" {
		t.Fatalf("logged error = %v, want flush failed", got)
	}
}
