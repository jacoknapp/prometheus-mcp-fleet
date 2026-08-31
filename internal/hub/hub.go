// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package hub is the composition root of the hub binary.
//
// It is one of only two packages permitted to import across the whole
// dependency graph. Everything below it is wired here and nowhere else. Keep
// behaviour out of this package: if a function here is doing something
// interesting rather than connecting two things, it belongs in a lower layer
// where it can be tested without a process.
//
// Startup order, and why:
//
//  1. logging, metrics, health, tracing        — so failures below are visible
//  2. Kubernetes client (or the file fallback) — the state layer needs it
//  3. CA and pepper, from the Secret           — before anything that signs or verifies
//  4. credential store                         — before authentication
//  5. registry, proxy, API, MCP surface        — the request path
//  6. listeners                                — last, so nothing is served half-built
//
// Shutdown runs in reverse, with a drain delay first so that the endpoint
// controller stops sending traffic before work stops being accepted.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/httpx"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/registry"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/filestore"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/secretstore"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// Run starts the hub and blocks until ctx is cancelled or a fatal error occurs.
// It returns nil on a clean shutdown.
func Run(ctx context.Context, cfg *config.Hub) error {
	logger, err := obs.NewLogger(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	build := version.Get()
	logger = logger.With("component", "hub")
	logger.InfoContext(ctx, "starting", "version", build.Version, "commit", build.Commit)

	promRegistry := obs.NewRegistry(build, "hub")
	metrics := newMetricsAdapter(obs.NewHubMetrics(promRegistry))
	health := obs.NewHealth(logger)
	health.Set("store", false, "not opened yet")
	health.Set("ca", false, "not loaded yet")
	health.Set("tunnel", false, "handler not mounted yet")

	shutdownTracing, err := obs.InitTracing(ctx, obs.TracingConfig{
		Endpoint:    cfg.OTLPEndpoint,
		SampleRatio: cfg.TraceSampleRatio,
		ServiceName: "prometheus-mcp-hub",
		Build:       build,
	})
	if err != nil {
		return fmt.Errorf("initialise tracing: %w", err)
	}
	defer flushTraces(ctx, logger, shutdownTracing)

	h := &hub{
		cfg:      cfg,
		logger:   logger,
		metrics:  metrics,
		health:   health,
		build:    build,
		promReg:  promRegistry,
		startedA: time.Now(),
	}
	return h.run(ctx)
}

// traceFlushTimeout bounds the final span export at shutdown. It is short: a
// collector that has not accepted the batch by then is not going to, and the
// process is trying to exit.
const traceFlushTimeout = 5 * time.Second

// flushTraces drains the trace exporter on the way out.
//
// A failure is logged and swallowed on purpose. Spans that never reached the
// collector are a diagnostic loss, and turning that into a non-zero exit code
// would make an unreachable collector look like a crashed hub.
func flushTraces(ctx context.Context, logger *slog.Logger, shutdown func(context.Context) error) {
	// The parent context is cancelled by the time this runs, so the flush
	// carries its own deadline rather than inheriting a dead one.
	flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), traceFlushTimeout)
	defer cancel()
	if err := shutdown(flush); err != nil {
		logger.WarnContext(flush, "flushing traces failed", "error", err)
	}
}

// hub holds the wired-up components for one process.
type hub struct {
	cfg      *config.Hub
	logger   *slog.Logger
	metrics  *metricsAdapter
	health   *obs.Health
	build    version.Build
	promReg  *prometheusRegistry
	startedA time.Time

	kube      *kube.Client
	authority *ca.CA
	hasher    *token.Hasher
	store     store.Store
	verifier  *authn.Verifier
	registry  *registry.Registry
	proxy     *promproxy.Proxy
	mcp       *mcpsurface.Server
	tunnel    *wstun.Server
	// now is injectable for tests; nil means time.Now.
	now func() time.Time
	// inCluster resolves the in-cluster Kubernetes client. It is injectable
	// because the real one reads a projected service account from an absolute
	// path outside the test's control, so the whole secret-backed startup path
	// would otherwise be unreachable from a test. nil means kube.InCluster.
	inCluster func() (*kube.Client, error)
}

// kubeClient resolves the in-cluster Kubernetes client.
func (h *hub) kubeClient() (*kube.Client, error) {
	if h.inCluster != nil {
		return h.inCluster()
	}
	return kube.InCluster()
}

func (h *hub) run(ctx context.Context) error {
	if err := h.openState(ctx); err != nil {
		return err
	}
	defer h.closeStore(ctx)

	// Mint the first admin credential before anything is served, so an
	// operator can administer a hub that has just come up for the first time.
	if err := h.bootstrapAdminKey(ctx); err != nil {
		return err
	}

	if err := h.buildRequestPath(); err != nil {
		return err
	}

	admin, err := h.startAdmin(ctx)
	if err != nil {
		return err
	}
	// The shutdown helpers run after this context is cancelled, so they build
	// their own deadline from ShutdownGrace rather than inheriting a dead one.
	//nolint:contextcheck // deliberate: the parent context is already cancelled by the time this runs.
	defer h.shutdown(admin, "admin")

	// The tunnel is a route on the MCP listener now, so it has to exist before
	// that listener is built rather than after it.
	if h.tunnel, err = h.newTunnelServer(ctx); err != nil {
		return err
	}

	public, err := h.startPublic(ctx)
	if err != nil {
		return err
	}
	//nolint:contextcheck // deliberate: the parent context is already cancelled by the time this runs.
	defer h.shutdown(public, "mcp")

	listener := h.tunnel.Listener()
	h.health.Set("tunnel", true, "")
	h.logger.InfoContext(ctx, "tunnel endpoint ready",
		"path", h.cfg.TunnelPath, "addr", public.Addr(), "max_spokes", h.cfg.MaxSpokes)

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return h.serveTunnel(gctx, listener) })
	group.Go(func() error { h.registry.Run(gctx); return nil })
	group.Go(func() error { h.watchCertExpiry(gctx); return nil })

	<-gctx.Done()
	// gctx is cancelled by definition on the line above; drain must not inherit it.
	//nolint:contextcheck // deliberate: draining needs a live deadline, not a cancelled parent.
	h.drain(listener)

	// serveTunnel already reports a cancelled context as a clean stop, and the
	// other two goroutines never fail, so there is nothing left to filter here.
	return group.Wait()
}

// closeStore reports a persistence shutdown failure without changing the
// process result. At this point all request-serving work is already stopping;
// returning a second error would hide the error that caused run to unwind.
func (h *hub) closeStore(ctx context.Context) {
	if err := h.store.Close(); err != nil {
		h.logger.WarnContext(ctx, "closing the credential store failed", "error", err)
	}
}

// openState brings up the Kubernetes client, the CA, the pepper and the
// credential store. Nothing that signs or verifies exists before this returns.
func (h *hub) openState(ctx context.Context) error {
	backend := h.cfg.StateBackend
	if backend == config.StateBackendAuto {
		if _, err := h.kubeClient(); err == nil {
			backend = config.StateBackendSecret
		} else {
			backend = config.StateBackendFile
		}
		h.logger.InfoContext(ctx, "resolved state backend", "backend", backend)
	}

	if backend == config.StateBackendSecret {
		client, err := h.kubeClient()
		if err != nil {
			return fmt.Errorf("state backend %q needs an in-cluster service account: %w",
				backend, err)
		}
		// A configured namespace overrides the projected one, and nothing
		// else. The API server address, the bearer token file and the CA
		// bundle are knowledge only the in-cluster resolver has, so building a
		// second client out of the namespace alone yields a client with no API
		// server to talk to -- which is a startup failure on every install
		// that sets PMF_NAMESPACE, and the chart always sets it.
		if h.cfg.Namespace != "" {
			if client, err = client.WithNamespace(h.cfg.Namespace); err != nil {
				return fmt.Errorf("configure the Kubernetes client: %w", err)
			}
		}
		h.kube = client
	}

	boot := &bootstrapper{
		client: h.kube,
		secret: h.cfg.CASecretName,
		dir:    h.cfg.DataDir,
		logger: h.logger,
	}
	authority, hasher, err := boot.prepare(ctx, h.cfg)
	if err != nil {
		return err
	}
	h.authority, h.hasher = authority, hasher
	h.metrics.CACertExpiry(authority.NotAfter())
	h.health.Set("ca", true, "")
	h.logger.InfoContext(ctx, "certificate authority ready",
		"not_after", authority.NotAfter().Format(time.RFC3339),
		"trust_domain", h.cfg.TrustDomain)

	switch backend {
	case config.StateBackendSecret:
		h.store, err = secretstore.Open(secretstore.Options{
			Client:     h.kube,
			SecretName: h.cfg.StateSecretName,
			Logger:     h.logger,
		})
	default:
		h.store, err = filestore.Open(filestore.Options{Path: h.cfg.StateFile})
	}
	if err != nil {
		return fmt.Errorf("open the credential store: %w", err)
	}
	h.health.Set("store", true, "")
	return nil
}

// buildRequestPath wires authentication, the registry and the proxy.
func (h *hub) buildRequestPath() error {
	var err error
	h.verifier, err = authn.New(authn.Options{
		Store:               h.store,
		Hasher:              h.hasher,
		Logger:              h.logger,
		Metrics:             h.metrics,
		ResourceMetadataURL: h.resourceMetadataURL(),
		// Classify a genuine miss so the metric label distinguishes an unknown
		// key from a store outage. Without this every miss reads as an error.
		IsNotFound: func(err error) bool { return errors.Is(err, store.ErrNotFound) },
	})
	if err != nil {
		return fmt.Errorf("configure authentication: %w", err)
	}

	h.registry, err = registry.New(registry.Options{
		Logger:            h.logger,
		Metrics:           h.metrics,
		FactsPollInterval: h.cfg.FactsPollInterval,
	})
	if err != nil {
		return fmt.Errorf("configure the registry: %w", err)
	}

	if h.proxy, err = h.newProxy(); err != nil {
		return err
	}
	h.mcp, err = h.buildMCP()
	return err
}

// newProxy builds the routing and budget layer.
func (h *hub) newProxy() (*promproxy.Proxy, error) {
	return promproxy.New(promproxy.Options{
		Registry:              h.registry,
		Logger:                h.logger,
		Metrics:               h.metrics,
		DefaultTimeout:        h.cfg.QueryTimeout,
		MaxTimeout:            h.cfg.RangeQueryTimeout,
		MaxResponseBytes:      h.cfg.MaxResponseBytes,
		GlobalResponseBudget:  h.cfg.MaxResponseBudgetBytes,
		MaxInflightPerCluster: h.cfg.MaxInflightPerCluster,
		EnableStatusConfig:    h.cfg.EnableStatusConfig,
	})
}

// apiOptions is the shared configuration for both HTTP surfaces.
func (h *hub) apiOptions() hubapi.Options {
	return hubapi.Options{
		Store:         h.store,
		Hasher:        h.hasher,
		CA:            h.authority,
		Verifier:      h.verifier,
		Logger:        h.logger,
		Metrics:       h.metrics,
		AgentKeyTTL:   h.cfg.AgentKeyTTL,
		EnrollmentTTL: h.cfg.EnrollmentTokenTTL,
		SpokeCertTTL:  h.cfg.SpokeCertTTL,
		RenewGrace:    h.cfg.RenewGrace,
		// The built-in CA is always the issuer in this release, so enrollment
		// is always available. An external-PKI mode would disable it outright
		// rather than leaving a second live credential path open.
		EnrollmentEnabled: true,
		Draining:          h.health.Draining,
		PublicURL:         h.cfg.PublicURL,
		IsNotFound:        func(err error) bool { return errors.Is(err, store.ErrNotFound) },
		IsConflict: func(err error) bool {
			return errors.Is(err, store.ErrEnrollmentUsed) ||
				errors.Is(err, store.ErrAlreadyExists)
		},
	}
}

// resourceMetadataURL is the RFC 9728 document location advertised in a 401.
//
// RFC 9728 §3.1 places the well-known segment at the *origin root* with the
// resource's path appended after it, not concatenated onto the end of the
// resource URL. For a resource of https://host/mcp the document therefore
// lives at https://host/.well-known/oauth-protected-resource/mcp — which is
// also where NewPublicMux serves it. Getting this wrong produces a challenge
// that points at a 404, which is worse than omitting the header.
func (h *hub) resourceMetadataURL() string {
	if h.cfg.PublicURL == "" {
		return ""
	}
	u, err := url.Parse(h.cfg.PublicURL)
	if err != nil || u.Host == "" {
		return ""
	}
	// hubapi.PRMPath already carries the resource path segment ("/mcp"), so the
	// document URL is the origin plus that constant and nothing else.
	origin := url.URL{Scheme: u.Scheme, Host: u.Host}
	return origin.String() + hubapi.PRMPath
}

// startAdmin brings up the admin API, metrics, health and pprof listener. It is
// bound to loopback by default and must never be exposed.
func (h *hub) startAdmin(ctx context.Context) (*httpx.Server, error) {
	adminMux, err := hubapi.NewAdminMux(h.apiOptions())
	if err != nil {
		return nil, fmt.Errorf("build the admin API: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/admin/", adminMux)
	mux.Handle("GET /healthz", h.health.LiveHandler())
	mux.Handle("GET /readyz", h.health.ReadyHandler())
	mux.Handle("GET /metrics", obs.MetricsHandler(h.promReg))
	if h.cfg.PprofEnabled {
		mux.Handle("/debug/pprof/", obs.PprofHandler())
		h.logger.WarnContext(ctx, "pprof is enabled; keep this listener off the network")
	}

	srv := httpx.NewServer(httpx.ServerConfig{
		Name:   "admin",
		Addr:   h.cfg.AdminAddr,
		Logger: h.logger,
		Handler: httpx.Chain(mux,
			httpx.RequestID, httpx.SecurityHeaders,
			httpx.Recover(h.logger, nil), httpx.AccessLog(h.logger)),
	})
	if err := srv.Start(ctx); err != nil {
		return nil, fmt.Errorf("start the admin listener: %w", err)
	}
	h.logger.InfoContext(ctx, "admin listener ready", "addr", srv.Addr())
	return srv, nil
}

// startPublic brings up the agent-facing listener: the MCP endpoint, plus the
// unauthenticated enrollment and PKI routes.
func (h *hub) startPublic(ctx context.Context) (*httpx.Server, error) {
	publicMux, err := hubapi.NewPublicMux(h.apiOptions())
	if err != nil {
		return nil, fmt.Errorf("build the public API: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", publicMux)
	if mcp := h.mcpHandler(); mcp != nil {
		mux.Handle("/mcp", mcp)
		mux.Handle("/mcp/", mcp)
	}
	// The tunnel shares this listener with MCP: one port, one Ingress rule,
	// one certificate for the whole product (ADR-0014).
	mux.Handle(h.cfg.TunnelPath, h.tunnel.Handler())

	srv := httpx.NewServer(httpx.ServerConfig{
		Name:   "mcp",
		Addr:   h.cfg.MCPAddr,
		Logger: h.logger,
		// WriteTimeout is deliberately left at zero: the MCP endpoint streams
		// server-sent events, and a write deadline would sever a long-running
		// tool call mid-stream.
		Handler: httpx.Chain(mux,
			httpx.RequestID, httpx.SecurityHeaders,
			httpx.Recover(h.logger, nil), httpx.AccessLog(h.logger)),
	})
	if err := srv.Start(ctx); err != nil {
		return nil, fmt.Errorf("start the MCP listener: %w", err)
	}
	h.logger.InfoContext(ctx, "mcp listener ready", "addr", srv.Addr())
	return srv, nil
}

// serveTunnel dispatches accepted sessions into the registry.
func (h *hub) serveTunnel(ctx context.Context, listener tunnel.Listener) error {
	err := listener.Serve(ctx, tunnel.SessionHandlerFunc(h.registry.OnSession))
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	return nil
}

// watchCertExpiry keeps the CA expiry gauge current and refuses readiness when
// the CA is about to lapse — at that point every renewal is about to start
// failing, and the operator needs to know before the fleet finds out.
func (h *hub) watchCertExpiry(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		notAfter := h.authority.NotAfter()
		h.metrics.CACertExpiry(notAfter)
		if remaining := time.Until(notAfter); remaining < 24*time.Hour {
			h.health.Set("ca", false,
				fmt.Sprintf("the CA certificate expires in %s", remaining.Round(time.Minute)))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// drain implements the shutdown ordering described in the package comment.
func (h *hub) drain(listener tunnel.Listener) {
	h.logger.Info("draining", "delay", h.cfg.ShutdownDrainDelay.String())
	h.health.StartDraining()

	// Report not-ready for a moment before refusing work, so the endpoint
	// controller removes this pod before traffic starts failing.
	time.Sleep(h.cfg.ShutdownDrainDelay)

	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.ShutdownGrace)
	defer cancel()

	// Close tunnels with a reason so spokes reconnect elsewhere immediately
	// rather than waiting out the keepalive timeout.
	h.registry.Close("hub-shutdown")
	if err := listener.Shutdown(ctx); err != nil {
		h.logger.Warn("tunnel listener did not shut down cleanly", "error", err)
	}
	h.verifier.Close()
}

// shutdown stops one HTTP server within the configured grace.
func (h *hub) shutdown(srv *httpx.Server, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		h.logger.Warn("listener did not shut down cleanly", "listener", name, "error", err)
	}
}
