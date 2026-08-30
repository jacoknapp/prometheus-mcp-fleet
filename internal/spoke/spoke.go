// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package spoke is the composition root of the spoke binary.
//
// It is one of only two packages permitted to import across the whole
// dependency graph; everything below it is wired here and nowhere else. Keep
// behaviour out of this package — if a function here is doing something
// interesting rather than connecting two things, it belongs in a lower layer
// where it can be tested without a process.
//
// Lifecycle, in order:
//
//	load or obtain an identity  ->  start the admin listener  ->  dial every hub
//	endpoint concurrently, each with its own backoff  ->  serve Prometheus
//	requests and cluster facts over those tunnels  ->  renew the certificate at
//	half its lifetime  ->  drain on SIGTERM.
package spoke

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/clusterfacts"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/httpx"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mtls"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
	"golang.org/x/sync/errgroup"
)

// protocolVersion is the hub<->spoke wire contract this build speaks. The hub
// supports the previous minor, because 100 clusters never upgrade in lockstep.
const protocolVersion = "v1"

// renewAtFraction is the point in a certificate's life at which the spoke
// renews. Half life leaves a full half-lifetime of retries before anything
// breaks.
const renewAtFraction = 0.5

// renewCheckInterval is how often the renewal decision is re-evaluated. The
// decision itself is cheap; the jitter is what matters.
const renewCheckInterval = time.Hour

// Run starts the spoke and blocks until ctx is cancelled or a fatal error
// occurs. It returns nil on a clean shutdown.
func Run(ctx context.Context, cfg *config.Spoke) error {
	logger, err := obs.NewLogger(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	build := version.Get()
	logger = logger.With("component", "spoke", "cluster_id", cfg.ClusterID)
	logger.Info("starting", "version", build.Version, "commit", build.Commit)

	registry := obs.NewRegistry(build, "spoke")
	metrics := obs.NewSpokeMetrics(registry)
	health := obs.NewHealth(logger)
	health.Set("tunnel", false, "no tunnel established yet")
	health.Set("prometheus", false, "not probed yet")

	shutdownTracing, err := obs.InitTracing(ctx, obs.TracingConfig{
		Endpoint:    cfg.OTLPEndpoint,
		SampleRatio: cfg.TraceSampleRatio,
		ServiceName: "prometheus-mcp-spoke",
		Build:       build,
	})
	if err != nil {
		return fmt.Errorf("initialise tracing: %w", err)
	}
	defer func() {
		flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(flush); err != nil {
			logger.Warn("flushing traces failed", "error", err)
		}
	}()

	s := &spoke{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		health:  health,
		build:   build,
		started: time.Now(),
	}
	return s.run(ctx, registry)
}

// spoke holds the wired-up components for one process.
type spoke struct {
	cfg     *config.Spoke
	logger  *slog.Logger
	metrics *obs.SpokeMetrics
	health  *obs.Health
	build   version.Build
	started time.Time

	prom      *promclient.Client
	facts     *clusterfacts.Collector
	store     identityStore
	enroller  *enroller
	identity  atomic.Pointer[Identity]
	reconnect chan struct{} // closed and replaced to force every dialer to redial
	mu        sync.Mutex
}

func (s *spoke) run(ctx context.Context, registry prometheusRegistry) error {
	admin, err := s.startAdmin(registry)
	if err != nil {
		return err
	}
	defer s.stopAdmin(admin)

	if s.prom, err = promclient.New(promclient.Config{
		BaseURL:          s.cfg.PrometheusURL,
		Timeout:          s.cfg.PrometheusTimeout,
		BearerTokenFile:  s.cfg.PrometheusBearerTokenFile,
		TLSCAFile:        s.cfg.PrometheusTLSCAFile,
		TLSInsecure:      s.cfg.PrometheusTLSSkipVerify,
		MaxResponseBytes: s.cfg.PrometheusMaxResponseBytes,
		UserAgent:        "prometheus-mcp-spoke/" + s.build.Version,
		Logger:           s.logger,
	}); err != nil {
		return fmt.Errorf("configure the Prometheus client: %w", err)
	}

	if s.facts, err = clusterfacts.New(clusterfacts.Config{
		ClusterID:       s.cfg.ClusterID,
		DisplayName:     s.cfg.ClusterDisplayName,
		Description:     s.cfg.ClusterDescription,
		Labels:          s.cfg.ClusterLabels,
		AgentVersion:    s.build.Version,
		ProtocolVersion: protocolVersion,
		StartedAt:       s.started,
		Client:          s.prom,
		RefreshInterval: s.cfg.FactsRefreshInterval,
		Logger:          s.logger,
	}); err != nil {
		return fmt.Errorf("configure the facts collector: %w", err)
	}

	if s.store, err = newIdentityStore(s.cfg, s.logger); err != nil {
		return fmt.Errorf("configure the identity store: %w", err)
	}
	s.logger.Info("identity store selected", "store", s.store.Describe())

	s.enroller = &enroller{
		apiURL:    s.cfg.HubAPIURL,
		caFile:    s.cfg.HubCAFile,
		insecure:  s.cfg.HubTLSInsecure,
		logger:    s.logger,
		userAgent: "prometheus-mcp-spoke/" + s.build.Version,
	}
	s.reconnect = make(chan struct{})

	if err := s.establishIdentity(ctx); err != nil {
		return err
	}

	// The first facts refresh is best-effort: a spoke whose Prometheus is down
	// must still connect and report that fact, because "cluster reachable,
	// Prometheus down" is far more useful to an agent than silence.
	if err := s.facts.Refresh(ctx); err != nil {
		s.logger.Warn("initial facts refresh incomplete", "error", err)
	}

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { s.runFacts(gctx); return nil })
	group.Go(func() error { return s.renewLoop(gctx) })
	group.Go(func() error { s.probeLoop(gctx); return nil })
	for _, endpoint := range s.cfg.HubEndpoints {
		group.Go(func() error { s.dialLoop(gctx, endpoint); return nil })
	}

	err = group.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	s.logger.Info("shutting down")
	s.health.StartDraining()
	return err
}

// runFacts drives the facts collector and records the outcome of each refresh.
//
// The collector owns its own ticker, but it does not know about metrics, so the
// counting happens here — otherwise promfleet_spoke_facts_refresh_total is a
// metric the charts alert on and nothing ever increments.
func (s *spoke) runFacts(ctx context.Context) {
	interval := s.cfg.FactsRefreshInterval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		refreshCtx, cancel := context.WithTimeout(ctx, interval)
		err := s.facts.Refresh(refreshCtx)
		cancel()

		result := "ok"
		if err != nil {
			// A partial refresh is normal: each source fails independently and
			// records a reason rather than blanking the rest.
			result = "error"
			s.logger.Warn("cluster facts refresh incomplete", "error", err)
		}
		s.metrics.FactsRefreshTotal.WithLabelValues(result).Inc()
	}
}

// establishIdentity loads a stored identity, or redeems the enrollment token
// for a new one. An expired stored certificate is discarded rather than used:
// connecting with it would fail the handshake and produce a confusing error.
func (s *spoke) establishIdentity(ctx context.Context) error {
	keyPEM, certPEM, caPEM, err := s.store.Load(ctx)
	switch {
	case err == nil:
		id, lerr := loadIdentity(keyPEM, certPEM, caPEM)
		if lerr != nil {
			s.logger.Warn("stored identity is unusable, re-enrolling", "error", lerr)
			break
		}
		if id.Expired(time.Now()) {
			s.logger.Warn("stored certificate has expired, re-enrolling",
				"not_after", id.Leaf.NotAfter.Format(time.RFC3339))
			break
		}
		s.setIdentity(id)
		s.logger.Info("loaded stored identity",
			"serial", id.Leaf.SerialNumber.Text(16),
			"not_after", id.Leaf.NotAfter.Format(time.RFC3339))
		return nil
	case !errors.Is(err, ErrNoIdentity):
		return fmt.Errorf("load identity: %w", err)
	}

	token, err := readToken(s.cfg.EnrollmentTokenFile)
	if err != nil {
		return err
	}
	id, err := s.enroller.enroll(ctx, s.cfg.ClusterID, token)
	if err != nil {
		return err
	}
	if err := s.store.Save(ctx, id.KeyPEM, id.CertPEM, id.CABundle); err != nil {
		// Not fatal: the spoke can run on an unsaved identity, it will just
		// need a fresh token after a restart. Failing here instead would burn
		// the token for nothing.
		s.logger.Error("could not persist the identity; a restart will need a new enrollment token",
			"error", err)
	}
	s.setIdentity(id)
	return nil
}

// setIdentity publishes a new identity and updates the expiry gauge.
func (s *spoke) setIdentity(id *Identity) {
	s.identity.Store(id)
	s.metrics.ClientCertExpiry.Set(float64(time.Until(id.Leaf.NotAfter).Seconds()))
}

// currentIdentity returns the identity in force.
func (s *spoke) currentIdentity() *Identity { return s.identity.Load() }

// signalReconnect tells every dialer to drop and redial, which is how a renewed
// certificate reaches the tunnels.
func (s *spoke) signalReconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.reconnect)
	s.reconnect = make(chan struct{})
}

// reconnectSignal returns the channel closed on the next reconnect request.
func (s *spoke) reconnectSignal() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconnect
}

// renewLoop renews the client certificate at half its lifetime, with jitter so
// that 100 spokes installed on the same afternoon do not all renew in the same
// minute a fortnight later.
func (s *spoke) renewLoop(ctx context.Context) error {
	// Spread the first check too; a hub restart plus a synchronised fleet is
	// exactly the thundering herd we are avoiding.
	timer := time.NewTimer(jitter(renewCheckInterval))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		timer.Reset(jitter(renewCheckInterval))

		id := s.currentIdentity()
		if id == nil || !id.NeedsRenewal(time.Now(), renewAtFraction) {
			continue
		}
		renewed, err := s.enroller.renew(ctx, id)
		if err != nil {
			remaining := time.Until(id.Leaf.NotAfter)
			level := slog.LevelWarn
			if remaining < 24*time.Hour {
				level = slog.LevelError
			}
			s.logger.Log(ctx, level, "certificate renewal failed",
				"error", err, "expires_in", remaining.Round(time.Minute).String())
			continue
		}
		if err := s.store.Save(ctx, renewed.KeyPEM, renewed.CertPEM, renewed.CABundle); err != nil {
			s.logger.Error("could not persist the renewed identity", "error", err)
		}
		s.setIdentity(renewed)
		s.logger.Info("certificate renewed, reconnecting tunnels",
			"not_after", renewed.Leaf.NotAfter.Format(time.RFC3339))
		s.signalReconnect()
	}
}

// probeLoop keeps the readiness signal for the local Prometheus current. A dead
// Prometheus must not restart the pod, so this feeds readiness only.
func (s *spoke) probeLoop(ctx context.Context) {
	interval := s.cfg.FactsRefreshInterval / 5
	if interval < 15*time.Second {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failures := 0
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.prom.Ping(probeCtx)
		cancel()

		if err == nil {
			failures = 0
			s.metrics.PromUp.Set(1)
			s.health.Set("prometheus", true, "")
		} else {
			failures++
			s.metrics.PromUp.Set(0)
			// Two consecutive failures, not one: a single slow scrape should
			// not flap readiness.
			if failures >= 2 {
				s.health.Set("prometheus", false, "local Prometheus unreachable: "+err.Error())
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// dialLoop maintains one tunnel to one hub endpoint, redialling with full
// jitter. Full jitter rather than plain exponential backoff because with ~100
// spokes, synchronised retry against a restarting hub is a self-inflicted
// denial of service.
func (s *spoke) dialLoop(ctx context.Context, endpoint string) {
	log := s.logger.With("endpoint", endpoint)
	attempt := 0

	// Stagger the very first dial so a fleet-wide rollout does not arrive at
	// the hub in one burst.
	if !sleepCtx(ctx, time.Duration(rand.Int64N(int64(5*time.Second)))) {
		return
	}

	for ctx.Err() == nil {
		connected := time.Now()
		reason := s.dialOnce(ctx, endpoint, log)
		s.metrics.TunnelUp.WithLabelValues(endpoint).Set(0)
		s.health.Set("tunnel", false, "no tunnel to "+endpoint)

		if ctx.Err() != nil {
			return
		}
		s.metrics.TunnelReconnectsTotal.WithLabelValues(reason).Inc()

		// Reset the backoff only after a connection that actually lasted. A
		// connection that dies immediately must not reset the counter, or a
		// crash-looping hub gets hammered.
		if time.Since(connected) > time.Minute {
			attempt = 0
		}
		delay := fullJitter(s.cfg.ReconnectMinBackoff, s.cfg.ReconnectMaxBackoff, attempt)
		attempt++
		log.Warn("tunnel closed, reconnecting", "reason", reason, "in", delay.Round(time.Millisecond).String())
		if !sleepCtx(ctx, delay) {
			return
		}
	}
}

// dialOnce runs a single connection to exhaustion and returns why it ended.
func (s *spoke) dialOnce(ctx context.Context, endpoint string, log *slog.Logger) string {
	id := s.currentIdentity()
	if id == nil {
		return "no-identity"
	}
	tlsCfg, err := mtls.ClientTLSConfig(id.Certificate, id.CABundle, hostOf(endpoint))
	if err != nil {
		log.Error("building the tunnel TLS configuration failed", "error", err)
		return "tls-config"
	}

	dialer := grpctun.NewDialer(grpctun.DialerConfig{
		TLSConfig:  tlsCfg,
		Logger:     log,
		Generation: s.started.UnixNano(),
	})

	// A renewal closes this context so the tunnel is rebuilt with the new
	// certificate rather than waiting out the old one.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.reconnectSignal():
			cancel()
		case <-dialCtx.Done():
		}
	}()

	s.metrics.TunnelUp.WithLabelValues(endpoint).Set(1)
	s.health.Set("tunnel", true, "")
	log.Info("tunnel established")

	if err := dialer.Dial(dialCtx, endpoint, s); err != nil {
		return classify(err)
	}
	return "closed"
}

// Do implements tunnel.Handler by delegating to the Prometheus client, which
// re-validates the request against its own copy of the allow-list. The hub's
// check is never the only one.
func (s *spoke) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	s.metrics.InflightRequests.Inc()
	defer s.metrics.InflightRequests.Dec()
	return s.prom.Do(ctx, req)
}

// Describe implements tunnel.Handler. It is answered from cache and never
// triggers collection inline, so hub polling cannot amplify into Prometheus
// load.
func (s *spoke) Describe(ctx context.Context, knownFingerprint string) (tunnel.Facts, error) {
	return s.facts.Describe(ctx, knownFingerprint)
}

// startAdmin brings up the metrics, health and pprof listener.
func (s *spoke) startAdmin(registry prometheusRegistry) (*httpx.Server, error) {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", s.health.LiveHandler())
	mux.Handle("GET /readyz", s.health.ReadyHandler())
	mux.Handle("GET /metrics", obs.MetricsHandler(registry))
	if s.cfg.PprofEnabled {
		mux.Handle("/debug/pprof/", obs.PprofHandler())
		s.logger.Warn("pprof is enabled; keep this listener off the network")
	}

	srv := httpx.NewServer(httpx.ServerConfig{
		Name:    "admin",
		Addr:    s.cfg.AdminAddr,
		Logger:  s.logger,
		Handler: httpx.Chain(mux, httpx.RequestID, httpx.SecurityHeaders, httpx.Recover(s.logger, nil)),
	})
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("start the admin listener: %w", err)
	}
	s.logger.Info("admin listener ready", "addr", srv.Addr())
	return srv, nil
}

// stopAdmin shuts the admin listener down within the configured grace.
func (s *spoke) stopAdmin(srv *httpx.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		s.logger.Warn("admin listener did not shut down cleanly", "error", err)
	}
}
