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

	"golang.org/x/sync/errgroup"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/clusterfacts"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/httpx"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
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

// defaultFactsRefresh is the facts collection period when none is configured.
const defaultFactsRefresh = 10 * time.Minute

// minProbeInterval floors the readiness probe. The probe follows the facts
// interval, but a fast facts interval must not turn a readiness check into a
// scrape storm against the local Prometheus.
const minProbeInterval = 15 * time.Second

// maxFirstDialDelay bounds the random delay before a dialer's first
// connection, so that a fleet-wide rollout does not arrive in one burst.
const maxFirstDialDelay = 5 * time.Second

// minConnectionLifetime is how long a tunnel must have lasted before its
// closure is treated as an ordinary disconnect and the backoff is reset. A
// connection that dies immediately is a symptom, not a success.
const minConnectionLifetime = time.Minute

// timings are the periods the background loops run on.
//
// They are derived once, in [newTimings], rather than recomputed inside each
// loop. The derivation is a decision — the probe interval has a floor, and the
// renewal check does not follow the facts interval at all — and a decision
// belongs somewhere it can be read and tested on its own.
type timings struct {
	// facts is how often cluster facts are recollected, and also the budget
	// for one collection: a refresh that outruns its own period is not a
	// refresh, it is a backlog.
	facts time.Duration
	// probe is how often the local Prometheus is probed for readiness.
	probe time.Duration
	// renewCheck is how often the renewal decision is re-evaluated.
	renewCheck time.Duration
	// dialStagger bounds a dialer's initial random delay.
	dialStagger time.Duration
}

// newTimings derives the loop periods from configuration.
func newTimings(cfg *config.Spoke) timings {
	facts := cfg.FactsRefreshInterval
	if facts <= 0 {
		facts = defaultFactsRefresh
	}
	probe := facts / 5
	if probe < minProbeInterval {
		probe = minProbeInterval
	}
	return timings{
		facts:       facts,
		probe:       probe,
		renewCheck:  renewCheckInterval,
		dialStagger: maxFirstDialDelay,
	}
}

// Run starts the spoke and blocks until ctx is cancelled or a fatal error
// occurs. It returns nil on a clean shutdown.
func Run(ctx context.Context, cfg *config.Spoke) error {
	logger, err := obs.NewLogger(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	build := version.Get()
	logger = logger.With("component", "spoke", "cluster_id", cfg.ClusterID)
	logger.InfoContext(ctx, "starting", "version", build.Version, "commit", build.Commit)

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
			logger.WarnContext(flush, "flushing traces failed", "error", err)
		}
	}()

	s := &spoke{
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
		health:  health,
		build:   build,
		now:     time.Now,
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
	// now reads the wall clock. It is injected the same way the registry and
	// the proxy inject theirs, because two decisions in this package are about
	// elapsed time rather than about sleeping: whether a tunnel lasted long
	// enough to reset the backoff, and how far through its life a certificate
	// is.
	now func() time.Time
	// timing holds the loop periods; see [newTimings].
	timing timings

	prom      *promclient.Client
	facts     *clusterfacts.Collector
	store     identityStore
	enroller  *enroller
	identity  atomic.Pointer[Identity]
	reconnect chan struct{} // closed and replaced to force every dialer to redial
	mu        sync.Mutex
}

func (s *spoke) run(ctx context.Context, registry prometheusRegistry) error {
	s.timing = newTimings(s.cfg)

	admin, err := s.startAdmin(ctx, registry)
	if err != nil {
		return err
	}
	//nolint:contextcheck // deliberate: the parent context is already cancelled by the time this runs.
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
		Labels:          labelsWithSDLC(s.cfg.ClusterLabels, s.cfg.ClusterSDLC),
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
	s.logger.InfoContext(ctx, "identity store selected", "store", s.store.Describe())

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
		s.logger.WarnContext(ctx, "initial facts refresh incomplete", "error", err)
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
	s.logger.InfoContext(ctx, "shutting down")
	s.health.StartDraining()
	return err
}

// runFacts drives the facts collector and records the outcome of each refresh.
//
// The collector owns its own ticker, but it does not know about metrics, so the
// counting happens here — otherwise promfleet_spoke_facts_refresh_total is a
// metric the charts alert on and nothing ever increments.
func (s *spoke) runFacts(ctx context.Context) {
	ticker := time.NewTicker(s.timing.facts)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		refreshCtx, cancel := context.WithTimeout(ctx, s.timing.facts)
		err := s.facts.Refresh(refreshCtx)
		cancel()

		result := "ok"
		if err != nil {
			// A partial refresh is normal: each source fails independently and
			// records a reason rather than blanking the rest.
			result = "error"
			s.logger.WarnContext(ctx, "cluster facts refresh incomplete", "error", err)
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
			s.logger.WarnContext(ctx, "stored identity is unusable, re-enrolling", "error", lerr)
			break
		}
		if id.Expired(s.now()) {
			s.logger.WarnContext(ctx, "stored certificate has expired, re-enrolling",
				"not_after", id.Leaf.NotAfter.Format(time.RFC3339))
			break
		}
		s.setIdentity(id)
		s.logger.InfoContext(ctx, "loaded stored identity",
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
		s.logger.ErrorContext(ctx, "could not persist the identity; a restart will need a new enrollment token",
			"error", err)
	}
	s.setIdentity(id)
	return nil
}

// setIdentity publishes a new identity and updates the expiry gauge.
func (s *spoke) setIdentity(id *Identity) {
	s.identity.Store(id)
	s.metrics.ClientCertExpiry.Set(id.Leaf.NotAfter.Sub(s.now()).Seconds())
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
	timer := time.NewTimer(jitter(s.timing.renewCheck))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			// Reported rather than swallowed, so that the one place which
			// decides whether a cancelled context is a failure is [spoke.run].
			return ctx.Err()
		case <-timer.C:
		}
		timer.Reset(jitter(s.timing.renewCheck))

		id := s.currentIdentity()
		if id == nil || !id.NeedsRenewal(s.now(), renewAtFraction) {
			continue
		}
		renewed, err := s.enroller.renew(ctx, id)
		if err != nil {
			remaining := id.Leaf.NotAfter.Sub(s.now())
			level := slog.LevelWarn
			if remaining < 24*time.Hour {
				level = slog.LevelError
			}
			s.logger.Log(ctx, level, "certificate renewal failed",
				"error", err, "expires_in", remaining.Round(time.Minute).String())
			continue
		}
		if err := s.store.Save(ctx, renewed.KeyPEM, renewed.CertPEM, renewed.CABundle); err != nil {
			s.logger.ErrorContext(ctx, "could not persist the renewed identity", "error", err)
		}
		s.setIdentity(renewed)
		s.logger.InfoContext(ctx, "certificate renewed, reconnecting tunnels",
			"not_after", renewed.Leaf.NotAfter.Format(time.RFC3339))
		s.signalReconnect()
	}
}

// probeLoop keeps the readiness signal for the local Prometheus current. A dead
// Prometheus must not restart the pod, so this feeds readiness only.
func (s *spoke) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(s.timing.probe)
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

	// Normalise once, so the log line and the error an operator sees name a
	// URL rather than whatever shorthand was configured. A value that cannot
	// be normalised will never work, so there is nothing to retry.
	target, err := wstun.NormalizeEndpoint(endpoint)
	if err != nil {
		log.ErrorContext(ctx, "hub endpoint is unusable", "error", err)
		return
	}
	if target != endpoint {
		log.InfoContext(ctx, "hub endpoint normalised", "url", target)
	}
	attempt := 0

	// Stagger the very first dial so a fleet-wide rollout does not arrive at
	// the hub in one burst.
	if !sleepCtx(ctx, time.Duration(rand.Int64N(int64(s.timing.dialStagger)))) {
		return
	}

	for ctx.Err() == nil {
		connected := s.now()
		reason := s.dialOnce(ctx, target, log)
		s.metrics.TunnelUp.WithLabelValues(target).Set(0)
		s.health.Set("tunnel", false, "no tunnel to "+target)

		if ctx.Err() != nil {
			return
		}
		s.metrics.TunnelReconnectsTotal.WithLabelValues(reason).Inc()

		// Reset the backoff only after a connection that actually lasted. A
		// connection that dies immediately must not reset the counter, or a
		// crash-looping hub gets hammered.
		if s.now().Sub(connected) > minConnectionLifetime {
			attempt = 0
		}
		delay := fullJitter(s.cfg.ReconnectMinBackoff, s.cfg.ReconnectMaxBackoff, attempt)
		attempt++
		log.WarnContext(ctx, "tunnel closed, reconnecting", "reason", reason, "in", delay.Round(time.Millisecond).String())
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

	// The certificate is presented inside the connection, not in a TLS
	// handshake: an Ingress terminates TLS and the hub would never see it.
	// CABundle here verifies whatever answers on the hub's behalf.
	//
	// Dial reports every outcome, including an orderly close, as a
	// *grpctun.DialError carrying a reason from a closed set, and classify
	// believes it. There is deliberately no separate "it returned nil" branch:
	// classify already answers "closed" for a nil error, and a second place
	// that knows that label is a second place for it to drift.
	return classify(wstun.Dial(dialCtx, wstun.ClientConfig{
		URL:          endpoint,
		Certificate:  id.Certificate,
		CABundle:     id.CABundle,
		TLSInsecure:  s.cfg.HubTLSInsecure,
		ClusterID:    s.cfg.ClusterID,
		AgentVersion: s.build.Version,
		Logger:       log,
		Generation:   s.started.UnixNano(),
	}, s))
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
func (s *spoke) startAdmin(ctx context.Context, registry prometheusRegistry) (*httpx.Server, error) {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", s.health.LiveHandler())
	mux.Handle("GET /readyz", s.health.ReadyHandler())
	mux.Handle("GET /metrics", obs.MetricsHandler(registry))
	if s.cfg.PprofEnabled {
		mux.Handle("/debug/pprof/", obs.PprofHandler())
		s.logger.WarnContext(ctx, "pprof is enabled; keep this listener off the network")
	}

	srv := httpx.NewServer(httpx.ServerConfig{
		Name:    "admin",
		Addr:    s.cfg.AdminAddr,
		Logger:  s.logger,
		Handler: httpx.Chain(mux, httpx.RequestID, httpx.SecurityHeaders, httpx.Recover(s.logger, nil)),
	})
	if err := srv.Start(ctx); err != nil {
		return nil, fmt.Errorf("start the admin listener: %w", err)
	}
	s.logger.InfoContext(ctx, "admin listener ready", "addr", srv.Addr())
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

// labelsWithSDLC merges the required lifecycle stage into the operator's
// labels under the reserved "sdlc" key.
//
// Publishing it as an ordinary label is what makes it usable: agent key scopes
// select clusters with matchLabels and fanout_query takes a label selector, so
// putting the stage there means every existing selector mechanism can target it
// with no special case anywhere. The dedicated field is what makes it
// *required*; this is what makes it *reachable*.
//
// The field wins over a hand-written "sdlc" label rather than the other way
// round: one of them was validated and normalised, and the other was typed into
// a map.
func labelsWithSDLC(labels map[string]string, sdlc string) map[string]string {
	if sdlc == "" {
		return labels
	}
	merged := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		merged[k] = v
	}
	merged["sdlc"] = sdlc
	return merged
}
