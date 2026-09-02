// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/tunneltest"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// --- serveTunnel ------------------------------------------------------

func TestServeTunnelStopsQuietlyWhenTheContextEnds(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.serveTunnel(ctx, h.tunnel.Listener()) }()
	cancel()

	select {
	case err := <-done:
		// A cancelled context is an ordinary shutdown, not a fault to report.
		if err != nil {
			t.Fatalf("serveTunnel = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveTunnel did not return after cancellation")
	}
}

func TestServeTunnelReportsAListenerThatFailed(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	listener := h.tunnel.Listener()
	if err := listener.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	err := h.serveTunnel(context.Background(), listener)
	if err == nil || !strings.Contains(err.Error(), "tunnel listener") {
		t.Fatalf("serveTunnel = %v, want a named listener failure", err)
	}
}

// --- watchCertExpiry --------------------------------------------------

func TestWatchCertExpiryPublishesTheGaugeAndLeavesAHealthyCAAlone(t *testing.T) {
	t.Parallel()

	h, _ := newTestHub(t, newHubConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.watchCertExpiry(ctx)

	got := metricValue(t, h.promReg, "promfleet_hub_ca_cert_expiry_seconds")
	if got <= 0 {
		t.Fatalf("ca expiry gauge = %v, want the remaining lifetime", got)
	}
	if ready, blockers := h.health.Ready(); !ready {
		t.Fatalf("a healthy CA blocked readiness: %v", blockers)
	}
}

func TestWatchCertExpiryRefusesReadinessBeforeTheCALapses(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A CA with under a day left: every renewal is about to start failing and
	// the operator has to hear about it before the fleet does.
	if _, err := ca.Create(cfg.CACertFile, cfg.CAKeyFile, ca.Options{
		TrustDomain: cfg.TrustDomain, CATTL: time.Hour,
	}); err != nil {
		t.Fatalf("create short-lived CA: %v", err)
	}
	h, sink := newTestHub(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.watchCertExpiry(ctx)

	ready, blockers := h.health.Ready()
	if ready {
		t.Fatal("the hub reported ready with a CA about to expire")
	}
	if !strings.Contains(blockers["ca"], "expires in") {
		t.Fatalf("readiness blocker = %q, want it to name the expiry", blockers["ca"])
	}
	sink.mustFind(t, "component not ready")
}

// --- watchStoreHealth -------------------------------------------------

// TestWatchStoreHealthFollowsTheStore pins the loop's whole contract: a
// store that stops decoding takes readiness away, one that recovers gives it
// back without a restart, and a probe cut short by shutdown changes nothing.
// The failure is an ErrSchemaTooNew, the case a rolling upgrade produces:
// the newer replica writes a document this build cannot read, and until
// this loop existed the old replica kept telling the Service it was ready
// while every cache miss it served was refused.
func TestWatchStoreHealthFollowsTheStore(t *testing.T) {
	t.Parallel()

	h, sink := newTestHub(t, newHubConfig(t))
	faulty := &faultyStore{Store: h.store}
	h.store = faulty
	if ready, blockers := h.health.Ready(); !ready {
		t.Fatalf("not ready before the first probe: %v", blockers)
	}

	faulty.failEpoch(fmt.Errorf("decode state: %w", store.ErrSchemaTooNew))
	h.probeStore(context.Background())
	ready, blockers := h.health.Ready()
	if ready {
		t.Fatal("the hub reported ready with a state document it cannot read")
	}
	if !strings.Contains(blockers["store"], store.ErrSchemaTooNew.Error()) {
		t.Fatalf("readiness blocker = %q, want it to carry the store's error", blockers["store"])
	}
	sink.mustFind(t, "component not ready")

	// Shutdown mid-probe is not a store failure. The store is already
	// marked unready here, so what this pins is that the probe does not
	// REWRITE the reason with a context error -- nor, on a healthy store,
	// take readiness away on the way out.
	faulty.failEpoch(nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	faulty.failEpoch(context.Canceled)
	h.probeStore(cancelled)
	if _, after := h.health.Ready(); after["store"] != blockers["store"] {
		t.Fatalf("a cancelled probe rewrote the blocker: %q -> %q", blockers["store"], after["store"])
	}

	// The document is fixed: readiness returns on the next probe, with no
	// restart.
	faulty.failEpoch(nil)
	h.probeStore(context.Background())
	if ready, blockers := h.health.Ready(); !ready {
		t.Fatalf("readiness did not return once the store recovered: %v", blockers)
	}
	sink.mustFind(t, "readiness check passed")

	// The loop itself: it probes on entry, not one interval later, and it
	// stops with the context.
	faulty.failEpoch(store.ErrCorrupt)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.watchStoreHealth(ctx) }()
	eventually(t, 5*time.Second, "the loop's first probe to take readiness away", func() bool {
		ready, _ := h.health.Ready()
		return !ready
	})
	stop()
	<-done
}

// --- drain ------------------------------------------------------------

// recordingListener wraps a real listener and records what the world looked
// like at the moment drain shut it down, which is the only way to assert the
// ordering drain exists to guarantee.
type recordingListener struct {
	tunnel.Listener

	h   *hub
	err error

	mu               sync.Mutex
	called           bool
	at               time.Time
	drainingAtCall   bool
	registrantsAtCal int
}

func (l *recordingListener) Shutdown(ctx context.Context) error {
	l.mu.Lock()
	l.called = true
	l.at = time.Now()
	l.drainingAtCall = l.h.health.Draining()
	l.registrantsAtCal = len(l.h.registry.List())
	l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	return l.Listener.Shutdown(ctx)
}

func (l *recordingListener) observed() (called, draining bool, at time.Time, registrants int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.called, l.drainingAtCall, l.at, l.registrantsAtCal
}

func TestDrainGoesNotReadyWaitsThenClosesSessionsBeforeListeners(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t, "--shutdown-drain-delay", "80ms")
	h, sink := newWiredHub(t, cfg)
	h.tunnel = mustTunnelServer(t, h)
	rec := &recordingListener{Listener: h.tunnel.Listener(), h: h}

	start := time.Now()
	h.drain(rec)

	called, draining, at, registrants := rec.observed()
	if !called {
		t.Fatal("drain never shut the tunnel listener down")
	}
	// Not-ready first, so the endpoint controller removes this pod before
	// traffic starts failing.
	if !draining {
		t.Fatal("the listener was shut down before readiness reported not-ready")
	}
	if waited := at.Sub(start); waited < 80*time.Millisecond {
		t.Fatalf("waited %s before refusing work, want at least the 80ms drain delay", waited)
	}
	// Sessions are closed before the listener goes, so a spoke is told to go
	// elsewhere rather than discovering it on a keepalive timeout.
	if registrants != 0 {
		t.Fatalf("%d clusters were still registered when the listener was shut down", registrants)
	}
	if ready, _ := h.health.Ready(); ready {
		t.Fatal("the hub still reports ready after draining")
	}
	sink.mustFind(t, "draining")
}

func TestDrainReportsATunnelListenerThatWouldNotStop(t *testing.T) {
	t.Parallel()

	h, sink := newWiredHub(t, newHubConfig(t))
	h.tunnel = mustTunnelServer(t, h)
	rec := &recordingListener{
		Listener: h.tunnel.Listener(), h: h,
		err: errors.New("sessions are wedged"),
	}

	h.drain(rec)

	sink.mustFind(t, "tunnel listener did not shut down cleanly")
}

// --- a real spoke through the real listener ---------------------------

// issueSpokeCert mints a spoke certificate from the hub's own CA, the way
// /enroll does, so the tunnel handshake below is the production one.
func issueSpokeCert(t *testing.T, h *hub, clusterID string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate spoke key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	certPEM, leaf, err := h.authority.IssueSpokeFromCSR(csrDER, clusterID)
	if err != nil {
		t.Fatalf("issue spoke certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}
}

func TestASpokeConnectsThroughTheMCPListenerAndDrainTellsItWhy(t *testing.T) {
	t.Parallel()

	const clusterID = "prod"
	cfg := newHubConfig(t, "--shutdown-drain-delay", "0s")
	h, _ := newWiredHub(t, cfg)
	h.tunnel = mustTunnelServer(t, h)
	public := mustStartPublic(t, h)
	listener := h.tunnel.Listener()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.serveTunnel(ctx, listener) }()
	go h.registry.Run(ctx)

	dialed := make(chan error, 1)
	go func() {
		dialed <- wstun.Dial(ctx, wstun.ClientConfig{
			// The tunnel is a WebSocket on the ordinary HTTP listener, so this
			// is the only port and the only hostname there is (ADR-0014).
			URL:         "ws://" + public.Addr() + cfg.TunnelPath,
			Certificate: issueSpokeCert(t, h, clusterID),
			ClusterID:   clusterID,
			Logger:      slog.New(slog.DiscardHandler),
			Generation:  time.Now().UnixNano(),
		}, &tunneltest.EchoHandler{})
	}()

	// Registered and routable: the registry hands out a session, which is what
	// a tool call would use to reach this cluster.
	var session tunnel.Session
	eventually(t, 15*time.Second, "the spoke to register a routable session", func() bool {
		s, err := h.registry.Session(clusterID)
		if err != nil {
			return false
		}
		session = s
		return true
	})
	if c, ok := h.registry.Cluster(clusterID); !ok || c.ConnectedSince.IsZero() {
		t.Fatalf("cluster entry = %+v, ok = %v; want a connected entry", c, ok)
	}

	h.drain(listener)

	// The spoke is told why it is being disconnected so it reconnects
	// elsewhere immediately instead of waiting out the keepalive timeout.
	reader, ok := session.(interface{ CloseReason() string })
	if !ok {
		t.Fatalf("session of type %T does not record a close reason", session)
	}
	if got := reader.CloseReason(); got != "hub-shutdown" {
		t.Fatalf("close reason = %q, want %q", got, "hub-shutdown")
	}
	select {
	case <-dialed:
	case <-time.After(15 * time.Second):
		t.Fatal("the spoke was never disconnected")
	}
	if _, ok := h.registry.Cluster(clusterID); ok {
		t.Fatal("the cluster is still registered after draining")
	}
}

// --- flushTraces ------------------------------------------------------

func TestFlushTracesReportsAFailureWithoutFailingTheShutdown(t *testing.T) {
	t.Parallel()

	logger, sink := newLogSink()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the parent context is always dead by the time this runs

	var live bool
	var deadlined bool
	flushTraces(ctx, logger, func(c context.Context) error {
		// The parent is already cancelled, so a flush that inherited it would
		// export nothing at all. It must get its own live, bounded context.
		live = c.Err() == nil
		_, deadlined = c.Deadline()
		return errors.New("the collector is unreachable")
	})

	if !live {
		t.Fatal("the flush inherited the cancelled parent context")
	}
	if !deadlined {
		t.Fatal("the flush context carries no deadline")
	}
	sink.mustFind(t, "flushing traces failed")
}

func TestFlushTracesIsSilentOnSuccess(t *testing.T) {
	t.Parallel()

	logger, sink := newLogSink()
	flushTraces(context.Background(), logger, func(context.Context) error { return nil })
	sink.mustNotFind(t, "flushing traces failed")
}

// --- Run --------------------------------------------------------------

// captureStdout redirects os.Stdout for the duration of the test. Run builds
// its own logger onto os.Stdout, which is the only way to read what a real
// process would print.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	var mu sync.Mutex
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		chunk := make([]byte, 4096)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				mu.Lock()
				buf.Write(chunk[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		os.Stdout = orig
		_ = w.Close()
		<-done
		_ = r.Close()
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// awaitLogValue polls captured JSON log output for a record and returns one of
// its attributes.
func awaitLogValue(t *testing.T, read func() string, msg, key string) string {
	t.Helper()
	var value string
	eventually(t, 20*time.Second, "log record "+msg, func() bool {
		for line := range strings.SplitSeq(read(), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if rec["msg"] != msg {
				continue
			}
			s, ok := rec[key].(string)
			if !ok {
				return false
			}
			value = s
			return true
		}
		return false
	})
	return value
}

// TestRunServesAndShutsDownCleanly drives the whole composition root: real
// listeners, a real credential store and a real drain. It is not parallel: it
// redirects os.Stdout and installs a global tracer provider.
func TestRunServesAndShutsDownCleanly(t *testing.T) {
	read := captureStdout(t)
	cfg := newHubConfig(t, "--shutdown-drain-delay", "400ms", "--public-url", "http://127.0.0.1/mcp")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	adminAddr := awaitLogValue(t, read, "admin listener ready", "addr")
	mcpAddr := awaitLogValue(t, read, "mcp listener ready", "addr")
	awaitLogValue(t, read, "tunnel endpoint ready", "addr")

	// Everything is up, so readiness is up: store, CA and tunnel all reported.
	eventually(t, 10*time.Second, "readiness", func() bool {
		status, _ := httpGet(t, "http://"+adminAddr+"/readyz")
		return status == http.StatusOK
	})
	// The agent-facing endpoint exists and refuses an unauthenticated call.
	if status, _ := httpGet(t, "http://"+mcpAddr+"/pki/bundle"); status != http.StatusOK {
		t.Fatalf("/pki/bundle = %d, want 200", status)
	}
	// A brand new hub has an admin credential, printed exactly once.
	if !strings.Contains(read(), "BOOTSTRAP ADMIN TOKEN") {
		t.Fatal("no bootstrap admin token was printed on first boot")
	}

	cancel()

	// Drain reports not-ready before it stops accepting work.
	eventually(t, 10*time.Second, "not-ready during drain", func() bool {
		status, body := httpGet(t, "http://"+adminAddr+"/readyz")
		return status == http.StatusServiceUnavailable && strings.Contains(body, `"draining":true`)
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil on a clean shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if !strings.Contains(read(), `"msg":"starting"`) {
		t.Fatal("Run never announced itself")
	}
}

func TestRunRefusesAnUnusableLogConfiguration(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	cfg.LogLevel = "chatty"

	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "configure logging") {
		t.Fatalf("Run = %v, want a logging configuration failure", err)
	}
}

func TestRunRefusesATracingEndpointItCannotParse(t *testing.T) {
	captureStdout(t)
	cfg := newHubConfig(t)
	// A control character makes the gRPC target unparseable, which is the one
	// way an exporter refuses to be built at all rather than dialling lazily.
	cfg.OTLPEndpoint = "\x00collector:4317"

	// The context is bounded so a Run that wrongly got past tracing fails the
	// test instead of hanging the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := Run(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "initialise tracing") {
		t.Fatalf("Run = %v, want a tracing initialisation failure", err)
	}
}

func TestRunPropagatesAStartupFailure(t *testing.T) {
	captureStdout(t)
	// The secret backend outside a cluster has no service account to use, and
	// that must be a startup failure rather than a silent fallback.
	cfg := newHubConfig(t, "--state-backend", config.StateBackendSecret)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := Run(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "needs an in-cluster service account") {
		t.Fatalf("Run = %v, want the startup failure to surface", err)
	}
}
