// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/rand"
	"encoding/pem"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// testNamespace is the namespace every fake API server in this package serves.
const testNamespace = "prometheus-mcp"

// ---------------------------------------------------------------------------
// Kubernetes API server
// ---------------------------------------------------------------------------

// fakeAPIServer is enough of the Kubernetes Secret API for the Secret identity
// backend to run against a real [kube.Client].
//
// It is an HTTP server rather than a stub of the client because the client is
// where the resource-version compare-and-swap, the 404-to-ErrNoIdentity
// translation and the AlreadyExists race actually live. A stub of the client
// would test the stub.
type fakeAPIServer struct {
	mu sync.Mutex
	// objects maps secret name to its stored data.
	objects map[string]map[string][]byte
	// versions maps secret name to its current resource version.
	versions map[string]int
	// failGet, failCreate and failUpdate, when set, replace the response for
	// that verb.
	failGet, failCreate, failUpdate *apiFailure
	// creates counts create attempts and updates counts accepted updates, so
	// a test can prove the AlreadyExists race retried rather than looped.
	creates, updates int
}

// apiFailure is a canned API server refusal.
type apiFailure struct {
	status int
	reason string
	// once makes the failure apply to a single request, which is how the
	// "another replica created it in the gap" race is staged.
	once bool
}

// newFakeAPIServer starts one and returns a client scoped to it.
func newFakeAPIServer(t *testing.T) (*fakeAPIServer, *kube.Client) {
	t.Helper()

	f := &fakeAPIServer{
		objects:  map[string]map[string][]byte{},
		versions: map[string]int{},
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)

	client, err := kube.New(kube.Config{
		APIServerURL: srv.URL,
		Namespace:    testNamespace,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("kube.New: %v", err)
	}
	return f, client
}

// seed installs a secret as though a previous process had written it.
func (f *fakeAPIServer) seed(name string, data map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[name] = data
	f.versions[name] = 1
}

// stored returns a copy of the named secret's data.
func (f *fakeAPIServer) stored(name string) map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.objects[name] {
		out[k] = v
	}
	return out
}

// counts reports how many creates were attempted and updates accepted.
func (f *fakeAPIServer) counts() (creates, updates int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.creates, f.updates
}

func (f *fakeAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/namespaces/" + testNamespace + "/secrets"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeStatus(w, http.StatusNotFound, "NotFound", "no such route "+r.URL.Path)
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")

	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		f.get(w, name)
	case http.MethodPost:
		f.create(w, r)
	case http.MethodPut:
		f.update(w, r, name)
	default:
		writeStatus(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (f *fakeAPIServer) get(w http.ResponseWriter, name string) {
	if fail := take(&f.failGet); fail != nil {
		writeStatus(w, fail.status, fail.reason, "get refused")
		return
	}
	data, ok := f.objects[name]
	if !ok {
		writeStatus(w, http.StatusNotFound, "NotFound", `secrets "`+name+`" not found`)
		return
	}
	writeSecret(w, http.StatusOK, name, f.versions[name], data)
}

func (f *fakeAPIServer) create(w http.ResponseWriter, r *http.Request) {
	f.creates++
	if fail := take(&f.failCreate); fail != nil {
		writeStatus(w, fail.status, fail.reason, "create refused")
		return
	}
	var body struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Data map[string][]byte `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeStatus(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if _, ok := f.objects[body.Metadata.Name]; ok {
		writeStatus(w, http.StatusConflict, "AlreadyExists",
			`secrets "`+body.Metadata.Name+`" already exists`)
		return
	}
	f.objects[body.Metadata.Name] = body.Data
	f.versions[body.Metadata.Name] = 1
	writeSecret(w, http.StatusCreated, body.Metadata.Name, 1, body.Data)
}

func (f *fakeAPIServer) update(w http.ResponseWriter, r *http.Request, name string) {
	if fail := take(&f.failUpdate); fail != nil {
		writeStatus(w, fail.status, fail.reason, "update refused")
		return
	}
	var body struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string][]byte `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeStatus(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	// The compare-and-swap the whole persistence design rests on.
	if body.Metadata.ResourceVersion != strconv.Itoa(f.versions[name]) {
		writeStatus(w, http.StatusConflict, "Conflict",
			"the object has been modified; please apply your changes to the latest version")
		return
	}
	f.objects[name] = body.Data
	f.versions[name]++
	f.updates++
	writeSecret(w, http.StatusOK, name, f.versions[name], body.Data)
}

// take consumes a staged failure, clearing it when it was a one-shot.
func take(slot **apiFailure) *apiFailure {
	fail := *slot
	if fail != nil && fail.once {
		*slot = nil
	}
	return fail
}

func writeSecret(w http.ResponseWriter, code int, name string, version int, data map[string][]byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       testNamespace,
			"resourceVersion": strconv.Itoa(version),
		},
		"type": "Opaque",
		"data": data,
	})
}

func writeStatus(w http.ResponseWriter, code int, reason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiVersion": "v1",
		"kind":       "Status",
		"status":     "Failure",
		"code":       code,
		"reason":     reason,
		"message":    message,
	})
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

// pool is the trust anchor a hub would verify a spoke against.
func (c *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// verify is the wstun.ServerConfig.Verify this CA supplies: chain verification
// plus the URI-SAN identity rule, which is the rule internal/ca stamps in and
// the hub reads out.
func (c *testCA) verify(chain []*x509.Certificate) (tunnel.Identity, error) {
	if len(chain) == 0 {
		return tunnel.Identity{}, errors.New("no certificate presented")
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, cert := range chain[1:] {
		inter.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.pool(),
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return tunnel.Identity{}, err
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "pmf" || leaf.URIs[0].Host != trustDomain {
		return tunnel.Identity{}, errors.New("certificate carries no spoke identity")
	}
	id, ok := strings.CutPrefix(leaf.URIs[0].Path, "/spoke/")
	if !ok || id == "" {
		return tunnel.Identity{}, errors.New("certificate carries no spoke identity")
	}
	return tunnel.Identity{
		ClusterID:    id,
		CertSerial:   fmt.Sprintf("%x", leaf.SerialNumber),
		CertNotAfter: leaf.NotAfter,
	}, nil
}

// identityOver mints an identity whose certificate is valid across an explicit
// window, so a pinned clock can be placed anywhere in its life.
func (c *testCA) identityOver(t *testing.T, clusterID string, notBefore, notAfter time.Time) *Identity {
	t.Helper()

	key, keyPEM, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkixName("spoke:" + clusterID),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "pmf", Host: trustDomain, Path: "/spoke/" + clusterID}},
	}, c.cert, key.Public(), c.key)
	if err != nil {
		t.Fatalf("create spoke certificate: %v", err)
	}
	id, err := loadIdentity(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.pem)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------------
// Tunnel hub
// ---------------------------------------------------------------------------

// tunnelHub is a real wstun server on a real HTTP listener: the hub half of
// ADR-0014, including the in-band handshake, chain verification and the
// identity rule. The spoke's dial path is only worth testing against something
// that would refuse it.
type tunnelHub struct {
	ca  *testCA
	url string
	// sessions receives every accepted session.
	sessions chan tunnel.Session
}

// newTunnelHub stands one up and serves until the test ends.
func newTunnelHub(t *testing.T, ca *testCA) *tunnelHub {
	t.Helper()

	srv, err := wstun.NewServer(wstun.ServerConfig{
		Verify:   ca.verify,
		Logger:   quiet(),
		ServerID: "hub-test-0",
		// Slack keepalive: the production 10s budget is not survivable on an
		// oversubscribed box running this package's tests under -race, and a
		// late ping has nothing to do with what is being asserted here.
		Keepalive: grpctun.KeepaliveParams{
			Time: time.Minute, Timeout: 30 * time.Second, PermitWithoutStream: true,
		},
	})
	if err != nil {
		t.Fatalf("wstun.NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(wstun.DefaultPath, srv.Handler())
	ts := httptest.NewServer(mux)

	h := &tunnelHub{
		ca:       ca,
		url:      "ws" + strings.TrimPrefix(ts.URL, "http") + wstun.DefaultPath,
		sessions: make(chan tunnel.Session, 8),
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- srv.Listener().Serve(ctx, tunnel.SessionHandlerFunc(
			func(_ context.Context, s tunnel.Session) (func(), error) {
				h.sessions <- s
				return nil, nil
			}))
	}()
	t.Cleanup(func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = srv.Listener().Shutdown(shutCtx)
		<-served
		ts.Close()
	})
	return h
}

// awaitSession blocks for the next accepted session.
func (h *tunnelHub) awaitSession(t *testing.T) tunnel.Session {
	t.Helper()
	select {
	case s := <-h.sessions:
		return s
	case <-time.After(20 * time.Second):
		t.Fatal("no spoke connected to the hub")
		return nil
	}
}

// ---------------------------------------------------------------------------
// Clock, logs and small utilities
// ---------------------------------------------------------------------------

// stubClock is a manually advanced clock.
//
// internal/testutil has one, but this package also needs a clock that moves on
// its own between two reads inside a running loop — which is how "did this
// connection last a minute?" is asked without waiting a minute — so the local
// one carries a per-read step as well.
type stubClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

// newStubClock starts at the wall clock, so certificates minted by the test CA
// (which uses the real clock) sit sensibly around it.
func newStubClock() *stubClock { return &stubClock{t: time.Now()} }

// Now returns the current time and then advances by the configured step.
func (c *stubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.t
	c.t = c.t.Add(c.step)
	return now
}

// Advance moves the clock forward by d.
func (c *stubClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setStep makes every subsequent read advance the clock by d.
func (c *stubClock) setStep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.step = d
}

// logCapture is an slog.Handler that keeps every record, so a test can assert
// on the level a message was logged at. The level is the behaviour in at least
// one place here: a renewal failing inside the last day is an error and
// earlier is a warning, and an operator's alerting depends on the difference.
type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func newLogCapture() (*logCapture, *slog.Logger) {
	c := &logCapture{}
	return c, slog.New(c)
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.Clone())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// find returns the first record whose message contains want.
func (c *logCapture) find(want string) (slog.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		if strings.Contains(r.Message, want) {
			return r, true
		}
	}
	return slog.Record{}, false
}

// has reports whether any record's message contains want.
func (c *logCapture) has(want string) bool {
	_, ok := c.find(want)
	return ok
}

// level returns the level a message was logged at, failing the test when the
// message was never logged.
func (c *logCapture) level(t *testing.T, want string) slog.Level {
	t.Helper()
	r, ok := c.find(want)
	if !ok {
		t.Fatalf("no log record mentioning %q; got %s", want, c.messages())
	}
	return r.Level
}

// messages renders every captured message, for failure output.
func (c *logCapture) messages() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.records))
	for _, r := range c.records {
		out = append(out, r.Level.String()+" "+r.Message)
	}
	return "[" + strings.Join(out, " | ") + "]"
}

// attr returns a record's named attribute as a string.
func attrString(r slog.Record, key string) string {
	var out string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			out = a.Value.String()
			return false
		}
		return true
	})
	return out
}

// spokeProbe is the test's window into one spoke: what it logged, and what a
// Prometheus scraping it would read.
type spokeProbe struct {
	*logCapture
	registry *prometheus.Registry
}

// metric reads one sample from the spoke's registry through the same handler
// the admin listener serves, because the exposition is the only value an
// operator ever sees. Labels are given as "key=value" and all must match. A
// series with no samples yet reads as zero, which is what an untouched counter
// means to a query.
func (p *spokeProbe) metric(t *testing.T, name string, labels ...string) float64 {
	t.Helper()

	rec := httptest.NewRecorder()
	obs.MetricsHandler(p.registry).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scraping /metrics returned %d", rec.Code)
	}
	for line := range strings.SplitSeq(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		// A longer metric name sharing this prefix, such as prom_up against
		// prom_requests_total.
		rest := line[len(name):]
		if rest == "" || (rest[0] != '{' && rest[0] != ' ') {
			continue
		}
		matched := true
		for _, label := range labels {
			key, value, _ := strings.Cut(label, "=")
			if !strings.Contains(rest, key+`="`+value+`"`) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		fields := strings.Fields(line)
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			t.Fatalf("metric line %q carries no value: %v", line, err)
		}
		return value
	}
	return 0
}

// newTestSpoke assembles a spoke with real metrics, real health, a captured
// log and a pinned clock — everything run() would wire, without a process. A
// nil cfg gets an empty one, which is what the loops that read no
// configuration want.
func newTestSpoke(t *testing.T, clock *stubClock, cfg *config.Spoke) (*spoke, *spokeProbe) {
	t.Helper()

	if cfg == nil {
		cfg = &config.Spoke{}
	}
	capture, logger := newLogCapture()
	build := version.Build{Version: "test", Commit: "deadbeef"}
	registry := obs.NewRegistry(build, "spoke")
	return &spoke{
		cfg:       cfg,
		logger:    logger,
		metrics:   obs.NewSpokeMetrics(registry),
		health:    obs.NewHealth(logger),
		build:     build,
		started:   clock.Now(),
		now:       clock.Now,
		timing:    newTimings(cfg),
		reconnect: make(chan struct{}),
	}, &spokeProbe{logCapture: capture, registry: registry}
}

// deadAddr returns a host:port that nothing is listening on, which is the
// fastest available "the other end is not there".
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// writeFile writes content into dir/name and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// mkdir creates dir/name as a directory and returns the path. Reading or
// writing it fails with EISDIR, which is how this package provokes a
// filesystem error that is not "does not exist" without depending on file
// modes: the tests may run as root, where a 0o000 file is still readable.
func mkdir(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

// eventually polls cond until it holds or ten seconds pass. The loops in this
// package are driven by real tickers, so a test waits for one to fire.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// notReady reports the readiness blocker recorded for a component, if any.
func notReady(h *obs.Health, component string) (string, bool) {
	_, blockers := h.Ready()
	reason, blocked := blockers[component]
	return reason, blocked
}

// errContains fails the test unless err mentions want.
func errContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v does not mention %q", err, want)
	}
}
