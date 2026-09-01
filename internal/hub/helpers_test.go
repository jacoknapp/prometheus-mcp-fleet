// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/filestore"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// testNamespace is the namespace every fake API server in this package serves.
const testNamespace = "monitoring"

// newHubConfig builds a valid hub configuration rooted in a temporary data
// directory, using the real loader so that the defaults and the --data-dir path
// derivation under test are the production ones rather than a test's guess.
func newHubConfig(t *testing.T, extra ...string) *config.Hub {
	t.Helper()

	args := append([]string{
		"--data-dir", t.TempDir(),
		"--state-backend", config.StateBackendFile,
		"--mcp-addr", "127.0.0.1:0",
		"--admin-addr", "127.0.0.1:0",
		"--public-url", "https://hub.example.test/mcp",
		"--shutdown-drain-delay", "0s",
		"--shutdown-grace", "10s",
	}, extra...)

	cfg, err := config.LoadHub(args, func(string) string { return "" })
	if err != nil {
		t.Fatalf("load hub config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("hub config is not valid: %v", err)
	}
	return cfg
}

// --- log capture -------------------------------------------------------

// logSink collects structured log records so a test can assert on what the hub
// reported, which for several of the behaviours here is the only externally
// visible effect.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// newLogSink returns a debug-level JSON logger and the sink behind it.
func newLogSink() (*slog.Logger, *logSink) {
	s := &logSink{}
	h := slog.NewJSONHandler(s, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), s
}

// Write implements io.Writer.
func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

// String returns everything logged so far.
func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// records decodes every log line written so far.
func (s *logSink) records() []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(s.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// find returns the first record whose msg is exactly msg.
func (s *logSink) find(msg string) map[string]any {
	for _, rec := range s.records() {
		if rec["msg"] == msg {
			return rec
		}
	}
	return nil
}

// count returns how many records carry exactly msg.
func (s *logSink) count(msg string) int {
	n := 0
	for _, rec := range s.records() {
		if rec["msg"] == msg {
			n++
		}
	}
	return n
}

// mustFind fails the test when no record carries msg.
func (s *logSink) mustFind(t *testing.T, msg string) map[string]any {
	t.Helper()
	rec := s.find(msg)
	if rec == nil {
		t.Fatalf("no log record %q; log was:\n%s", msg, s.String())
	}
	return rec
}

// mustNotFind fails the test when any record carries msg.
func (s *logSink) mustNotFind(t *testing.T, msg string) {
	t.Helper()
	if rec := s.find(msg); rec != nil {
		t.Fatalf("unexpected log record %q: %v", msg, rec)
	}
}

// --- fake Kubernetes API server ---------------------------------------

// fault is a canned API server rejection.
type fault struct {
	code    int
	reason  string
	message string
}

// wireSec mirrors the JSON shape internal/kube exchanges with the API server.
// []byte marshals as base64 in both directions, exactly as a Secret's data
// does, so a value with arbitrary bytes round trips.
type wireSec struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Metadata   struct {
		Name            string            `json:"name,omitempty"`
		Namespace       string            `json:"namespace,omitempty"`
		ResourceVersion string            `json:"resourceVersion,omitempty"`
		Labels          map[string]string `json:"labels,omitempty"`
		Annotations     map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Type string            `json:"type,omitempty"`
	Data map[string][]byte `json:"data,omitempty"`
}

// fakeObject is one stored Secret.
type fakeObject struct {
	data        map[string][]byte
	labels      map[string]string
	annotations map[string]string
	version     int
}

// fakeAPI is an in-memory stand-in for the Kubernetes API server's Secret
// endpoints in one namespace. It implements the compare-and-swap on
// resourceVersion that ADR-0005 rests on, so a test can drive a real create
// race rather than asserting against a mock's expectations.
type fakeAPI struct {
	srv *httptest.Server

	mu      sync.Mutex
	objects map[string]*fakeObject
	nextRV  int

	gets, creates, updates int
	// seenNS records which namespace each request addressed, which is the only
	// way to prove a namespace override actually reached the API server.
	seenNS map[string]int

	// Hooks replace the operation with a rejection. n is the 1-based ordinal
	// of the call, so a test can fail only the second GET.
	onGet    func(name string, n int) *fault
	onCreate func(name string, n int) *fault
	onUpdate func(name string, n int) *fault
}

// newFakeAPI starts a fake API server and stops it when the test ends.
func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{objects: map[string]*fakeObject{}, nextRV: 1, seenNS: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// client returns a kube.Client scoped to testNamespace and pointed at the fake.
func (f *fakeAPI) client(t *testing.T) *kube.Client {
	t.Helper()
	return f.clientIn(t, testNamespace)
}

// clientIn returns a kube.Client scoped to ns.
func (f *fakeAPI) clientIn(t *testing.T, ns string) *kube.Client {
	t.Helper()
	c, err := kube.New(kube.Config{
		APIServerURL: f.srv.URL,
		Namespace:    ns,
		HTTPClient:   f.srv.Client(),
	})
	if err != nil {
		t.Fatalf("build kube client: %v", err)
	}
	return c
}

// put installs an object directly, bypassing the handler, so a test can set up
// the state another replica would have left behind.
func (f *fakeAPI) put(name string, data map[string][]byte) {
	f.putAnnotated(name, data, nil)
}

// putAnnotated installs an object with annotations. The CA rotation's operator
// trigger is an annotation, so a test has to be able to set one the way
// `kubectl annotate` would.
func (f *fakeAPI) putAnnotated(name string, data map[string][]byte, annotations map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[name] = &fakeObject{
		data:        cloneData(data),
		annotations: maps.Clone(annotations),
		version:     f.nextRV,
	}
	f.nextRV++
}

// annotationsOf reads an object's annotations directly.
func (f *fakeAPI) annotationsOf(name string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := f.objects[name]
	if obj == nil {
		return nil
	}
	return maps.Clone(obj.annotations)
}

// get reads an object's data directly.
func (f *fakeAPI) get(name string) map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := f.objects[name]
	if obj == nil {
		return nil
	}
	return cloneData(obj.data)
}

// labels reads an object's labels directly.
func (f *fakeAPI) labelsOf(name string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := f.objects[name]
	if obj == nil {
		return nil
	}
	out := make(map[string]string, len(obj.labels))
	for k, v := range obj.labels {
		out[k] = v
	}
	return out
}

// namespaces reports how many requests addressed each namespace.
func (f *fakeAPI) namespaces() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.seenNS))
	for k, v := range f.seenNS {
		out[k] = v
	}
	return out
}

// counts reports how many of each verb the fake has served.
func (f *fakeAPI) counts() (gets, creates, updates int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.creates, f.updates
}

func cloneData(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = bytes.Clone(v)
	}
	return out
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/")
	if !ok {
		f.writeStatus(w, http.StatusNotFound, "NotFound", "unexpected path "+r.URL.Path)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "secrets" {
		f.writeStatus(w, http.StatusNotFound, "NotFound", "unexpected path "+r.URL.Path)
		return
	}
	f.mu.Lock()
	f.seenNS[parts[0]]++
	f.mu.Unlock()
	name := ""
	if len(parts) > 2 {
		name = parts[2]
	}

	switch r.Method {
	case http.MethodGet:
		f.serveGet(w, name)
	case http.MethodPost:
		f.servePost(w, r)
	case http.MethodPut:
		f.servePut(w, r, name)
	default:
		f.writeStatus(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (f *fakeAPI) serveGet(w http.ResponseWriter, name string) {
	f.mu.Lock()
	f.gets++
	n, hook := f.gets, f.onGet
	f.mu.Unlock()

	if hook != nil {
		if flt := hook(name, n); flt != nil {
			f.writeStatus(w, flt.code, flt.reason, flt.message)
			return
		}
	}

	f.mu.Lock()
	obj, ok := f.objects[name]
	var out wireSec
	if ok {
		out = renderSecret(name, obj)
	}
	f.mu.Unlock()

	if !ok {
		f.writeStatus(w, http.StatusNotFound, "NotFound", `secrets "`+name+`" not found`)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (f *fakeAPI) servePost(w http.ResponseWriter, r *http.Request) {
	var in wireSec
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		f.writeStatus(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	name := in.Metadata.Name

	f.mu.Lock()
	f.creates++
	n, hook := f.creates, f.onCreate
	f.mu.Unlock()

	if hook != nil {
		if flt := hook(name, n); flt != nil {
			f.writeStatus(w, flt.code, flt.reason, flt.message)
			return
		}
	}

	f.mu.Lock()
	if _, exists := f.objects[name]; exists {
		f.mu.Unlock()
		f.writeStatus(w, http.StatusConflict, "AlreadyExists", `secrets "`+name+`" already exists`)
		return
	}
	obj := &fakeObject{
		data:        cloneData(in.Data),
		labels:      in.Metadata.Labels,
		annotations: maps.Clone(in.Metadata.Annotations),
		version:     f.nextRV,
	}
	f.nextRV++
	f.objects[name] = obj
	out := renderSecret(name, obj)
	f.mu.Unlock()

	writeJSON(w, http.StatusCreated, out)
}

func (f *fakeAPI) servePut(w http.ResponseWriter, r *http.Request, name string) {
	var in wireSec
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		f.writeStatus(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}

	f.mu.Lock()
	f.updates++
	n, hook := f.updates, f.onUpdate
	f.mu.Unlock()

	if hook != nil {
		if flt := hook(name, n); flt != nil {
			f.writeStatus(w, flt.code, flt.reason, flt.message)
			return
		}
	}

	f.mu.Lock()
	obj, ok := f.objects[name]
	if !ok {
		f.mu.Unlock()
		f.writeStatus(w, http.StatusNotFound, "NotFound", `secrets "`+name+`" not found`)
		return
	}
	if in.Metadata.ResourceVersion != strconv.Itoa(obj.version) {
		f.mu.Unlock()
		f.writeStatus(w, http.StatusConflict, "Conflict",
			"the object has been modified; please apply your changes to the latest version")
		return
	}
	obj.data = cloneData(in.Data)
	obj.annotations = maps.Clone(in.Metadata.Annotations)
	obj.version = f.nextRV
	f.nextRV++
	out := renderSecret(name, obj)
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, out)
}

func renderSecret(name string, obj *fakeObject) wireSec {
	var out wireSec
	out.APIVersion, out.Kind, out.Type = "v1", "Secret", "Opaque"
	out.Metadata.Name = name
	out.Metadata.Namespace = testNamespace
	out.Metadata.ResourceVersion = strconv.Itoa(obj.version)
	out.Metadata.Labels = obj.labels
	out.Metadata.Annotations = maps.Clone(obj.annotations)
	out.Data = cloneData(obj.data)
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) writeStatus(w http.ResponseWriter, code int, reason, message string) {
	writeJSON(w, code, map[string]any{
		"kind": "Status", "apiVersion": "v1",
		"status": "Failure", "code": code, "reason": reason, "message": message,
	})
}

// --- CA material -------------------------------------------------------

// caFixture is a CA keypair plus a pepper, as they would appear in the CA
// Secret. It is generated with the real internal/ca so the bytes the
// bootstrapper adopts are bytes it could actually have written.
type caFixture struct {
	certPEM []byte
	keyPEM  []byte
	pepper  []byte
	ca      *ca.CA
}

// newCAFixture mints a CA into a throwaway directory and reads it back out.
func newCAFixture(t *testing.T, trustDomain string) caFixture {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	authority, err := ca.Create(certPath, keyPath, ca.Options{TrustDomain: trustDomain})
	if err != nil {
		t.Fatalf("create CA fixture: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read CA fixture certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read CA fixture key: %v", err)
	}
	pepper, err := token.GeneratePepper()
	if err != nil {
		t.Fatalf("generate pepper: %v", err)
	}
	return caFixture{certPEM: certPEM, keyPEM: keyPEM, pepper: pepper, ca: authority}
}

// secretData renders the fixture as the CA Secret's data map.
func (f caFixture) secretData() map[string][]byte {
	return map[string][]byte{
		secretKeyCACert: f.certPEM,
		secretKeyCAKey:  f.keyPEM,
		secretKeyPepper: f.pepper,
	}
}

// --- stores ------------------------------------------------------------

// newFileStore opens a real file-backed credential store in a temp directory.
func newFileStore(t *testing.T) *filestore.Store {
	t.Helper()
	s, err := filestore.Open(filestore.Options{Path: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// faultyStore wraps a real store and can be made to fail the two reads the
// revocation cache depends on, so an outage can be simulated without giving up
// a real implementation underneath.
type faultyStore struct {
	store.Store

	mu           sync.Mutex
	epochErr     error
	revokedErr   error
	closeErr     error
	epochCalls   int
	revokedCalls int
}

func (s *faultyStore) Close() error {
	if s.closeErr != nil {
		return s.closeErr
	}
	return s.Store.Close()
}

func (s *faultyStore) failEpoch(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epochErr = err
}

func (s *faultyStore) failRevoked(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedErr = err
}

func (s *faultyStore) calls() (epoch, revoked int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epochCalls, s.revokedCalls
}

func (s *faultyStore) Epoch(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	s.epochCalls++
	err := s.epochErr
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.Store.Epoch(ctx)
}

func (s *faultyStore) ListRevokedCerts(ctx context.Context) ([]store.RevokedCert, error) {
	s.mu.Lock()
	s.revokedCalls++
	err := s.revokedErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.ListRevokedCerts(ctx)
}

// --- assembled hubs ----------------------------------------------------

// newBareHub builds a hub with observability wired and nothing else, which is
// the state Run hands to run.
func newBareHub(t *testing.T, cfg *config.Hub) (*hub, *logSink) {
	t.Helper()
	logger, sink := newLogSink()
	build := version.Get()
	reg := obs.NewRegistry(build, "hub")
	return &hub{
		cfg:      cfg,
		logger:   logger,
		metrics:  newMetricsAdapter(obs.NewHubMetrics(reg)),
		health:   obs.NewHealth(logger),
		build:    build,
		promReg:  reg,
		startedA: time.Now(),
	}, sink
}

// newTestHub builds a hub whose state layer is open but whose request path is
// not, which is the state every method below openState expects to find.
func newTestHub(t *testing.T, cfg *config.Hub) (*hub, *logSink) {
	t.Helper()
	h, sink := newBareHub(t, cfg)
	if err := h.openState(context.Background()); err != nil {
		t.Fatalf("openState: %v", err)
	}
	opened := h.store
	t.Cleanup(func() { _ = opened.Close() })
	return h, sink
}

// newWiredHub builds a hub with the full request path assembled, which is what
// the listener, tunnel and drain paths need.
func newWiredHub(t *testing.T, cfg *config.Hub) (*hub, *logSink) {
	t.Helper()
	h, sink := newTestHub(t, cfg)
	if err := h.buildRequestPath(); err != nil {
		t.Fatalf("buildRequestPath: %v", err)
	}
	built := h.verifier
	t.Cleanup(built.Close)
	return h, sink
}

// --- misc --------------------------------------------------------------

// mintKey stores a credential of the given class and returns the raw token.
func mintKey(t *testing.T, h *hub, class fleet.KeyClass, scope *fleet.Scope) string {
	t.Helper()
	minted, err := token.Mint(class)
	if err != nil {
		t.Fatalf("mint %s key: %v", class, err)
	}
	now := time.Now()
	rec := &fleet.Key{
		KID:        minted.KID,
		Class:      class,
		Name:       "test-" + string(class),
		SecretHMAC: h.hasher.Sum(minted.Secret),
		Scope:      scope,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := h.store.PutKey(context.Background(), rec); err != nil {
		t.Fatalf("store %s key: %v", class, err)
	}
	return minted.Raw.Reveal()
}

// httpGet performs a GET and returns the status and body.
func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
