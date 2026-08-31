// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// testNow is the fixed instant the fake clock starts at.
var testNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// testPepper is a fixed, non-secret pepper.
var testPepper = []byte("0123456789abcdef0123456789abcdef")

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: testNow} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeStore is an in-memory [AdminStore] and [authn.KeyStore].
//
// BurnEnrollment holds the same mutex as every other mutation, which is the
// property the real Secret-backed store gets from a conditional update on
// resourceVersion: concurrent redemptions serialize and exactly one wins.
type fakeStore struct {
	mu      sync.Mutex
	keys    map[string]*fleet.Key
	revoked map[string]RevokedCert
	epoch   uint64
	touched map[string]time.Time

	// Fault injection. Each is returned by the matching method when non-nil.
	errPut          error
	errGet          error
	errList         error
	errRevokeKey    error
	errDelete       error
	errBurn         error
	errRevokeCert   error
	errListRevoked  error
	errEpoch        error
	putConflictOnce bool
	// putAlwaysConflict makes every PutKey report a key identifier collision,
	// which is how the retry budget is exhausted deterministically.
	putAlwaysConflict bool
	// getNil makes GetKey return (nil, nil), the shape a store bug could take
	// and which every caller must treat as "absent" rather than dereference.
	getNil bool
	// errGetKID restricts errGet and getNil to one key identifier. Without it
	// a test that breaks a lookup also breaks the verifier's lookup of the
	// caller's own admin credential, and every route answers 401 instead of
	// the failure being examined.
	errGetKID string
	// revokedCertsNil makes ListRevokedCerts return a nil slice with no error,
	// the shape a store backed by a data format with no empty/absent
	// distinction (or a bug in one) could plausibly return. Every other path
	// through this fake builds a non-nil empty slice even when there is
	// nothing revoked, so this is the only way to exercise a handler's own
	// nil-to-empty normalization.
	revokedCertsNil bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		keys:    map[string]*fleet.Key{},
		revoked: map[string]RevokedCert{},
		touched: map[string]time.Time{},
		epoch:   1,
	}
}

func (f *fakeStore) PutKey(_ context.Context, k *fleet.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putConflictOnce || f.putAlwaysConflict {
		f.putConflictOnce = false
		return fmt.Errorf("kid %s: %w", k.KID, ErrAlreadyExists)
	}
	if f.errPut != nil {
		return f.errPut
	}
	if _, ok := f.keys[k.KID]; ok {
		return fmt.Errorf("kid %s: %w", k.KID, ErrAlreadyExists)
	}
	f.keys[k.KID] = cloneKey(k)
	f.epoch++
	return nil
}

func (f *fakeStore) GetKey(_ context.Context, kid string) (*fleet.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errGetKID == "" || f.errGetKID == kid {
		if f.errGet != nil {
			return nil, f.errGet
		}
		if f.getNil {
			return nil, nil
		}
	}
	k, ok := f.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %s: %w", kid, ErrNotFound)
	}
	return cloneKey(k), nil
}

func (f *fakeStore) ListKeys(_ context.Context, class fleet.KeyClass) ([]*fleet.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errList != nil {
		return nil, f.errList
	}
	out := make([]*fleet.Key, 0, len(f.keys))
	for _, k := range f.keys {
		if class != "" && k.Class != class {
			continue
		}
		out = append(out, cloneKey(k))
	}
	slices.SortFunc(out, func(a, b *fleet.Key) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.KID, b.KID)
	})
	return out, nil
}

func (f *fakeStore) RevokeKey(_ context.Context, kid, reason string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errRevokeKey != nil {
		return f.errRevokeKey
	}
	k, ok := f.keys[kid]
	if !ok {
		return fmt.Errorf("kid %s: %w", kid, ErrNotFound)
	}
	if k.RevokedAt != nil {
		return nil
	}
	when := at
	k.RevokedAt = &when
	k.RevokedReason = reason
	f.epoch++
	return nil
}

func (f *fakeStore) DeleteKey(_ context.Context, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errDelete != nil {
		return f.errDelete
	}
	if _, ok := f.keys[kid]; !ok {
		return fmt.Errorf("kid %s: %w", kid, ErrNotFound)
	}
	delete(f.keys, kid)
	f.epoch++
	return nil
}

func (f *fakeStore) TouchKey(_ context.Context, kid string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched[kid] = at
	return nil
}

func (f *fakeStore) BurnEnrollment(_ context.Context, kid, certSerial string, at time.Time) (*fleet.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errBurn != nil {
		return nil, f.errBurn
	}
	k, ok := f.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %s: %w", kid, ErrNotFound)
	}
	if k.Class != fleet.ClassEnrollment || k.Enrollment == nil {
		return nil, fmt.Errorf("kid %s: not an enrollment token", kid)
	}
	// A reusable grant is redeemed rather than burned, capped by
	// MaxRedemptions (zero meaning unlimited); this mirrors
	// internal/store.State.BurnEnrollment so a test exercising handleEnroll
	// against this fake sees the same behaviour a real backend would give it.
	if k.Enrollment.Reusable {
		if m := k.Enrollment.MaxRedemptions; m > 0 && k.Enrollment.Redemptions >= m {
			return nil, fmt.Errorf("kid %s: %w", kid, ErrEnrollmentUsed)
		}
	} else if k.Enrollment.UsedAt != nil {
		return nil, fmt.Errorf("kid %s: %w", kid, ErrEnrollmentUsed)
	}
	when := at
	k.Enrollment.UsedAt = &when
	k.Enrollment.CertSerial = certSerial
	k.Enrollment.Redemptions++
	f.epoch++
	return cloneKey(k), nil
}

func (f *fakeStore) RevokeCert(_ context.Context, rc RevokedCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errRevokeCert != nil {
		return f.errRevokeCert
	}
	f.revoked[rc.Serial] = rc
	f.epoch++
	return nil
}

func (f *fakeStore) ListRevokedCerts(context.Context) ([]RevokedCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errListRevoked != nil {
		return nil, f.errListRevoked
	}
	if f.revokedCertsNil {
		return nil, nil
	}
	out := make([]RevokedCert, 0, len(f.revoked))
	for _, rc := range f.revoked {
		out = append(out, rc)
	}
	slices.SortFunc(out, func(a, b RevokedCert) int { return strings.Compare(a.Serial, b.Serial) })
	return out, nil
}

func (f *fakeStore) Epoch(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errEpoch != nil {
		return 0, f.errEpoch
	}
	return f.epoch, nil
}

// get returns a copy of a stored key, for assertions.
func (f *fakeStore) get(kid string) (*fleet.Key, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[kid]
	if !ok {
		return nil, false
	}
	return cloneKey(k), true
}

// cloneKey deep-copies a stored record.
//
// The shallow copy this fake used to return aliased the stored
// [fleet.EnrollmentGrant] through its pointer, so a handler holding a "copy"
// read the same memory a concurrent burn wrote -- a data race the real store
// does not have, because it decodes each record from JSON. A fake whose
// aliasing behaviour differs from production hides exactly the bugs the race
// detector is being run to find.
func cloneKey(k *fleet.Key) *fleet.Key {
	cp := *k
	cp.SecretHMAC = bytes.Clone(k.SecretHMAC)
	if k.Scope != nil {
		scope := *k.Scope
		cp.Scope = &scope
	}
	if k.Enrollment != nil {
		grant := *k.Enrollment
		if k.Enrollment.UsedAt != nil {
			used := *k.Enrollment.UsedAt
			grant.UsedAt = &used
		}
		grant.Labels = maps.Clone(k.Enrollment.Labels)
		cp.Enrollment = &grant
	}
	if k.LastUsed != nil {
		last := *k.LastUsed
		cp.LastUsed = &last
	}
	if k.RevokedAt != nil {
		rev := *k.RevokedAt
		cp.RevokedAt = &rev
	}
	return &cp
}

// inject sets a fault and clears it when the test ends.
func (f *fakeStore) inject(t *testing.T, set func(*fakeStore)) {
	t.Helper()
	f.mu.Lock()
	set(f)
	f.mu.Unlock()
}

// Compile-time proof that one fake satisfies both narrow interfaces, which is
// also the shape the real store has to have.
var (
	_ AdminStore     = (*fakeStore)(nil)
	_ authn.KeyStore = (*fakeStore)(nil)
)

// fakeMetrics records every metric call.
type fakeMetrics struct {
	mu         sync.Mutex
	enrollment map[string]int
	events     map[string]int
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{enrollment: map[string]int{}, events: map[string]int{}}
}

func (m *fakeMetrics) Enrollment(result string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrollment[result]++
}

func (m *fakeMetrics) SecurityEvent(event string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[event]++
}

func (m *fakeMetrics) enrollments(result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enrollment[result]
}

func (m *fakeMetrics) securityEvents(event string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[event]
}

// syncBuffer is a concurrency-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// harness is one fully wired hub API: a real CA on disk, a real verifier, the
// real muxes, and an in-memory store.
type harness struct {
	t        *testing.T
	store    *fakeStore
	hasher   *token.Hasher
	ca       *ca.CA
	verifier *authn.Verifier
	clock    *fakeClock
	metrics  *fakeMetrics
	logs     *syncBuffer
	// caKeyPEM is the CA's private key as it sits on disk. It exists only so
	// assertNoSecretMaterial can prove it never appears anywhere else.
	caKeyPEM []byte

	admin  *httptest.Server
	public *httptest.Server
	// publicMux is the same handler h.public serves, kept so a test can mount
	// it a second time behind a TLS listener.
	publicMux http.Handler

	adminToken string
	agentToken string

	draining bool
	drainMu  sync.Mutex
}

// newHarness builds the harness. tweak may adjust the options before the muxes
// are constructed.
func newHarness(t *testing.T, tweak func(*Options)) *harness {
	t.Helper()
	dir := t.TempDir()
	clock := newFakeClock()
	keyPath := filepath.Join(dir, "ca.key")
	authority, err := ca.LoadOrCreate(filepath.Join(dir, "ca.crt"), keyPath, ca.Options{Clock: clock.Now})
	if err != nil {
		t.Fatalf("ca.LoadOrCreate: %v", err)
	}
	caKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read ca key: %v", err)
	}
	hasher, err := token.NewHasher(testPepper)
	if err != nil {
		t.Fatalf("token.NewHasher: %v", err)
	}
	h := &harness{
		t:        t,
		store:    newFakeStore(),
		hasher:   hasher,
		ca:       authority,
		clock:    clock,
		metrics:  newFakeMetrics(),
		logs:     &syncBuffer{},
		caKeyPEM: caKeyPEM,
	}
	logger := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	verifier, err := authn.New(authn.Options{
		Store:      h.store,
		Hasher:     hasher,
		Logger:     logger,
		Clock:      clock.Now,
		IsNotFound: func(err error) bool { return errors.Is(err, ErrNotFound) },
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	t.Cleanup(verifier.Close)
	h.verifier = verifier

	opts := Options{
		Store:             h.store,
		Hasher:            hasher,
		CA:                authority,
		Verifier:          verifier,
		Logger:            logger,
		Metrics:           h.metrics,
		Clock:             clock.Now,
		EnrollmentEnabled: true,
		PublicURL:         "https://hub.example/mcp",
		Draining:          h.isDraining,
	}
	if tweak != nil {
		tweak(&opts)
	}
	adminMux, err := NewAdminMux(opts)
	if err != nil {
		t.Fatalf("NewAdminMux: %v", err)
	}
	publicMux, err := NewPublicMux(opts)
	if err != nil {
		t.Fatalf("NewPublicMux: %v", err)
	}
	h.publicMux = publicMux
	h.admin = httptest.NewServer(adminMux)
	h.public = httptest.NewServer(publicMux)
	t.Cleanup(h.admin.Close)
	t.Cleanup(h.public.Close)

	h.adminToken = h.mint(fleet.ClassAdmin, nil)
	h.agentToken = h.mint(fleet.ClassAgent, func(k *fleet.Key) {
		k.Scope = &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"*"}},
			Tools:    fleet.ToolScope{Allow: []string{"prom.query"}},
		}
	})
	return h
}

func (h *harness) isDraining() bool {
	h.drainMu.Lock()
	defer h.drainMu.Unlock()
	return h.draining
}

func (h *harness) setDraining(v bool) {
	h.drainMu.Lock()
	defer h.drainMu.Unlock()
	h.draining = v
}

// mint stores a credential directly, bypassing the API, and returns the raw
// token. It is how a test obtains the admin credential it needs to call the
// API in the first place.
func (h *harness) mint(class fleet.KeyClass, mutate func(*fleet.Key)) string {
	h.t.Helper()
	m, err := token.Mint(class)
	if err != nil {
		h.t.Fatalf("token.Mint: %v", err)
	}
	k := &fleet.Key{
		KID:        m.KID,
		Class:      class,
		Name:       "seed-" + string(class),
		SecretHMAC: h.hasher.Sum(m.Secret),
		CreatedAt:  h.clock.Now().Add(-time.Hour),
		ExpiresAt:  h.clock.Now().Add(24 * time.Hour),
	}
	if mutate != nil {
		mutate(k)
	}
	if err := h.store.PutKey(context.Background(), k); err != nil {
		h.t.Fatalf("PutKey: %v", err)
	}
	return m.Raw.Reveal()
}

// do issues a request against one of the harness's servers.
func (h *harness) do(srv *httptest.Server, method, path, bearer string, body any) *http.Response {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, rdr)
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("Do %s %s: %v", method, path, err)
	}
	return resp
}

// adminDo issues an authenticated admin request.
func (h *harness) adminDo(method, path string, body any) *http.Response {
	h.t.Helper()
	return h.do(h.admin, method, path, h.adminToken, body)
}

// decode reads a JSON response body into dst and returns the raw text so a
// test can assert on what was and was not present.
func decode(t *testing.T, resp *http.Response, dst any) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if dst != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatalf("decode %q: %v", raw, err)
		}
	}
	return string(raw)
}

// envelopeOf decodes an error envelope.
func envelopeOf(t *testing.T, resp *http.Response) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	decode(t, resp, &env)
	return env
}

// allHMACs returns a copy of every stored secret digest, so an assertion can
// prove none of them reached a response body or a log line.
func (f *fakeStore) allHMACs() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, 0, len(f.keys))
	for _, k := range f.keys {
		if len(k.SecretHMAC) > 0 {
			out = append(out, bytes.Clone(k.SecretHMAC))
		}
	}
	return out
}

// mintEnrollment seeds a single-use enrollment token bound to clusterID and
// returns its key identifier.
func (h *harness) mintEnrollment(clusterID string) string {
	h.t.Helper()
	_, kid := h.mintEnrollmentToken(clusterID)
	return kid
}

// mintEnrollmentToken seeds a single-use enrollment token bound to clusterID
// and returns both the raw credential and its key identifier.
func (h *harness) mintEnrollmentToken(clusterID string) (raw, kid string) {
	h.t.Helper()
	raw = h.mint(fleet.ClassEnrollment, func(k *fleet.Key) {
		k.Name = "enroll:" + clusterID
		k.Enrollment = &fleet.EnrollmentGrant{ClusterID: clusterID}
	})
	return raw, kidOf(h.t, raw)
}

// tokenShapeRE matches any well-formed `pmf_` credential. It is the shape, not
// a particular value, so it catches a leak of a token this test never saw.
var tokenShapeRE = regexp.MustCompile(token.Pattern())

// assertNoSecretMaterial is the package's central security assertion.
//
// It proves that neither the response body under examination nor anything the
// hub has logged so far contains a stored secret digest, the pepper, or CA
// private key material, in any of the encodings something might plausibly
// render them in. It additionally proves that no token-shaped string has ever
// reached the log, which covers credentials this test never handled -- the
// response body is exempt from that last check only because a mint response is
// the one place a raw token legitimately appears.
func assertNoSecretMaterial(t *testing.T, h *harness, body string) {
	t.Helper()
	logs := h.logs.String()

	needles := map[string][]byte{"pepper": testPepper, "ca private key": h.caKeyPEM}
	for i, sum := range h.store.allHMACs() {
		needles["stored hmac "+strconv.Itoa(i)] = sum
	}
	for what, secret := range needles {
		for enc, s := range encodings(secret) {
			if s == "" {
				continue
			}
			if strings.Contains(body, s) {
				t.Errorf("the response body contains the %s (%s encoded)", what, enc)
			}
			if strings.Contains(logs, s) {
				t.Errorf("the log contains the %s (%s encoded)", what, enc)
			}
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the response body contains a PEM private key block")
	}
	if strings.Contains(logs, "PRIVATE KEY") {
		t.Error("the log contains a PEM private key block")
	}
	if m := tokenShapeRE.FindString(logs); m != "" {
		t.Errorf("a token-shaped credential reached the log (%d bytes)", len(m))
	}
}

// encodings renders b in every representation a leak might plausibly take.
func encodings(b []byte) map[string]string {
	if len(b) == 0 {
		return nil
	}
	return map[string]string{
		"raw":         string(b),
		"hex":         hex.EncodeToString(b),
		"base64":      base64.StdEncoding.EncodeToString(b),
		"base64raw":   base64.RawStdEncoding.EncodeToString(b),
		"base64url":   base64.URLEncoding.EncodeToString(b),
		"jsonEscaped": strings.Trim(mustJSON(b), `"`),
	}
}

// mustJSON renders b the way encoding/json would put it in a response body.
func mustJSON(b []byte) string {
	out, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	return string(out)
}

// doRaw issues a request with a body this package did not encode, so a test
// can present malformed JSON, a second document, or an oversized payload.
func (h *harness) doRaw(srv *httptest.Server, method, path, bearer, body string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("Do %s %s: %v", method, path, err)
	}
	return resp
}

// oversizeJSON returns a syntactically valid JSON document larger than
// [MaxBodyBytes], for proving the body limit on a route.
func oversizeJSON(field string) string {
	return `{"` + field + `":"` + strings.Repeat("x", MaxBodyBytes+1024) + `"}`
}

// newKeyPair returns a fresh P-256 key, which is what a spoke generates.
func newKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// csrOptions describes a certificate signing request a client might send,
// including one that asks for an identity it must not receive.
type csrOptions struct {
	// CommonName is what the requester puts in its subject. The hub discards
	// it; the tests exist to prove that.
	CommonName string
	// DNSNames and URIs are SANs the requester asks for. Also discarded.
	DNSNames []string
	URIs     []*url.URL
	// Key reuses an existing private key, so a renewal can present the same
	// key it enrolled with. Nil generates a fresh one.
	Key *ecdsa.PrivateKey
}

// makeCSR builds a DER certificate signing request and returns it base64
// encoded alongside the key that signed it.
func makeCSR(t *testing.T, opts csrOptions) (b64 string, key *ecdsa.PrivateKey) {
	t.Helper()
	key = opts.Key
	if key == nil {
		key = newKeyPair(t)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: opts.CommonName},
		DNSNames: opts.DNSNames,
		URIs:     opts.URIs,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), key
}

// spokeIdentity is a client certificate an authority has issued, in the shape a
// spoke holds it: the DER chain it sends to /renew and the key that signs the
// challenge.
type spokeIdentity struct {
	clusterID string
	serial    string
	tlsCert   tls.Certificate
	key       *ecdsa.PrivateKey
}

// chain is the DER certificate chain as [RenewRequest.Chain] carries it.
func (s spokeIdentity) chain() [][]byte { return s.tlsCert.Certificate }

// issueSpoke issues a client certificate for clusterID the way a successful
// enrollment would.
func (h *harness) issueSpoke(clusterID string) spokeIdentity {
	h.t.Helper()
	return issueSpokeFrom(h.t, h.ca, clusterID)
}

// issueSpokeFrom issues a spoke certificate from an arbitrary authority, so a
// test can present one that is perfectly formed and signed by the wrong CA.
func issueSpokeFrom(t *testing.T, authority *ca.CA, clusterID string) spokeIdentity {
	t.Helper()
	b64, key := makeCSR(t, csrOptions{CommonName: "spoke"})
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode csr: %v", err)
	}
	certPEM, cert, err := authority.IssueSpokeFromCSR(der, clusterID)
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
	return spokeIdentity{
		clusterID: clusterID,
		serial:    ca.SerialHex(cert.SerialNumber),
		tlsCert:   tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: cert},
		key:       key,
	}
}

// otherAuthority builds a second CA with the same trust domain as the harness
// one. A certificate it issues is perfect in every observable way except its
// signature, which is exactly the case chain verification exists to catch.
func (h *harness) otherAuthority() *ca.CA {
	h.t.Helper()
	dir := h.t.TempDir()
	authority, err := ca.LoadOrCreate(
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		ca.Options{Clock: h.clock.Now, TrustDomain: h.ca.TrustDomain()})
	if err != nil {
		h.t.Fatalf("ca.LoadOrCreate: %v", err)
	}
	return authority
}

// challenge fetches one renewal challenge from the public mux.
func (h *harness) challenge() RenewChallengeResponse {
	h.t.Helper()
	resp := h.do(h.public, http.MethodGet, "/renew/challenge", "", nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /renew/challenge: status = %d", resp.StatusCode)
	}
	var out RenewChallengeResponse
	decode(h.t, resp, &out)
	if len(out.Nonce) == 0 {
		h.t.Fatal("the hub issued an empty renewal challenge")
	}
	return out
}

// verifyNonce runs the hub's own challenge check, so a test can assert that
// what the hub issued is what the hub accepts without going through a route.
func (h *harness) verifyNonce(nonce []byte) error {
	h.t.Helper()
	srv, err := newServer(Options{
		Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier, Clock: h.clock.Now,
	})
	if err != nil {
		h.t.Fatalf("newServer: %v", err)
	}
	return srv.verifyRenewNonce(nonce, h.clock.Now())
}

// signRenew produces the proof of possession a renewal carries. Every argument
// is explicit so a test can sign the wrong thing on purpose.
func signRenew(t *testing.T, key *ecdsa.PrivateKey, nonce []byte, protocolVersion, clusterID string) []byte {
	t.Helper()
	sig, err := certproof.Sign(key, nonce, protocolVersion, clusterID)
	if err != nil {
		t.Fatalf("certproof.Sign: %v", err)
	}
	return sig
}

// renewRequestFor builds a well-formed renewal for id against a fresh
// challenge, reusing id's key for the CSR the way a real spoke would not (it
// generates a new one) but which keeps the fixture small where the key under
// test is the one that signs.
func (h *harness) renewRequestFor(id spokeIdentity) RenewRequest {
	h.t.Helper()
	nonce := h.challenge().Nonce
	csr, _ := makeCSR(h.t, csrOptions{CommonName: "spoke"})
	return RenewRequest{
		CSR:       csr,
		Chain:     id.chain(),
		Signature: signRenew(h.t, id.key, nonce, certproof.RenewProtocolVersion, id.clusterID),
		Nonce:     nonce,
	}
}

// renew posts a renewal to the plain-HTTP public mux, which is the production
// shape: the hub is behind an ingress that terminates TLS, so r.TLS is nil.
func (h *harness) renew(body any) *http.Response {
	h.t.Helper()
	return h.do(h.public, http.MethodPost, "/renew", "", body)
}

// tlsServer starts the public mux behind a TLS listener that will accept a
// client certificate but decides nothing on the strength of one.
//
// No route needs it any more: renewal proves possession inside the request
// body, because behind the ingress of ADR-0014 there is no TLS state to read.
// It survives so that one test can present a client certificate at the TLS
// layer and prove the handler pays it no attention at all.
func (h *harness) tlsServer(clientAuth tls.ClientAuthType) *httptest.Server {
	h.t.Helper()
	return h.startTLS(&tls.Config{
		Certificates: []tls.Certificate{h.serverCert()},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   clientAuth,
		ClientCAs:    h.ca.Pool(),
		Time:         h.clock.Now,
	})
}

// serverCert issues the listener's own certificate.
func (h *harness) serverCert() tls.Certificate {
	h.t.Helper()
	// Self-signed and local: the CA no longer issues server certificates,
	// because behind the ingress of ADR-0014 the hub presents none. The client
	// in this test skips verification anyway -- the point is only that a TLS
	// layer exists for the handler to ignore.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatalf("generate server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// Wall clock, not the harness clock: crypto/tls checks validity
		// against real time, and the harness clock is pinned to a fixed
		// instant in the past.
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		h.t.Fatalf("create server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLS mounts the public mux on a TLS listener with the given config.
func (h *harness) startTLS(conf *tls.Config) *httptest.Server {
	h.t.Helper()
	srv := httptest.NewUnstartedServer(h.publicMux)
	srv.TLS = conf
	srv.StartTLS()
	h.t.Cleanup(srv.Close)
	return srv
}

// tlsClient returns an HTTP client that trusts the harness CA and presents the
// given identity. A zero identity presents no client certificate.
func (h *harness) tlsClient(id spokeIdentity) *http.Client {
	h.t.Helper()
	// The server certificate is self-signed and irrelevant: this harness
	// exists to prove the handler ignores the TLS layer, not to exercise
	// server trust, and the CA no longer issues server certificates at all.
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} //nolint:gosec // G402: test-only listener; see comment
	if len(id.tlsCert.Certificate) > 0 {
		conf.Certificates = []tls.Certificate{id.tlsCert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: conf}}
}

// postJSON issues a POST with an explicit client, for the tests that need a
// TLS connection of their own rather than the harness's plain-HTTP server.
func postJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// unmarshal decodes a JSON document a test already has as text.
func unmarshal(raw string, dst any) error {
	return json.Unmarshal([]byte(raw), dst)
}

// postRaw issues a POST with an unencoded body and returns the status and
// body, reporting transport failures as an error instead of failing the test.
// It is safe to call from a goroutine, which t.Fatalf is not.
func postRaw(client *http.Client, url, bearer, body string) (int, string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(raw), nil
}

// postJSONRaw marshals v and calls postRaw. It is the goroutine-safe request
// helper the concurrent redemption test uses.
func postJSONRaw(client *http.Client, url, bearer string, v any) (int, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, "", err
	}
	return postRaw(client, url, bearer, string(raw))
}

// rogueClientCert signs a client certificate with the harness CA's own key
// that carries no spoke URI SAN.
//
// The CA package cannot produce one -- every certificate it issues either has
// the URI SAN or is a server certificate, and a server certificate is rejected
// by chain verification for its key usage before any handler sees it. Signing
// directly is the only way to reach the handler's own identity check with a
// certificate that is genuinely trusted and genuinely identity-less, which is
// precisely the case where "trusted" must not be confused with "is a spoke".
func (h *harness) rogueClientCert(commonName string) spokeIdentity {
	h.t.Helper()
	block, _ := pem.Decode(h.caKeyPEM)
	if block == nil {
		h.t.Fatal("ca key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		h.t.Fatalf("parse ca key: %v", err)
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		h.t.Fatalf("ca key is %T, want *ecdsa.PrivateKey", parsed)
	}
	leafKey := newKeyPair(h.t)
	now := h.clock.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0xfeed),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.ca.Certificate(), leafKey.Public(), caKey)
	if err != nil {
		h.t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		h.t.Fatalf("ParseCertificate: %v", err)
	}
	return spokeIdentity{
		serial:  ca.SerialHex(leaf.SerialNumber),
		tlsCert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey, Leaf: leaf},
		key:     leafKey,
	}
}

// failingRandReader is a [crypto/rand.Reader] replacement that always fails,
// for exercising the entropy-failure paths of [token.Mint] and [ca.CA]'s
// serial and CRL/certificate signing -- none of which internal/hubapi can
// inject directly, since the seams for that (internal/token's randRead,
// internal/ca's caRandomInt) are private to their own packages and internal/ca
// is out of scope for this pass. crypto/rand.Reader is the one entropy source
// every one of them ultimately reads from, and it is an exported, assignable
// package variable for exactly this purpose.
type failingRandReader struct{}

func (failingRandReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

// withFailingRand replaces crypto/rand.Reader with one that always fails for
// the remainder of the test, restoring it in cleanup.
//
// It must be called only from a test that never calls t.Parallel(), directly
// or in any subtest: crypto/rand.Reader is process-global state, and a
// parallel test's body could be reading real entropy concurrently. This is
// safe because the testing package does not start running any test that has
// called t.Parallel() until every non-parallel top-level test has already
// returned -- so a plain, serial top-level test in this package is guaranteed
// to run with no parallel test executing alongside it. See
// internal/ca/ca_test.go's TestCAOperationalFailures for the same pattern
// applied to that package's own, private entropy seam.
func withFailingRand(t *testing.T) {
	t.Helper()
	orig := rand.Reader
	rand.Reader = failingRandReader{}
	t.Cleanup(func() { rand.Reader = orig })
}

// failingResponseWriter is an http.ResponseWriter whose Write always fails
// after a real status and headers have been recorded, the shape a client that
// hung up mid-response takes. It exists to reach the log-and-continue branch
// every handler in this package runs after writing a body, without the
// httptest.Server/net/http client round trip that a real broken connection
// would otherwise require to simulate reliably.
type failingResponseWriter struct {
	header http.Header
	status int
}

func newFailingResponseWriter() *failingResponseWriter {
	return &failingResponseWriter{header: http.Header{}}
}

func (f *failingResponseWriter) Header() http.Header { return f.header }

func (f *failingResponseWriter) WriteHeader(status int) { f.status = status }

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("write: connection reset by peer")
}

// mustRequest builds a request or fails the test.
func mustRequest(t *testing.T, method, url, bearer, body string) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}
