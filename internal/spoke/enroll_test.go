// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
)

// trustDomain mirrors what the hub's CA stamps into a spoke URI SAN.
const trustDomain = "fleet.test"

// quiet keeps test output readable.
func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// testCA is a throwaway authority standing in for the hub's.
//
// It is not internal/ca: the spoke must never link the code that issues
// identities for the fleet, and an architecture test forbids the edge. What the
// spoke needs from an authority is certificates, and minting them here proves
// the client half works against any hub that speaks the protocol.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spoke test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue mints a spoke certificate for pub, carrying the URI SAN identity is
// read from, and fails the test if it cannot.
func (c *testCA) issue(t *testing.T, clusterID string, pub any) []byte {
	t.Helper()
	certPEM, err := c.sign(clusterID, pub)
	if err != nil {
		t.Fatalf("issue spoke certificate: %v", err)
	}
	return certPEM
}

// sign is issue without a *testing.T, for the fake hub's HTTP handlers, which
// have none and must report a failure as a status code instead.
func (c *testCA) sign(clusterID string, pub any) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "spoke:" + clusterID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "pmf", Host: trustDomain, Path: "/spoke/" + clusterID}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// newIdentity mints a fresh key and the certificate for it, in the shape the
// spoke holds one between restarts.
func (c *testCA) newIdentity(t *testing.T, clusterID string) *Identity {
	t.Helper()
	key, keyPEM, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	id, err := loadIdentity(keyPEM, c.issue(t, clusterID, key.Public()), c.pem)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	return id
}

// fakeHub is the hub half of the enrollment API, recording what it received.
//
// It verifies the renewal proof with internal/certproof, which is the same code
// the real hub runs. A fake that accepted anything would let the spoke send
// nonsense and still pass.
type fakeHub struct {
	ca *testCA

	mu sync.Mutex
	// lastRenew is the last renewal body the hub decoded.
	lastRenew renewRequest
	// lastEnrollBody is the raw last /enroll body, so a test can assert on the
	// exact document rather than on a re-encoding of it.
	lastEnrollBody string
	// lastEnrollAuth is the Authorization header of that request.
	lastEnrollAuth string
	// sawClientCert records whether any request arrived with a TLS client
	// certificate. It must stay false: behind an ingress there is nowhere for
	// one to go.
	sawClientCert bool
	// challenges counts how many challenges were issued.
	challenges int

	// nonce, when non-nil, is served instead of a fresh challenge.
	nonce []byte
	// renewStatus, when non-zero, is returned by /renew instead of a
	// certificate.
	renewStatus int
	// renewBody is the body returned alongside renewStatus.
	renewBody string
	// challengeStatus, when non-zero, is returned by /renew/challenge.
	challengeStatus int
	// challengeBody is the body returned alongside challengeStatus, or in place
	// of a well-formed challenge when challengeStatus is zero.
	challengeBody string
}

func (f *fakeHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /renew/challenge", f.challenge)
	mux.HandleFunc("POST /renew", f.renew)
	mux.HandleFunc("POST /enroll", f.enroll)
	return mux
}

func (f *fakeHub) note(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		f.sawClientCert = true
	}
}

func (f *fakeHub) challenge(w http.ResponseWriter, r *http.Request) {
	f.note(r)
	f.mu.Lock()
	f.challenges++
	nonce := f.nonce
	status, body := f.challengeStatus, f.challengeBody
	f.mu.Unlock()

	if status != 0 {
		http.Error(w, body, status)
		return
	}
	if body != "" {
		_, _ = io.WriteString(w, body)
		return
	}
	if nonce == nil {
		nonce = []byte("challenge-" + strings.Repeat("x", 24))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nonce":     nonce,
		"expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
}

func (f *fakeHub) renew(w http.ResponseWriter, r *http.Request) {
	f.note(r)
	var req renewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastRenew = req
	status, body := f.renewStatus, f.renewBody
	f.mu.Unlock()
	if status != 0 {
		http.Error(w, body, status)
		return
	}

	if len(req.Chain) == 0 {
		http.Error(w, "no chain", http.StatusUnauthorized)
		return
	}
	leaf, err := x509.ParseCertificate(req.Chain[0])
	if err != nil {
		http.Error(w, "bad chain", http.StatusBadRequest)
		return
	}
	clusterID := clusterIDFromCert(leaf)
	if err := certproof.Verify(leaf, req.Signature, req.Nonce,
		certproof.RenewProtocolVersion, clusterID); err != nil {
		http.Error(w, "bad proof", http.StatusForbidden)
		return
	}
	f.issueFor(w, r, req.CSR, clusterID)
}

func (f *fakeHub) enroll(w http.ResponseWriter, r *http.Request) {
	f.note(r)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastEnrollBody = string(raw)
	f.lastEnrollAuth = r.Header.Get("Authorization")
	f.mu.Unlock()

	var req enrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.issueFor(w, r, req.CSR, "prod-eu-1")
}

// issueFor signs the CSR's public key for clusterID and writes the reply.
func (f *fakeHub) issueFor(w http.ResponseWriter, _ *http.Request, csrB64, clusterID string) {
	der, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	certPEM, err := f.ca.sign(clusterID, csr.PublicKey)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"certificate": string(certPEM),
		"caBundle":    string(f.ca.pem),
		"clusterId":   clusterID,
		"notAfter":    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	})
}

// newEnroller stands up a fake hub and an enroller pointed at it over plain
// HTTP, which is what a spoke sees through an ingress.
func newEnroller(t *testing.T) (*enroller, *fakeHub) {
	t.Helper()
	hub := &fakeHub{ca: newTestCA(t)}
	srv := httptest.NewServer(hub.handler())
	t.Cleanup(srv.Close)
	return &enroller{apiURL: srv.URL, logger: quiet(), userAgent: "pmf-spoke/test"}, hub
}

// TestRenewPresentsNoClientCertificateAndStillSucceeds is the spoke half of the
// regression test for the renewal bug.
//
// The hub is behind an ingress that terminates TLS (ADR-0014), so a certificate
// offered at the TLS layer reaches the ingress and stops. Renewal used to do
// exactly that and therefore failed everywhere it mattered. The proof now
// travels in the request body, and this test pins down that the transport
// carries no certificate at all.
func TestRenewPresentsNoClientCertificateAndStillSucceeds(t *testing.T) {
	t.Parallel()
	e, hub := newEnroller(t)
	current := hub.ca.newIdentity(t, "prod-eu-1")

	renewed, err := e.renew(context.Background(), current)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if hub.sawClientCert {
		t.Error("the spoke presented a client certificate at the TLS layer, which an ingress would swallow")
	}
	if hub.challenges != 1 {
		t.Errorf("challenges fetched = %d, want 1", hub.challenges)
	}
	if len(hub.lastRenew.Chain) == 0 {
		t.Error("the renewal carried no certificate chain")
	}
	if len(hub.lastRenew.Signature) == 0 {
		t.Error("the renewal carried no proof of possession")
	}
	if len(hub.lastRenew.Nonce) == 0 {
		t.Error("the renewal did not echo the challenge")
	}
	if renewed.Leaf.SerialNumber.Cmp(current.Leaf.SerialNumber) == 0 {
		t.Error("the renewal returned the same certificate")
	}
	if got := clusterIDFromCert(renewed.Leaf); got != "prod-eu-1" {
		t.Errorf("renewed cluster = %q, want prod-eu-1", got)
	}
}

// TestRenewSendsTheCertificateItHolds proves the chain on the wire is the
// spoke's current certificate and the signature verifies under it.
func TestRenewSendsTheCertificateItHolds(t *testing.T) {
	t.Parallel()
	e, hub := newEnroller(t)
	current := hub.ca.newIdentity(t, "prod-eu-1")

	if _, err := e.renew(context.Background(), current); err != nil {
		t.Fatalf("renew: %v", err)
	}

	hub.mu.Lock()
	got := hub.lastRenew
	hub.mu.Unlock()

	if len(got.Chain) != len(current.Certificate.Certificate) {
		t.Fatalf("chain has %d entries, want %d", len(got.Chain), len(current.Certificate.Certificate))
	}
	if string(got.Chain[0]) != string(current.Certificate.Certificate[0]) {
		t.Error("the chain is not the certificate the spoke holds")
	}
	// The key that signed is the one behind the certificate that was sent, and
	// the transcript is scoped to the cluster that certificate names. Verifying
	// it here with the shared package is what proves the two halves agree.
	if err := certproof.Verify(current.Leaf, got.Signature, got.Nonce,
		certproof.RenewProtocolVersion, "prod-eu-1"); err != nil {
		t.Errorf("the hub cannot verify the spoke's proof: %v", err)
	}
}

// TestRenewNewKeyNeverLeavesTheProcess proves the renewal asks for a
// certificate over a fresh key rather than re-certifying the old one.
func TestRenewNewKeyNeverLeavesTheProcess(t *testing.T) {
	t.Parallel()
	e, hub := newEnroller(t)
	current := hub.ca.newIdentity(t, "prod-eu-1")

	renewed, err := e.renew(context.Background(), current)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}

	hub.mu.Lock()
	body := hub.lastRenew
	hub.mu.Unlock()

	if string(renewed.KeyPEM) == string(current.KeyPEM) {
		t.Error("the renewal reused the previous private key")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Error("a private key was sent to the hub")
	}
}

// TestRenewFailures covers the ways the exchange can go wrong.
func TestRenewFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// arrange breaks the hub before the renewal runs.
		arrange func(*fakeHub)
		// mangle replaces the identity the spoke renews with.
		mangle  func(t *testing.T, hub *fakeHub, id *Identity)
		wantErr error
		// wantContains, when set, must appear in the error text.
		wantContains string
	}{
		{
			name:    "the challenge endpoint refuses",
			arrange: func(f *fakeHub) { f.challengeStatus = http.StatusServiceUnavailable },
			wantErr: ErrEnrollRejected,
		},
		{
			name:         "the challenge is empty",
			arrange:      func(f *fakeHub) { f.challengeBody = `{"nonce":"","expiresAt":""}` },
			wantErr:      ErrEnrollRejected,
			wantContains: "empty renewal challenge",
		},
		{
			name:         "the challenge is not json",
			arrange:      func(f *fakeHub) { f.challengeBody = "{{{" },
			wantContains: "decode /renew/challenge",
		},
		{
			name:    "the hub refuses the proof",
			arrange: func(f *fakeHub) { f.renewStatus = http.StatusForbidden },
			wantErr: ErrEnrollRejected,
			// A 403 here has nothing to do with an enrollment token, and the
			// operator must not be sent to look at one.
			wantContains: "renewal presents the spoke's current certificate",
		},
		{
			name:    "the hub returns no certificate",
			arrange: func(f *fakeHub) { f.renewStatus = 0 },
			mangle: func(_ *testing.T, _ *fakeHub, id *Identity) {
				// A certificate the hub's fake cannot read a cluster from means
				// it signs for "", and the reply carries no usable identity.
				id.Leaf.URIs = nil
				id.Leaf.Subject.CommonName = ""
			},
			wantContains: "renew",
		},
		{
			name: "the stored key cannot sign",
			mangle: func(_ *testing.T, _ *fakeHub, id *Identity) {
				id.Certificate.PrivateKey = "not a key"
			},
			wantErr:      ErrEnrollRejected,
			wantContains: "cannot sign a renewal challenge",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, hub := newEnroller(t)
			if tc.arrange != nil {
				tc.arrange(hub)
			}
			id := hub.ca.newIdentity(t, "prod-eu-1")
			if tc.mangle != nil {
				tc.mangle(t, hub, id)
			}

			_, err := e.renew(context.Background(), id)
			if err == nil {
				t.Fatal("renew() = nil, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("renew() = %v, want it to wrap %v", err, tc.wantErr)
			}
			if tc.wantContains != "" && !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("renew() = %v, want it to mention %q", err, tc.wantContains)
			}
		})
	}
}

// TestEnrollBodyStaysExactlyTheCSR guards the contract with the hub's strict
// decoder: /enroll takes one field, and adding a second to the renewal type
// must not leak into it.
func TestEnrollBodyStaysExactlyTheCSR(t *testing.T) {
	t.Parallel()
	e, hub := newEnroller(t)

	if _, err := e.enroll(context.Background(), "prod-eu-1", "pmf_enr_secret"); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	hub.mu.Lock()
	body, auth, sawCert := hub.lastEnrollBody, hub.lastEnrollAuth, hub.sawClientCert
	hub.mu.Unlock()

	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatalf("decode enroll body %q: %v", body, err)
	}
	if len(fields) != 1 {
		t.Errorf("enroll body has %d fields (%v), want exactly csr", len(fields), fields)
	}
	if _, ok := fields["csr"]; !ok {
		t.Errorf("enroll body has no csr field: %s", body)
	}
	if auth != "Bearer pmf_enr_secret" {
		t.Errorf("Authorization = %q, want the enrollment token", auth)
	}
	if sawCert {
		t.Error("enrollment presented a client certificate, which it has none to present")
	}
}

// TestEnrollRejection maps the hub's refusals onto the errors an operator acts
// on. A replayed token is a leaked install secret, not a retry.
func TestEnrollRejection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{
			name:    "already redeemed",
			status:  http.StatusConflict,
			body:    `{"error":{"code":"conflict","message":"already redeemed"}}`,
			wantErr: ErrTokenAlreadyUsed,
		},
		{
			name:    "unauthenticated",
			status:  http.StatusUnauthorized,
			body:    `{"error":{"code":"unauthenticated","message":"no"}}`,
			wantErr: ErrEnrollRejected,
		},
		{
			name:    "server error with a non-json body",
			status:  http.StatusInternalServerError,
			body:    "boom",
			wantErr: ErrEnrollRejected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)
			e := &enroller{apiURL: srv.URL, logger: quiet(), userAgent: "pmf-spoke/test"}

			if _, err := e.enroll(context.Background(), "prod-eu-1", "tok"); !errors.Is(err, tc.wantErr) {
				t.Errorf("enroll() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
