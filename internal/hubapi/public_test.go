// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/wstun"
)

// parseIssued decodes the PEM certificate an enrollment or renewal returned.
func parseIssued(t *testing.T, pemBytes string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("response certificate is not a PEM CERTIFICATE block: %q", pemBytes)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestEnroll walks the single-use redemption route end to end through the real
// public mux.
func TestEnroll(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		raw, kid := h.mintEnrollmentToken("prod-eu-1")
		csr, _ := makeCSR(t, csrOptions{CommonName: "whatever"})

		var got EnrollResponse
		resp := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
		}
		body := decode(t, resp, &got)
		assertNoSecretMaterial(t, h, body)

		if got.ClusterID != "prod-eu-1" {
			t.Errorf("ClusterID = %q, want %q", got.ClusterID, "prod-eu-1")
		}
		cert := parseIssued(t, got.Certificate)
		if ca.SerialHex(cert.SerialNumber) != got.Serial {
			t.Errorf("Serial = %q, want %q", got.Serial, ca.SerialHex(cert.SerialNumber))
		}
		if !got.NotAfter.Equal(cert.NotAfter) {
			t.Errorf("NotAfter = %s, want %s", got.NotAfter, cert.NotAfter)
		}
		if !strings.Contains(got.CABundle, "BEGIN CERTIFICATE") {
			t.Errorf("CABundle is not PEM: %q", got.CABundle)
		}

		// The burn is recorded, and it records the certificate it bought.
		stored, ok := h.store.get(kid)
		if !ok || stored.Enrollment == nil || stored.Enrollment.UsedAt == nil {
			t.Fatalf("the enrollment token was not burned: %+v", stored)
		}
		if stored.Enrollment.CertSerial != got.Serial {
			t.Errorf("burn recorded serial %q, want the issued %q", stored.Enrollment.CertSerial, got.Serial)
		}
		if h.metrics.enrollments(ResultIssued) != 1 {
			t.Errorf("issued enrollments = %d, want 1", h.metrics.enrollments(ResultIssued))
		}
		for _, event := range []string{EventEnrollmentBurned, EventCertIssued} {
			if h.metrics.securityEvents(event) != 1 {
				t.Errorf("security event %q recorded %d times, want 1", event, h.metrics.securityEvents(event))
			}
		}
	})

	t.Run("replay is refused and reported as a security event", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		raw, _ := h.mintEnrollmentToken("prod-eu-1")
		csr, _ := makeCSR(t, csrOptions{})

		first := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
		if first.StatusCode != http.StatusCreated {
			t.Fatalf("first status = %d, want %d (%s)", first.StatusCode, http.StatusCreated, decode(t, first, nil))
		}
		first.Body.Close()

		second := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
		if second.StatusCode != http.StatusConflict {
			t.Fatalf("replay status = %d, want %d", second.StatusCode, http.StatusConflict)
		}
		body := decode(t, second, nil)
		if strings.Contains(body, "BEGIN CERTIFICATE") {
			t.Fatal("the replay response contains a certificate")
		}
		var env ErrorEnvelope
		if err := unmarshal(body, &env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if env.Error.Code != CodeConflict {
			t.Errorf("code = %q, want %q", env.Error.Code, CodeConflict)
		}
		if h.metrics.enrollments(ResultReplay) != 1 {
			t.Errorf("replay enrollments = %d, want 1", h.metrics.enrollments(ResultReplay))
		}
		if h.metrics.securityEvents(EventEnrollmentReplay) != 1 {
			t.Errorf("enrollment.replay events = %d, want 1", h.metrics.securityEvents(EventEnrollmentReplay))
		}
		if !strings.Contains(h.logs.String(), `"event":"`+EventEnrollmentReplay+`"`) {
			t.Error("the replay was not written to the security log")
		}
	})

	t.Run("a losing burn never returns the certificate it signed", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		raw, _ := h.mintEnrollmentToken("prod-eu-1")
		csr, _ := makeCSR(t, csrOptions{})
		// The pre-check passes and the certificate is signed; only the
		// conditional store update loses. This is the branch that proves the
		// signed certificate is dropped rather than served.
		h.store.inject(t, func(f *fakeStore) { f.errBurn = fmt.Errorf("lost the race: %w", ErrEnrollmentUsed) })

		resp := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
		if body := decode(t, resp, nil); strings.Contains(body, "BEGIN CERTIFICATE") {
			t.Fatal("a certificate was returned even though the burn lost")
		}
	})
}

// TestEnrollIgnoresTheCSRSubjectAndSANs is the spec's "a CSR requesting
// CN=admin produces a certificate that does not contain it".
func TestEnrollIgnoresTheCSRSubjectAndSANs(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	raw, _ := h.mintEnrollmentToken("prod-eu-1")

	hostile, err := url.Parse("pmf://" + h.ca.TrustDomain() + "/spoke/some-other-cluster")
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	csr, _ := makeCSR(t, csrOptions{
		CommonName: "admin",
		DNSNames:   []string{"hub.internal", "kubernetes.default.svc"},
		URIs:       []*url.URL{hostile},
	})

	var got EnrollResponse
	resp := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
	}
	decode(t, resp, &got)
	cert := parseIssued(t, got.Certificate)

	if cert.Subject.CommonName == "admin" {
		t.Error("the issued certificate carries the CSR's requested common name")
	}
	if want := "spoke:prod-eu-1"; cert.Subject.CommonName != want {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, want)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", cert.DNSNames)
	}
	wantURIs := []string{"pmf://" + h.ca.TrustDomain() + "/spoke/prod-eu-1"}
	gotURIs := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		gotURIs = append(gotURIs, u.String())
	}
	if diff := cmp.Diff(wantURIs, gotURIs); diff != "" {
		t.Errorf("issued URI SANs (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, cert.ExtKeyUsage); diff != "" {
		t.Errorf("extended key usage (-want +got):\n%s", diff)
	}
	if cert.IsCA {
		t.Error("the issued certificate is a CA")
	}
}

// TestEnrollConcurrentRedemptionHasExactlyOneWinner drives real goroutines at
// one token. Under -race this is also the concurrency check on the handler.
func TestEnrollConcurrentRedemptionHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	const racers = 12
	h := newHarness(t, nil)
	raw, kid := h.mintEnrollmentToken("prod-eu-1")

	csrs := make([]string, racers)
	for i := range csrs {
		csrs[i], _ = makeCSR(t, csrOptions{})
	}

	var (
		start   sync.WaitGroup
		done    sync.WaitGroup
		results = make([]int, racers)
		bodies  = make([]string, racers)
	)
	start.Add(1)
	client := h.public.Client()
	for i := range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			status, body, err := postJSONRaw(client, h.public.URL+"/enroll", raw, EnrollRequest{CSR: csrs[i]})
			if err != nil {
				results[i], bodies[i] = -1, err.Error()
				return
			}
			results[i], bodies[i] = status, body
		}()
	}
	start.Done()
	done.Wait()

	var created, conflict int
	for i, status := range results {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
			if strings.Contains(bodies[i], "BEGIN CERTIFICATE") {
				t.Error("a losing redemption still received a certificate")
			}
		default:
			t.Errorf("racer %d got status %d: %s", i, status, bodies[i])
		}
	}
	if created != 1 {
		t.Errorf("successful redemptions = %d, want exactly 1", created)
	}
	if conflict != racers-1 {
		t.Errorf("refused redemptions = %d, want %d", conflict, racers-1)
	}
	stored, _ := h.store.get(kid)
	if stored.Enrollment.UsedAt == nil || stored.Enrollment.CertSerial == "" {
		t.Fatalf("the token was not burned exactly once: %+v", stored.Enrollment)
	}
	if h.metrics.enrollments(ResultIssued) != 1 {
		t.Errorf("issued enrollments = %d, want 1", h.metrics.enrollments(ResultIssued))
	}
	if h.metrics.enrollments(ResultReplay) != racers-1 {
		t.Errorf("replay enrollments = %d, want %d", h.metrics.enrollments(ResultReplay), racers-1)
	}
}

// TestEnrollRejections covers every way in which /enroll refuses before it
// signs anything.
func TestEnrollRejections(t *testing.T) {
	t.Parallel()

	validCSR, _ := makeCSR(t, csrOptions{})

	tests := []struct {
		name       string
		tweak      func(*Options)
		setup      func(t *testing.T, h *harness) (bearer string, body any)
		wantStatus int
		wantCode   string
		wantResult string
	}{
		{
			name:       "no credential",
			setup:      func(*testing.T, *harness) (string, any) { return "", EnrollRequest{CSR: validCSR} },
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "agent credential cannot enroll",
			setup: func(_ *testing.T, h *harness) (string, any) {
				return h.agentToken, EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "admin credential cannot enroll",
			setup: func(_ *testing.T, h *harness) (string, any) {
				return h.adminToken, EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "revoked enrollment token",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, kid := h.mintEnrollmentToken("prod-eu-1")
				if err := h.store.RevokeKey(t.Context(), kid, "closed", testNow); err != nil {
					t.Fatalf("RevokeKey: %v", err)
				}
				return raw, EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired enrollment token",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw := h.mint(fleet.ClassEnrollment, func(k *fleet.Key) {
					k.Enrollment = &fleet.EnrollmentGrant{ClusterID: "prod-eu-1"}
					k.ExpiresAt = testNow.Add(-time.Minute)
				})
				return raw, EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "token with no cluster binding",
			setup: func(_ *testing.T, h *harness) (string, any) {
				return h.mint(fleet.ClassEnrollment, nil), EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantResult: ResultDenied,
		},
		{
			name: "missing csr",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, _ := h.mintEnrollmentToken("prod-eu-1")
				return raw, EnrollRequest{}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
			wantResult: ResultInvalid,
		},
		{
			name: "csr is not base64",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, _ := h.mintEnrollmentToken("prod-eu-1")
				return raw, EnrollRequest{CSR: "!!! not base64 !!!"}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
			wantResult: ResultInvalid,
		},
		{
			name: "csr is base64 but not a csr",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, _ := h.mintEnrollmentToken("prod-eu-1")
				return raw, EnrollRequest{CSR: base64.StdEncoding.EncodeToString([]byte("hello"))}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
			wantResult: ResultInvalid,
		},
		{
			name: "csr above the field limit",
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, _ := h.mintEnrollmentToken("prod-eu-1")
				return raw, EnrollRequest{CSR: strings.Repeat("A", MaxCSRBytes+4)}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
			wantResult: ResultInvalid,
		},
		{
			name:  "enrollment disabled",
			tweak: func(o *Options) { o.EnrollmentEnabled = false },
			setup: func(_ *testing.T, h *harness) (string, any) {
				raw, _ := h.mintEnrollmentToken("prod-eu-1")
				return raw, EnrollRequest{CSR: validCSR}
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   CodeUnavailable,
			wantResult: ResultDenied,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, tc.tweak)
			bearer, body := tc.setup(t, h)
			resp := h.do(h.public, http.MethodPost, "/enroll", bearer, body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, decode(t, resp, nil))
			}
			raw := decode(t, resp, nil)
			if strings.Contains(raw, "BEGIN CERTIFICATE") {
				t.Fatal("a refused enrollment still returned a certificate")
			}
			if tc.wantCode != "" {
				var env ErrorEnvelope
				if err := unmarshal(raw, &env); err != nil {
					t.Fatalf("decode envelope: %v", err)
				}
				if env.Error.Code != tc.wantCode {
					t.Errorf("code = %q, want %q", env.Error.Code, tc.wantCode)
				}
			}
			if tc.wantResult != "" && h.metrics.enrollments(tc.wantResult) == 0 {
				t.Errorf("no %q enrollment metric was recorded", tc.wantResult)
			}
			if h.metrics.enrollments(ResultIssued) != 0 {
				t.Error("a refused enrollment was counted as issued")
			}
			assertNoSecretMaterial(t, h, raw)
		})
	}
}

// TestEnrollWhileDraining proves the shutdown gate closes the route before any
// credential is verified.
func TestEnrollWhileDraining(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	raw, _ := h.mintEnrollmentToken("prod-eu-1")
	csr, _ := makeCSR(t, csrOptions{})
	h.setDraining(true)

	resp := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if env := envelopeOf(t, resp); env.Error.Code != CodeUnavailable {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeUnavailable)
	}
}

// TestEnrollBodyLimit proves the route reads a bounded body.
func TestEnrollBodyLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	raw, _ := h.mintEnrollmentToken("prod-eu-1")

	resp := h.doRaw(h.public, http.MethodPost, "/enroll", raw, oversizeJSON("csr"))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if env := envelopeOf(t, resp); env.Error.Code != CodePayloadTooLarge {
		t.Errorf("code = %q, want %q", env.Error.Code, CodePayloadTooLarge)
	}
}

// TestEnrollStoreFailures proves a broken store denies rather than issues, and
// that the underlying error never reaches the caller.
func TestEnrollStoreFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("secret hub-state unreadable by service account hub")
	csr, _ := makeCSR(t, csrOptions{})

	tests := []struct {
		name   string
		inject func(*fakeStore)
	}{
		{name: "get", inject: func(f *fakeStore) { f.errGet = boom }},
		{name: "burn", inject: func(f *fakeStore) { f.errBurn = boom }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			raw, _ := h.mintEnrollmentToken("prod-eu-1")
			// The verifier must authenticate before the fault is installed:
			// injecting GetKey failures first would deny at the middleware.
			warm := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{})
			warm.Body.Close()
			h.store.inject(t, tc.inject)

			resp := h.do(h.public, http.MethodPost, "/enroll", raw, EnrollRequest{CSR: csr})
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
			}
			body := decode(t, resp, nil)
			if strings.Contains(body, "service account") {
				t.Errorf("the store error leaked into the response: %s", body)
			}
			if h.metrics.enrollments(ResultError) == 0 {
				t.Error("no error enrollment metric was recorded")
			}
		})
	}
}

// TestRenewChallenge covers the unauthenticated half of the renewal exchange.
func TestRenewChallenge(t *testing.T) {
	t.Parallel()

	t.Run("issues a bounded, self-authenticating nonce", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)

		got := h.challenge()
		if want := testNow.Add(RenewChallengeTTL); !got.ExpiresAt.Equal(want) {
			t.Errorf("ExpiresAt = %s, want %s", got.ExpiresAt, want)
		}
		if len(got.Nonce) != renewNonceLen {
			t.Errorf("nonce is %d bytes, want %d", len(got.Nonce), renewNonceLen)
		}
		if err := h.verifyNonce(got.Nonce); err != nil {
			t.Errorf("the hub does not accept the challenge it just issued: %v", err)
		}
	})

	t.Run("two challenges differ", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		if bytes.Equal(h.challenge().Nonce, h.challenge().Nonce) {
			t.Error("the hub issued the same challenge twice")
		}
	})

	t.Run("a draining hub still issues one", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		h.setDraining(true)

		// The challenge is stateless, so one minted by a replica on its way out
		// is still good at whichever replica serves the POST. Refusing here
		// would make a rolling restart look like an outage to every spoke that
		// happened to ask the wrong pod.
		resp := h.do(h.public, http.MethodGet, "/renew/challenge", "", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		resp.Body.Close()
	})

	t.Run("a challenge minted under another pepper is refused", func(t *testing.T) {
		t.Parallel()
		// The pepper is what makes a nonce verifiable at a replica that never
		// issued it: replicas of one hub share it, and nothing else has it. A
		// challenge authenticated under a different pepper must not verify,
		// which is what stops the nonce from being forgeable by anyone who has
		// worked out its layout — the layout is not the secret.
		issuer := newHarness(t, nil)
		verifier := newHarness(t, func(o *Options) {
			hasher, err := token.NewHasher([]byte("fedcba9876543210fedcba9876543210"))
			if err != nil {
				t.Fatalf("token.NewHasher: %v", err)
			}
			o.Hasher = hasher
		})

		id := verifier.issueSpoke("prod-eu-1")
		nonce := issuer.challenge().Nonce
		csr, _ := makeCSR(t, csrOptions{})

		resp := verifier.renew(RenewRequest{
			CSR:       csr,
			Chain:     id.chain(),
			Signature: signRenew(t, id.key, nonce, certproof.RenewProtocolVersion, id.clusterID),
			Nonce:     nonce,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusUnauthorized, decode(t, resp, nil))
		}
	})
}

// TestRenewSucceedsWithoutAnyTLSClientCertificate is the regression test for
// the bug this route was rewritten to fix.
//
// The hub sits behind an ingress that terminates TLS (ADR-0014), so in
// production r.TLS is nil on every request and no client certificate ever
// reaches the handler. The previous implementation authenticated from
// r.TLS.PeerCertificates and therefore refused every renewal in the field while
// passing a suite that spoke TLS directly to it. Spoke certificates live 14
// days and renew at half life, so the fleet would have dropped off on day 14
// needing a hundred fresh enrollment tokens to come back.
//
// h.public is a plain HTTP server: there is no TLS state here at all. If this
// test ever needs a TLS listener in order to pass, the bug is back.
func TestRenewSucceedsWithoutAnyTLSClientCertificate(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	id := h.issueSpoke("prod-eu-1")

	var got EnrollResponse
	resp := h.renew(h.renewRequestFor(id))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
	}
	body := decode(t, resp, &got)
	assertNoSecretMaterial(t, h, body)

	if got.ClusterID != "prod-eu-1" {
		t.Errorf("ClusterID = %q, want prod-eu-1", got.ClusterID)
	}
	if got.Serial == id.serial {
		t.Error("renewal reused the previous serial")
	}
	if got.CABundle != string(h.ca.BundlePEM()) {
		t.Error("the renewal did not return the current trust anchor")
	}
	if !got.NotAfter.After(h.clock.Now()) {
		t.Errorf("NotAfter = %s, which is not in the future", got.NotAfter)
	}
	if h.metrics.securityEvents(EventCertRenewed) != 1 {
		t.Error("no cert.renewed security event")
	}
	if h.metrics.enrollments(ResultIssued) != 1 {
		t.Error("no issued enrollment metric was recorded")
	}
	if !strings.Contains(h.logs.String(), id.serial) {
		t.Error("the renewal audit line does not name the previous serial")
	}
}

// TestRenewIgnoresTheTLSLayerEntirely presents one spoke's certificate at the
// TLS layer while the request body proves possession of another's.
//
// The answer must be the identity the body proved. Renewal reads r.TLS for
// nothing, and pinning that down stops anybody reintroducing a "prefer the peer
// certificate when there is one" branch that would work in a lab and fail
// behind every real ingress.
func TestRenewIgnoresTheTLSLayerEntirely(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	proven := h.issueSpoke("prod-eu-1")
	presented := h.issueSpoke("prod-us-9")

	srv := h.tlsServer(tls.RequireAndVerifyClientCert)
	var got EnrollResponse
	resp := postJSON(t, h.tlsClient(presented), srv.URL+"/renew", h.renewRequestFor(proven))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
	}
	decode(t, resp, &got)
	if got.ClusterID != "prod-eu-1" {
		t.Errorf("ClusterID = %q, want the identity proved in the body, not the one at the TLS layer",
			got.ClusterID)
	}
}

// TestRenewIdentityComesFromTheCertificate proves that nothing a caller puts in
// the request decides which cluster it renews as.
func TestRenewIdentityComesFromTheCertificate(t *testing.T) {
	t.Parallel()

	t.Run("a hostile csr buys nothing", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		id := h.issueSpoke("prod-eu-1")

		// The CSR asks to become another cluster and to be called admin. Both
		// are discarded: only its public key survives.
		hostile, err := url.Parse("pmf://" + h.ca.TrustDomain() + "/spoke/prod-us-9")
		if err != nil {
			t.Fatalf("parse uri: %v", err)
		}
		csr, _ := makeCSR(t, csrOptions{CommonName: "admin", URIs: []*url.URL{hostile}})

		req := h.renewRequestFor(id)
		req.CSR = csr

		var got EnrollResponse
		resp := h.renew(req)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
		}
		decode(t, resp, &got)

		if got.ClusterID != "prod-eu-1" {
			t.Errorf("ClusterID = %q, want the identity from the presented certificate", got.ClusterID)
		}
		cert := parseIssued(t, got.Certificate)
		if want := "spoke:prod-eu-1"; cert.Subject.CommonName != want {
			t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, want)
		}
		if len(cert.URIs) != 1 || cert.URIs[0].Path != "/spoke/prod-eu-1" {
			t.Errorf("URI SANs = %v, want exactly the spoke's own", cert.URIs)
		}
	})

	t.Run("a body cannot name a cluster", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		id := h.issueSpoke("prod-eu-1")

		// RenewRequest has no cluster field and the hub decodes strictly, so an
		// attempt to name one is a 400 rather than a value somebody has to
		// remember to ignore.
		raw, err := json.Marshal(h.renewRequestFor(id))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		hostile := strings.Replace(string(raw), `{"csr":`, `{"clusterId":"prod-us-9","csr":`, 1)

		status, body, err := postRaw(h.public.Client(), h.public.URL+"/renew", "", hostile)
		if err != nil {
			t.Fatalf("POST /renew: %v", err)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d (%s)", status, http.StatusBadRequest, body)
		}
		if h.metrics.enrollments(ResultIssued) != 0 {
			t.Error("a certificate was issued for a body that named a cluster")
		}
	})
}

// TestRenewRejections is the table of every way a renewal must fail.
//
// Each case starts from a request that would otherwise succeed and breaks
// exactly one thing, so a case that stops failing names the specific check that
// has stopped happening.
func TestRenewRejections(t *testing.T) {
	t.Parallel()

	const cluster = "prod-eu-1"

	tests := []struct {
		name string
		// prepare runs before the request is built, for store state.
		prepare func(t *testing.T, h *harness, id spokeIdentity)
		// build breaks one thing about an otherwise valid request.
		build      func(t *testing.T, h *harness, id spokeIdentity, req *RenewRequest)
		wantStatus int
		wantCode   string
		// wantEvent, when set, must have been recorded exactly once.
		wantEvent string
	}{
		{
			name: "no challenge at all",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.Nonce = nil
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "expired challenge",
			build: func(_ *testing.T, h *harness, _ spokeIdentity, _ *RenewRequest) {
				// The proof is perfect; only the window has closed.
				h.clock.advance(RenewChallengeTTL + time.Second)
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "challenge with a corrupted authentication tag",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				// Flip a bit inside the HMAC. Everything else about the nonce,
				// including its expiry, is untouched and still in date.
				req.Nonce[len(req.Nonce)-1] ^= 0x01
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "challenge with a rewritten expiry",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				// Push the expiry into the far future. The tag covers it, so
				// the whole nonce stops verifying rather than lasting longer.
				req.Nonce[renewNonceRandomBytes] ^= 0x7f
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "challenge of the wrong length",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.Nonce = req.Nonce[:len(req.Nonce)-1]
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "no certificate chain",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.Chain = nil
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   CodeUnauthenticated,
		},
		{
			name: "unparseable certificate chain",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.Chain = [][]byte{[]byte("not a certificate")}
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "chain longer than the limit",
			build: func(_ *testing.T, _ *harness, id spokeIdentity, req *RenewRequest) {
				req.Chain = slices.Repeat(id.chain(), MaxChainCerts+1)
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "certificate from a different ca",
			build: func(t *testing.T, h *harness, _ spokeIdentity, req *RenewRequest) {
				// Same trust domain, same cluster ID, same shape, and the
				// signature over the challenge is genuine. Only the issuer is
				// wrong, which is the whole of the difference between a spoke
				// and somebody with a certificate generator.
				foreign := issueSpokeFrom(t, h.otherAuthority(), cluster)
				req.Chain = foreign.chain()
				req.Signature = signRenew(t, foreign.key, req.Nonce, certproof.RenewProtocolVersion, cluster)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name: "certificate carrying no spoke identity",
			build: func(t *testing.T, h *harness, _ spokeIdentity, req *RenewRequest) {
				// Signed by this CA, so genuinely trusted; it simply has no URI
				// SAN. Being trusted is not the same as being a spoke.
				rogue := h.rogueClientCert("admin")
				req.Chain = rogue.chain()
				req.Signature = signRenew(t, rogue.key, req.Nonce, certproof.RenewProtocolVersion, cluster)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
		},
		{
			name: "revoked certificate",
			prepare: func(t *testing.T, h *harness, id spokeIdentity) {
				if err := h.store.RevokeCert(t.Context(), RevokedCert{
					Serial: id.serial, RevokedAt: testNow,
					NotAfter: testNow.Add(time.Hour), Reason: "decommissioned",
				}); err != nil {
					t.Fatalf("RevokeCert: %v", err)
				}
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventCertRevoked,
		},
		{
			name: "signature over a different nonce",
			build: func(t *testing.T, h *harness, id spokeIdentity, req *RenewRequest) {
				// Both nonces are ones this hub issued and both are in date.
				// The signature simply does not cover the one that was sent.
				other := h.challenge().Nonce
				req.Signature = signRenew(t, id.key, other, certproof.RenewProtocolVersion, cluster)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventRenewalUnproven,
		},
		{
			name: "signature scoped to a different cluster",
			build: func(t *testing.T, _ *harness, id spokeIdentity, req *RenewRequest) {
				req.Signature = signRenew(t, id.key, req.Nonce, certproof.RenewProtocolVersion, "prod-us-9")
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventRenewalUnproven,
		},
		{
			name: "signature made for the tunnel handshake",
			build: func(t *testing.T, _ *harness, id spokeIdentity, req *RenewRequest) {
				// Nonce, certificate and cluster are all right; only the
				// protocol version in the transcript belongs to the other
				// exchange. This is what stops a proof captured from a tunnel
				// handshake being redeemed here for a certificate.
				req.Signature = signRenew(t, id.key, req.Nonce, wstun.ProtocolVersion, cluster)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventRenewalUnproven,
		},
		{
			name: "tampered signature",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.Signature[len(req.Signature)-1] ^= 0x01
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventRenewalUnproven,
		},
		{
			name: "signature by a key that is not the certificate's",
			build: func(t *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				// Quoting somebody else's certificate is easy: it is public.
				// Signing for it is the part that is not.
				req.Signature = signRenew(t, newKeyPair(t), req.Nonce, certproof.RenewProtocolVersion, cluster)
			},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeForbidden,
			wantEvent:  EventRenewalUnproven,
		},
		{
			name: "no csr",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.CSR = ""
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "csr that is not base64",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.CSR = "!!! not base64 !!!"
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "csr that is not a certificate request",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.CSR = base64.StdEncoding.EncodeToString([]byte("not a csr"))
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "oversized csr",
			build: func(_ *testing.T, _ *harness, _ spokeIdentity, req *RenewRequest) {
				req.CSR = strings.Repeat("A", MaxCSRBytes+4)
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			id := h.issueSpoke(cluster)
			if tc.prepare != nil {
				tc.prepare(t, h, id)
			}
			req := h.renewRequestFor(id)
			if tc.build != nil {
				tc.build(t, h, id, &req)
			}

			resp := h.renew(req)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, decode(t, resp, nil))
			}
			env := envelopeOf(t, resp)
			if env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", env.Error.Code, tc.wantCode)
			}
			if tc.wantEvent != "" && h.metrics.securityEvents(tc.wantEvent) != 1 {
				t.Errorf("security event %q recorded %d times, want 1",
					tc.wantEvent, h.metrics.securityEvents(tc.wantEvent))
			}
			if h.metrics.enrollments(ResultIssued) != 0 {
				t.Error("a certificate was issued for a request that had to be refused")
			}
			assertNoSecretMaterial(t, h, env.Error.Message)
		})
	}
}

// TestRenewOperationalRefusals covers the refusals that are about the hub's own
// state rather than the caller's credentials.
func TestRenewOperationalRefusals(t *testing.T) {
	t.Parallel()

	t.Run("draining", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		id := h.issueSpoke("prod-eu-1")
		req := h.renewRequestFor(id)
		h.setDraining(true)

		resp := h.renew(req)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
		resp.Body.Close()
	})

	t.Run("bearer credentials do not work here", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		// An admin token is the most authority this hub issues, and it buys
		// exactly nothing here: renewal takes a certificate and a proof, and
		// there is no bearer path to fall back to.
		resp := h.do(h.public, http.MethodPost, "/renew", h.adminToken, RenewRequest{})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
		resp.Body.Close()
	})

	t.Run("body limit", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		status, _, err := postRaw(h.public.Client(), h.public.URL+"/renew", "", oversizeJSON("csr"))
		if err != nil {
			t.Fatalf("POST /renew: %v", err)
		}
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", status, http.StatusRequestEntityTooLarge)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		status, _, err := postRaw(h.public.Client(), h.public.URL+"/renew", "", `{"csr":`)
		if err != nil {
			t.Fatalf("POST /renew: %v", err)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("store failure listing revocations", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		id := h.issueSpoke("prod-eu-1")
		req := h.renewRequestFor(id)
		h.store.inject(t, func(f *fakeStore) { f.errListRevoked = errors.New("state secret unreadable") })

		resp := h.renew(req)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
		}
		body := decode(t, resp, nil)
		if strings.Contains(body, "state secret") {
			t.Errorf("the store error leaked into the response: %s", body)
		}
		if h.metrics.enrollments(ResultError) == 0 {
			t.Error("no error enrollment metric was recorded")
		}
	})
}

// TestPKIRoutesAreUnauthenticated proves the trust anchor and the revocation
// list are reachable without a credential, which is what breaks the bootstrap
// loop, and that what they serve is correct.
func TestPKIRoutesAreUnauthenticated(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	id := h.issueSpoke("prod-eu-1")
	if err := h.store.RevokeCert(t.Context(), RevokedCert{
		Serial: id.serial, RevokedAt: testNow, NotAfter: testNow.Add(24 * time.Hour), Reason: "rotated",
	}); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	t.Run("bundle", func(t *testing.T) {
		resp := h.do(h.public, http.MethodGet, "/pki/bundle", "", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/x-pem-file" {
			t.Errorf("Content-Type = %q, want application/x-pem-file", got)
		}
		body := decode(t, resp, nil)
		if body != string(h.ca.BundlePEM()) {
			t.Error("the served bundle is not the CA bundle")
		}
		block, _ := pem.Decode([]byte(body))
		if block == nil {
			t.Fatal("the bundle is not PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		if !cert.IsCA {
			t.Error("the served certificate is not a CA")
		}
		assertNoSecretMaterial(t, h, body)
	})

	t.Run("crl", func(t *testing.T) {
		resp := h.do(h.public, http.MethodGet, "/pki/crl", "", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/pkix-crl" {
			t.Errorf("Content-Type = %q, want application/pkix-crl", got)
		}
		der := []byte(decode(t, resp, nil))
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if err := crl.CheckSignatureFrom(h.ca.Certificate()); err != nil {
			t.Errorf("the CRL is not signed by the hub CA: %v", err)
		}
		if len(crl.RevokedCertificateEntries) != 1 {
			t.Fatalf("revoked entries = %d, want 1", len(crl.RevokedCertificateEntries))
		}
		if got := ca.SerialHex(crl.RevokedCertificateEntries[0].SerialNumber); got != id.serial {
			t.Errorf("revoked serial = %q, want %q", got, id.serial)
		}
		if !crl.NextUpdate.After(crl.ThisUpdate) {
			t.Errorf("NextUpdate %s is not after ThisUpdate %s", crl.NextUpdate, crl.ThisUpdate)
		}
	})

	t.Run("crl store failure", func(t *testing.T) {
		h := newHarness(t, nil)
		h.store.inject(t, func(f *fakeStore) { f.errListRevoked = errors.New("state secret unreadable") })
		resp := h.do(h.public, http.MethodGet, "/pki/crl", "", nil)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
		}
		resp.Body.Close()
	})
}

// TestCRLSurvivesEveryAdmissibleSerial is the regression test for a revocation
// entry that the CRL builder would refuse. An operator must not be able to
// break an unauthenticated public endpoint by revoking a serial.
func TestCRLSurvivesEveryAdmissibleSerial(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	tests := []struct {
		name       string
		serial     string
		wantStatus int
	}{
		{name: "single digit", serial: "a", wantStatus: http.StatusNoContent},
		{name: "leading zero", serial: "0a1b", wantStatus: http.StatusNoContent},
		{name: "zero", serial: "00", wantStatus: http.StatusBadRequest},
		{name: "all zeroes", serial: "0000", wantStatus: http.StatusBadRequest},
		{name: "uppercase", serial: "0A1B", wantStatus: http.StatusBadRequest},
		{name: "too long", serial: strings.Repeat("a", 65), wantStatus: http.StatusBadRequest},
	}
	for _, tc := range tests {
		resp := h.adminDo(http.MethodPost, "/admin/v1/certs/"+tc.serial+"/revoke",
			RevokeCertRequest{Reason: "test"})
		resp.Body.Close()
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("revoke %s (%s): status = %d, want %d", tc.name, tc.serial, resp.StatusCode, tc.wantStatus)
		}
	}

	resp := h.do(h.public, http.MethodGet, "/pki/crl", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("crl status = %d, want %d after admissible revocations", resp.StatusCode, http.StatusOK)
	}
	if _, err := x509.ParseRevocationList([]byte(decode(t, resp, nil))); err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
}

// TestProtectedResourceMetadata checks the RFC 9728 document.
func TestProtectedResourceMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	resp := h.do(h.public, http.MethodGet, PRMPath, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}

	var doc ProtectedResourceMetadata
	body := decode(t, resp, &doc)
	assertNoSecretMaterial(t, h, body)

	want := ProtectedResourceMetadata{
		Resource:               "https://hub.example/mcp",
		AuthorizationServers:   []string{},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported: []string{
			"class:" + string(fleet.ClassAgent),
			"role:" + string(fleet.RoleViewer),
			"role:" + string(fleet.RoleOperator),
		},
		ResourceName:          "prometheus-mcp-fleet hub",
		ResourceDocumentation: ProjectURL,
		PMFAuth:               []string{"static-bearer"},
	}
	if diff := cmp.Diff(want, doc); diff != "" {
		t.Errorf("protected resource metadata (-want +got):\n%s", diff)
	}
	// RFC 9728 requires authorization_servers to be present as an array even
	// when there is nowhere to go, so a client does not have to guess.
	if !strings.Contains(body, `"authorization_servers":[]`) {
		t.Errorf("authorization_servers is not an explicit empty array: %s", body)
	}
	if _, err := url.Parse(doc.Resource); err != nil || doc.Resource == "" {
		t.Errorf("resource = %q, want the canonical MCP url", doc.Resource)
	}
}

// TestPublicMuxRegistersNoCatchAll proves the mux can be mounted beside the
// MCP handler without shadowing it.
func TestPublicMuxRegistersNoCatchAll(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	resp := h.do(h.public, http.MethodGet, "/mcp", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q; the public mux answered a path it does not own", ct)
	}
}
