// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestTheFakeHubIsAsStrictAsTheRealOne. Every other assertion in this package
// about request bodies is worth exactly as much as this one: a hub stub that
// ignored an unknown field would have accepted the enrollment body that the
// real hub, which decodes strictly, refused.
func TestTheFakeHubIsAsStrictAsTheRealOne(t *testing.T) {
	t.Parallel()

	e, _ := newEnroller(t)
	client, err := e.httpClient()
	if err != nil {
		t.Fatalf("httpClient: %v", err)
	}

	for _, tc := range []struct {
		name, path, body string
	}{
		{
			name: "an enrollment naming its own cluster",
			path: "/enroll",
			body: `{"csr":"","clusterId":"someone-else"}`,
		},
		{
			// RenewRequest has no cluster field at all: the identity comes
			// from the verified certificate and from nowhere else.
			name: "a renewal naming its own cluster",
			path: "/renew",
			body: `{"csr":"","chain":[],"signature":"","nonce":"","clusterId":"someone-else"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				e.apiURL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("post %s: %v", tc.path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("POST %s with an unknown field = %d, want 400", tc.path, resp.StatusCode)
			}
		})
	}
}

// TestEnrollFailsBeforeTheTokenIsSpent. Key generation and the CSR happen
// before the request, so a failure in either has to stop there: the token is
// still unredeemed and an operator can retry with it.
func TestEnrollFailsBeforeTheTokenIsSpent(t *testing.T) {
	originalKey, originalCSR := spokeGenerateKey, spokeCreateCSR
	t.Cleanup(func() { spokeGenerateKey, spokeCreateCSR = originalKey, originalCSR })

	boom := errors.New("injected cryptographic failure")

	t.Run("the key cannot be generated", func(t *testing.T) {
		e, hub := newEnroller(t)
		// The identity is minted before the failure is installed: it stands in
		// for one the spoke already holds.
		current := hub.ca.newIdentity(t, "prod-eu-1")
		spokeGenerateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, boom }
		defer func() { spokeGenerateKey = originalKey }()

		if _, err := e.enroll(t.Context(), "prod-eu-1", "tok"); !errors.Is(err, boom) {
			t.Fatalf("enroll = %v, want the key failure", err)
		}
		if _, err := e.renew(t.Context(), current); !errors.Is(err, boom) {
			t.Fatalf("renew = %v, want the key failure", err)
		}
		hub.mu.Lock()
		defer hub.mu.Unlock()
		if hub.lastEnrollBody != "" {
			t.Error("the token was sent to the hub despite having no key to certify")
		}
	})

	t.Run("the CSR cannot be signed", func(t *testing.T) {
		e, hub := newEnroller(t)
		current := hub.ca.newIdentity(t, "prod-eu-1")
		spokeCreateCSR = func(io.Reader, *x509.CertificateRequest, any) ([]byte, error) { return nil, boom }
		defer func() { spokeCreateCSR = originalCSR }()

		if _, err := e.enroll(t.Context(), "prod-eu-1", "tok"); !errors.Is(err, boom) {
			t.Fatalf("enroll = %v, want the CSR failure", err)
		}
		if _, err := e.renew(t.Context(), current); !errors.Is(err, boom) {
			t.Fatalf("renew = %v, want the CSR failure", err)
		}
		hub.mu.Lock()
		defer hub.mu.Unlock()
		if hub.lastEnrollBody != "" {
			t.Error("the token was sent to the hub despite having no CSR to send")
		}
	})
}

// refusingSigner holds a real public key and a private half that will not
// sign: a key sealed by a hardware token that has gone away, or one whose
// backing device has been detached.
type refusingSigner struct {
	pub crypto.PublicKey
	err error
}

func (s refusingSigner) Public() crypto.PublicKey { return s.pub }

func (s refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// TestRenewFailsWhenTheKeyWillNotSign. The renewal proof is the only
// credential this route accepts, so a key that cannot produce one has to stop
// the renewal here rather than post an unsigned request the hub would answer
// with a 403 an operator then goes and misdiagnoses.
func TestRenewFailsWhenTheKeyWillNotSign(t *testing.T) {
	t.Parallel()

	e, hub := newEnroller(t)
	id := hub.ca.newIdentity(t, "prod-eu-1")
	boom := errors.New("the signing device is gone")
	id.Certificate.PrivateKey = refusingSigner{pub: id.Leaf.PublicKey, err: boom}

	_, err := e.renew(t.Context(), id)
	if !errors.Is(err, boom) {
		t.Fatalf("renew = %v, want it to wrap the signing failure", err)
	}
	errContains(t, err, "sign the renewal challenge")

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.lastRenew.Chain) != 0 {
		t.Error("a renewal was posted without a usable proof of possession")
	}
}

// TestHTTPClientTrustsTheConfiguredBundle. The hub behind an ingress presents
// the ingress's certificate, so this bundle is the only thing standing between
// an enrollment and whatever answers on that name.
func TestHTTPClientTrustsTheConfiguredBundle(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{ca: newTestCA(t)}
	srv := httptest.NewTLSServer(hub.handler())
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	t.Run("a bundle that verifies the server", func(t *testing.T) {
		t.Parallel()
		e := &enroller{
			apiURL:    srv.URL,
			caFile:    writeFile(t, t.TempDir(), "ca.crt", string(caPEM)),
			logger:    quiet(),
			userAgent: "pmf-spoke/test",
		}
		if _, err := e.enroll(t.Context(), "prod-eu-1", "tok"); err != nil {
			t.Fatalf("enroll over TLS with the hub's bundle: %v", err)
		}
	})

	t.Run("no bundle at all refuses the server", func(t *testing.T) {
		t.Parallel()
		e := &enroller{apiURL: srv.URL, logger: quiet(), userAgent: "pmf-spoke/test"}
		_, err := e.enroll(t.Context(), "prod-eu-1", "tok")
		errContains(t, err, "certificate")
	})

	t.Run("verification can be turned off for a lab", func(t *testing.T) {
		t.Parallel()
		capture, logger := newLogCapture()
		e := &enroller{apiURL: srv.URL, insecure: true, logger: logger, userAgent: "pmf-spoke/test"}
		if _, err := e.enroll(t.Context(), "prod-eu-1", "tok"); err != nil {
			t.Fatalf("enroll with verification disabled: %v", err)
		}
		if !capture.has("hub TLS verification is disabled") {
			t.Errorf("an insecure client was built without saying so; got %s", capture.messages())
		}
	})
}

// TestHTTPClientRefusesAnUnusableBundle. Failing here is the point: carrying
// on with the system roots would silently downgrade the operator's explicit
// trust decision to "whoever a public CA vouched for".
func TestHTTPClientRefusesAnUnusableBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tests := []struct {
		name    string
		caFile  string
		wantMsg string
	}{
		{
			name:    "a file that is not there",
			caFile:  dir + "/missing.crt",
			wantMsg: "read hub CA file",
		},
		{
			name:    "a file with no certificate in it",
			caFile:  writeFile(t, dir, "empty.crt", "this is not a certificate\n"),
			wantMsg: "contains no certificates",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := &enroller{apiURL: "https://hub.test", caFile: tc.caFile, logger: quiet()}
			client, err := e.httpClient()
			if client != nil {
				t.Error("an unusable bundle still produced a client")
			}
			errContains(t, err, tc.wantMsg)

			// Both entry points have to refuse, not just the one that happens
			// to be tested elsewhere.
			_, err = e.enroll(t.Context(), "prod-eu-1", "tok")
			errContains(t, err, tc.wantMsg)
			_, err = e.renew(t.Context(), newTestCA(t).newIdentity(t, "prod-eu-1"))
			errContains(t, err, tc.wantMsg)
		})
	}
}

// TestRequestsAgainstAnUnusableAPIURL. A URL that cannot be turned into a
// request never reaches the network, and the error has to name the step rather
// than surfacing as a connection failure an operator would go and debug.
func TestRequestsAgainstAnUnusableAPIURL(t *testing.T) {
	t.Parallel()

	// A control character cannot appear in a URL, so http.NewRequest refuses
	// it before any I/O.
	e := &enroller{apiURL: "http://hub.test/\x7f", logger: quiet(), userAgent: "pmf-spoke/test"}

	_, err := e.enroll(t.Context(), "prod-eu-1", "tok")
	errContains(t, err, "build request")

	_, err = e.renew(t.Context(), newTestCA(t).newIdentity(t, "prod-eu-1"))
	errContains(t, err, "build request")
}

// TestPostRefusesABodyItCannotEncode. post takes each route's own document
// because the two routes send different ones; a document that will not encode
// is a programming error and has to say so rather than posting nothing.
func TestPostRefusesABodyItCannotEncode(t *testing.T) {
	t.Parallel()

	e, _ := newEnroller(t)
	client, err := e.httpClient()
	if err != nil {
		t.Fatalf("httpClient: %v", err)
	}
	_, err = e.post(t.Context(), client, "/enroll", "", make(chan int))
	errContains(t, err, "encode request")
}

// TestRepliesThatCannotBeRead covers a hub, or something in front of it, that
// announces a body and then hangs up. It must not be mistaken for a
// certificate that failed to parse.
func TestRepliesThatCannotBeRead(t *testing.T) {
	t.Parallel()

	// A truncated response: the declared length never arrives.
	url := rawHTTPServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n{\"cert")

	e := &enroller{apiURL: url, logger: quiet(), userAgent: "pmf-spoke/test"}
	_, err := e.enroll(t.Context(), "prod-eu-1", "tok")
	errContains(t, err, "read /enroll response")

	_, err = e.renew(t.Context(), newTestCA(t).newIdentity(t, "prod-eu-1"))
	errContains(t, err, "read /renew/challenge response")
}

// TestRepliesThatAreNotWhatWasAsked walks the shapes a 200 can take and still
// be useless. Each has to be distinguishable in a log from the others.
func TestRepliesThatAreNotWhatWasAsked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{name: "not JSON at all", body: "<html>login</html>", wantMsg: "decode /enroll response"},
		{name: "JSON with no certificate", body: `{"caBundle":"x"}`, wantMsg: "carried no certificate"},
		{name: "a certificate that is not PEM", body: `{"certificate":"nonsense"}`, wantMsg: "parse stored identity"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)

			e := &enroller{apiURL: srv.URL, logger: quiet(), userAgent: "pmf-spoke/test"}
			_, err := e.enroll(t.Context(), "prod-eu-1", "tok")
			errContains(t, err, tc.wantMsg)
		})
	}
}

// TestChallengeFailuresAreNamed. The challenge is the step that lets a spoke
// authenticate at all, so its failures must not be reported as a rejected
// renewal — the operator would go looking at the certificate instead of at the
// hub being unreachable.
func TestChallengeFailuresAreNamed(t *testing.T) {
	t.Parallel()

	e := &enroller{apiURL: "http://" + deadAddr(t), logger: quiet(), userAgent: "pmf-spoke/test"}
	_, err := e.renew(t.Context(), newTestCA(t).newIdentity(t, "prod-eu-1"))
	errContains(t, err, "get /renew/challenge")
}

// TestStatusErrorTruncatesAnUnboundedBody. The body of a refusal is under
// someone else's control; echoing all of it into a log is how a hostile or
// merely misconfigured endpoint writes whatever it likes into the operator's
// logging pipeline.
func TestStatusErrorTruncatesAnUnboundedBody(t *testing.T) {
	t.Parallel()

	e := &enroller{apiURL: "https://hub.test", logger: quiet()}
	err := e.statusError("/enroll", http.StatusInternalServerError, []byte(strings.Repeat("A", 4096)))

	msg := err.Error()
	if !strings.Contains(msg, "…") {
		t.Errorf("a 4KiB refusal was not truncated: %q", msg)
	}
	if strings.Count(msg, "A") > 512 {
		t.Errorf("the refusal carried %d body bytes into the error, want at most 512",
			strings.Count(msg, "A"))
	}
}

// TestStatusErrorDoesNotTruncateAtExactlyTheLimit pins the boundary of the
// truncation check itself: TestStatusErrorTruncatesAnUnboundedBody only proves
// a body far over the limit gets truncated, which an off-by-one threshold
// would just as happily do. A detail of exactly 512 bytes is the only input
// that tells "> 512" apart from ">= 512".
func TestStatusErrorDoesNotTruncateAtExactlyTheLimit(t *testing.T) {
	t.Parallel()

	e := &enroller{apiURL: "https://hub.test", logger: quiet()}
	err := e.statusError("/enroll", http.StatusInternalServerError, []byte(strings.Repeat("A", 512)))
	if strings.Contains(err.Error(), "…") {
		t.Errorf("a 512-byte detail was truncated, want the boundary itself left untouched: %v", err)
	}
	if strings.Count(err.Error(), "A") != 512 {
		t.Errorf("error carries %d body bytes, want all 512", strings.Count(err.Error(), "A"))
	}
}

// TestHTTPClientTimeouts pins the exact timeout budget of the client used for
// enrollment and renewal. Nothing else in this package inspects these fields
// directly; the behavioural tests only prove the client works at all, not
// that a slow or hanging hub is bounded by the budget this package documents.
func TestHTTPClientTimeouts(t *testing.T) {
	t.Parallel()

	e := &enroller{logger: quiet()}
	client, err := e.httpClient()
	if err != nil {
		t.Fatalf("httpClient: %v", err)
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("client.Timeout = %s, want 30s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", client.Transport)
	}
	if tr.MaxIdleConnsPerHost != 2 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 2", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %s, want 30s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %s, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 20*time.Second {
		t.Errorf("ResponseHeaderTimeout = %s, want 20s", tr.ResponseHeaderTimeout)
	}
}

// TestClusterIDFromCert walks every source clusterIDFromCert reads from: the
// URI SAN when it carries the expected prefix, and the common-name fallback
// when the URI is absent, lacks the prefix, or is exactly the prefix with
// nothing after it (which TrimPrefix reduces to the empty string).
func TestClusterIDFromCert(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{
			name: "a uri with the spoke prefix",
			cert: &x509.Certificate{URIs: []*url.URL{{Path: "/spoke/prod-eu-1"}}},
			want: "prod-eu-1",
		},
		{
			name: "a uri without the spoke prefix falls back to the common name",
			cert: &x509.Certificate{
				URIs:    []*url.URL{{Path: "/other/prod-eu-1"}},
				Subject: pkix.Name{CommonName: "spoke:prod-eu-1"},
			},
			want: "prod-eu-1",
		},
		{
			name: "a uri that is exactly the prefix falls back to the common name",
			cert: &x509.Certificate{
				URIs:    []*url.URL{{Path: "/spoke/"}},
				Subject: pkix.Name{CommonName: "spoke:prod-eu-1"},
			},
			want: "prod-eu-1",
		},
		{
			name: "no uris at all falls back to the common name",
			cert: &x509.Certificate{Subject: pkix.Name{CommonName: "spoke:prod-eu-1"}},
			want: "prod-eu-1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clusterIDFromCert(tc.cert); got != tc.want {
				t.Errorf("clusterIDFromCert() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStatusErrorPointsAtTheRightCredential. A 401 on /renew has nothing to do
// with an enrollment token, and an operator sent to check one that was never
// used has been sent to the wrong place.
func TestStatusErrorPointsAtTheRightCredential(t *testing.T) {
	t.Parallel()

	e := &enroller{apiURL: "https://hub.test", logger: quiet()}

	enrollErr := e.statusError("/enroll", http.StatusUnauthorized, []byte(`{"error":{"message":"nope"}}`))
	if !strings.Contains(enrollErr.Error(), "check the token") {
		t.Errorf("a 401 from /enroll does not mention the token: %v", enrollErr)
	}
	renewErr := e.statusError("/renew", http.StatusForbidden, nil)
	if strings.Contains(renewErr.Error(), "check the token") {
		t.Errorf("a 403 from /renew blames the enrollment token, which renewal never uses: %v", renewErr)
	}
	if !strings.Contains(renewErr.Error(), "expired, revoked or from another hub") {
		t.Errorf("a 403 from /renew does not say what to look at: %v", renewErr)
	}
}

// rawHTTPServer answers every connection with a fixed byte string and then
// hangs up, which is how a truncated reply is staged without a cooperating
// http.Handler.
func rawHTTPServer(t *testing.T, response string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the request head so the client does not see a reset before
			// it has finished writing.
			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.WriteString(conn, response)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return "http://" + ln.Addr().String()
}
