// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
)

// Enrollment and renewal errors.
var (
	// ErrTokenAlreadyUsed means the hub refused the enrollment token because it
	// had already been redeemed. This is a security event, not a retryable
	// condition: it means the install secret leaked.
	ErrTokenAlreadyUsed = errors.New("spoke: enrollment token has already been used")
	// ErrEnrollRejected means the hub refused the request.
	ErrEnrollRejected = errors.New("spoke: hub rejected the enrollment")
)

// maxEnrollResponseBytes bounds what we will read from the hub. An enrollment
// response is a few kilobytes; anything larger is a misconfigured endpoint or a
// hostile one.
const maxEnrollResponseBytes = 1 << 20

// enrollRequest is the body of POST /enroll.
//
// It carries the CSR and nothing else, matching hubapi.EnrollRequest exactly.
// The hub decodes strictly and rejects unknown fields, so this must not grow a
// field the hub does not have — and it has no reason to: the cluster identity
// comes from the enrollment token, so a client-supplied cluster ID here would
// be either redundant or an attempt to claim something.
type enrollRequest struct {
	// CSR is the DER certificate signing request, base64 encoded.
	CSR string `json:"csr"`
}

// renewChallenge is the reply to GET /renew/challenge, matching
// hubapi.RenewChallengeResponse.
type renewChallenge struct {
	// Nonce is the value to sign. encoding/json decodes it from base64.
	Nonce []byte `json:"nonce"`
	// ExpiresAt is when the hub stops accepting it. It is read only for the
	// log line: the hub is the authority on its own window, and a spoke that
	// second-guessed it would just fail differently.
	ExpiresAt string `json:"expiresAt"`
}

// renewRequest is the body of POST /renew, matching hubapi.RenewRequest.
//
// It is a separate type from [enrollRequest] because the two routes take
// different documents and the hub rejects unknown fields on both. There is no
// cluster field: the hub reads the identity from the certificate in Chain, and
// offering it one to prefer would be offering it a way to be wrong.
type renewRequest struct {
	CSR       string   `json:"csr"`
	Chain     [][]byte `json:"chain"`
	Signature []byte   `json:"signature"`
	Nonce     []byte   `json:"nonce"`
}

// enrollResponse is the hub's reply.
type enrollResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"caBundle"`
	ClusterID   string `json:"clusterId"`
	NotAfter    string `json:"notAfter"`
}

// apiError is the hub's error envelope.
type apiError struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

// enroller exchanges a certificate signing request for a client certificate.
//
// Two flows share almost all their code and differ in exactly one way that
// matters: /enroll authenticates with a single-use bearer token and is only
// ever run once, while /renew authenticates by proving possession of the key
// behind the certificate it already holds, and needs no token at all. Keeping
// them in one type makes it hard for the renewal path to accidentally acquire a
// token requirement.
type enroller struct {
	apiURL    string
	caFile    string
	insecure  bool
	logger    *slog.Logger
	userAgent string
}

// enroll redeems a single-use token for a client certificate. The private key
// is generated here and never leaves the process.
func (e *enroller) enroll(ctx context.Context, clusterID, token string) (*Identity, error) {
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	csr, err := buildCSR(key, clusterID)
	if err != nil {
		return nil, err
	}

	client, err := e.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := e.post(ctx, client, "/enroll", token, enrollRequest{
		CSR: base64.StdEncoding.EncodeToString(csr),
	})
	if err != nil {
		return nil, err
	}
	return e.assemble(keyPEM, resp)
}

// renew obtains a fresh certificate by proving possession of the key behind the
// one the spoke already holds. No enrollment token is involved, which is the
// whole point: a spoke that renews on schedule never needs an operator again.
//
// It presents no client certificate at the TLS layer, and must not: the hub
// sits behind an ingress that terminates TLS (ADR-0014), so a certificate
// offered there reaches the ingress and stops. The proof travels in the request
// body instead — the certificate chain plus a signature over a challenge the
// hub issued — which is the same construction the tunnel handshake uses, from
// the same package, so the two cannot drift apart.
//
// The private key never moves. The new one is generated locally and only its
// CSR is sent; the old one signs the challenge and stays where it is.
func (e *enroller) renew(ctx context.Context, current *Identity) (*Identity, error) {
	signer, ok := current.Certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: the stored private key of type %T cannot sign a renewal challenge",
			ErrEnrollRejected, current.Certificate.PrivateKey)
	}
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	clusterID := clusterIDFromCert(current.Leaf)
	csr, err := buildCSR(key, clusterID)
	if err != nil {
		return nil, err
	}

	client, err := e.httpClient()
	if err != nil {
		return nil, err
	}
	challenge, err := e.challenge(ctx, client)
	if err != nil {
		return nil, err
	}
	// The cluster ID signed here is the one read from the certificate the hub
	// issued, not the one in local configuration: the hub verifies the
	// signature against the identity it derives from that same certificate, so
	// any other value would simply fail to verify.
	sig, err := certproof.Sign(signer, challenge.Nonce, certproof.RenewProtocolVersion, clusterID,
		certproof.CSRBinding(csr))
	if err != nil {
		return nil, fmt.Errorf("sign the renewal challenge: %w", err)
	}

	resp, err := e.post(ctx, client, "/renew", "", renewRequest{
		CSR:       base64.StdEncoding.EncodeToString(csr),
		Chain:     current.Certificate.Certificate,
		Signature: sig,
		Nonce:     challenge.Nonce,
	})
	if err != nil {
		return nil, err
	}
	return e.assemble(keyPEM, resp)
}

// challenge fetches the nonce a renewal must sign.
//
// The challenge is not a credential and carries no authorization: it is a value
// with an expiry that the hub can recognise as its own without having stored it.
// Fetching one costs nothing and needs nothing, which is what lets a spoke whose
// certificate is its only credential authenticate at all.
func (e *enroller) challenge(ctx context.Context, client *http.Client) (*renewChallenge, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(e.apiURL, "/")+"/renew/challenge", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", e.userAgent)

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get /renew/challenge: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(res.Body, maxEnrollResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read /renew/challenge response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, e.statusError("/renew/challenge", res.StatusCode, payload)
	}

	var out renewChallenge
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("decode /renew/challenge response: %w", err)
	}
	if len(out.Nonce) == 0 {
		return nil, fmt.Errorf("%w: the hub issued an empty renewal challenge", ErrEnrollRejected)
	}
	return &out, nil
}

// post performs one enrollment-style request and decodes the certificate reply.
//
// payload is the route's own request document — [enrollRequest] or
// [renewRequest] — rather than a fixed shape, because the hub decodes strictly
// and the two routes take different bodies.
func (e *enroller) post(
	ctx context.Context, client *http.Client, path, token string, payload any,
) (*enrollResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(e.apiURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.userAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()

	reply, err := io.ReadAll(io.LimitReader(res.Body, maxEnrollResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", path, err)
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, e.statusError(path, res.StatusCode, reply)
	}

	var out enrollResponse
	if err := json.Unmarshal(reply, &out); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", path, err)
	}
	if out.Certificate == "" {
		return nil, fmt.Errorf("%w: response carried no certificate", ErrEnrollRejected)
	}
	return &out, nil
}

// statusError turns a non-2xx reply into an actionable error. The distinction
// between "already used" and everything else matters: the former means a
// credential leaked and must be investigated, not retried.
func (e *enroller) statusError(path string, status int, body []byte) error {
	var envelope apiError
	_ = json.Unmarshal(body, &envelope)
	detail := envelope.Error.Message
	if detail == "" {
		detail = strings.TrimSpace(string(body))
	}
	if len(detail) > 512 {
		detail = detail[:512] + "…"
	}

	switch status {
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrTokenAlreadyUsed, detail)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s %d: %s (%s)", ErrEnrollRejected, path, status, detail, authHint(path))
	default:
		return fmt.Errorf("%w: %s %d: %s", ErrEnrollRejected, path, status, detail)
	}
}

// authHint names the likely cause of a 401 or 403 for the route that produced
// it. The two routes fail for entirely different reasons, and an operator
// reading "check the token" after a renewal that never used a token has been
// sent to look in the wrong place.
func authHint(path string) string {
	if strings.HasPrefix(path, "/renew") {
		return "renewal presents the spoke's current certificate and a signature over the hub's " +
			"challenge; this means the certificate is expired, revoked or from another hub, or the " +
			"stored private key no longer matches it"
	}
	return "check the token has not expired — enrollment tokens are single-use and short-lived"
}

// assemble turns the hub's reply into a usable Identity.
func (e *enroller) assemble(keyPEM []byte, resp *enrollResponse) (*Identity, error) {
	certPEM := []byte(resp.Certificate)
	caPEM := []byte(resp.CABundle)
	id, err := loadIdentity(keyPEM, certPEM, caPEM)
	if err != nil {
		return nil, err
	}
	// cluster_id is already bound on the spoke's logger; repeating it here
	// produced a duplicate key in every JSON line.
	e.logger.Info("obtained client certificate",
		"serial", id.Leaf.SerialNumber.Text(16),
		"not_after", id.Leaf.NotAfter.Format(time.RFC3339))
	return id, nil
}

// httpClient builds the client for one enrollment or renewal call.
//
// It never presents a client certificate. It used to, for /renew, and that was
// the bug: the hub is behind an ingress that terminates TLS, so the certificate
// went to the ingress and the hub saw nothing. Possession is proved in the
// request body now; see [enroller.renew].
func (e *enroller) httpClient() (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	switch {
	case e.caFile != "":
		pem, err := os.ReadFile(e.caFile)
		if err != nil {
			return nil, fmt.Errorf("read hub CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("hub CA file %s contains no certificates", e.caFile)
		}
		tlsCfg.RootCAs = pool
	case e.insecure:
		// Guarded by config validation, which requires PMF_ALLOW_INSECURE as a
		// second, deliberate opt-in. Never reachable by accident.
		tlsCfg.InsecureSkipVerify = true
		e.logger.Warn("hub TLS verification is disabled; do not do this outside development")
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
	}, nil
}

// readToken reads and trims an enrollment token from a file.
func readToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: no enrollment token file configured", ErrEnrollmentRequired)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("%w: enrollment token file %s is empty", ErrEnrollmentRequired, path)
	}
	return tok, nil
}

// pkixName builds a subject with only a common name. The hub discards it.
func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

// clusterIDFromCert recovers the cluster ID from an issued certificate's URI
// SAN, falling back to the common name only for diagnostics.
func clusterIDFromCert(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if id := strings.TrimPrefix(u.Path, "/spoke/"); id != u.Path && id != "" {
			return id
		}
	}
	return strings.TrimPrefix(cert.Subject.CommonName, "spoke:")
}
