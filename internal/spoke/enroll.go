// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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

// enrollRequest is the body of POST /enroll and POST /renew.
//
// It carries the CSR and nothing else, matching hubapi.EnrollRequest exactly.
// The hub decodes strictly and rejects unknown fields, which is the right
// behaviour: the cluster identity comes from the enrollment token on /enroll
// and from the client certificate on /renew, so a client-supplied cluster ID
// here would be either redundant or an attempt to claim something.
type enrollRequest struct {
	// CSR is the DER certificate signing request, base64 encoded.
	CSR string `json:"csr"`
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
// ever run once, while /renew authenticates with the existing client
// certificate and needs no token at all. Keeping them in one type makes it hard
// for the renewal path to accidentally acquire a token requirement.
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

	client, err := e.httpClient(nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.post(ctx, client, "/enroll", token, csr, clusterID)
	if err != nil {
		return nil, err
	}
	return e.assemble(keyPEM, resp)
}

// renew obtains a fresh certificate over the existing mutually authenticated
// connection. No enrollment token is involved, which is the whole point: a
// spoke that renews on schedule never needs an operator again.
func (e *enroller) renew(ctx context.Context, current *Identity) (*Identity, error) {
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	clusterID := clusterIDFromCert(current.Leaf)
	csr, err := buildCSR(key, clusterID)
	if err != nil {
		return nil, err
	}

	client, err := e.httpClient(current)
	if err != nil {
		return nil, err
	}
	resp, err := e.post(ctx, client, "/renew", "", csr, clusterID)
	if err != nil {
		return nil, err
	}
	return e.assemble(keyPEM, resp)
}

// post performs one enrollment-style request.
func (e *enroller) post(
	ctx context.Context, client *http.Client, path, token string, csrDER []byte, clusterID string,
) (*enrollResponse, error) {
	body, err := json.Marshal(enrollRequest{
		CSR: base64.StdEncoding.EncodeToString(csrDER),
	})
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

	payload, err := io.ReadAll(io.LimitReader(res.Body, maxEnrollResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", path, err)
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, e.statusError(path, res.StatusCode, payload)
	}

	var out enrollResponse
	if err := json.Unmarshal(payload, &out); err != nil {
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
		return fmt.Errorf("%w: %s %d: %s (check the token has not expired — "+
			"enrollment tokens are single-use and short-lived)",
			ErrEnrollRejected, path, status, detail)
	default:
		return fmt.Errorf("%w: %s %d: %s", ErrEnrollRejected, path, status, detail)
	}
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

// httpClient builds the client for one enrollment call. When current is
// non-nil it presents that certificate, which is how /renew authenticates.
func (e *enroller) httpClient(current *Identity) (*http.Client, error) {
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

	if current != nil {
		tlsCfg.Certificates = []tls.Certificate{current.Certificate}
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

// ensure ecdsa stays referenced when build tags trim this file down.
var _ = (*ecdsa.PrivateKey)(nil)
