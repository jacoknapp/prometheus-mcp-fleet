// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// PRMPath is the RFC 9728 protected-resource metadata path for the MCP
// endpoint.
const PRMPath = "/.well-known/oauth-protected-resource/mcp"

// ProjectURL is published as the protected resource's documentation link.
const ProjectURL = "https://github.com/jacoknapp/prometheus-mcp-fleet"

// NewPublicMux returns the handler for the routes that must be reachable from
// a cluster the hub has never met.
//
// It registers no catch-all pattern, because it is mounted on the same
// listener as the MCP handler and a catch-all would shadow it.
//
// Routes:
//
//	POST /enroll                                     single-use `pmf_enr_` bearer
//	POST /renew                                      mutual TLS only, no bearer
//	GET  /pki/bundle                                 CA bundle, unauthenticated
//	GET  /pki/crl                                    DER CRL, unauthenticated
//	GET  /.well-known/oauth-protected-resource/mcp   RFC 9728 metadata
//
// The two PKI routes are deliberately unauthenticated: a trust anchor and a
// revocation list are public by construction, and requiring a credential to
// fetch the trust anchor you need in order to present a credential is a
// bootstrap loop.
func NewPublicMux(opts Options) (http.Handler, error) {
	s, err := newServer(opts)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	enroll := s.verifier.Middleware(fleet.ClassEnrollment)(http.HandlerFunc(s.handleEnroll))
	mux.Handle("POST /enroll", s.enrollmentGate(enroll))
	mux.HandleFunc("POST /renew", s.handleRenew)
	mux.HandleFunc("GET /pki/bundle", s.handlePKIBundle)
	mux.HandleFunc("GET /pki/crl", s.handlePKICRL)
	mux.HandleFunc("GET "+PRMPath, s.handleProtectedResourceMetadata)
	return mux, nil
}

// enrollmentGate closes /enroll before any credential is verified when
// enrollment is disabled or the process is draining. Refusing early means a
// closed hub spends nothing on an enrollment attempt.
func (s *server) enrollmentGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.enrollmentEnabled {
			s.metrics.Enrollment(ResultDenied)
			s.fail(w, r, CodeUnavailable, "enrollment is disabled on this hub")
			return
		}
		if s.draining() {
			s.metrics.Enrollment(ResultDenied)
			s.fail(w, r, CodeUnavailable, "the hub is shutting down and is not accepting enrollments")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleEnroll redeems a single-use enrollment token for one spoke
// certificate.
//
// Ordering is the security property. The certificate is signed first, because
// the burn has to record which serial the token bought, and only then is the
// token burned with one atomic conditional store update. The response is
// written only if that burn wins. A losing burn means the token was already
// redeemed: the certificate that was just signed is dropped on the floor, the
// caller gets 409, and the event is logged as a security event, because a
// replayed enrollment token means the install secret has leaked.
//
// The CSR contributes exactly one thing: its public key. Its subject, its SANs
// and its extensions are discarded by [ca.CA.IssueSpokeFromCSR], so a request
// asking for "CN=admin" or for another cluster's URI SAN receives a
// certificate for the cluster the hub bound the token to and nothing else.
func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	p := authn.PrincipalFrom(r.Context())
	if p == nil {
		s.metrics.Enrollment(ResultDenied)
		s.fail(w, r, CodeUnauthenticated, "an enrollment credential is required")
		return
	}
	csrDER, ok := s.readCSR(w, r)
	if !ok {
		return
	}

	key, err := s.store.GetKey(r.Context(), p.KID)
	if err != nil || key == nil {
		s.metrics.Enrollment(ResultError)
		if err == nil {
			err = ErrNotFound
		}
		s.failInternal(w, r, "load enrollment", err)
		return
	}
	if key.Enrollment == nil || key.Enrollment.ClusterID == "" {
		// A `pmf_enr_` credential with no cluster binding cannot buy anything:
		// the hub would have to take the identity from the CSR, which is
		// exactly what this design refuses to do.
		s.metrics.Enrollment(ResultDenied)
		s.fail(w, r, CodeForbidden, "this enrollment token is not bound to a cluster")
		return
	}
	clusterID := key.Enrollment.ClusterID
	if key.Enrollment.UsedAt != nil {
		s.replay(w, r, key.KID, clusterID)
		return
	}

	certPEM, cert, err := s.ca.IssueSpokeFromCSR(csrDER, clusterID)
	if err != nil {
		if errors.Is(err, ca.ErrCSRInvalid) || errors.Is(err, ca.ErrInvalidClusterID) {
			s.metrics.Enrollment(ResultInvalid)
			s.fail(w, r, CodeInvalidRequest, "the certificate signing request was rejected: "+err.Error())
			return
		}
		s.metrics.Enrollment(ResultError)
		s.failInternal(w, r, "issue spoke certificate", err)
		return
	}
	serial := ca.SerialHex(cert.SerialNumber)

	if _, err := s.store.BurnEnrollment(r.Context(), key.KID, serial, s.clock()); err != nil {
		if s.isConflict(err) {
			s.replay(w, r, key.KID, clusterID)
			return
		}
		s.metrics.Enrollment(ResultError)
		s.failInternal(w, r, "burn enrollment", err)
		return
	}

	s.security(r, EventEnrollmentBurned,
		slog.String("kid", key.KID),
		slog.String("cluster", clusterID),
		slog.String("serial", serial))
	s.security(r, EventCertIssued,
		slog.String("cluster", clusterID),
		slog.String("serial", serial),
		slog.String("notAfter", cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z07:00")))
	s.metrics.Enrollment(ResultIssued)
	s.writeJSON(w, r, http.StatusCreated, EnrollResponse{
		Certificate: string(certPEM),
		CABundle:    string(s.ca.BundlePEM()),
		NotAfter:    cert.NotAfter,
		ClusterID:   clusterID,
		Serial:      serial,
	})
}

// replay answers a second redemption and records it as a security event.
func (s *server) replay(w http.ResponseWriter, r *http.Request, kid, clusterID string) {
	s.security(r, EventEnrollmentReplay,
		slog.String("kid", kid),
		slog.String("cluster", clusterID))
	s.metrics.Enrollment(ResultReplay)
	s.fail(w, r, CodeConflict,
		"this enrollment token has already been redeemed and cannot be redeemed again")
}

// handleRenew issues a fresh certificate to a spoke that already holds one.
//
// Authentication is the client certificate and nothing else: there is no
// bearer credential on this route, and the cluster identity comes from the
// verified certificate's URI SAN by way of [ca.CA.IdentityFromCert]. Nothing
// in the request body can influence which identity is issued, so a spoke
// cannot renew its way into being a different cluster.
//
// The listener must be configured with [ca.CA.ServerTLSConfig] (or an
// equivalent that verifies the client chain against the hub CA); this handler
// refuses any request whose TLS state carries no verified chain.
func (s *server) handleRenew(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		s.metrics.Enrollment(ResultDenied)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		s.metrics.Enrollment(ResultDenied)
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "renew without a verified client certificate",
			slog.String("remoteAddr", authn.SourceAddr(r)))
		s.fail(w, r, CodeUnauthenticated,
			"renewal requires a verified client certificate; there is no bearer credential for this route")
		return
	}
	identity, err := s.ca.IdentityFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		s.metrics.Enrollment(ResultDenied)
		s.fail(w, r, CodeForbidden, "the client certificate carries no usable spoke identity")
		return
	}
	revoked, err := s.revokedSerials(r)
	if err != nil {
		s.metrics.Enrollment(ResultError)
		s.failInternal(w, r, "list revoked certificates", err)
		return
	}
	if _, bad := revoked[identity.CertSerial]; bad {
		s.metrics.Enrollment(ResultDenied)
		s.security(r, EventCertRevoked,
			slog.String("cluster", identity.ClusterID),
			slog.String("serial", identity.CertSerial),
			slog.String("note", "revoked certificate attempted renewal"))
		s.fail(w, r, CodeForbidden, "the client certificate has been revoked")
		return
	}
	csrDER, ok := s.readCSR(w, r)
	if !ok {
		return
	}

	certPEM, cert, err := s.ca.IssueSpokeFromCSR(csrDER, identity.ClusterID)
	if err != nil {
		if errors.Is(err, ca.ErrCSRInvalid) {
			s.metrics.Enrollment(ResultInvalid)
			s.fail(w, r, CodeInvalidRequest, "the certificate signing request was rejected: "+err.Error())
			return
		}
		s.metrics.Enrollment(ResultError)
		s.failInternal(w, r, "renew spoke certificate", err)
		return
	}
	serial := ca.SerialHex(cert.SerialNumber)
	s.security(r, EventCertRenewed,
		slog.String("cluster", identity.ClusterID),
		slog.String("serial", serial),
		slog.String("previousSerial", identity.CertSerial))
	s.metrics.Enrollment(ResultIssued)
	s.writeJSON(w, r, http.StatusCreated, EnrollResponse{
		Certificate: string(certPEM),
		CABundle:    string(s.ca.BundlePEM()),
		NotAfter:    cert.NotAfter,
		ClusterID:   identity.ClusterID,
		Serial:      serial,
	})
}

// handlePKIBundle serves the CA certificate as PEM.
func (s *server) handlePKIBundle(w http.ResponseWriter, r *http.Request) {
	bundle := s.ca.BundlePEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(bundle); err != nil {
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "write ca bundle", slog.String("error", err.Error()))
	}
}

// handlePKICRL serves the DER certificate revocation list.
func (s *server) handlePKICRL(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListRevokedCerts(r.Context())
	if err != nil {
		s.failInternal(w, r, "list revoked certificates", err)
		return
	}
	now := s.clock()
	revoked := make([]ca.RevokedEntry, 0, len(entries))
	for _, e := range entries {
		revoked = append(revoked, ca.RevokedEntry{Serial: e.Serial, RevokedAt: e.RevokedAt})
	}
	der, err := s.ca.CRL(revoked, now, s.crlValidity)
	if err != nil {
		s.failInternal(w, r, "sign crl", err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(der); err != nil {
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "write crl", slog.String("error", err.Error()))
	}
}

// handleProtectedResourceMetadata serves the RFC 9728 document.
//
// To be explicit about what this is: the hub does not implement OAuth. There
// is no authorization server, no token endpoint and no dynamic client
// registration. Credentials are static bearer keys an operator mints through
// the admin API. The document exists because a spec-compliant MCP client that
// receives a 401 with a WWW-Authenticate challenge will fetch this URL, and
// answering it with a well-formed body that says "authorization_servers: []"
// plus an explicit x-pmf-auth extension is a far better failure than a 404 the
// client has to interpret.
func (s *server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	// RFC 9728 metadata is public discovery data, so cross-origin reads are
	// allowed; the document contains no secret and no per-caller state.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	doc := ProtectedResourceMetadata{
		Resource:               s.publicURL,
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
	if err := writeJSONBody(w, doc); err != nil {
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "write protected resource metadata",
			slog.String("error", err.Error()))
	}
}

// readCSR decodes and bounds the base64 DER certificate signing request.
func (s *server) readCSR(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var req EnrollRequest
	if !s.readBody(w, r, &req) {
		s.metrics.Enrollment(ResultInvalid)
		return nil, false
	}
	if req.CSR == "" {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, "csr is required: a base64 DER certificate signing request")
		return nil, false
	}
	if len(req.CSR) > MaxCSRBytes {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, fmt.Sprintf("csr exceeds %d base64 characters", MaxCSRBytes))
		return nil, false
	}
	der, err := decodeCSR(req.CSR)
	if err != nil {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, "csr is not valid base64 DER")
		return nil, false
	}
	return der, true
}

// decodeCSR accepts padded or unpadded standard base64. It does not parse the
// request: that is the CA's job, and doing it twice would mean two places
// could disagree about what a valid CSR is.
func decodeCSR(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	if der, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return der, nil
	}
	der, err := base64.RawStdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decode csr: %w", err)
	}
	return der, nil
}

// revokedSerials returns the revoked certificate serials as a set.
func (s *server) revokedSerials(r *http.Request) (map[string]struct{}, error) {
	entries, err := s.store.ListRevokedCerts(r.Context())
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		set[e.Serial] = struct{}{}
	}
	return set, nil
}
