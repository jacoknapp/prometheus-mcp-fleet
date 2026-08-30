// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof"
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
//	GET  /renew/challenge                            unauthenticated, see below
//	POST /renew                                      certificate + proof, no bearer
//	GET  /pki/bundle                                 CA bundle, unauthenticated
//	GET  /pki/crl                                    DER CRL, unauthenticated
//	GET  /.well-known/oauth-protected-resource/mcp   RFC 9728 metadata
//
// The two PKI routes are deliberately unauthenticated: a trust anchor and a
// revocation list are public by construction, and requiring a credential to
// fetch the trust anchor you need in order to present a credential is a
// bootstrap loop.
//
// /renew/challenge is unauthenticated for the same shape of reason: it is the
// step that lets a caller authenticate at all, and what it returns is a nonce
// with an expiry, which is neither a secret nor a capability. Everything that
// decides anything happens at POST /renew.
func NewPublicMux(opts Options) (http.Handler, error) {
	s, err := newServer(opts)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	enroll := s.verifier.Middleware(fleet.ClassEnrollment)(http.HandlerFunc(s.handleEnroll))
	mux.Handle("POST /enroll", s.enrollmentGate(enroll))
	mux.HandleFunc("GET /renew/challenge", s.handleRenewChallenge)
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

// handleRenewChallenge issues the nonce a renewal must sign.
//
// It is deliberately free of side effects: nothing is stored, no rate is
// consumed and no credential is required, so it cannot be used to exhaust
// anything a real spoke needs. It is answered even while the hub is draining,
// because the challenge is stateless and remains valid at whichever replica
// eventually serves the POST.
func (s *server) handleRenewChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, expiresAt := s.issueRenewNonce(s.clock())
	s.writeJSON(w, r, http.StatusOK, RenewChallengeResponse{Nonce: nonce, ExpiresAt: expiresAt})
}

// handleRenew issues a fresh certificate to a spoke that already holds one.
//
// # Why this is not mutual TLS
//
// It was, once, and that is the bug this shape exists to fix. Under ADR-0014
// the hub sits behind a standard Kubernetes Ingress that terminates TLS and
// forwards plain HTTP, so r.TLS is nil on every request that arrives in
// production and crypto/tls never sees a spoke's certificate. A handler that
// read r.TLS.PeerCertificates therefore refused every renewal in the field
// while passing every test that spoke TLS directly to it — and since spoke
// certificates live 14 days and renew at half life, the whole fleet would have
// disconnected on day 14 needing 100 fresh enrollment tokens to recover.
//
// Authentication is therefore the same construction the tunnel handshake
// already uses, one layer up from TLS: a nonce this fleet issued, a certificate
// chain, and a signature over a transcript binding the two to a cluster. The
// order below is the security property.
//
//  1. The nonce must be one this fleet minted and still inside its window. It
//     is checked first because it is the cheapest check and it is self-
//     contained, so a caller with no challenge at all is turned away before the
//     hub parses any certificate it supplied.
//  2. The chain must verify against this CA. [ca.CA.VerifyChain] is the whole
//     trust decision, and the cluster ID comes from the leaf's URI SAN.
//  3. The serial must not be on the revocation denylist. Revocation changes far
//     more often than the trust anchor, so it is a separate, live lookup.
//  4. The signature must verify under the leaf's public key, over the cluster
//     ID *the hub derived in step 2*. This is the step that makes the
//     certificate a credential rather than a public document anyone could
//     quote, and passing the derived cluster ID rather than a claimed one is
//     what stops a caller re-scoping a proof to somebody else's cluster.
//
// Only then is a certificate issued, for the identity from step 2. Nothing in
// the request body can influence which identity that is: [RenewRequest] has no
// cluster field, and [ca.CA.IssueSpokeFromCSR] discards the CSR's subject, SANs
// and extensions, so a request asking for "CN=admin" or for another cluster's
// URI SAN receives a certificate for its own cluster and nothing else.
func (s *server) handleRenew(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		s.metrics.Enrollment(ResultDenied)
		return
	}
	var req RenewRequest
	if !s.readBody(w, r, &req) {
		s.metrics.Enrollment(ResultInvalid)
		return
	}

	if err := s.verifyRenewNonce(req.Nonce, s.clock()); err != nil {
		s.metrics.Enrollment(ResultDenied)
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "renewal challenge refused",
			slog.String("remoteAddr", authn.SourceAddr(r)),
			slog.String("error", err.Error()))
		s.fail(w, r, CodeUnauthenticated,
			"the renewal challenge is missing, expired or was not issued by this hub; "+
				"fetch a fresh one from GET /renew/challenge")
		return
	}

	chain, ok := s.readChain(w, r, req.Chain)
	if !ok {
		return
	}
	identity, err := s.ca.VerifyChain(chain)
	if err != nil {
		s.metrics.Enrollment(ResultDenied)
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "renewal certificate refused",
			slog.String("remoteAddr", authn.SourceAddr(r)),
			slog.String("error", err.Error()))
		s.fail(w, r, CodeForbidden,
			"the presented certificate is not a spoke identity issued by this hub")
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
		s.fail(w, r, CodeForbidden, "the presented certificate has been revoked")
		return
	}

	// The cluster ID passed here is the one derived from the certificate in
	// step 2, never one the caller supplied: the transcript is what binds the
	// proof to an identity, so verifying it against a claimed value would make
	// the binding decorative.
	if err := certproof.Verify(chain[0], req.Signature, req.Nonce,
		certproof.RenewProtocolVersion, identity.ClusterID); err != nil {
		s.metrics.Enrollment(ResultDenied)
		s.security(r, EventRenewalUnproven,
			slog.String("cluster", identity.ClusterID),
			slog.String("serial", identity.CertSerial))
		s.fail(w, r, CodeForbidden,
			"the signature does not prove possession of the private key for the presented certificate")
		return
	}

	csrDER, ok := s.decodeCSRField(w, r, req.CSR)
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

// readChain parses the DER certificates a renewal presented, leaf first.
//
// An absent chain is an authentication failure rather than a malformed request:
// the caller offered no credential at all. An unparseable one is a malformed
// request, because something was offered and it was not a certificate.
func (s *server) readChain(w http.ResponseWriter, r *http.Request, der [][]byte) ([]*x509.Certificate, bool) {
	if len(der) == 0 {
		s.metrics.Enrollment(ResultDenied)
		s.fail(w, r, CodeUnauthenticated,
			"chain is required: the spoke's current certificate, DER encoded, leaf first")
		return nil, false
	}
	if len(der) > MaxChainCerts {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, fmt.Sprintf("chain carries more than %d certificates", MaxChainCerts))
		return nil, false
	}
	chain := make([]*x509.Certificate, 0, len(der))
	for i, b := range der {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			s.metrics.Enrollment(ResultInvalid)
			s.fail(w, r, CodeInvalidRequest,
				fmt.Sprintf("chain entry %d is not a parseable DER certificate", i))
			return nil, false
		}
		chain = append(chain, cert)
	}
	return chain, true
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

// readCSR decodes the body of POST /enroll down to its certificate signing
// request.
func (s *server) readCSR(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	var req EnrollRequest
	if !s.readBody(w, r, &req) {
		s.metrics.Enrollment(ResultInvalid)
		return nil, false
	}
	return s.decodeCSRField(w, r, req.CSR)
}

// decodeCSRField bounds and decodes one base64 DER certificate signing request.
//
// It is shared by /enroll and /renew so that the two routes cannot disagree
// about what a CSR field may contain. On /renew it runs only after the caller
// has proved possession, so an unauthenticated peer never reaches the decoder.
func (s *server) decodeCSRField(w http.ResponseWriter, r *http.Request, csr string) ([]byte, bool) {
	if csr == "" {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, "csr is required: a base64 DER certificate signing request")
		return nil, false
	}
	if len(csr) > MaxCSRBytes {
		s.metrics.Enrollment(ResultInvalid)
		s.fail(w, r, CodeInvalidRequest, fmt.Sprintf("csr exceeds %d base64 characters", MaxCSRBytes))
		return nil, false
	}
	der, err := decodeCSR(csr)
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
