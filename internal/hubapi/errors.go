// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Sentinel errors this package matches store failures against by default. A
// store that uses different sentinels is pointed at them through
// [Options.IsNotFound] and [Options.IsConflict] rather than by importing its
// package here.
var (
	// ErrNotFound reports that no record exists under the given identifier.
	ErrNotFound = errors.New("hubapi: not found")
	// ErrAlreadyExists reports a create whose identifier is already taken.
	ErrAlreadyExists = errors.New("hubapi: already exists")
	// ErrEnrollmentUsed reports a second redemption of a single-use
	// enrollment token. It is a security event, not a retryable condition.
	ErrEnrollmentUsed = errors.New("hubapi: enrollment token already used")
)

// Error codes carried in the JSON envelope. They are stable machine strings: a
// client may branch on them, so they are part of the API.
const (
	// CodeInvalidRequest is a malformed or semantically invalid body,
	// parameter or path segment.
	CodeInvalidRequest = "invalid_request"
	// CodeNotFound is a request for a record that does not exist.
	CodeNotFound = "not_found"
	// CodeConflict is a create or burn that lost a race, including a replayed
	// enrollment token.
	CodeConflict = "conflict"
	// CodeForbidden is an authenticated caller that may not perform the
	// action.
	CodeForbidden = "forbidden"
	// CodeUnauthenticated is a missing or invalid credential.
	CodeUnauthenticated = "unauthenticated"
	// CodeUnavailable is a route closed because the process is draining or
	// enrollment is disabled.
	CodeUnavailable = "unavailable"
	// CodePayloadTooLarge is a body above [MaxBodyBytes].
	CodePayloadTooLarge = "payload_too_large"
	// CodeInternal is a failure of the hub itself. Its message is always
	// generic: the underlying error goes to the log, never to the client.
	CodeInternal = "internal"
)

// Enrollment results reported to [Metrics.Enrollment]. Closed set.
const (
	// ResultIssued is a certificate successfully issued.
	ResultIssued = "issued"
	// ResultReplay is a second redemption of an enrollment token.
	ResultReplay = "replay"
	// ResultDenied is a request refused before issuance: disabled, draining,
	// unauthenticated, a challenge that does not verify, an untrusted or
	// revoked certificate, or a proof of possession that does not check out.
	ResultDenied = "denied"
	// ResultInvalid is a malformed CSR or request body.
	ResultInvalid = "invalid"
	// ResultError is a failure of the hub or its store.
	ResultError = "error"
)

// Security event names reported to [Metrics.SecurityEvent] and used as the
// "event" field of the security log line. Closed set.
const (
	// EventKeyMinted is a new agent or admin credential.
	EventKeyMinted = "key.minted"
	// EventKeyRevoked is a credential revocation.
	EventKeyRevoked = "key.revoked"
	// EventKeyDeleted is a credential purge, which destroys its audit trail.
	EventKeyDeleted = "key.deleted"
	// EventKeyRotated is a rotation: one mint plus one revocation.
	EventKeyRotated = "key.rotated"
	// EventEnrollmentMinted is a new single-use enrollment token.
	EventEnrollmentMinted = "enrollment.minted"
	// EventEnrollmentBurned is a successful, single redemption.
	EventEnrollmentBurned = "enrollment.burned"
	// EventEnrollmentReplay is a second redemption attempt. It means the
	// install secret leaked, or a spoke is retrying a request it must not.
	EventEnrollmentReplay = "enrollment.replay"
	// EventCertIssued is a spoke certificate leaving the hub.
	EventCertIssued = "cert.issued"
	// EventCertRevoked is a certificate revocation.
	EventCertRevoked = "cert.revoked"
	// EventSessionRevoked is one or more live spoke tunnels torn down because
	// the certificate that admitted them was revoked. It is recorded
	// separately from EventCertRevoked because the two are different facts:
	// the revocation is a change to a list, this is the connection it
	// actually ended. A revocation of a serial that holds no live session
	// records only EventCertRevoked, so the presence of this event is the
	// evidence that a compromised spoke was disconnected rather than merely
	// listed.
	EventSessionRevoked = "session.revoked"
	// EventCertRenewed is a successful certificate renewal.
	EventCertRenewed = "cert.renewed"
	// EventRenewalUnproven is a renewal that presented a trusted, unrevoked
	// certificate but could not sign the challenge for it. It is a security
	// event rather than a plain refusal: the certificate is public, so this is
	// what somebody quoting one they do not hold the key for looks like.
	EventRenewalUnproven = "renewal.unproven"
	// EventCertRenewedExpired is a renewal accepted on a certificate that had
	// already expired, inside the configured grace period. It is recorded
	// separately from EventCertRenewed because it means a spoke was gone for
	// more than half a certificate lifetime, which is worth noticing whether it
	// was a long outage or somebody replaying an old identity -- the possession
	// proof still had to pass, but the certificate itself no longer vouches for
	// currency.
	EventCertRenewedExpired = "cert.renewed.expired"
)

// ErrorEnvelope is the single error shape every route in this package returns.
// Having exactly one shape is what lets a client write one error path.
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the payload of an [ErrorEnvelope].
type ErrorBody struct {
	// Code is a stable machine string from the Code constants.
	Code string `json:"code"`
	// Message is human-readable and safe to display. It never contains a
	// credential, a digest, a private key or an internal error string.
	Message string `json:"message"`
	// RequestID correlates the response with the hub's own log line.
	RequestID string `json:"requestId,omitempty"`
}

// httpStatus maps an error code to its HTTP status.
func httpStatus(code string) int {
	switch code {
	case CodeInvalidRequest:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict:
		return http.StatusConflict
	case CodeForbidden:
		return http.StatusForbidden
	case CodeUnauthenticated:
		return http.StatusUnauthorized
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// fail writes the JSON error envelope for code with the given message.
//
// message is authored by this package, never by the caller and never by an
// underlying error: an internal failure is logged in full and reported
// generically, so a store error string cannot become a channel for leaking
// paths, hostnames or record contents.
func (s *server) fail(w http.ResponseWriter, r *http.Request, code, message string) {
	status := httpStatus(code)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{Error: ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: requestID(w, r),
	}})
}

// failInternal logs err and answers with a generic 500.
func (s *server) failInternal(w http.ResponseWriter, r *http.Request, op string, err error) {
	s.log.LogAttrs(r.Context(), slog.LevelError, "admin api failure",
		slog.String("op", op),
		slog.String("path", r.URL.Path),
		slog.String("error", err.Error()))
	s.fail(w, r, CodeInternal, "the hub could not complete the request")
}

// requestID returns the correlation id stamped on the response by the
// request-id middleware, falling back to one the client supplied.
func requestID(w http.ResponseWriter, r *http.Request) string {
	if id := w.Header().Get(authnRequestIDHeader); id != "" {
		return id
	}
	return r.Header.Get(authnRequestIDHeader)
}
