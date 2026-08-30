// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Sentinel errors. Every error this package returns is wrapped with the
// request it came from, so callers must match with errors.Is.
var (
	// ErrNotFound reports that the named object does not exist (HTTP 404).
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists reports a create whose name is already taken
	// (HTTP 409 with reason AlreadyExists).
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict reports that the object changed since the caller read it
	// (HTTP 409 with reason Conflict). It is the compare-and-swap failure of
	// [Client.UpdateSecret] and is the one error here that is expected in
	// normal operation: the caller re-reads and retries.
	ErrConflict = errors.New("resource version conflict")
	// ErrForbidden reports that the service account lacks the RBAC rule for
	// the request (HTTP 403). It is by far the most common misconfiguration,
	// so [APIError.Error] names the missing rule verbatim.
	ErrForbidden = errors.New("forbidden")
	// ErrUnauthorized reports a rejected or absent bearer token (HTTP 401).
	// Persisting past a token rotation would produce this, which is why the
	// token file is re-read rather than cached for the process lifetime.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrNotInCluster reports that the projected service account files or the
	// KUBERNETES_SERVICE_HOST/PORT environment are absent, so the process is
	// not running inside a cluster. Callers treat it as "fall back to the
	// file backend", not as a failure.
	ErrNotInCluster = errors.New("not running in a kubernetes cluster")
	// ErrResponseTooLarge reports an API server response above
	// [MaxResponseBytes]. A Secret caps at 1 MiB, so anything near the bound
	// is a wrong endpoint or a hostile proxy, not a legitimate object.
	ErrResponseTooLarge = errors.New("response too large")
)

// APIError is a non-2xx response from the API server, decoded from the
// metav1.Status document the API server returns. Callers normally match the
// sentinel it unwraps to; the struct is exported for the rare caller that
// wants the API server's own reason string.
type APIError struct {
	// Verb is the operation that failed, e.g. "get secret".
	Verb string
	// Status is the HTTP status code.
	Status int
	// Reason is the API server's machine reason, e.g. "AlreadyExists".
	Reason string
	// Message is the API server's human message. It is the field that says
	// which RBAC rule was missing, so it is preserved verbatim.
	Message string
	// Namespace is the namespace the request was made against, used to name
	// the missing RBAC rule.
	Namespace string
}

// Error implements error. For a 403 it appends the exact Role rule the
// operator is missing, because a bare "403 Forbidden" from the Kubernetes API
// reliably costs an hour of guessing.
func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	s := fmt.Sprintf("kubernetes %s: %d %s", e.Verb, e.Status, msg)
	if e.Reason != "" {
		s += " (reason " + e.Reason + ")"
	}
	if e.Status == http.StatusForbidden {
		s += fmt.Sprintf("; the ServiceAccount needs %q -- "+
			`Role rule {apiGroups: [""], resources: ["secrets"], verbs: ["get","create","update"]} `+
			"plus a RoleBinding to it", rbacHint(e.Namespace))
	}
	return s
}

// Unwrap maps the HTTP status onto this package's sentinels.
func (e *APIError) Unwrap() error {
	switch e.Status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusConflict:
		// The API server distinguishes the two 409s by reason. Fall back to
		// the verb when the body is missing or unparseable, because a create
		// only ever conflicts on the name.
		switch {
		case e.Reason == reasonAlreadyExists:
			return ErrAlreadyExists
		case e.Reason == reasonConflict:
			return ErrConflict
		case e.Verb == verbCreateSecret:
			return ErrAlreadyExists
		default:
			return ErrConflict
		}
	default:
		return nil
	}
}

// rbacHint renders the RBAC rule the hub needs in the operator's own
// vocabulary.
func rbacHint(ns string) string {
	if ns == "" {
		ns = "<namespace>"
	}
	return "secrets get/create/update in namespace " + ns
}

// API server reason strings this package distinguishes.
const (
	reasonAlreadyExists = "AlreadyExists"
	reasonConflict      = "Conflict"
)

// wireStatus is the subset of metav1.Status this package reads.
type wireStatus struct {
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// statusError builds an [APIError] from a response body. A body that is not a
// metav1.Status -- an HTML error page from an intermediary, say -- is not an
// error in itself: the status code still carries the meaning, so the message
// falls back to the standard status text rather than echoing an unbounded and
// possibly attacker-influenced body into the logs.
func statusError(verb, ns string, code int, body []byte) *APIError {
	e := &APIError{Verb: verb, Status: code, Namespace: ns}
	var ws wireStatus
	if err := json.Unmarshal(body, &ws); err == nil {
		e.Message = ws.Message
		e.Reason = ws.Reason
	}
	return e
}
