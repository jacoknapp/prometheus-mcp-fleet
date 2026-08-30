// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import "errors"

// Sentinel errors returned by [Verifier.Verify]. Callers branch with
// errors.Is. None of them ever embeds any part of the presented credential:
// an error from this package is safe to log verbatim.
var (
	// ErrUnauthenticated reports that no usable credential was presented. It
	// deliberately covers a malformed token, an unknown key identifier and a
	// wrong secret alike, because distinguishing those to the caller would
	// turn the error into an oracle for which key identifiers exist.
	ErrUnauthenticated = errors.New("authn: unauthenticated")

	// ErrWrongClass reports a credential that is genuine but belongs to a
	// different class than the listener requires, for example an agent key
	// presented to the admin API. It is separate from ErrUnauthenticated so
	// that an operator debugging a misconfigured client sees the real cause in
	// the hub's log; the HTTP layer still answers 401 either way.
	ErrWrongClass = errors.New("authn: wrong credential class")

	// ErrExpired reports a credential whose ExpiresAt has passed.
	ErrExpired = errors.New("authn: credential expired")

	// ErrRevoked reports a credential that has been revoked.
	ErrRevoked = errors.New("authn: credential revoked")

	// ErrRateLimited reports that the source address has produced too many
	// authentication failures recently and is in backoff. It exists so the
	// HTTP layer can answer 429 rather than 401, which tells a
	// well-behaved client to slow down instead of retrying immediately.
	ErrRateLimited = errors.New("authn: too many authentication failures")

	// ErrKeyNotFound is the error a [KeyStore] is expected to return, or to
	// wrap, when no record exists for a key identifier. It is declared here
	// rather than imported from the store so that this package does not depend
	// on a particular persistence implementation; see [Options.IsNotFound] for
	// how to point the verifier at a different sentinel.
	ErrKeyNotFound = errors.New("authn: key not found")
)

// Failure reasons reported to [Metrics.AuthFailure]. The set is closed: it is
// used as a Prometheus label value and must never grow with caller input.
const (
	// ReasonMalformed is a token that failed [token.Parse].
	ReasonMalformed = "malformed"
	// ReasonMissing is a request with no bearer credential at all.
	ReasonMissing = "missing"
	// ReasonUnknownKey is a key identifier with no stored record.
	ReasonUnknownKey = "unknown_key"
	// ReasonBadSecret is a known key identifier with the wrong secret.
	ReasonBadSecret = "bad_secret"
	// ReasonWrongClass is a credential of the wrong class for the listener.
	ReasonWrongClass = "wrong_class"
	// ReasonExpired is a credential past its expiry.
	ReasonExpired = "expired"
	// ReasonRevoked is a revoked credential.
	ReasonRevoked = "revoked"
	// ReasonRateLimited is a source address in failure backoff.
	ReasonRateLimited = "rate_limited"
	// ReasonStoreError is a store that could not be consulted. The request is
	// denied: the verifier never serves a stale decision.
	ReasonStoreError = "store_error"
)
