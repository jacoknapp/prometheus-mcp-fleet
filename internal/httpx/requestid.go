// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// HeaderRequestID is the canonical header carrying the request identifier,
// both inbound and on every response.
const HeaderRequestID = "X-Request-Id"

// maxRequestIDLen is the longest inbound identifier that will be echoed. Long
// enough for a 128-bit hex or a UUID from an upstream proxy, short enough that
// it cannot be used to pad a log line or a response header.
const maxRequestIDLen = 64

// requestIDBytes is the entropy of a generated identifier, hex-encoded to 32
// characters. 128 bits makes a collision within a fleet's retention window
// impossible in practice.
const requestIDBytes = 16

// ctxKey is this package's private context key type. A distinct unexported
// type means no other package can collide with or forge these values.
type ctxKey int

// requestIDKey is the context key under which the request identifier is
// stored.
const requestIDKey ctxKey = iota

// RequestID assigns every request an identifier, stores it in the request
// context and sets it on the response.
//
// An inbound X-Request-Id is honoured only when it is safe to echo: at most 64
// characters drawn from [A-Za-z0-9_-]. Anything else -- a CRLF sequence, a
// control character, HTML, or an over-long value -- is discarded and replaced
// with a freshly generated identifier, because the value is reflected into a
// response header and into log output, and neither is a safe place for
// attacker-chosen bytes.
//
// Generated identifiers are 16 bytes of crypto/rand output, hex-encoded.
//
// Retrieve the identifier with [RequestIDFrom].
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// RequestIDFrom returns the request identifier carried by ctx, or "" when the
// context did not pass through [RequestID].
func RequestIDFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// validRequestID reports whether id is safe to echo into a response header and
// a log line.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// newRequestID returns a fresh hex-encoded identifier. crypto/rand.Read is
// documented never to fail, so there is no error path to handle here.
func newRequestID() string {
	var b [requestIDBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
