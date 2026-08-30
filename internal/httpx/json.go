// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// ContentTypeJSON is the media type every JSON response carries. The explicit
// charset stops a browser from sniffing the body as something else.
const ContentTypeJSON = "application/json; charset=utf-8"

// CodeInternal is the machine-readable code used for an unexpected
// server-side failure, including a panic and a response that could not be
// encoded.
const CodeInternal = "internal_error"

// ErrorBody is the envelope of every error response this package writes.
type ErrorBody struct {
	// Error carries the machine code, the human message and the request id.
	Error ErrorDetail `json:"error"`
}

// ErrorDetail is the content of an [ErrorBody].
type ErrorDetail struct {
	// Code is a stable machine-readable identifier. Callers branch on this,
	// never on Message.
	Code string `json:"code"`
	// Message is a human-readable explanation. It never contains a stack
	// frame, an internal path or a secret.
	Message string `json:"message"`
	// RequestID correlates the response with the server's logs. It is omitted
	// when the request did not pass through [RequestID].
	RequestID string `json:"request_id,omitempty"`
}

// WriteJSON writes v as a JSON response with the given status.
//
// The value is encoded into a buffer before anything is sent, so an encoding
// failure produces a complete 500 error body rather than a 200 followed by
// half an object -- a truncated body is far harder for a caller to diagnose
// than an honest error. The request identifier from r's context, when present,
// is set on the response as X-Request-Id.
//
// r may be nil, in which case no request identifier is attached.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		// Nothing has been written yet, so replacing the response wholesale is
		// still possible.
		writeJSONBytes(w, r, http.StatusInternalServerError, errorJSON(requestIDOf(r), CodeInternal, "response could not be encoded"))
		return
	}
	writeJSONBytes(w, r, status, buf.Bytes())
}

// WriteError writes a JSON [ErrorBody] with the given status, machine code and
// human message.
//
// message is written verbatim, so callers must not build it from a panic
// value, an internal path or anything secret. The request identifier from r's
// context is included in the body and set on the response header.
//
// r may be nil.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSONBytes(w, r, status, errorJSON(requestIDOf(r), code, message))
}

// errorJSON renders an [ErrorBody]. The struct contains only strings, so
// encoding cannot fail; the error is discarded rather than ignored silently by
// falling back to a hand-written body.
func errorJSON(requestID, code, message string) []byte {
	body := ErrorBody{Error: ErrorDetail{Code: code, Message: message, RequestID: requestID}}
	b, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":{"code":"` + CodeInternal + `","message":"internal error"}}`)
	}
	return append(b, '\n')
}

// writeJSONBytes sends an already-encoded body with the JSON content type and
// the request identifier header.
func writeJSONBytes(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", ContentTypeJSON)
	h.Set("X-Content-Type-Options", "nosniff")
	if id := requestIDOf(r); id != "" && h.Get(HeaderRequestID) == "" {
		h.Set(HeaderRequestID, id)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// requestIDOf returns the identifier carried by r, tolerating a nil request.
func requestIDOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	return RequestIDFrom(r.Context())
}
