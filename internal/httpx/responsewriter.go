// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"bufio"
	"net"
	"net/http"
)

// responseWriter records the status code and byte count of a response so
// [AccessLog] can report them and [Recover] can tell whether the response has
// already begun.
//
// It deliberately implements http.Flusher and http.Hijacker. The MCP endpoint
// streams Server-Sent Events, and a handler that streams asks for a flusher
// with a type assertion; a wrapper that does not satisfy http.Flusher silently
// turns a live stream into a buffered one that only appears when the handler
// returns. That failure is invisible in tests that read the whole body, which
// is why it survives in most hand-rolled versions of this type. Unwrap is
// implemented as well so http.ResponseController keeps working through the
// chain.
type responseWriter struct {
	http.ResponseWriter

	status      int
	written     int64
	wroteHeader bool
}

// wrapResponseWriter returns w as a *responseWriter, reusing an existing
// wrapper rather than nesting a second one so that status and byte counts are
// recorded exactly once no matter how many middlewares ask for them.
func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	if rw, ok := w.(*responseWriter); ok {
		return rw
	}
	return &responseWriter{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader records the status and forwards it. Repeat calls are ignored,
// matching net/http, so a middleware cannot be tricked into reporting a status
// the client never saw.
func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

// Write records the byte count and forwards the write, implying a 200 the
// first time it is called without an explicit status.
func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush implements http.Flusher so streaming survives the middleware chain. It
// implies a 200 the same way Write does, and is a no-op when nothing beneath
// the wrapper can flush.
func (w *responseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	// ResponseController walks the Unwrap chain, so this reaches the real
	// writer however deeply it is wrapped.
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack implements http.Hijacker, delegating to the underlying writer. A
// hijacked connection is no longer the server's to write to, so the recorded
// byte count stops here by design.
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// Unwrap returns the wrapped writer for http.ResponseController.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Status returns the status code sent to the client, defaulting to 200 when
// the handler wrote a body without setting one.
func (w *responseWriter) Status() int { return w.status }

// BytesWritten returns how many body bytes reached the client.
func (w *responseWriter) BytesWritten() int64 { return w.written }

// Wrote reports whether the response head has already been sent, at which
// point no middleware may change the status or replace the body.
func (w *responseWriter) Wrote() bool { return w.wroteHeader }

// responseState is the part of *responseWriter that [Recover] needs. Taking it
// as an anonymous interface means recovery works whether or not an outer
// middleware already installed the wrapper.
type responseState interface {
	Wrote() bool
}
