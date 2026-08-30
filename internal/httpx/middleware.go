// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Middleware is a handler decorator. [Chain] composes them.
type Middleware = func(http.Handler) http.Handler

// CodeRequestTooLarge is the machine code returned when a request body exceeds
// the limit installed by [MaxBody].
const CodeRequestTooLarge = "request_too_large"

// contentSecurityPolicy denies everything. These listeners serve JSON and an
// SSE stream to programmatic clients; nothing here is a document, so no source
// of any kind needs to be allowed. A blanket denial also neutralises a
// reflected payload should a future handler ever echo input into HTML.
const contentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"

// hstsValue is one year with subdomains, sent only over TLS.
const hstsValue = "max-age=31536000; includeSubDomains"

// Chain wraps h with mw, applying them so that mw[0] is the outermost handler
// and therefore sees the request first and the response last.
//
//	httpx.Chain(mux,
//	    httpx.RequestID,               // outermost: everything below can log the id
//	    httpx.Recover(logger, onPanic),
//	    httpx.AccessLog(logger),
//	    httpx.SecurityHeaders,
//	)
//
// A nil entry in mw is skipped, which keeps a conditionally-enabled middleware
// from needing a slice built by hand. A nil h becomes http.NotFoundHandler.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	if h == nil {
		h = http.NotFoundHandler()
	}
	for i := len(mw) - 1; i >= 0; i-- {
		if mw[i] == nil {
			continue
		}
		h = mw[i](h)
	}
	return h
}

// Recover turns a panic in a downstream handler into a 500 instead of a dead
// connection and a crashed process.
//
// The panic value and stack go to logger at error level. The client gets a
// generic JSON error: no panic text, no stack frame, no internal path. Panic
// values routinely contain a database DSN, a file path or a credential, so
// forwarding one to the caller is a disclosure bug, not a debugging aid.
//
// onPanic, when non-nil, is invoked once per recovered panic. Wire it to a
// counter so panics are alertable rather than merely greppable.
//
// A panic that happens *after* the handler has already written the response
// head cannot be answered with a 500 -- the status is spent and the client is
// mid-body, so writing an error object there would splice invalid JSON onto a
// truncated payload. In that case recovery re-panics with http.ErrAbortHandler,
// which makes net/http drop the connection; the client then sees a truncated
// response, which is the honest signal that something went wrong.
//
// http.ErrAbortHandler is passed straight through, since it is a deliberate
// abort rather than a bug.
//
// A nil logger uses slog.Default.
func Recover(logger *slog.Logger, onPanic func()) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := wrapResponseWriter(w)
			//nolint:contextcheck // the closure logs with r.Context(); contextcheck cannot see through a deferred func literal inside an http.HandlerFunc.
			defer func() {
				rv := recover()
				if rv == nil {
					return
				}
				if err, ok := rv.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rv) //nolint:forbidigo // deliberate abort, not a bug: net/http handles it.
				}
				if onPanic != nil {
					onPanic()
				}
				logger.LogAttrs(r.Context(), slog.LevelError, "panic recovered",
					slog.Any("panic", rv),
					slog.String("method", r.Method),
					slog.String("path", pathOf(r)),
					slog.String("request_id", RequestIDFrom(r.Context())),
					slog.String("stack", string(debug.Stack())),
				)
				if wroteResponse(rw) {
					// The head is already on the wire. Abort rather than
					// corrupt what the client has.
					panic(http.ErrAbortHandler) //nolint:forbidigo // see the doc comment.
				}
				WriteError(rw, r, http.StatusInternalServerError, CodeInternal, "internal error")
			}()
			next.ServeHTTP(rw, r)
		})
	}
}

// wroteResponse reports whether the response head has already been sent.
func wroteResponse(w http.ResponseWriter) bool {
	rs, ok := w.(responseState)
	return ok && rs.Wrote()
}

// AccessLog emits exactly one line per request.
//
// The level follows the status class: debug for 2xx and 3xx, warn for 4xx and
// error for 5xx. Successful traffic is therefore free at the default level
// while every failure is visible.
//
// The fields are method, path, status, bytes, duration_ms, request_id and
// remote_addr, and that list is closed. In particular this middleware never
// logs a header value (an Authorization header is a bearer token in
// cleartext), a request body, or a query string: on this service the query
// string carries the PromQL expression, and a PromQL expression routinely
// contains a customer or tenant identifier. Sending that to a log aggregator
// would turn every query into a privacy incident.
//
// path is the route pattern when the middleware is mounted per-route and
// http.ServeMux has already matched, and the request path otherwise. Either
// way it excludes the query string.
//
// A nil logger uses slog.Default.
func AccessLog(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := wrapResponseWriter(w)
			start := time.Now()
			//nolint:contextcheck // the closure logs with r.Context(); contextcheck cannot see through a deferred func literal inside an http.HandlerFunc.
			defer func() {
				elapsed := time.Since(start)
				logger.LogAttrs(r.Context(), levelForStatus(rw.Status()), "http request",
					slog.String("method", r.Method),
					slog.String("path", pathOf(r)),
					slog.Int("status", rw.Status()),
					slog.Int64("bytes", rw.BytesWritten()),
					slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000.0),
					slog.String("request_id", RequestIDFrom(r.Context())),
					slog.String("remote_addr", r.RemoteAddr),
				)
			}()
			next.ServeHTTP(rw, r)
		})
	}
}

// levelForStatus maps a status code to the level its line is logged at.
func levelForStatus(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelDebug
	}
}

// pathOf returns the route pattern when one has been matched and the escaped
// request path otherwise. It never includes the query string.
func pathOf(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	if r.URL == nil {
		return ""
	}
	return r.URL.EscapedPath()
}

// SecurityHeaders sets the response headers that harden a JSON API against
// being misinterpreted by a browser.
//
// Always: X-Content-Type-Options, Referrer-Policy, X-Frame-Options,
// Cache-Control and a Content-Security-Policy that permits nothing.
//
// Strict-Transport-Security is set only when the request arrived over TLS.
// HSTS delivered over plaintext is ignored by every conforming client, and
// emitting it from a local development server on http://localhost pins the
// developer's browser to HTTPS for a host that has no certificate -- an
// actively hostile default. The TLS-terminating proxy in front of the hub is
// the correct place to add HSTS for plaintext hops.
//
// Headers are set before the handler runs so they are present even on a
// response the handler streams or aborts.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBody caps the number of bytes a handler can read from a request body.
//
// A declared Content-Length above the cap is rejected up front with 413 so an
// oversized upload is refused before it is read. A body that lies about its
// length is caught by http.MaxBytesReader, which makes the handler's Read
// return an error at the cap; handlers must therefore still check their decode
// error rather than assume a truncated body is valid.
//
// n <= 0 disables the limit and the middleware becomes a pass-through.
func MaxBody(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		if n <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				WriteError(w, r, http.StatusRequestEntityTooLarge, CodeRequestTooLarge, "request body too large")
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
