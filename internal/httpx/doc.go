// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package httpx is the shared HTTP plumbing: request-scoped identifiers, the
// middleware chain (request id, panic recovery, access logging, security
// headers, body limits), a JSON response writer and a gracefully shutting-down
// server.
//
// It sits at L1 alongside internal/obs. Anything at L1 or above may import it;
// it imports only the standard library, so the domain and configuration layers
// stay free of transport concerns.
//
// # Privacy
//
// This package is on the path of every request the hub serves, which makes it
// the single most likely place for a credential or a customer identifier to
// escape into a log aggregator. Two rules are therefore structural rather than
// advisory:
//
//   - [AccessLog] emits a fixed set of fields. It never logs a header value,
//     a request body, or a query string. A PromQL expression carrying a
//     customer name lives in the query string, so logging it would leak
//     tenant data on every single call.
//   - [Recover] reports the panic value and stack to the logger only. The
//     client receives a generic 500 with no stack frame, no internal path and
//     no panic text.
//
// # Concurrency
//
// The middleware constructors return handlers that are safe for concurrent
// use. [Server] is safe for concurrent use; in particular [Server.Shutdown]
// may be called from a signal handler while [Server.Wait] blocks elsewhere,
// and may be called more than once or before [Server.Start].
package httpx
