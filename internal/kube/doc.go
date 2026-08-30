// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package kube is a minimal Kubernetes API client for the one resource this
// project persists to: a Secret.
//
// # Responsibility
//
// It owns the wire protocol -- URL shape, bearer token, TLS trust, response
// bounds and the mapping from an HTTP status to a Go sentinel -- and nothing
// else. It holds no application state, performs no retries and knows nothing
// about what the Secret contains. Retrying [ErrConflict] is the caller's job
// (see internal/store/secretstore) because only the caller knows how to
// recompute the value it wanted to write.
//
// It exists so that the hub does not depend on k8s.io/client-go, which would
// pull in several hundred transitive modules to issue three HTTP requests.
//
// # Optimistic concurrency
//
// [Client.UpdateSecret] sends metadata.resourceVersion and maps the API
// server's 409 to [ErrConflict]. That compare-and-swap is what makes a
// single-use enrollment token atomic across hub replicas: every replica
// read-modify-writes the same Secret, and exactly one write per resource
// version is accepted.
//
// # Tokens
//
// The projected service account token is rotated by the kubelet, typically
// hourly, so a token read once at startup begins returning 401 after an hour.
// Every request therefore takes its token from [tokenSource], which re-reads
// the file when a short TTL has elapsed and the file's mtime or size has
// changed. Reading the file on literally every request would be correct too,
// but it turns each API call into a syscall pair on the hot path for no
// benefit; a stat is cheaper and detects rotation just as reliably, because
// the kubelet replaces the file by rename.
//
// # Security
//
// The API server is verified against the projected CA bundle. The string
// InsecureSkipVerify does not appear in this package and must not be added:
// an unverified API server connection is a credential-exfiltration channel,
// since every request carries the service account bearer token. Response
// bodies are bounded at [MaxResponseBytes]. Secret names are validated before
// they reach a URL path, so a caller cannot traverse out of the namespace.
//
// # Importers and concurrency
//
// Layer L1. May be imported by internal/store/secretstore, the spoke's
// identity persistence and the composition roots. It imports only the
// standard library. A [Client] is immutable after construction and safe for
// concurrent use by multiple goroutines.
package kube
