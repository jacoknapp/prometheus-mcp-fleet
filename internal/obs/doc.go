// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package obs is the observability layer: structured logging, Prometheus
// metrics, OpenTelemetry tracing, health endpoints, pprof and the redacting
// [Secret] type.
//
// It sits at L1. It may be imported by anything above L1 and imports only
// internal/version from this module, which keeps the domain and configuration
// layers free of metric and tracing dependencies.
//
// Everything here is safe for concurrent use once constructed. [InitTracing]
// mutates OpenTelemetry global state and is therefore intended to be called
// exactly once, from a composition root.
//
// Cardinality: the metric constructors expose only the label sets listed in
// the build specification. PromQL text, matchers, label values, request IDs,
// key identifiers and spoke addresses must never be passed as label values;
// cluster, endpoint, tool, code, result, reason and op are all closed or
// bounded sets.
package obs
