// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package render turns Prometheus API responses into the token-efficient
// shapes an AI agent actually reads, and sanitises every untrusted string on
// the way through.
//
// # Why it exists
//
// Prometheus' native JSON repeats a full label set per series and a full
// timestamp per sample, and encodes every value as a string. A six-hour range
// query over 84 series at a 15-second scrape interval is roughly 4.6 MB, on
// the order of 1.4 million tokens: it does not fit in any context window that
// exists. See docs/adr/0012-token-efficient-tool-output.md.
//
// This package therefore owns four concerns:
//
//   - Columnar encoding. One start and one stepSeconds for the whole result;
//     each series carries a bare values array whose index implies the
//     timestamp. Labels shared by every series are factored into sharedLabels.
//   - Step selection. [SelectStep] picks a step that keeps the point count
//     bounded, snapped to a human-sensible ladder and never below the
//     cluster's reported scrape interval, and always reports what it did in a
//     [Downsampled].
//   - Truncation. Every reduction is reported in a [Truncation] carrying the
//     returned count, the true total, a machine-readable reason, a hint and,
//     for series truncation, the selection strategy. Nothing is ever dropped
//     silently.
//   - Sanitisation. Metric labels, help strings, alert annotations and scrape
//     errors are attacker-influenced: anyone who can expose a metrics endpoint
//     or write an alert rule in any monitored cluster can plant text there.
//     [Sanitize] and its clipping wrappers are a security control, not
//     cosmetics.
//
// # Importers and concurrency
//
// Layer L3, alongside internal/mcptools, which is its only intended importer.
// It performs no I/O, holds no mutable global state, and every exported
// function is safe for concurrent use.
package render
