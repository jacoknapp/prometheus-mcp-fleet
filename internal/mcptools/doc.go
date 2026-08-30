// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package mcptools implements the hub's sixteen MCP tools, its four resources
// and its five prompts.
//
// # What it is responsible for
//
// This is the layer an AI agent actually talks to. It turns tool arguments
// into allow-listed [promapi] calls through [promproxy], turns the responses
// into the token-efficient shapes in internal/render, and turns every failure
// into a machine-readable [ToolError] that names the next call to try.
//
// Three properties matter more than the rest:
//
//   - Two independent authorization checks. Every tool tests
//     principal.Scope.AllowsTool against its own name before it does anything
//     at all, and internal/promproxy independently re-tests the principal's
//     cluster scope on every upstream call. Neither check is ever the only
//     one, and a scope denial is a protocol error, never a tool result: a
//     model that reads "forbidden" as tool output will try to fix it by
//     rewriting its PromQL.
//   - Errors are prompts. A [ToolError] carries a stable machine Code, a human
//     Message, an echo of the offending Input, a Hint naming a concrete next
//     call, and Retryable. [CodeUnknownCluster] carries the five nearest
//     visible cluster names, [CodePromQLParse] carries Prometheus' own message
//     and a caret, and [CodeRangeTooLarge] carries a literal corrected
//     argument object.
//   - Remote data is hostile. Anyone who can expose a metrics endpoint or
//     write an alerting rule in any monitored cluster can plant text in a
//     label, a help string, an annotation or a scrape error. Everything that
//     came from a cluster passes through internal/render's sanitiser, is
//     carried only as a JSON value, and is preceded by exactly one
//     [render.UntrustedNotice] per result. Scrape URLs are redacted outright
//     because they routinely carry bearer tokens as query parameters.
//
// # Importers and concurrency
//
// Layer L3. Only the hub's composition root imports it. A [Tools] is safe for
// concurrent use once [New] returns; registration on a
// [mcpsurface.Server] must complete before that server is served.
package mcptools
