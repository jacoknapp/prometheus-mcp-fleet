// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package mcpsurface is the project's only contact point with the Model
// Context Protocol Go SDK.
//
// # Why the indirection exists
//
// github.com/modelcontextprotocol/go-sdk is a v1 module, so Go's module
// compatibility rules apply, but the project publishes no written stability
// guarantee beyond that and the protocol it implements is itself moving —
// revision 2026-07-28 removed protocol sessions, the resumable GET stream and
// the initialize handshake outright. Every SDK type is therefore confined to
// this package. A tool implementation in internal/mcptools names
// [Tool], [Request] and [Result]; it never imports mcp, auth or jsonrpc. When
// the SDK changes shape, this is the file that changes.
//
// # What it configures, and why
//
//   - Streamable HTTP, stateless. Protocol revision 2026-07-28 removed
//     sessions, so there is no Mcp-Session-Id to mint, honour or echo, and the
//     hub scales horizontally behind a plain layer-7 load balancer. See
//     docs/adr/0003-mcp-streamable-http-stateless.md.
//   - A request body cap, because the MCP endpoint is reachable by anything
//     that can present a bearer token.
//   - Cross-origin protection, because the spec requires Origin validation and
//     an MCP endpoint reachable from a browser is a CSRF target.
//   - Bearer authentication in front of the handler. An authentication failure
//     is an HTTP status and a WWW-Authenticate challenge, never a tool result:
//     a model that receives a 401 as tool output will try to fix it by
//     rewriting its PromQL.
//
// # Authorization split
//
// This package authenticates. It does not authorize. The verified
// [fleet.Principal] is attached to every request and read back by a tool
// through [PrincipalOf]; deciding what that principal may call is
// internal/mcptools' job, and deciding which clusters it may reach is
// internal/promproxy's. Those two checks are deliberately independent.
//
// # Importers and concurrency
//
// Layer L2. internal/mcptools registers against it and the hub's composition
// root mounts it. A [Server] must be fully populated before it is served;
// after that every method on it, and the handler it returns, is safe for
// concurrent use.
package mcpsurface
