# 0003. MCP over stateless Streamable HTTP

* Status: Accepted
* Date: 2026-08-29

## Context

The hub is a Model Context Protocol server. MCP offers stdio and HTTP
transports, and the HTTP transport has changed shape across revisions.

Two facts about the current specification (revision `2026-07-28`) drive this
decision:

* **Protocol sessions are gone.** `Mcp-Session-Id` existed from `2025-03-26`
  through `2025-11-25` and was removed. So were the long-lived GET stream,
  `Last-Event-ID` resumability and DELETE. There is one endpoint, POST only,
  and cancellation is the client closing the stream.
* **Authorization is optional**, and where implemented it describes an OAuth 2.1
  resource server with RFC 9728 protected-resource metadata and RFC 8707
  audience binding.

The second is awkward for us. The product requirement is "an API key can be
generated for access" — an operator mints `pmf_agt_…` and pastes it into an
agent's configuration. That is not OAuth, and pretending otherwise would be
worse than being straightforward about it.

## Decision

Serve MCP over **Streamable HTTP at `POST /mcp`, in stateless mode**, using the
official Go SDK (`github.com/modelcontextprotocol/go-sdk`, pinned to v1.7.0)
behind a thin internal adapter so an SDK API change is a one-file edit.

Authentication is a **static bearer API key** verified by our own middleware. On
a 401 we still emit a specification-shaped
`WWW-Authenticate: Bearer realm=…, scope=…` challenge, and we still serve an
RFC 9728 document at `/.well-known/oauth-protected-resource/mcp` advertising
`authorization_servers: []` plus an `x-pmf-auth: ["static-bearer"]` extension.
A compliant client gets a coherent, machine-readable failure; a simple client
just sets a header.

Because the specification removed sessions, we build nothing that would have
needed one. All state is keyed by *cluster*, not by connection.

## Consequences

**Better.** The hub is horizontally scalable behind an ordinary L7 load
balancer with no sticky routing, which composes cleanly with
[ADR-0005](0005-no-database-state-in-secrets.md): credentials are shared through
a Secret, so any replica can serve any agent request. Setting up an agent is one
header, which is what an operator actually wants.

**Worse.** We are not an OAuth resource server, so a host that insists on the
full authorization flow will not work out of the box. We say so in the metadata
document rather than emitting something that looks like OAuth and is not — a
half-implemented authorization server is a security liability, not a feature.
A real OAuth mode remains a clean future addition behind the same `Principal`
abstraction.

**A pinned pre-release-shaped dependency.** The SDK is v1.x, so Go's module
compatibility rules apply, but the project publishes no separate written
stability guarantee. We pin exactly and wrap it.

**Sessions may come back.** If a future revision reintroduces them, the stateless
choice is still valid — but any feature we might have hung off a session would
need rethinking. We have deliberately built none.

## Alternatives considered

* **Stateful Streamable HTTP with `Mcp-Session-Id`.** Rejected: removed from
  the current specification, and it would force sticky load balancing for no
  gain.
* **The older HTTP+SSE transport.** Rejected: superseded, and its long-lived GET
  stream is exactly the thing that makes horizontal scaling awkward.
* **stdio only.** Rejected as the primary transport — the hub is a shared,
  network-reachable service — but stdio remains useful for local development and
  is cheap to add.
* **Implementing full OAuth 2.1.** Rejected for the first release: it requires an
  authorization server we do not have and do not want to become, to solve a
  problem an operator-minted key already solves.
