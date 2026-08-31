# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, minor releases may contain breaking changes. The
hub↔spoke wire protocol carries an explicit version and the hub supports the
previous spoke minor from the outset, because 100 clusters never upgrade in
lockstep.

## [Unreleased]

## [0.1.0] - 2026-08-29

Initial release.

### Added

- **Hub** — a Model Context Protocol server (Streamable HTTP, stateless) that
  gives AI agents Prometheus access across an entire fleet, an admin REST API
  for credential lifecycle, and a built-in CA that issues, renews and revokes
  spoke identities.
- **Spoke** — a small per-cluster agent that dials out to the hub, proxies the
  local Prometheus HTTP API through the tunnel, and publishes cluster facts so
  the hub can route and so an agent can discover what exists without querying.
- **WebSocket tunnel through a standard Ingress** — the spoke's tunnel is a
  WebSocket on the hub's ordinary MCP listener at `/tunnel`, so a plain
  `networking.k8s.io/v1` Ingress is the only exposure the hub needs: no TCP
  passthrough, no LoadBalancer, no NodePort, no second port. Because the
  Ingress terminates TLS and the hub therefore never sees a client
  certificate, the spoke proves possession of its key at the application layer
  — the hub issues a nonce and the spoke signs a length-prefixed transcript
  binding that nonce, the protocol version and its cluster ID. Identity still
  comes only from the certificate's URI SAN, and a spoke whose self-reported
  cluster ID disagrees with its certificate is refused rather than corrected.
  See [ADR-0014](docs/adr/0014-websocket-tunnel-through-standard-ingress.md).
- **In-band certificate renewal** — `POST /renew` authenticates with the same
  challenge-response construction as the tunnel handshake, sharing one
  implementation (`internal/certproof`), so renewal works behind the same
  Ingress that made mTLS impossible. The nonce is stateless — random, expiry
  and an HMAC under the hub's pepper — so any replica can verify a nonce any
  other issued. Renewal binds a distinct protocol version into the transcript
  from the tunnel handshake, so a signature harvested at one cannot be redeemed
  at the other.
- **No database** — the hub keeps its CA keypair, HMAC pepper and credential
  records in two Kubernetes Secrets it owns, and nothing else durable. The
  cluster registry is derived rather than stored: spokes re-publish their facts
  on every connect, so it rebuilds itself within one reconnect interval. There
  is no PersistentVolumeClaim, no StorageClass dependency and no backup
  procedure, and the hub is a plain Deployment.
  See [ADR-0005](docs/adr/0005-no-database-state-in-secrets.md).
- **Credential model** — three prefixed, checksummed bearer classes
  (`pmf_adm_`, `pmf_agt_`, `pmf_enr_`) stored as HMAC-SHA256 with an
  out-of-database pepper, plus X.509 spoke identities issued from the hub's CA
  against single-use enrollment tokens.
- **Scoped authorization** — per-key cluster selectors, tool allow/deny lists
  and cost limits, evaluated deny-by-default.
- **MCP tool surface** — cluster discovery, instant and range queries, series,
  labels, label values, metric metadata, scrape targets, rules, alerts,
  cardinality statistics, runtime information and cross-cluster fan-out, all
  with token-efficient columnar output and explicit truncation markers.
- **Helm charts** — `prometheus-mcp-hub` and `prometheus-mcp-spoke`, published
  as OCI artifacts, with an opt-in, digest-pinned, signature-verified and
  automatically staggered weekly auto-update CronJob.
- **Supply chain** — multi-architecture images, SLSA provenance, SBOMs, keyless
  cosign signatures, a weekly rebuild for base-image CVEs, and a
  human-approved promotion gate that is the fleet-wide kill switch.

[Unreleased]: https://github.com/jacoknapp/prometheus-mcp-fleet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jacoknapp/prometheus-mcp-fleet/releases/tag/v0.1.0
