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
  for credential lifecycle, a built-in CA, and a tunnel listener terminating
  mutually authenticated connections from spokes.
- **Spoke** — a small per-cluster agent that dials out to the hub, proxies the
  local Prometheus HTTP API through the tunnel, and publishes cluster facts so
  the hub can route and so an agent can discover what exists without querying.
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
