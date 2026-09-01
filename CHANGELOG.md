# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, minor releases may contain breaking changes. The
hub↔spoke wire protocol carries an explicit version and the hub supports the
previous spoke minor from the outset, because 100 clusters never upgrade in
lockstep.

## [Unreleased]

## [0.9.0] - 2026-09-01

### Added

- **The admin operations are subcommands.** `hub keys list`, `keys revoke`,
  `keys rotate`, `enroll list`, `enroll revoke`, `certs revoke` and
  `certs list` join the existing creates. Every admin route now has a command
  except `GET /admin/v1/ca`, which needs no credential — `curl` against the
  public `/pki/bundle` is shorter than a command would be.

  This closes a gap the no-expiry work opened: `docs/security.md` says expiry
  is not among the controls on a leaked agent key and "revocation is the
  control that has to work", yet revoking was the one operation with no
  tooling — a port-forward and a hand-assembled request, at whatever hour it
  was needed. Minting, the safe operation, had a command; withdrawing did not.

  Listings carry a STATUS column — live, expired, revoked — because that is
  the one thing that decides whether a credential still works, and a key
  minted with no expiry reads `never` rather than a zero year. Revoking is
  the default; `--purge` is an explicit flag, since deletion destroys the
  audit trail.

### Fixed

- `cmd/hub` routed CLI nouns by matching `enroll` or `keys` literally, so
  `hub certs revoke` fell through to the server's flag parser and answered a
  revocation request with the server's usage text. Found by running the
  commands against a real hub rather than only against fakes.
- The quickstart could not actually mint a key: steps 4 and 5 read an admin
  token from a file that the chart only mounts when `adminToken.existingSecret`
  is set, and no earlier step set it. Four smaller doc corrections alongside,
  including README's credential table still claiming a 30-day agent key.
- `make lint` now installs the linter CI uses instead of trusting PATH. An
  older golangci-lint does not report findings against a newer module — it
  panics inside the type checker — which is how a batch of gosec, errcheck,
  revive and staticcheck findings reached main while local checks looked
  clean.

## [0.8.2] - 2026-09-01

### Fixed

- **A data race in the tunnel listener.** It claimed a session slot under its
  mutex and counted the servicing goroutine separately, after that lock was
  released. In between, `Shutdown` could mark the listener closed and enter
  `wg.Wait`, so the accept loop took the WaitGroup from zero to one while a
  wait was already running -- concurrent `Add` and `Wait`, which Go's contract
  forbids. The hub runs exactly that shape (`Serve` in a run group, `Shutdown`
  on context cancel), so it was reachable in production. The closed check, the
  slot claim and the `Add` are now one critical section.
- State pruning is jittered by ±20%, so replicas started together do not wake
  in lockstep every interval. Multi-replica pruning needs no leader and is now
  covered by a test that drives four replicas at one Secret simultaneously.
- An unchecked `uint64`→`int` conversion on the session round-robin counter,
  which goes negative when the counter wraps, and an unchecked `int`→`int32`
  on the operator-supplied node count, which reported a negative node count
  rather than saturating.
- Import grouping across ten files, which had been failing the lint gate and
  masking every other finding in that job behind it.

## [0.8.1] - 2026-09-01

### Added

- The hub prunes its own state document. Every replica sweeps on
  `--state-prune-interval` (6h), dropping expired credentials and revocations
  for certificates that have expired anyway, each retained
  `--state-retention` (30d) past the moment it stopped mattering. A credential
  with no expiry is never dropped, revoked or not: its record is the only
  thing refusing it. The epoch is not bumped, because nothing removed can
  change an answer. New counter `promfleet_hub_state_pruned_total{kind}`.

### Fixed

- Both charts declared `appVersion: 0.1.0`, and the image tag defaults to the
  chart's appVersion — so a `helm install` of the 0.8.0 charts deployed the
  0.1.0 images.

## [0.8.0] - 2026-09-01

### Added

- **Automatic CA rotation.** A four-phase state machine
  (steady → publishing → signing → steady) persisted in the CA Secret and
  advanced by whichever replica wins a compare-and-swap on it. Retirement of
  the outgoing root is gated on evidence — no live session may still chain to
  it — behind a clock of `SpokeCertTTL + RenewGrace` padded by two poll
  intervals. An unrecognised phase freezes the controller and widens trust to
  everything present rather than guessing. See ADR-0015.
- **Hub replica coverage for spokes.** The hub advertises its replica count;
  spokes hold one tunnel per replica and run one probe dialer above that
  count so a scale-up is noticed within about a minute. Surplus dialers retire
  themselves after a scale-down. Several configured endpoints switch to
  explicit mode: one tunnel each, no probe.
- Agent keys may be minted with no expiry (`--no-expiry`, agent class only);
  the default lifetime is 90 days. Admin key lifetime moves to its own
  `--admin-key-ttl`.
- Three MCP tools: `query_exemplars`, `target_metadata`, `alertmanagers`.
- Alerts: `PrometheusMCPHubStateSecretLarge`, `PrometheusMCPHubRevocationStale`,
  `PrometheusMCPHubPeerDiscoveryBroken`, `PrometheusMCPHubCARotationStalled`.

### Fixed

- The periodic facts refresh stored spoke-reported labels verbatim, so a
  compromised cluster could relabel itself into any `matchLabels` scope.
- The CA issuer tracker was keyed per cluster, so a renewed sibling's
  handshake hid a live holdout on the outgoing root.
- Key rotation was two writes; a failed revoke left a live credential whose
  raw token was already unrecoverable. Now one compare-and-swap.
- `fleet.Role` was documented as a capability tier and enforced nowhere.
- MCP resource reads bypassed the per-key rate limiter entirely.
- The bootstrap admin key took its lifetime from `--agent-key-ttl`.
- A spoke would adopt another cluster's certificate from a shared identity
  Secret and renew it forever while every handshake failed.
- Spoke readiness and `tunnel_up` were last-writer-wins across dialers.

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
