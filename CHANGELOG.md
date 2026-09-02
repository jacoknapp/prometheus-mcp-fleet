# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, minor releases may contain breaking changes. The
hub↔spoke wire protocol carries an explicit version and the hub supports the
previous spoke minor from the outset, because 100 clusters never upgrade in
lockstep. The exception is called out where it happens: 0.10.0's `renew-v2`
is a hard cut on the renewal proof alone, with existing tunnels unaffected
and `--renew-grace` covering spokes that upgrade late.

## [0.10.2] - 2026-09-02

### Changed

- The charts now carry the application's version: `Chart.yaml`'s `version` and
  `appVersion` are both `0.10.2`, in both charts, and move only when a release
  is cut. Two numbering schemes for one artifact set meant "which chart has
  the fix" was answerable only from the release notes. `chart.yml` fails a
  pull request where the two fields disagree or the charts disagree with each
  other, and `release.yml` refuses to publish a chart whose version is not the
  tag being released. Chart versions 0.5.x are superseded; 0.6.0 was never
  published.

## [0.10.1] - 2026-09-02

### Fixed

- The v0.10.0 release published the hub chart and then failed pushing the
  spoke chart with nothing in the log but the exit code: `helm push` ran
  inside a command substitution under `set -e`, so the step ended before its
  output was echoed. The push is now captured with `||` and the error printed.
  A chart that an earlier attempt at the same tag already published is reused
  (its digest read back with `helm pull`) rather than refused, so a release
  can be re-cut from where it stopped instead of needing a new chart version.
  Charts move to 0.5.1; `prometheus-mcp-spoke` 0.5.0 was never published and
  `prometheus-mcp-hub` 0.5.0 remains valid for 0.10.0.

## [0.10.0] - 2026-09-01

### Changed

- **Renewal proofs cover the certificate signing request (`renew-v2`).**
  The signed transcript a spoke presents to `/renew` now binds
  `sha256(CSR)` alongside the nonce, protocol version and cluster ID. Before,
  the signature proved possession of the old key but said nothing about
  *which* CSR was being signed, so anything on the path between the spoke and
  the hub that could read the request — the Ingress terminates TLS and sees
  `/renew` in plaintext — could swap in a CSR over its own key and be issued
  that spoke's identity. `docs/security.md` had listed a compromised Ingress
  as a threat the design contained; it did not.

  This is a hard cut with no compatibility flag: a v0.9 spoke renewing
  against a v0.10 hub, or the reverse, is refused with `forbidden` (security
  event `renewal.unproven`) until both sides match. Existing tunnels are unaffected — the transcript is
  only checked at renewal — and `--renew-grace` (30 days) is what recovers a
  spoke that was upgraded late: it renews on its expired certificate the
  moment it comes back. Upgrade the hub first, then the spokes, inside one
  certificate lifetime.

- **Authentication backoff is per (source address, KID), not per address.**
  Behind an Ingress every agent shares the Ingress pod's address, so the
  old per-address bucket let one client retrying a revoked key put the whole
  fleet into `429` on its next cache miss — and let anyone outside, holding
  no credential, keep it there. A bad key's penalty is now confined to that
  key. Forwarded-for headers stay ignored.

### Fixed

- `make mutate` failed on every run since 0.9.0: `internal/hubcli` shipped
  without an entry in `hack/mutation-baseline.txt`. The package now has one
  (94, measured 97.35) and three tests that kill the survivors that were not
  equivalent: the error envelope is reported as `status: message` rather than
  dumped, a token without labels prints no empty `labels:` line, and
  `keys rotate --no-expiry` alone is sent as such.
- Range tools (`query_range`, `exemplars`, `metadata`), `fanout` in both
  modes, and the instant `query` ignored the principal's scope limits: a key
  scoped to `maxLookback: 1h` could read a year, and `maxSeries` /
  `maxPoints` were never applied to instant queries or the fan-out. Every
  path now takes the tighter of the scope and the hub default. Two ways
  around the check found in review are closed too: the fan-out's range start
  is now aligned *up* to the step boundary, so a large `step` can no longer
  pull the first sample before the lookback-checked window; and
  `format: "json"` on `query` / `query_range` is refused for a key whose
  scope caps `maxSeries` or `maxPoints`, because the raw payload bypasses
  the encoder that applies them.
- The spoke's first facts collection at start-up had no deadline of its own,
  so a Prometheus that accepted the connection and then hung held the whole
  start-up — and with the 130-second upstream ceiling, for over two minutes
  per source — before the first dial to the hub. It now runs under the same
  budget as every later refresh.
- Every HTTP listener now sets a 60-second `ReadTimeout` (`httpx`), closing
  the body-shaped slowloris the header timeout left open: a client that
  sends a complete request head and then dribbles the body. Long tool calls,
  SSE streams and the tunnel upgrade are unaffected, because net/http clears
  the read deadline once the body has been read to EOF and on hijack — a
  behaviour the package comment had described backwards.
- `hub keys list --json` prints the admin API's own listing for scripts. The
  runbook's emergency revoke-everything loop parsed the table with `awk` on
  column number, which skipped any key whose name contains a space; it now
  selects on `.revoked` from the JSON.
- `fanout` against a query that returns a scalar (`count(up)`, `time()`)
  reported `ALL_CLUSTERS_FAILED` as retryable. Scalars are rendered as a
  one-sample series; a matrix in instant mode and a string are per-cluster
  `INVALID_ARGUMENT`; and when every cluster failed permanently the error is
  no longer marked retryable.
- The state prune could delete the enrollment record that is the authority
  for a cluster's operator-pinned labels, silently turning a pinned
  `tier=pci` into a spoke-asserted one at the next reconnect. The newest
  non-revoked enrollment record per cluster is now never pruned.
- The prune could also drop a certificate revocation inside the renew grace
  window — the only thing refusing that certificate at `/renew` — with a
  short `--state-retention`. Records are now held for
  `expiry + --renew-grace + --state-retention`.
- `POST /admin/v1/certs/{serial}/revoke` accepted a `notAfter` in the past
  and answered 204 for a revocation the tunnel would ignore as moot. It is
  now refused with `invalid_request`; omit the field to cover the longest
  possible lifetime.
- The `fleet://alerts/firing` resource fanned out to every cluster with no
  cluster cap, no deadline and no token ceiling. It is now bounded the way
  the `fanout` tool is: clusters are capped, the fan-out carries the default
  deadline, and the rendering is fitted with a truncation note.
- The spoke's Prometheus metrics `prom_requests_total{endpoint,code}` and
  `prom_duration_seconds{endpoint}` were declared but never written, so the
  `PrometheusMCPSpokePromErrorRatioHigh` alert could not fire. Every upstream
  call now records them; `code` is the HTTP status or `timeout` / `error`,
  `endpoint` is the allow-list name (a new `healthy` value covers the
  readiness probe).
- The spoke's `--prometheus-timeout` (25 s) silently overrode any longer
  deadline the hub forwarded down the tunnel, so a range query granted 120 s
  died at 25 s. The default is now 130 s and the flag is documented as the
  ceiling it is; the hub's per-call deadline is the usual bound. The hub's
  `--range-query-timeout` help now says what it does: the ceiling any call
  may raise its timeout to, not a range-only setting.
- A refused WebSocket upgrade (a 403 from the Ingress, say) left the spoke's
  dial transport holding an idle keep-alive connection and two goroutines per
  attempt, for the life of the process. The dial transport is now one-shot.
- A spoke that renewed its certificate between reading its identity and
  arming the reconnect signal missed the renewal until the next reconnect.
- Closing a tunnelled request body while another goroutine was blocked
  reading it could not unblock the read. Close now cancels the stream first.
- A `promfleet.io/rotate-now` annotation applied while the state Secret still
  held leftovers from an interrupted rotation was consumed by the tidy-up
  and the rotation never started. The annotation now survives the tidy-up.
- A CA rotation in the `publishing` phase waited the full spoke certificate
  lifetime even after the outgoing root had expired, during which nothing
  could be issued. The successor is promoted as soon as the signer expires.
- The `signing` phase's retirement gate was computed from the live
  `--spoke-cert-ttl` and `--renew-grace`, so shortening either mid-rotation
  could drop the outgoing root while certificates issued under the longer
  values were still live. The horizon is now recorded at promotion
  (`ca-rotation.retire-after`) and the gate takes the later of the two.
- Store health was evaluated once at startup. A replica whose state Secret
  became unreadable (a schema written by a newer build, a corrupt document,
  an unreachable API server) stayed ready while failing every cache miss.
  The store is now re-probed every 15 s and readiness follows it.
- `hub` with no recognised subcommand printed a usage line that still named
  only `enroll create` and `keys create`.
- Helm: the hub chart with a plain `helm install` rendered no
  `PMF_PUBLIC_URL`, which the hub refuses at startup; the URL is now derived
  from `ingress.host`, and the template fails with a clear message when
  neither that nor `config.publicURL` is set. `service-headless` and the peer
  ConfigMap used `.Release.Namespace` and broke `namespaceOverride`. The
  NetworkPolicy allowed the API server on port 443 only; `kubeAPIPorts`
  (hub) and `kubeAPI.ports` (spoke) default to `[443, 6443]`, with the old
  scalar keys still honoured. The hub NOTES printed `hub.apiUrl` with the
  `/mcp` path and a `curl` with no credential.
- Docs: the quickstart, troubleshooting guide, runbook and enrollment guide
  told operators to mount `/pki/bundle` (the spoke-identity CA) as the CA the
  spoke should trust the hub's Ingress with, which fails TLS against any real
  Ingress certificate; `--hub-ca-file` claimed a fallback to the enrollment
  bundle that does not exist, and `spoke --help` said the same. All
  corrected. The runbook's response-code
  table, the admin CLI recipes, `mcp-tools.md`'s error shapes and the
  `fanout` parameter table were brought in line with the code; the error
  table now lists every code a tool can return, and the fan-out section
  documents how each result type merges and what `ALL_CLUSTERS_FAILED`
  carries. `--query-timeout` / `--range-query-timeout` are described as the
  code implements them: the first is the deadline for calls that state none,
  the second the ceiling every per-call deadline is clamped to, which the
  tool layer already caps at 120 seconds. The enrollment guide's
  reconciliation paragraph no longer claims `hub certs list` shows what the
  hub trusts (it lists revocations), and ADR-0015's diagram shows the early
  promotion when the outgoing signer has already expired.

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
