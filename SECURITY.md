# Security Policy

## Supported versions

`prometheus-mcp-fleet` is pre-1.0. Only the latest minor release receives
security fixes. Once 1.0 ships, the latest two minor releases will be supported.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/jacoknapp/prometheus-mcp-fleet/security/advisories/new),
which is enabled on this repository. If that is unavailable to you, email
`jacoknapp@gmail.com` with `[SECURITY] prometheus-mcp-fleet` in the subject.

Please include:

- the affected component (`hub`, `spoke`, a Helm chart, a workflow) and version;
- a description of the impact — what an attacker gains, not only what misbehaves;
- reproduction steps or a proof of concept;
- any suggested remediation.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for critical issues | 30 days |
| Coordinated disclosure | By agreement; 90 days by default |

You will be credited in the advisory and the changelog unless you ask not to be.
This project has no bug bounty.

## Scope

**In scope**

- The `hub` and `spoke` binaries and container images.
- The Helm charts under `charts/`.
- The release and supply-chain workflows under `.github/workflows/`.
- Anything that breaks one of the security invariants below.

**Out of scope**

- Vulnerabilities in Prometheus itself — report those to the Prometheus project.
- Findings that require an attacker to already hold a valid admin credential.
- A deployment that has explicitly disabled a documented control, for example
  `PMF_HUB_TLS_INSECURE=true` or an operator-supplied scope granting `clusters.allow: ["*"]`.
- Missing hardening that the documentation already calls out as the operator's
  responsibility, such as exposing the admin listener publicly.
- Denial of service through simply sending a very large volume of authenticated
  traffic. Resource exhaustion that bypasses the documented budgets *is* in scope.

## Security invariants

A report that demonstrates a break of any of these is treated as a valid
vulnerability regardless of severity rating:

1. **No agent-controlled URLs.** An AI agent names an MCP tool; the tool maps to
   a hard-coded path in `internal/promapi`. There must be no input that causes
   the hub or the spoke to issue a request to a path outside that table, or to a
   host other than the spoke's configured Prometheus.
2. **The spoke re-validates.** A hub that has been compromised or is buggy must
   still not be able to make a spoke call a non-allow-listed endpoint.
3. **Certificate-bound identity.** A spoke's `clusterID` derives only from the
   URI SAN of its verified client certificate. No self-reported value may
   override it, and no spoke may answer for another spoke's cluster.
4. **Bounded enrollment redemption.** An enrollment token minted with
   `--single-use` can be redeemed exactly once; a second redemption must fail
   and raise a security event. A reusable token (the default) can be redeemed
   only up to its configured `--max-redemptions` cap, if one was set, and never
   for a cluster ID other than the one it was bound to, past its TTL, or after
   revocation.
5. **CSR subject is discarded.** The hub mints its own subject and SANs and
   ignores whatever the CSR requested.
6. **No secret at rest in plaintext.** API keys are stored as
   HMAC-SHA256(pepper, secret) with the pepper held outside the database.
   Comparisons are constant-time.
7. **No secret in logs.** Raw tokens, HMACs, the pepper, private keys and
   `Authorization` headers must never appear in any log line, error message,
   panic trace or admin API response.
8. **Destructive Prometheus endpoints are unreachable.** `admin/tsdb/*`,
   `/api/v1/write`, `/api/v1/read`, `/-/reload`, `/-/quit` and `/debug/pprof/*`
   are absent from the allow-list on both sides.

See [docs/security.md](docs/security.md) for the full threat model, and
[docs/adr/](docs/adr/) for the reasoning behind these choices.

## A note on AI agents and prompt injection

This project deliberately hands cluster telemetry to a large language model.
Metric labels, `help` strings, alert annotations and scrape errors are
attacker-influenced: anyone who can expose a metrics endpoint or author an alert
rule in any monitored cluster can plant text that a model will read.

We mitigate this structurally — untrusted strings are returned only as JSON
values inside an explicitly marked envelope, control characters and bidirectional
overrides are stripped, lengths are clipped, links are never rendered as
markdown, and nothing a spoke reports ever becomes a tool name, tool description
or prompt. See [docs/security.md](docs/security.md#prompt-injection).

**We assume injection sometimes succeeds.** The real control is that a
successfully injected agent still cannot exceed the scope document attached to
its API key. Scope your agent keys to the clusters and tools they actually need.
A report showing that an injected agent can exceed its scope is a vulnerability;
a report showing that a model can be persuaded to say something odd about a
metric is not.
