# 0010. A closed dependency budget

* Status: Accepted
* Date: 2026-08-29

## Context

The spoke is installed into roughly 100 Kubernetes clusters owned by teams who
did not write it and have no reason to trust it. Every one of them may run a
scanner against the image and read the SBOM. Every transitive module is
something they have to accept, something that can carry a CVE, and something
that can go unmaintained.

Dependency growth is also not a decision anyone makes; it is a hundred small
conveniences that each looked free.

## Decision

The set of direct dependencies is **closed**. Adding one requires an ADR that
states what it does that the standard library cannot, and what it costs in
transitive modules.

Allowed:

| Module | Why it earns its place |
|---|---|
| `google.golang.org/grpc`, `google.golang.org/protobuf` | Multiplexed streams, flow control, cancellation and deadline propagation. Hand-rolling this is the one place we refuse to save bytes ([ADR-0002](0002-spoke-dialed-reversed-grpc-tunnel.md)). |
| `github.com/prometheus/client_golang` | Self-metrics. It *is* the ecosystem contract; reimplementing the exposition format would be absurd in this project of all projects. |
| `github.com/modelcontextprotocol/go-sdk` | Specification conformance. A hand-rolled JSON-RPC session layer would silently drift from a moving specification. |
| `github.com/google/jsonschema-go` | Not a choice so much as a consequence: `mcp.Tool.InputSchema` is a `*jsonschema.Schema`, so code that inspects or emits a tool schema must name the type. It arrives with the SDK regardless; only `internal/mcpsurface` imports it. |
| `go.opentelemetry.io/otel` (+ sdk, otlptracegrpc, otelgrpc) | Distributed tracing across the hub→spoke hop. Inert unless an endpoint is configured, and it reuses the gRPC stack we already have. |
| `golang.org/x/sync` | `errgroup`. Small, canonical. |
| `github.com/google/go-cmp` | Test only. |

Explicitly refused, with the standard-library replacement:

* `viper`, `cobra` → `flag` and a switch on `os.Args[1]`.
* `zap`, `logrus`, `zerolog` → `log/slog`.
* `gin`, `echo`, `chi`, `gorilla` → `net/http`, whose `ServeMux` has had method
  and path patterns since Go 1.22.
* `testify`, `ginkgo`, `gomock` → table-driven tests and hand-written fakes.
* `google/uuid` → `crypto/rand` plus hex.
* `golang.org/x/crypto` → `crypto/hmac`; see [ADR-0007](0007-hmac-pepper-not-argon2.md).
* `github.com/prometheus/prometheus` → see [ADR-0006](0006-no-promql-parsing-in-process.md).
* `k8s.io/client-go` and friends → see [ADR-0009](0009-no-client-go.md).
* Any database driver or ORM → see [ADR-0005](0005-no-database-state-in-secrets.md).

CI asserts the direct-require count so growth is a visible, reviewed diff.

## Consequences

**Better.** Small images, a short SBOM, a small CVE surface and a review a
platform team can actually complete. Upgrades are rare and legible.

**Worse.** We write code that a library would have given us: an LRU cache, a
Levenshtein distance, a token bucket, a Kubernetes client, a flag-and-environment
loader. That is a few hundred lines we now maintain and must test properly,
and each is a place where a subtle bug could live that a widely-used library
would have had shaken out years ago. The mitigation is coverage: these are
exactly the packages held to the highest thresholds.

**The failure mode to watch for.** A closed budget becomes dogma if it is
defended after it stops making sense. The rule is an ADR, not a refusal — the
point is that the cost gets stated out loud, not that the answer is always no.

## Alternatives considered

* **No policy.** The default, and how a 40 MB binary with 200 modules happens
  without anyone choosing it.
* **A soft guideline.** Guidelines lose to convenience under deadline. A CI
  assertion does not.
* **Vendoring everything.** Solves availability, not surface area, and makes
  every upgrade a large diff.
