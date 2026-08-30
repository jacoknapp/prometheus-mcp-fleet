# Architecture Decision Records

Each record captures one decision, the forces that shaped it, and what it costs.
They are written so that a future maintainer can tell the difference between a
choice that was reasoned about and one that was an accident.

Records are immutable once accepted. A decision that changes gets a new record
that supersedes the old one; the old one stays, marked superseded, because the
reasoning that turned out to be wrong is often the most useful part.

| # | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-spoke-dialed-reversed-grpc-tunnel.md) | Spoke-dialed tunnel with reversed gRPC roles | Accepted |
| [0003](0003-mcp-streamable-http-stateless.md) | MCP over stateless Streamable HTTP | Accepted |
| [0004](0004-built-in-ca-for-spoke-identity.md) | A built-in CA issues spoke identities | Accepted |
| [0005](0005-no-database-state-in-secrets.md) | No database: state lives in Kubernetes Secrets | Accepted |
| [0006](0006-no-promql-parsing-in-process.md) | Do not parse PromQL in process | Accepted |
| [0007](0007-hmac-pepper-not-argon2.md) | HMAC with a pepper, not a password KDF | Accepted |
| [0008](0008-metric-naming-and-cardinality.md) | Metric naming and cardinality policy | Accepted |
| [0009](0009-no-client-go.md) | No client-go; a minimal Kubernetes client instead | Accepted |
| [0010](0010-dependency-budget.md) | A closed dependency budget | Accepted |
| [0011](0011-auto-update-is-opt-in.md) | Fleet auto-update is opt-in, verified and staggered | Accepted |
| [0012](0012-token-efficient-tool-output.md) | Tool output is token-efficient by default | Accepted |
| [0013](0013-no-hub-peer-forwarding.md) | No hub-to-hub forwarding | Accepted |

## Template

```markdown
# NNNN. Title

* Status: Proposed | Accepted | Superseded by [NNNN](...)
* Date: YYYY-MM-DD

## Context
What forces are at play? What is true regardless of the decision?

## Decision
What we are doing, stated in the active voice.

## Consequences
What becomes easier, what becomes harder, and what we have given up.

## Alternatives considered
Each with the reason it lost. An alternative with no stated reason is a
decision that was never really made.
```
