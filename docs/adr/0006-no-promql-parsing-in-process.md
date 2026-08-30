# 0006. Do not parse PromQL in process

* Status: Accepted
* Date: 2026-08-29

## Context

An AI agent will write bad PromQL, and it will write expensive PromQL. The
obvious defence is to parse the expression at the hub, reject unbounded
selectors such as `{__name__=~".+"}`, and bound the cost before dispatch.

The canonical parser is `github.com/prometheus/prometheus/promql/parser`.
Importing it pulls in the Prometheus server module, which brings hundreds of
transitive modules and tens of megabytes into a binary whose entire point is to
be small. It also couples our release cadence to Prometheus' internal package
layout, which is explicitly not a stable API.

There is a second, subtler problem. A parser we own is a parser that can
disagree with the one actually evaluating the query. Any divergence between our
validation and the server's semantics is a bypass: a query our parser reads as
safe and the server reads as something else.

## Decision

We do not parse PromQL. The expression is treated as an opaque, length-bounded,
control-character-screened string, and Prometheus itself is the validator — it
returns HTTP 400 with a precise parse error and character offset, which we pass
through to the agent along with a hint and a caret.

Cost is bounded **structurally** instead, by properties we can enforce without
understanding the expression:

* a hard cap on `(end - start) / step`, with automatic step selection;
* a maximum lookback window;
* a per-request timeout, clamped, and propagated to the server's own `timeout`;
* a per-cluster in-flight concurrency semaphore;
* a global response-byte budget, enforced during the read rather than trusted
  from `Content-Length`;
* a decompressed-size cap, so a gzip bomb cannot get through;
* the operator's own `--query.max-samples` on the Prometheus server, which we
  document as the backstop that actually bounds evaluation cost.

## Consequences

**Better.** The dependency tree stays inside the budget. There is exactly one
PromQL implementation in the system, so there is nothing to diverge. Errors the
agent receives are the *real* errors, with real offsets, which is what lets a
model self-correct in one turn rather than guessing.

**Worse, and stated plainly.** We cannot reject a pathological query before
sending it. `{__name__=~".+"}` reaches Prometheus and is refused there, or
worse, served there. Our protection is the response-byte cap and the server's
sample limit, both of which fire *after* the server has begun work. On a large
TSDB an unbounded selector can still cost the server real CPU before our cap
trips.

This is the honest trade: we accept some wasted server-side work in exchange for
never having a validator that disagrees with the evaluator. Operators running
this against a large TSDB should set `--query.max-samples` and a query timeout,
and the deployment documentation says so rather than implying the hub protects
them.

We also give the agent a cheap way to avoid the problem: `explain_promql`
validates an expression without executing it, so a fixable mistake costs a few
hundred tokens instead of a failed range query.

## Alternatives considered

* **Import the Prometheus parser.** Rejected on dependency weight and on the
  divergence risk above.
* **Write a minimal PromQL parser.** Strictly worse: all of the divergence risk,
  none of the correctness, and a permanent maintenance burden tracking a
  language we do not own.
* **Regex heuristics against known-bad patterns.** Rejected. A regex that
  half-understands a grammar produces both false positives that block valid
  work and false negatives that provide false assurance. If we cannot do it
  correctly we should not claim to do it at all.
