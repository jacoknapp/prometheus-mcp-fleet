# 0008. Metric naming and cardinality policy

* Status: Accepted
* Date: 2026-08-29

## Context

This is a project about Prometheus, installed by people who operate Prometheus.
Emitting metrics that blow up their cardinality would be a particular kind of
embarrassing, and it is an easy mistake: the most natural labels to reach for
here — the PromQL expression, the matcher, the cluster's label values, the
request ID — are all unbounded.

A single counter labelled by query text would create one series per distinct
query an AI agent invents. That is unbounded by construction, because the whole
point of the product is that a model writes novel queries.

## Decision

All metrics use the `promfleet_` namespace with a `hub_` or `spoke_` subsystem.

**Every label must come from a closed set.** Specifically:

* `endpoint` is the `promapi.Endpoint` enum — about sixteen values, fixed at
  compile time.
* `result`, `reason` and `code` are closed enums defined in code, never a raw
  upstream string.
* `cluster` is permitted. It is bounded by the size of the fleet, which is the
  operator's own scale, and without it the metrics cannot answer "which cluster
  is failing" — the question they exist to answer.

**Forbidden as labels, permanently:** PromQL text, matchers, label values from
monitored clusters, metric names from monitored clusters, request IDs, agent key
identifiers, session identifiers, spoke IP addresses, and any free text from a
remote cluster.

That last category matters twice over: cluster-supplied strings are also
attacker-influenced ([docs/security.md](../security.md)), so putting them in a
label would let a remote operator inflate our series count on purpose.

Worst case is roughly the fleet size times the endpoint count — about 1,600
series per labelled counter at 100 clusters, which is nothing.

Where a high-cardinality value is genuinely needed for debugging, it goes in a
**structured log field or a trace attribute**, never a metric label. Both are
sampled and both are dropped by retention; a time series is neither.

## Consequences

**Better.** An operator can scrape this at default settings without thinking
about it. The metric surface is auditable by reading one file. A new label
cannot be added casually, because the enum has to be extended in code.

**Worse.** Some questions cannot be answered from metrics alone — "which query
is slow" needs a trace or a log, not a histogram. That is the correct division
of labour, but it does mean an operator debugging a specific slow call has to
turn on tracing rather than reading a dashboard.

**The rule that keeps it true.** A pull request adding a metric label must state
the label's cardinality bound. "It is usually small" is not a bound.

## Alternatives considered

* **Label by query, sampled or hashed.** A hash is still unbounded and is now
  also unreadable. Sampling makes the counter wrong.
* **Drop the `cluster` label.** Bounds cardinality further but removes the
  ability to answer the operational question the metrics exist for.
* **Expose everything and let operators drop what they do not want.** Pushes our
  design mistake into 100 people's relabel configs.
