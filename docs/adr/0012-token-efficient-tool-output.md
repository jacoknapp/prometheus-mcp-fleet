# 0012. Tool output is token-efficient by default

* Status: Accepted
* Date: 2026-08-29

## Context

Prometheus' native JSON is designed for a browser and a Go client, not for a
language model's context window. Its range-query shape repeats a full label set
per series and a full timestamp per sample, and encodes every value as a string:

```json
{"metric":{"__name__":"...","job":"...","instance":"..."},
 "values":[[1756400000,"0.43210987"],[1756400015,"0.43310021"], ...]}
```

Take a realistic request: `rate(container_cpu_usage_seconds_total{namespace="prod"}[5m])`
over six hours at a 15-second scrape interval, matching 84 series. That is
120,960 samples, roughly 4.6 MB of JSON, on the order of 1.4 million tokens. It
does not fit in any context window that exists, and an agent that requests it has
destroyed its own session — including the part of the session holding the
incident it was investigating.

Passing the upstream response through unchanged is therefore not a neutral
default. It is a footgun aimed at the user.

## Decision

The default output encoding is **columnar and lossy in stated ways**.

* One `start` and one `stepSeconds` for the whole result; each series carries a
  bare `values` array where the index implies the timestamp. Timestamp elision
  alone is most of the saving: `[1756400000,"0.43210987"]` is about twelve
  tokens, `0.432` is about three.
* Values are JSON numbers, not strings. Gaps are `null`.
* Labels shared by every series are factored out into `sharedLabels`; only the
  differing labels stay per-series.
* **Step is selected automatically**: `step = max(userStep, ceil((end-start)/maxPoints))`,
  snapped up to a human-sensible ladder, never below the cluster's reported scrape
  interval. Every response reports
  `downsampled: {requestedStep, appliedStep, reason}` — an agent reasoning about
  a latency spike must know it is looking at averaged data.
* **Truncation is explicit and machine-readable**, never silent:
  `truncated: {returned, total, reason, hint}`. Series truncation selects the top
  N by maximum value and says `selection: "top_20_by_max"`.
* A `format` parameter offers `compact` (default), `json` (upstream passthrough,
  documented in the tool description as costing ten to fifty times more tokens)
  and `table` (fixed-width text, cheapest for wide, shallow results such as
  targets and alerts).
* A **hub-side token ceiling** of roughly 25,000 estimated tokens force-truncates
  any result regardless of the caller's `limit`. An agent must not be able to
  blow its own context in a single call, even by asking for it.

The same query above comes back at roughly 34 KB — about 11,500 tokens, some
5% of a 200k window, leaving room to actually think.

## Consequences

**Better.** Queries that were impossible become routine. An agent can run a
dozen tool calls in an investigation instead of dying on the first. The explicit
`downsampled` and `truncated` markers mean the model knows what it is looking at,
which matters more than the saving: silently averaged data that the model
believes is raw produces confident wrong conclusions.

**Worse.** The default output is not what a Prometheus user recognises, so
anyone debugging the hub against a raw `curl` sees two different shapes. The
`format: "json"` escape hatch exists for exactly that, and the schema documents
the cost.

**Lossy by design.** Top-N-by-max is a heuristic, and it will sometimes discard
the series that mattered — a flatlined series that *should* have been spiking is
precisely the one a max-based selection drops. This is why the selection strategy
is named in the response rather than implied, and why the hint tells the agent
how to narrow the query instead. An agent that needs a specific series should
select it with a matcher, not hope it survives truncation.

**A ceiling that can surprise.** The hub-side token ceiling overrides an explicit
`limit`, which will occasionally frustrate an operator who knows what they are
asking for. The response says `reason: "hub_token_ceiling"` so it is diagnosable
rather than mysterious, and it is configurable.

## Alternatives considered

* **Pass upstream JSON through unchanged.** Rejected: the arithmetic above.
* **Compact encoding only on request.** Rejected: a default that destroys the
  caller's session the first time they use it is not a default, and an agent has
  no way to know in advance how large a result will be.
* **Return a reference and let the agent paginate.** Adds a round trip and
  server-side result state to a deliberately stateless server
  ([ADR-0003](0003-mcp-streamable-http-stateless.md)), for a case that
  auto-stepping already handles.
* **Server-side summarisation with a model.** An LLM in the data path of a
  monitoring tool, with its own failure modes and its own prompt-injection
  surface. Firmly rejected.
