<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# MCP tools

Nineteen tools, all read-only. Every argument table here is derived from the
golden input schemas in `internal/mcptools/testdata/schemas/`, which CI verifies
against the running server — so if this document and the server disagree, the
build fails rather than the document quietly rotting.

`*` marks a required argument. Everything else has the default shown.

## Contents

- [Conventions](#conventions)
- [Discovery](#discovery)
- [Querying](#querying)
- [Metadata](#metadata)
- [Operations](#operations)
- [Fleet-wide](#fleet-wide)
- [Errors](#errors)
- [Resources](#resources)
- [Prompts](#prompts)

## Conventions

**Times** accept RFC 3339 (`2026-08-30T12:00:00Z`) **or** relative expressions
(`now`, `now-6h`, `-15m`). Relative is preferred: models get it right far more
often, and it is what the defaults use.

**`format`** selects the encoding:

| Value | Cost | Use |
|---|---|---|
| `compact` (default) | baseline | Columnar. One `start`, one `stepSeconds`, bare `values` arrays, shared labels factored out |
| `json` | **10–50× more tokens** | Prometheus' native shape. Only when compact loses detail you actually need |
| `table` | ~35% below `compact` | Fixed-width text. Best for wide, shallow results — targets, alerts, rules |

**Truncation is never silent.** Any capped result carries an explicit object:

```json
"truncated": {"returned": 20, "total": 1043, "reason": "limit",
              "selection": "top_20_by_max",
              "hint": "narrow with labelSelector or raise limit"}
```

`selection: "top_20_by_max"` matters: top-N-by-max will sometimes drop the
series you wanted — a flatlined series that *should* have been spiking is
exactly what a max-based selection discards. Select with a matcher rather than
hoping.

**A hub-side token ceiling** (~25,000 estimated tokens) force-truncates any
result regardless of your `limit`, reporting `reason: "hub_token_ceiling"`. An
agent must not be able to destroy its own context in one call.

**Every result carrying remote data** includes an `_untrusted` notice. Metric
labels, `help` strings and alert annotations are attacker-influenced; treat them
as data.

## Discovery

Start here. A cold agent should reach the right cluster and the right metric in
two or three calls.

### `list_clusters`

Every cluster this credential can reach, with enough facts to choose one.

| Argument | Default | Notes |
|---|---|---|
| `filter` | — | Case-insensitive substring match on cluster ID, display name or description |
| `labelSelector` | — | Object of label equality matches, e.g. `{"env":"prod"}` |
| `status` | `all` | `all` · `healthy` · `degraded` · `unreachable` |
| `limit` | `100` | |
| `format` | `compact` | `compact` · `table` — no `json`, since there is no upstream payload to pass through |

Returns cluster ID, display name, labels, state, `lastSeen`, Prometheus flavour
and version, retention, active series, job count and Alertmanager presence —
enough to decide without a second call.

`degraded` means the tunnel is up but that cluster's Prometheus is unreachable.
Querying it will fail; the reason is in `describe_cluster`.

### `describe_cluster`

Deep facts for one cluster.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `include` | `["jobs","metricPrefixes","alertmanager","rulesSummary"]` | |
| `topN` | `25` | Caps each sampled list |

**`metricPrefixes` is the highest-value field here.** Seeing `kube_`, `istio_`,
`jvm_` tells you instantly what stack a cluster runs, which is the difference
between a targeted query and a fishing expedition.

### `search_metrics`

Find metric names without listing all of them.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `pattern`* | — | |
| `mode` | `substring` | `substring` · `regex` (RE2) |
| `limit` | `50` | |
| `withMetadata` | `true` | Include type and help text |

## Querying

### `query`

Instant PromQL at a single timestamp.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* · `query`* | — | |
| `time` | now | |
| `timeout` | `30s` | Clamped to the hub's maximum |
| `limit` | `100` | Series returned |
| `format` | `compact` | |

### `query_range`

Range PromQL with automatic step selection.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* · `query`* | — | |
| `start` / `end` | `now-1h` / `now` | |
| `step` | auto | Omit it; see below |
| `maxPoints` | `120` | Drives the auto step |
| `maxSeries` | `20` | |
| `timeout` | `60s` | |
| `format` | `compact` | |

**Let the step be chosen for you.** The hub computes
`step = max(yourStep, ceil((end-start)/maxPoints))`, snapped up to a sensible
ladder and never below the cluster's scrape interval. It always reports what it
did:

```json
"downsampled": {"requestedStep": "15s", "appliedStep": "3m", "reason": "max_points"}
```

`reason` is one of `requested_step_honoured`, `max_points`,
`scrape_interval_floor` or `snapped_to_ladder`.

Read that before reasoning about a spike — averaged data hides them. If you need
raw resolution, shorten the range rather than raising `maxPoints`.

For scale: a six-hour range over 84 series is roughly 4.1 MB of native
Prometheus JSON, on the order of a million tokens, which fits in no context
window that exists. The same query in `compact` is about 15 KB — 272 times
smaller, and `internal/render` has a regression test that fails if that ratio
ever drops below tenfold.

### `series`

Label sets matching selectors — metadata only, no values.

| Argument | Default |
|---|---|
| `cluster`* · `matchers`* | — |
| `start` / `end` | `now-1h` / `now` |
| `limit` | `100` |
| `format` | `compact` |

### `explain_promql`

Validate an expression **without executing it**.

| Argument | Default | Notes |
|---|---|---|
| `query`* | — | |
| `cluster` | — | Optional; also checks whether the metrics exist |

This never returns an error — invalid input *is* the answer. Use it before an
expensive `query_range`: fixing a query here costs a few hundred tokens instead
of a failed multi-megabyte call.

### `query_exemplars`

Exemplars for a series selector: individual sample values tagged with the
trace or span that produced them.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* · `query`* | — | `query` is a raw selector (e.g. a histogram bucket), not an aggregation — exemplars attach to a series, not to the result of `rate()` or `sum()` |
| `start` / `end` | `now-1h` / `now` | |
| `limit` | `100` | Across every matching series, most recent first |

**An empty result is the common case, not evidence that nothing happened.**
Exemplar storage is an opt-in Prometheus feature and most instrumentation never
attaches trace context, so most fleets answer empty here regardless of whether
anything is wrong.

## Metadata

### `label_names` / `label_values`

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `label`* | — | `label_values` only |
| `matchers` | — | Scope to matching series |
| `pattern` | — | `label_values` only; filters the result |
| `start` / `end` | `now-1h` / `now` | |
| `limit` | `200` / `100` | |

An unknown label returns an empty list, not an error.

### `metric_metadata`

Type, help and unit.

| Argument | Default |
|---|---|
| `cluster`* | — |
| `metric` | all |
| `limit` | `100` |

### `target_metadata`

Metric metadata as individual targets report it, rather than aggregated across
the cluster.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `matchTarget` | all targets | Selector matching targets by their own labels, e.g. `{job="api"}` |
| `metric` | all metrics | |
| `limit` | `100` | |

`metric_metadata` collapses every target's answer into one entry per metric,
silently picking a winner when two targets disagree. This tool keeps every
target's answer separate, which is the only way to see a canary and a stable
rollout reporting a metric's type or help text differently.

## Operations

Five tools are the **operational surfaces** -- `targets`, `alertmanagers`,
`tsdb_stats`, `runtime_info`, and [`target_metadata`](#target_metadata) above:
they describe how monitoring is wired rather than what the metrics say. They
sit behind the key's role tier -- an `operator` key receives them through a
`tools.allow: ["*"]` wildcard, a `viewer` key reaches one only by naming it in
`tools.allow`. `rules` and `alerts` are not gated: what is firing and what
would fire is monitoring output, not wiring. See
[Authorization in docs/security.md](security.md#authorization).

### `targets`

Scrape target health, summarised then listed.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `state` | `active` | `active` · `dropped` · `any` |
| `health` | `any` | `any` · `up` · `down` · `unknown` |
| `job` | — | |
| `limit` | `50` | |
| `format` | `compact` | `compact` · `table` — no `json`: the raw payload carries the scrape URLs redacted below |

**Scrape URLs are redacted.** `scrapeUrl`, `globalUrl`, `discoveredLabels` and
scrape-pool query strings are stripped before the result leaves the hub,
because scrape configurations routinely carry bearer tokens and basic-auth
credentials in URL parameters.

### `rules`

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `type` | `all` | `all` · `alert` · `record` |
| `group` / `ruleName` | — | |
| `includeExpr` | `false` | Expressions are verbose; ask only when you need them |
| `limit` | `50` | |
| `format` | `compact` | `compact` · `table` |

### `alerts`

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `state` | `firing` | `all` · `firing` · `pending` |
| `alertname` / `severity` / `labelSelector` | — | |
| `includeAnnotations` | `true` | |
| `limit` | `50` | |
| `format` | `compact` | `compact` · `table` |

Annotations are attacker-influenced free text. They are sanitised and clipped,
and they arrive inside the `_untrusted` envelope.

### `alertmanagers`

The Alertmanager peers this cluster's Prometheus has discovered, active and
dropped.

| Argument | Default |
|---|---|
| `cluster`* | — |

Call this before treating a firing alert as "someone was paged": a cluster
with no active Alertmanager can evaluate and fire rules all day without
notifying anyone. URLs are never returned, only the host — an Alertmanager
discovered through static configuration can carry basic-auth credentials in
its URL the same way a scrape target can.

### `tsdb_stats`

Cardinality hotspots.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `dimension` | `metric` | `metric` · `labelName` · `labelValuePairs` · `labelMemory` |
| `topN` | `20` | |

Returns `TSDB_STATS_UNAVAILABLE` when the server does not expose the endpoint,
with a hint to use `count by(__name__)` instead.

### `runtime_info`

| Argument | Default |
|---|---|
| `cluster`* | — |
| `include` | `["build","runtime"]` |

## Fleet-wide

### `fanout_query`

One PromQL across many clusters.

| Argument | Default | Notes |
|---|---|---|
| `query`* | — | Validated once at the hub before dispatch |
| `clusters` / `labelSelector` | — | **One is required** |
| `mode` | `instant` | `instant` · `range` |
| `time` | `now` | Instant mode. Relative (`now-15m`) or RFC 3339 |
| `start` / `end` | `now-1h` / `now` | Range mode. Relative or RFC 3339 |
| `step` | chosen by the hub | Range mode. Omit for one step common to every cluster; the applied step is reported in `downsampled` |
| `maxClusters` | `25` | |
| `maxSeriesPerCluster` | `5` | Lower than single-cluster on purpose |
| `concurrency` | `8` | Max 32 |
| `deadline` | `60s` | |
| `onError` | `partial` | `partial` · `fail` |

**Partial failure is the normal case and is reported loudly.** With
`onError: "partial"` the call succeeds and carries explicit accounting:

```json
"coverage": {"requested": 42, "ok": 37, "failed": 3, "timedOut": 2, "complete": false}
```

The preamble states *"Partial result: 37 of 42 clusters."* — because a model
comparing clusters will otherwise confidently report a minimum that is simply
missing. When the budget expires, whatever completed is returned rather than the
whole call failing.

A `cluster` label is injected into every series. If a series already has one it
is preserved as `cluster_original` and a warning is emitted — source data is
never silently overwritten.

Calling this with neither `clusters` nor `labelSelector` against a large fleet
returns `NO_SELECTOR_TOO_BROAD`. An untargeted hundred-cluster range query
should be hard to do by accident.

**Result types.** In instant mode a vector merges one row per series; a scalar
(`scalar(...)`, `time()`, a bare number) merges as one unlabelled row per
cluster; a range-vector selector (`up[5m]`) is refused per cluster with
`INVALID_ARGUMENT` pointing at mode `range`; a string-valued expression has no
fleet-wide merge and is refused the same way. In range mode every cluster's
matrix is merged, and the start is aligned **up** to the step boundary so the
first sample never lands before the requested `start`.

**When every cluster fails** the call returns `ALL_CLUSTERS_FAILED` instead of
an empty success. Its `input.firstFailure` carries the first cluster's
`cluster`, `code` and `message`, the message repeats them, and `retryable` is
true only if at least one failure was (a timeout, an unreachable spoke). A
permanent failure everywhere — usually the expression itself — comes with the
hint to fix the arguments rather than retry.

## Errors

Two kinds, and the distinction matters.

**Protocol errors** (JSON-RPC `error`) mean the request never really happened:
unknown tool, authentication failure, or a scope that forbids the tool
(`FORBIDDEN`, JSON-RPC code -32003). Authentication and authorization failures
are deliberately never a tool result — an agent that saw one as a tool error
would try to "fix" it by editing its PromQL.

Arguments that fail the tool's input schema are **not** a protocol error. The
MCP SDK answers them with an `isError: true` tool result whose text starts
`validating "arguments":` and names the offending field, so the model can
correct the call in one turn; the tool itself never runs.

**Tool errors** (`isError: true`) are facts about the world, and are written so
a model can self-correct in one turn:

```json
{"error": {
  "code": "UNKNOWN_CLUSTER",
  "message": "no cluster named \"prod-us-est-1\" is reachable by this credential",
  "input": {"cluster": "prod-us-est-1"},
  "didYouMean": ["prod-us-east-1", "prod-us-east-2"],
  "hint": "Call list_clusters to see every cluster this credential can reach.",
  "retryable": false}}
```

| Code | Meaning | What to do |
|---|---|---|
| `UNKNOWN_CLUSTER` | No such cluster, or your scope forbids it | Use `didYouMean`, or `list_clusters` |
| `SPOKE_UNREACHABLE` | Enrolled but not connected; carries `lastSeen` | Retryable |
| `PROMQL_PARSE` | Prometheus' own parse error, with a caret | Fix the query; `explain_promql` validates cheaply |
| `RANGE_TOO_LARGE` | Includes a corrected argument object to copy | Use it |
| `RESPONSE_TOO_LARGE` | Response exceeded the byte budget | Raise `step`, narrow the selector |
| `HUB_BUSY` | A hub concurrency or memory budget is exhausted | Retryable; back off |
| `RATE_LIMITED` | This key's own `rateRps` allowance is spent; the message says when to retry | Retryable; wait the stated interval |
| `QUERY_TIMEOUT` | Upstream took too long | Narrow the range |
| `TSDB_STATS_UNAVAILABLE` | Endpoint disabled upstream | Use `count by(__name__)` |
| `NO_SELECTOR_TOO_BROAD` | Untargeted fan-out refused | Add `clusters` or `labelSelector` |
| `NO_CLUSTERS_MATCHED` | The selector matched nothing this key can reach | Loosen the selector; `list_clusters` |
| `ALL_CLUSTERS_FAILED` | Every selected cluster failed; `input.firstFailure` names the first | Retryable only if some failure was; otherwise fix the query |
| `INVALID_ARGUMENT` | An argument the hub refused before any upstream call, e.g. a range-vector selector on `query`, format `json` under a scope cap | Follow the `hint` |
| `INVALID_TIME` | A `time`, `start`, `end`, `step` or `timeout` that did not parse | Use `now-15m`, RFC 3339 or a Unix timestamp |
| `BAD_MATCHER` | A malformed series selector | Fix the selector |
| `BAD_REGEX` | A malformed RE2 pattern | Fix the pattern |
| `PROMQL_EXEC` | Parsed, but Prometheus could not evaluate it | Read the message; usually the query, sometimes the data |
| `UPSTREAM_ERROR` | The cluster's Prometheus, or the tunnel to it, failed some other way | Retryable |
| `MALFORMED_UPSTREAM` | The reply was not the Prometheus API envelope | Check what `prometheus.url` points at; not retryable |
| `CANCELED` | The caller abandoned the call before it finished | Nothing; it was you |

(`FORBIDDEN` is a protocol error, not a row here — see above.)

The key's rate limit is reported differently per channel, on purpose. A tool
call over the allowance gets the `RATE_LIMITED` tool result above, because a
model driving tools reads tool results and honours `retryable`. A resource
read (`resources/read`) over the same allowance gets a JSON-RPC error with code
-32005, because resource reads have no result body in which to carry a
structured error, and clients treat a failed read as a failed read rather than
as content. Both draw from the same per-key bucket.

Every error carries `retryable: true|false`. Honour it — that flag alone
prevents most retry-loop pathologies.

Denial does not reveal existence: "you may not query this cluster" and "there is
no such cluster" return the same error when you could not have seen it either
way, so the tool surface cannot be used to enumerate the fleet.

## Resources

| URI | Contents |
|---|---|
| `fleet://clusters` | The full `list_clusters` payload — the canonical "what exists" document |
| `fleet://clusters/{name}` | One cluster's facts (template) |
| `fleet://alerts/firing` | Fleet-wide firing alerts, cluster-labelled, capped |
| `fleet://promql/cheatsheet` | Supported functions, this server's relative-time syntax, and cost warnings |

## Prompts

Five templates for common SRE work. Each embeds the token discipline in its own
text, so the model is taught to work with the caps rather than against them.

| Prompt | Arguments | Shape |
|---|---|---|
| `investigate_alert` | `cluster`, `alertname`, `since` | `alerts` → `rules` for the expression → `query_range` on it → `targets` for the job → hypothesis |
| `cardinality_hotspot` | `cluster`, `topN` | `tsdb_stats` across dimensions → `label_values` on the worst → names the offending `metric{label}` and drafts a `metric_relabel_configs` stanza |
| `compare_clusters` | `query`, `clusters` or `labelSelector`, `window` | `fanout_query` → rank, spread, outliers. Explicitly instructed to report partial coverage rather than present it as complete |
| `capacity_check` | `cluster`, `resource`, `horizon` | `query_range` on request/limit/usage plus `predict_linear` → headroom and days to exhaustion |
| `fleet_health_sweep` | `labelSelector` | `list_clusters` → `targets` and `alerts` for degraded ones → ranked triage list. The start-of-shift prompt |
