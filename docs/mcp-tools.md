<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# MCP tools

Sixteen tools, all read-only. Every argument table here is derived from the
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
| `table` | ~35% below `json` | Fixed-width text. Best for wide, shallow results — targets, alerts, rules |

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
| `filter` | — | Substring match on cluster ID or display name |
| `labelSelector` | — | Object of label equality matches, e.g. `{"env":"prod"}` |
| `status` | `all` | `all` · `connected` · `degraded` · `disconnected` |
| `limit` | `100` | |
| `format` | `compact` | |

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
"downsampled": {"requestedStep": "15s", "appliedStep": "3m", "reason": "maxPoints=120"}
```

Read that before reasoning about a spike — averaged data hides them. If you need
raw resolution, shorten the range rather than raising `maxPoints`.

For scale: a six-hour range over 84 series is roughly 4.6 MB of native
Prometheus JSON, on the order of 1.4 million tokens, which fits in no context
window that exists. The same query in `compact` is about 34 KB.

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

## Operations

### `targets`

Scrape target health, summarised then listed.

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `state` | `active` | `active` · `dropped` · `any` |
| `health` | `any` | `any` · `up` · `down` · `unknown` |
| `job` | — | |
| `limit` | `50` | |

**Scrape URLs are redacted.** `scrapeUrl`, `globalUrl` and query strings are
stripped before the result leaves the hub, because scrape configurations
routinely carry bearer tokens and basic-auth credentials in URL parameters.

### `rules`

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `type` | `all` | `all` · `alert` · `record` |
| `group` / `ruleName` | — | |
| `includeExpr` | `false` | Expressions are verbose; ask only when you need them |
| `limit` | `50` | |

### `alerts`

| Argument | Default | Notes |
|---|---|---|
| `cluster`* | — | |
| `state` | `firing` | `all` · `firing` · `pending` |
| `alertname` / `severity` / `labelSelector` | — | |
| `includeAnnotations` | `true` | |
| `limit` | `50` | |

Annotations are attacker-influenced free text. They are sanitised and clipped,
and they arrive inside the `_untrusted` envelope.

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
| `start` / `end` | `now` / `now` | Range mode |
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

## Errors

Two kinds, and the distinction matters.

**Protocol errors** (JSON-RPC `error`) mean the request never really happened:
unknown tool, schema-invalid arguments, authentication failure. An
authentication failure is deliberately never a tool result — an agent that saw
one as a tool error would try to "fix" it by editing its PromQL.

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
| `FORBIDDEN` | Your scope forbids this tool or cluster | Ask an operator to widen the key's scope |
| `SPOKE_UNREACHABLE` | Enrolled but not connected; carries `lastSeen` | Retryable |
| `PROMQL_PARSE` | Prometheus' own parse error, with a caret | Fix the query; `explain_promql` validates cheaply |
| `RANGE_TOO_LARGE` | Includes a corrected argument object to copy | Use it |
| `TOO_LARGE` | Response exceeded the byte budget | Raise `step`, narrow the selector |
| `BUSY` | Per-cluster in-flight limit reached | Retryable; back off |
| `QUERY_TIMEOUT` | Upstream took too long | Narrow the range |
| `TSDB_STATS_UNAVAILABLE` | Endpoint disabled upstream | Use `count by(__name__)` |
| `NO_SELECTOR_TOO_BROAD` | Untargeted fan-out refused | Add `clusters` or `labelSelector` |

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
