<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0
-->

# Development

How to build, test and debug this project. For the rules a pull request is held
to, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Go | 1.27+ | Everything |
| `buf` | 1.72+ | Regenerating protobuf, only if you touch `api/proto` |
| `golangci-lint` | v2 | `make lint` |
| Docker | any recent | Building images, kind |
| `helm` | 3.19+ | Chart work |
| `kubectl`, `kind` | recent | End-to-end tests |
| `helm-unittest`, `helm-docs` | — | Chart tests and README generation |
| `deadcode` | x/tools v0.49.0 | Production reachability gate |
| `gremlins` | v0.6.0 | Mutation coverage and test-efficacy gate |

`make help` lists every target.

## The loop

```bash
make check     # what CI runs on a pull request: fmt, vet, lint, test -race
make test      # go test -race -covermode=atomic ./...
make cover     # per-package coverage summary
make deadcode  # fail review on production functions neither binary can reach
make mutation  # 100% mutant coverage and efficacy; intentionally slow
make build     # both binaries into ./bin
```

A single package while you work on it:

```bash
go test -race -cover ./internal/promproxy/
go test -race -run TestGenerationCAS -v ./internal/registry/
make mutation MUTATION_PACKAGES=./internal/registry MUTATION_WORKERS=4
```

`make test` rejects any uncovered statement block in handwritten code. Generated
protobuf is excluded from that number because `buf breaking` and the regenerate
diff are its executable contract; commands and reusable test-support packages
are included. `make mutation` uses a 99.99 threshold because Gremlins treats a
score *equal* to the configured threshold as a failure—99.99 therefore means an
actual 100% for both mutant coverage and killed-mutant efficacy.

## Running it locally, without Kubernetes

Both binaries run outside a cluster. The hub falls back to the file state
backend when it cannot find a projected service account token.

```bash
# Terminal 1 — a Prometheus to talk to
docker run --rm -p 9090:9090 prom/prometheus

# Terminal 2 — the hub
mkdir -p /tmp/pmf
./bin/hub \
  --state-backend=file --state-file=/tmp/pmf/state.json \
  --pepper-file=/tmp/pmf/pepper --ca-cert-file=/tmp/pmf/ca.crt \
  --ca-key-file=/tmp/pmf/ca.key \
  --mcp-addr=:8080 --admin-addr=127.0.0.1:9091 \
  --public-url=http://127.0.0.1:8080/mcp \
  --log-level=debug
# The bootstrap admin key is printed once on first start. Save it.

# Terminal 3 — mint credentials
export PMF_ADMIN_TOKEN=pmf_adm_...
./bin/hub keys create --class agent --name dev --clusters '*' --tools '*'
./bin/hub enroll create --cluster local-dev --labels env=dev

# Terminal 4 — the spoke
./bin/spoke \
  --cluster-id=local-dev --hub-endpoints=ws://127.0.0.1:8080/tunnel \
  --hub-api-url=https://127.0.0.1:8080 --hub-ca-file=/tmp/pmf/ca.crt \
  --enrollment-token-file=/tmp/pmf/enroll.token \
  --identity-backend=file --data-dir=/tmp/pmf/spoke \
  --prometheus-url=http://127.0.0.1:9090 --log-level=debug
```

Then drive the MCP surface directly:

```bash
curl -sS localhost:8080/mcp \
  -H "Authorization: Bearer $PMF_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

Or point a real MCP client at `http://localhost:8080/mcp` with that bearer
token — that is the fastest way to find a tool whose schema reads badly to a
model.

## Layout

See [architecture.md](architecture.md#package-layout) for the layers.
`test/arch` enforces them, so a misplaced import fails a test rather than
getting through review.

The three packages worth reading first, in order:

1. `internal/promapi` — the allow-list. Everything the system can ask Prometheus
   to do is one table in one file.
2. `internal/tunnel` — the transport contract, with no gRPC in it. Read this
   before `wstun`, or the role reversal will make no sense.
3. `internal/fleet` — the domain types the whole graph hangs off.

## Protobuf

```bash
make proto            # buf lint + generate + gofmt
make proto-breaking   # fail if the wire contract broke against origin/main
```

Generated code is committed. CI regenerates and fails on a diff, so a
regeneration you forgot is caught rather than silently shipped.

The hub must support the previous spoke minor version — see
[CONTRIBUTING.md](../CONTRIBUTING.md#wire-compatibility). Adding a field is
fine; changing what one means is not.

## Testing

**Table-driven, parallel, no framework.** `t.Parallel()` in both the outer
function and each subtest, `cmp.Diff` for structs, `errors.Is`/`errors.As` for
errors. No testify, no gomock — fakes are hand-written and live next to the code
that needs them.

**The tunnel conformance suite** is the interesting one.
`internal/tunnel/tunneltest` is a single suite run against **all three**
transports: the in-process one (`memtun`), the gRPC-over-socket one (`grpctun`),
and the production WebSocket one (`wstun`) over a real `httptest.Server`. That is
what proves the transport is genuinely swappable, and it means hub routing can be
tested with no network at all.

A fake that is easier than reality is worse than no fake — `memtun` reproduces
cancellation, deadlines, byte caps and close semantics faithfully, and if you
add a behaviour to `grpctun` you must add it to `memtun` too.

**Fakes available to you:** `internal/testutil` has a `FakePrometheus`
(`httptest.Server` with realistic fixtures and injectable latency, failures,
oversized bodies and slow bodies) and a manually advanced `Clock`.

**Fuzzing:**

```bash
make fuzz                                             # every target, 30s each
go test -run '^$' -fuzz FuzzLookup -fuzztime=5m ./internal/promapi/
```

The seed corpus in `testdata/fuzz/` is committed, including inputs that once
failed — those are regression tests now. `FuzzLookup` found both a panic and a
percent-encoding path-aliasing bug in the allow-list; if you touch parsing or
validation, extend a target.

**Golden files.** MCP tool schemas are golden files under
`internal/mcptools/testdata/schemas/`. Regenerate with `-update` and *read the
diff* — a schema change is a compatibility change for every agent already using
the tool.

```bash
go test ./internal/mcptools/ -update
```

## Charts

```bash
make helm-lint       # --strict, against every ci/ values file
make helm-template   # render with defaults
make helm-unittest
make helm-docs       # regenerate chart READMEs from values.yaml
```

Chart READMEs are generated from the `# --` description comments in
`values.yaml`, and CI verifies they are current. Document the value, not the
README.

## End to end

```bash
make e2e   # needs kind and docker; takes several minutes
```

It stands up a kind cluster with a real Prometheus, builds and loads both
images, installs both charts, waits for the spoke to enroll, and drives a real
MCP `query` call through the hub asserting `up == 1`. If enrollment or the
tunnel breaks, this is what catches it — the unit tests cannot.

## Images

```bash
make images                       # both, locally
make image-hub VERSION=dev
```

Builds are static (`CGO_ENABLED=0`), `-trimpath`, and reproducible:
`SOURCE_DATE_EPOCH` comes from the tag's commit time, so rebuilding the same
commit on fresh base images produces byte-identical binaries. That is what makes
the weekly CVE rebuild verifiable rather than a leap of faith.

Base images are digest-pinned. Renovate bumps them; do not replace a digest with
a tag.

## Debugging

**Logs.** `--log-level=debug` logs one line per request. Secrets are wrapped in
a redacting type, so `%+v` on a config or a key is safe — but never add a raw
token to a log line to "just check", because that habit is how they end up in
production.

**Metrics.** `curl localhost:9091/metrics`. Names and the cardinality policy are
in [ADR-0008](adr/0008-metric-naming-and-cardinality.md); a new label needs a
stated cardinality bound.

**Tracing.** Set `OTEL_EXPORTER_OTLP_ENDPOINT` and traces span
`mcp.tool.call → hub.proxy → spoke.prom.request` across the tunnel. Unset, the
provider is a no-op with no network activity.

**pprof.** `--pprof-enabled` exposes it on the admin listener, which defaults to
loopback and is never in the chart's Service.

**A spoke that will not connect** is nearly always one of: an expired enrollment
token (15 minutes, single use), a cluster ID that does not match the one the
token was minted for, or the hub's tunnel address not being reachable. The
spoke's logs name which.

## Common tasks

**Adding an MCP tool.** Add the endpoint to `internal/promapi` if it is not
there; implement in `internal/mcptools` with `mcp.AddTool[In,Out]` so the schema
is inferred from the struct; add the golden schema file; document it in
[mcp-tools.md](mcp-tools.md). Then read the tool description as if you were the
model — a description that is ambiguous to you is worse to it.

**Adding a config key.** `internal/config` only; the flag and environment name
derive from one declaration so they cannot drift. Add it to
[configuration.md](configuration.md) and to both charts.

**Adding a metric.** `internal/obs`. Every label must come from a closed set,
and the pull request must state the cardinality bound.

**Adding a dependency.** Write an ADR first. `test/arch` will fail until
`allowedDirectRequires` is extended, which is intentional friction.
