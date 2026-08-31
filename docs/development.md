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
| `gremlins` | v0.6.0 | Mutation testing (`make mutate`); fetched on demand |

`make help` lists every target.

## The loop

```bash
make check     # what CI runs on a pull request: fmt, vet, lint, test -race
make test      # go test -race -covermode=atomic ./...
make cover     # per-package coverage summary
make deadcode  # fail review on production functions neither binary can reach
make mutate    # mutation testing against the per-package baseline; slow
make build     # both binaries into ./bin
```

A single package while you work on it:

```bash
go test -race -cover ./internal/promproxy/
go test -race -run TestGenerationCAS -v ./internal/registry/
make mutate MUTATION_PACKAGES=./internal/registry MUTATION_WORKERS=4
```

`make test` rejects any uncovered statement block in handwritten code. Generated
protobuf is excluded from that number because `buf breaking` and the regenerate
diff are its executable contract; commands and reusable test-support packages
are included.

## Mutation testing

100% statement coverage says every line ran. It does not say a test would have
noticed if the line were wrong, and the gap between those two claims is where
this project's real test debt lives. `make mutate` measures it: it rewrites one
operator at a time — `>` to `>=`, `==` to `!=`, `+` to `-` — reruns the
package's tests, and reports the mutants that survived.

```bash
make mutate                                       # every package
make mutate MUTATION_PACKAGES=./internal/promapi   # one, while you work on it
make mutate-deep MUTATION_PACKAGES=./internal/render  # wider mutators, noisy
```

Each package is scored separately against `hack/mutation-baseline.txt`, which
records the efficacy it is expected to hold. **The baselines are not all 100,
and they should not be.** Some mutants are *equivalent*: they change the source
without changing anything a test could observe. `internal/certproof` sizes its
transcript buffer with `make([]byte, 0, a+b+c)`; mutating that arithmetic
changes an allocation hint and nothing else, because `append` grows the slice
regardless. No test can distinguish those, and writing one that appears to
would be writing a test for the tool rather than for the software.

The current entries are **conservative floors, not measured scores**: the first
full sweep's number, floored to a whole percent and then reduced by three. That
margin is the tool's measured reproducibility, not padding. Efficacy is
`killed/(killed+lived)`, and a mutant that merely runs slowly is recorded as
TIMED OUT — leaving the numerator without leaving the denominator — so the
score moves with machine load. `internal/hub`, source unchanged, scored 92.93%
on 8 workers, 90.54% on 4, and 89.71% on 4 with a memory cap. A baseline set to
the best of those would fail on any differently loaded machine, and a flaky
gate teaches people to ignore the job.

A package below 100 has not yet had its survivors classified; that work is
per-package and ongoing. When you finish one, raise its number and record
beside it the reason it stopped where it did.

So when a mutant survives, classify it before reaching for the keyboard:

- **A missing assertion.** The common case, and the valuable one. The recurring
  shape in this codebase is an upper bound tested only from above: a test proves
  that one byte over the limit is refused, and none proves that a value sitting
  exactly *on* the documented limit is accepted, so nothing distinguishes `>`
  from `>=`. Add the assertion.
- **An equivalent mutant.** Record it, lower the baseline, move on.
- **A real defect.** Fix the code and say so loudly in the commit message.

Two properties of the tool are worth knowing before you trust a number:

- **Cap the memory.** Mutating a bound check is the point of the tool, and a
  bound check is sometimes the only thing between a test and an unbounded
  allocation: flip the comparison on a size cap and the mutated binary allocates
  whatever the input asks for. The timeout does not save you — the machine is
  gone long before a 40× timeout expires. `hack/mutation.sh` runs each package
  inside a `systemd-run` cgroup scope (`MUTATION_MEMORY_MAX`, default 8G) and
  warns if no cgroup is available. A mutant that hits the ceiling is OOM-killed
  and recorded as killed, which is honest: it was detected, by dying. There is
  deliberately no `GOMEMLIMIT` — it makes the GC fight near the limit and turns
  kills into timeouts.
- **Pin the timeout coefficient.** Gremlins derives each mutant's test timeout
  from the unmutated run. For a package whose tests finish in milliseconds the
  compile dominates and *every* mutant is reported as TIMED OUT — producing a
  clean-looking run with a fabricated score. `hack/mutation.sh` pins the
  coefficient high and fails loudly if a package reports no kills and no
  escapes; do not run `gremlins unleash` bare and believe the output.
- **The suite must be green first.** Gremlins compares each mutant against a
  passing baseline. Against a failing one it reads every mutant as killed and
  reports a perfect score.

`make mutate-deep` runs go-mutesting instead, which also deletes statements and
whole branches. That finds a class Gremlins cannot see — a test that ranges
over a slice it never asserts is non-empty passes just as happily when the
slice is empty — but it produces far more equivalent mutants. It is a reading
exercise, not a gate.

CI runs `make mutate` weekly and on demand, and does not block a merge.
`.github/workflows/mutation.yml` records what would have to be true first.

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

Nothing in the build or release path pulls from Docker Hub. The Go toolchain
image and the QEMU emulator both come from `mirror.gcr.io`, and `docker.io` is
not on the release workflow's egress allowlist. The mirror serves the identical
digests, so these are the same images by content address rather than
substitutes — a Docker Hub fetch failing is what broke the first v0.1.0 release
attempt, and a build that can be stopped by a registry we do not publish to is
a dependency worth not having. Published images go to GHCR.

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
