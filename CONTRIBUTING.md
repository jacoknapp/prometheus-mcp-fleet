# Contributing

Thanks for considering it. This document covers what you need to know before
opening a pull request; [docs/development.md](docs/development.md) covers the
mechanics of building and testing.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Contributions are licensed under [Apache-2.0](LICENSE).

## Before you start

**Open an issue first for anything structural.** A new MCP tool, a change to the
hub↔spoke wire protocol, a new dependency or a change to the security model is
much cheaper to discuss than to review. Small fixes, documentation and tests
need no preamble — just send them.

**Read the ADRs.** Several things in this codebase look wrong on first contact
and are deliberate: gRPC's client and server roles are inverted, PromQL is never
parsed, there is no database, and the MCP server is not an OAuth resource
server. Each has a record in [docs/adr/](docs/adr/) explaining the trade. If you
think one is wrong, say so — a superseding ADR is a perfectly good pull request.

## The three rules that get pull requests sent back

### 1. The dependency budget is closed

The direct dependency list in `go.mod` is fixed and asserted by
`test/arch`. Adding to it requires an ADR stating what the dependency does that
the standard library cannot, and what it costs in transitive modules.

This is not asceticism. The spoke is installed into roughly 100 clusters by
teams who did not write it and will read its SBOM. See
[ADR-0010](docs/adr/0010-dependency-budget.md) for the reasoning and for the
standard-library replacement we expect instead.

In particular: `log/slog` not zap, `flag` not cobra, `net/http` not a router
framework, table-driven tests and hand-written fakes not testify or gomock.

### 2. Layering is enforced

`test/arch` asserts the dependency direction. A package may import its own layer
or lower, never higher, and several specific edges are banned outright with the
reason recorded next to them.

If you need something from a higher layer, the answer is almost always to
declare a small interface at the point of use and let the composition root wire
the real implementation — that is how `registry` and `promproxy` stay testable
without a Prometheus registry or a network.

A new package must be added to the layer map, which is a deliberate way of
making you say where it belongs.

### 3. Security invariants are not negotiable

[SECURITY.md](SECURITY.md#security-invariants) lists eight. A change that breaks
one will not be merged regardless of what else it does. The three that catch
people out:

- **The agent never supplies a path.** If you are adding a tool, it maps to an
  existing `promapi.Endpoint` or you add one to the table. Do not add a
  parameter that lets a caller influence a URL.
- **The spoke re-validates independently.** Do not "optimise away" the
  spoke-side check because the hub already did it. That redundancy is the point.
- **Secrets are a type, not a string.** Anything secret is wrapped so `String()`,
  `LogValue()` and `MarshalJSON()` all return `[REDACTED]`. Never rely on
  remembering not to log something.

## Standards

**Every exported symbol is documented**, with the sentence starting with the
symbol's own name. Every package has a `doc.go` stating its responsibility, who
may import it, and its concurrency guarantees. `revive`'s exported rule enforces
the first; reviewers enforce the rest.

**Errors** are package-level sentinels, wrapped with `%w` and non-redundant
context — `fmt.Errorf("route %s: %w", id, err)`, never `"failed to route"`.
Callers branch with `errors.Is` and `errors.As`, never on strings.

**Context** is the first parameter of every function that touches I/O.
`context.Background()` appears only in `main` and in tests.

**Tests are table-driven**, with `t.Parallel()` in both the outer function and
each subtest, `cmp.Diff` for structs and `errors.Is`/`errors.As` for errors.

**Comments explain why, not what.** A comment restating the code is noise; a
comment explaining why the obvious approach was rejected is the most valuable
line in the file.

## Coverage

The repository gate is 80%. These packages are held to 90% or higher because a
bug in them is a security bug or a fleet-wide outage: `fleet`, `config`,
`token`, `authn`, `ca`, `promapi`, `store`, `registry`, `promproxy`, `kube`.

Coverage is a floor, not a goal. A test that executes a line without asserting
anything meaningful is worse than no test, because it makes the number lie. What
we actually look for is that every `if err != nil` branch in those packages has a
test that reaches it.

**Fuzz targets earn their keep here.** `FuzzLookup` found both a panic and a
path-aliasing bug in the allow-list that no example-based test would have. If
you touch parsing or validation, add or extend one.

## Wire compatibility

The hub must support the **previous spoke minor version**. A hundred clusters
never upgrade in lockstep, and a change that requires them to is not shippable.

Concretely: adding a protobuf field is fine, changing the meaning of one is not,
and removing one requires a deprecation release first. `buf breaking` runs in CI
against `main` and will tell you.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`. Breaking
changes get a `!` and a `BREAKING CHANGE:` footer. The changelog is generated
from these, so a lazy message becomes a bad release note.

Keep pull requests focused. A refactor bundled with a behaviour change makes
both harder to review and impossible to revert cleanly.

The pull request template's checklist is real. In particular, a chart change
needs a chart version bump — `ct lint --check-version-increment` will fail
otherwise.

## Review

Expect a first response within a few days. Reviews go after the design and the
edge cases; style is handled by `golangci-lint` and is not worth a human's
attention.

You will be asked "what happens when this fails?" a lot. This is a monitoring
tool: it is at its most important when something is already broken, so a code
path that only works on the happy path is not finished.

## Releasing

Maintainers only. `release-please` opens a release pull request from the
Conventional Commit history; merging it tags `vX.Y.Z`, which triggers the
release workflow. Publishing does **not** promote — moving the `stable` tag is a
separate, human-approved workflow, and it is the fleet-wide kill switch. See
[ADR-0011](docs/adr/0011-auto-update-is-opt-in.md).
