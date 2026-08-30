<!--
Copyright The prometheus-mcp-fleet Authors.
SPDX-License-Identifier: Apache-2.0

Thanks for the change. The checklist below is short on purpose: every line is
something that has actually gone wrong in a project of this shape. Tick what
applies and strike through what does not, with a reason.

If this fixes a security vulnerability, do not describe it here — see SECURITY.md.
-->

## What this changes

<!-- One paragraph. What behaviour is different afterwards, and for whom (agent,
hub operator, one of the ~100 spoke operators)? -->

## Why

<!-- Link the issue if there is one. If there is not, say what prompted this. -->

Fixes #

## How it was verified

<!-- Not "it compiles". What did you actually run, and what did you observe? -->

---

## Checklist

### Correctness

- [ ] `make check` passes locally (`fmt-check`, `vet`, `lint`, `test -race`).
- [ ] New or changed behaviour has a **table-driven test** with `t.Parallel()` in
      both scopes; error assertions use `errors.Is`/`errors.As`, struct
      assertions use `cmp.Diff`.
- [ ] Coverage did not go down. Packages under the 90% gate (`config`, `token`,
      `authn`, `ca`, `promapi`, `store`, `registry`, `promproxy`, `fleet`) are
      still above it.
- [ ] No new direct dependency, or an ADR is included justifying it against the
      closed dependency budget (BUILD_SPEC section 2).

### Wire compatibility — the hub must serve the previous spoke minor

<!-- ~100 clusters never upgrade in lockstep. A hub that only speaks to spokes
built from the same commit is not a fleet product. -->

- [ ] This change does **not** touch `api/proto/**`.
- [ ] Or: it touches the proto and the change is **additive only** — no field
      renumbered, no field removed, no field type changed, no RPC removed,
      no enum value repurposed. `buf breaking` is green against `main`.
- [ ] An **older spoke minor still works against this hub**, and a newer spoke
      degrades cleanly against an older hub (unknown fields ignored, not fatal).
      Say below how you checked, or why it cannot apply.

<!-- How wire compatibility was verified: -->

### Charts

- [ ] No chart change.
- [ ] Or: `Chart.yaml` `version` is bumped (independent SemVer — `ct lint
      --check-version-increment` enforces this, and a chart version is
      immutable once published).
- [ ] `values.yaml` keys are documented with `# --` comments and
      `values.schema.json` is updated; typos must fail `helm install`, not
      silently default.
- [ ] `helm unittest` suites and `__snapshot__` files are updated — a silently
      vanished `securityContext` is exactly what the snapshots exist to catch.
- [ ] `README.md` regenerated with `make helm-docs` (CI verifies this).
- [ ] Anything added to the **spoke** chart is justified: it will be reviewed by
      ~100 platform teams, and new RBAC especially needs a sentence in the
      chart README saying plainly what it grants and why.

### Documentation

- [ ] Exported symbols are documented, sentence starting with the symbol name.
- [ ] New or changed `PMF_*` config keys are in the config reference **and** in
      the corresponding chart values.
- [ ] Operator-visible behaviour change is reflected in `README.md` / `docs/`.
- [ ] A new alert or metric is documented with its runbook.

### Security and supply chain

- [ ] No secret is logged, formatted with `%v`, or serialised. Secrets are a
      type whose `String()`/`LogValue()`/`MarshalJSON()` return `[REDACTED]`.
- [ ] Any new route is on the hard-coded allow-list in `internal/promapi` and is
      re-validated spoke-side. The agent still never supplies a URL or path.
- [ ] Any new workflow or action is pinned by full 40-character commit SHA with
      a `# vX.Y.Z` comment, declares minimal `permissions:`, and starts with
      `step-security/harden-runner`.
- [ ] Nothing privileged became reachable from a fork pull request.

### Release impact

- [ ] This does not move the `stable` tag. (Nothing in a PR should. `stable`
      moves only through the environment-protected `promote` workflow.)
- [ ] Commit messages follow Conventional Commits; a breaking change is marked
      `!` and explained in the body.
