# Workflows

Everything CI does for `prometheus-mcp-fleet`, what it is allowed to touch, and
how to do it by hand when GitHub Actions is unavailable.

Four rules hold across every file here. If you are adding a workflow, they are
not negotiable:

1. **Every action is pinned by full 40-character commit SHA**, with a trailing
   `# vX.Y.Z` comment — `actions/*` included. Renovate refreshes both the SHA
   and the comment. A floating tag is a remote-code-execution primitive that
   updates itself.
2. **`permissions:` is `contents: read` at the workflow level**, and any job
   needing more declares exactly what it needs and nothing else.
3. **`step-security/harden-runner` is the first step of every job** —
   `egress-policy: audit` on CI, `block` with an explicit allow-list on anything
   that can publish, sign or promote.
4. **Nothing privileged runs on a fork pull request.** There is no
   `pull_request_target` anywhere in this repository, and there is no reason to
   add one: a fork PR gets `contents: read` and no secrets, which is why the
   e2e job mints its own credentials with `openssl rand` instead of reading any.

---

## What runs when

| Workflow | Trigger | What it does | Permissions above the default | Secrets |
|---|---|---|---|---|
| [`ci.yml`](ci.yml) | `pull_request`, `push: main` | `golangci-lint` v2 + `gofmt` + `go vet`; `go test -race -covermode=atomic` with the coverage percentage in the step summary and a hard floor; cross-compile matrix (linux/darwin × amd64/arm64); `govulncheck`; `buf lint`/`format`/`breaking` vs `main`; `tidy-check`; `generate-check`; `arch` (layering + dependency budget, `test/arch`) | none | none |
| [`chart.yml`](chart.yml) | `pull_request` touching `charts/**`, `push: main` | `helm lint --strict` over every `ci/` values file; `helm unittest` incl. `__snapshot__`; `kubeconform` against k8s 1.28 / 1.31 / 1.34; `ct lint --check-version-increment` and `ct install` on kind across the same three; `helm-docs` verify-only | none | none |
| [`e2e.yml`](e2e.yml) | `pull_request`, nightly `03:17 UTC`, `workflow_dispatch` | kind cluster, real `kube-prometheus-stack`, both images built and side-loaded, hub then spoke installed from the real charts, spoke enrolment asserted from the hub's own metrics, then `go test -tags e2e ./test/e2e/...` drives a real MCP `query` tool call and asserts `up == 1`. Uploads `kubectl cluster-info dump` and every pod log on failure | none | none |
| [`release.yml`](release.yml) | `push: tags v*` | GoReleaser (binaries, archives, checksums, SBOMs, source archive, GitHub Release); multi-arch hub and spoke images to GHCR, **Trivy-gated before push**, SLSA-provenance- and SBOM-attested, cosign-signed; both charts packaged with the release `appVersion` and the published image digests, pushed as OCI and cosign-signed | `contents: write` (release only), `packages: write`, `id-token: write`, `attestations: write` | `GITHUB_TOKEN` only |
| [`weekly-rebuild.yml`](weekly-rebuild.yml) | `schedule: 0 6 * * 1`, `workflow_dispatch` | Rebuilds the latest release tag from unchanged source onto freshly pulled base images, publishes `X.Y.Z-build.N`, re-attests and re-signs, runs Trivy and Grype, and opens or updates one tracking issue when a new unfixable HIGH/CRITICAL appears | `packages: write`, `id-token: write`, `attestations: write`, `issues: write` | `GITHUB_TOKEN` only |
| [`promote.yml`](promote.yml) | `workflow_dispatch` | **The fleet-wide kill switch.** Verifies a digest's cosign signature, its SLSA provenance and its soak age in an unprivileged job, then — behind the protected `production` environment and a human approval — moves the `stable` OCI tag to it | `packages: write`, `attestations: read`; job gated on environment `production` | `GITHUB_TOKEN` only |
| [`codeql.yml`](codeql.yml) | `pull_request`, `push: main`, weekly Tue `04:41 UTC` | CodeQL for Go with `security-extended` | `security-events: write`, `actions: read` | none |
| [`scorecard.yml`](scorecard.yml) | `push: main`, weekly Wed `05:23 UTC`, `workflow_dispatch` | OpenSSF Scorecard, SARIF uploaded to code scanning and published to the OpenSSF API | `security-events: write`, `id-token: write`, `actions: read`, `checks/issues/pull-requests: read` | none |
| [`stale.yml`](stale.yml) | daily `01:07 UTC`, `workflow_dispatch` | Conservative stale policy: issues 90d to stale / 30d to close, PRs 45d to stale and never auto-closed, generous exempt labels | `issues: write`, `pull-requests: write` | none |

**No workflow in this repository uses a PAT.** GHCR pushes authenticate with the
job's `GITHUB_TOKEN`; cosign and the attestation actions are keyless via the
job's OIDC token. If you find yourself wanting a PAT, you almost certainly want
a GitHub App token or a different job boundary instead.

---

## Required status checks

Point branch protection at the two aggregate jobs, not the individual ones, so
adding a job later does not mean editing the protection rule:

- `ci-required` (from `ci.yml`)
- `chart-required` (from `chart.yml`)

`e2e` is deliberately *not* required on every PR — it is slow and it depends on
upstream chart repositories being reachable. It runs on PRs that touch code,
charts or the Dockerfile, and nightly.

---

## One-time repository setup

These are not in code and CI cannot create them:

1. **Environment `production`** — Settings → Environments → New environment.
   Add at least one required reviewer, and restrict deployment branches to
   `main`. `promote.yml` will not work without it, which is the point.
2. **Dependabot security updates** — Settings → Code security → enable.
   `.github/dependabot.yml` disables Dependabot *version* updates for `gomod`
   and `docker` (Renovate owns those) but security updates are a separate
   switch and must be on.
3. **Private vulnerability reporting** — Settings → Code security → enable.
   `SECURITY.md` sends reporters there.
4. **Branch protection on `main`** — require the two checks above, require a
   Code Owner review, and require linear history.
5. **Actions permissions** — Settings → Actions → General → "Allow enterprise,
   and select non-enterprise, actions and reusable workflows", listing the
   action owners used here. Also set the default workflow token to read-only.
6. **GHCR package visibility** — the first push creates the packages as private.
   Make `prometheus-mcp-fleet/hub`, `prometheus-mcp-fleet/spoke` and both chart
   packages public, and link them to this repository so `GITHUB_TOKEN` retains
   write access.

---

## Cutting a release by hand

For when Actions is down, GitHub is degraded, or you need a release from a
machine you control. This reproduces `release.yml` step for step. It needs
`go`, `docker` with buildx, `helm`, `cosign`, `syft`, `goreleaser` and `gh`.

Everything below assumes the tag already exists and is pushed.

### 0. Set the variables the workflow would have computed

```bash
export TAG=v1.2.3
export VERSION=${TAG#v}                          # charts use the v-less form
export COMMIT=$(git rev-list -n1 "$TAG")
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct "$TAG")
export REGISTRY=ghcr.io/jacoknapp/prometheus-mcp-fleet
export CHART_REGISTRY=ghcr.io/jacoknapp/charts

git checkout "$TAG"
git status --porcelain   # MUST be empty. A dirty tree means a lying build stamp.
```

`SOURCE_DATE_EPOCH` is the tagged commit's committer time and is what makes the
build reproducible — the weekly rebuild reuses the same value so the compiled
binary is byte-identical and only the base layer differs. Do not substitute
`date +%s` here; that quietly destroys the property.

### 1. Log in to GHCR

Use a token with `write:packages`, and prefer a short-lived one.

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u jacoknapp --password-stdin
echo "$GHCR_TOKEN" | helm registry login ghcr.io --username jacoknapp --password-stdin
```

### 2. Binaries, checksums, SBOMs and the GitHub Release

```bash
export GITHUB_TOKEN=...        # repo scope, for creating the Release
goreleaser release --clean
```

Artifacts land in `dist/`. `checksums.txt` is cosign-signed by GoReleaser's
`signs:` block; that needs an interactive Sigstore browser flow when it is not
running under an OIDC-providing CI. If you cannot do the keyless flow, run
`goreleaser release --clean --skip=sign` and say so in the release notes rather
than pretending an unsigned artifact is signed.

### 3. Images

Build and scan a single-arch image first. Scanning after the push means the
vulnerable digest is already pullable, which is not a gate.

```bash
for component in hub spoke; do
  docker buildx build \
    --platform linux/amd64 --load --pull \
    --build-arg COMPONENT="$component" \
    --build-arg VERSION="$VERSION" \
    --build-arg COMMIT="$COMMIT" \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -t "$REGISTRY/$component:scan" -f Dockerfile .

  trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
    "$REGISTRY/$component:scan"
done
```

Then build and push the real multi-arch image:

```bash
for component in hub spoke; do
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" docker buildx build \
    --platform linux/amd64,linux/arm64 --push --pull \
    --provenance mode=max --sbom true \
    --build-arg COMPONENT="$component" \
    --build-arg VERSION="$VERSION" \
    --build-arg COMMIT="$COMMIT" \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --label org.opencontainers.image.version="$VERSION" \
    --label org.opencontainers.image.revision="$COMMIT" \
    -t "$REGISTRY/$component:$VERSION" \
    -t "$REGISTRY/$component:${VERSION%.*}" \
    -f Dockerfile .
done
```

Do **not** add `:latest` and do **not** add `:stable`.

Capture the digests and sign them:

```bash
for component in hub spoke; do
  digest=$(crane digest "$REGISTRY/$component:$VERSION")
  echo "$component -> $digest"
  cosign sign --yes "$REGISTRY/$component@$digest"
  syft "$REGISTRY/$component@$digest" -o spdx-json > "sbom-$component.spdx.json"
  cosign attest --yes --predicate "sbom-$component.spdx.json" \
    --type spdxjson "$REGISTRY/$component@$digest"
done
```

SLSA provenance from `actions/attest-build-provenance` is a CI-only artifact —
it attests *that GitHub Actions built it*, which by definition a laptop cannot.
A manual release will therefore have a cosign signature and an SBOM attestation
but no GitHub provenance. **Say this explicitly in the release notes**, because
`promote.yml` verifies provenance and will refuse to promote such a digest.
Promoting a hand-built image requires a deliberate, documented exception.

### 4. Charts

Chart versions are immutable once published. If `helm show chart` finds the
version already in the registry, bump `Chart.yaml`'s `version` and start again.

```bash
for chart in charts/prometheus-mcp-hub charts/prometheus-mcp-spoke; do
  name=$(basename "$chart")
  ver=$(helm show chart "$chart" | awk '$1=="version:"{print $2}')

  helm show chart "oci://$CHART_REGISTRY/$name" --version "$ver" >/dev/null 2>&1 \
    && { echo "$name $ver already published — bump Chart.yaml"; exit 1; }

  component=hub; [ "$name" = prometheus-mcp-spoke ] && component=spoke
  digest=$(crane digest "$REGISTRY/$component:$VERSION")

  yq -i ".image.tag = \"$VERSION\""     "$chart/values.yaml"
  yq -i ".image.digest = \"$digest\""   "$chart/values.yaml"

  helm package "$chart" --app-version "$VERSION" --destination dist-charts
  out=$(helm push "dist-charts/$name-$ver.tgz" "oci://$CHART_REGISTRY")
  echo "$out"
  cosign sign --yes "$CHART_REGISTRY/$name@$(echo "$out" | awk '/^Digest:/{print $2}')"
done

git checkout -- charts/   # the digest pin is a packaging step, not a commit
```

### 5. Do not move `stable`

A release publishes; it does not promote. `stable` is what ~100 production
clusters follow, and it moves only through `promote.yml` behind the `production`
environment. If you have just hand-built a release because Actions is down, you
almost certainly should **not** be promoting it at the same time — the whole
value of the split is that publishing is routine and promoting is not.

If you genuinely must promote by hand, verify first, exactly as the workflow
does, and then:

```bash
cosign verify "$REGISTRY/hub@$digest" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/jacoknapp/prometheus-mcp-fleet/\.github/workflows/.+@refs/tags/v.+$'

gh attestation verify "oci://$REGISTRY/hub@$digest" --repo jacoknapp/prometheus-mcp-fleet

crane digest "$REGISTRY/hub:stable"   # write this down — it is your rollback
crane tag "$REGISTRY/hub@$digest" stable
```

Roll back by running `crane tag` again with the digest you wrote down.

---

## Rebuilding for CVEs by hand

Same as a release, with three differences: check out the *existing* release tag
rather than a new one, keep that tag's `SOURCE_DATE_EPOCH`, and publish under
`X.Y.Z-build.N` where `N` is one more than the highest existing build number.
Build with `--no-cache --pull` so the base image is genuinely re-resolved;
without that this is an expensive no-op.

A HIGH/CRITICAL finding that **has** a fix means the rebuild failed at its job —
bump the base image digest in the `Dockerfile` instead of shipping it. A finding
with **no** fix cannot be rebuilt away; publish, and record it on the tracking
issue so the exposure is visible rather than absorbed into a green tick.

---

## Local equivalents

Most of CI is a Makefile target, on purpose — a check you cannot run locally is
a check you will learn to ignore.

| CI job | Local |
|---|---|
| `ci / lint` | `make fmt-check vet lint` |
| `ci / test` + coverage | `make cover` |
| `ci / build` | `GOOS=darwin GOARCH=arm64 make build` |
| `ci / govulncheck` | `make vuln` |
| `ci / buf` | `make proto` and `make proto-breaking` |
| `ci / tidy-check` | `make tidy && git diff --exit-code go.mod go.sum` |
| `ci / generate-check` | `make proto && git diff --exit-code internal/gen` |
| `ci / arch` | `go test ./test/arch/...` |
| `chart / lint` | `make helm-lint` and `make helm-template` |
| `chart / unittest` | `make helm-unittest` |
| `chart / helm-docs` | `make helm-docs` |
| `chart / ct` | `ct lint --config .github/ct.yaml --all` |
| `e2e` | `make e2e` (needs kind and docker) |
| `release / images` | `make images` |

`make check` is the pull-request gate in one command.
