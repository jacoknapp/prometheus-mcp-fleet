# 0009. No client-go; a minimal Kubernetes client instead

* Status: Accepted
* Date: 2026-08-29

## Context

[ADR-0005](0005-no-database-state-in-secrets.md) put the hub's durable state in a
Kubernetes Secret, and the spoke's issued key and certificate in a Secret in its
own namespace. Both now need to talk to the Kubernetes API.

The default answer is `k8s.io/client-go`. It is correct, well maintained and
universally understood. It also brings `k8s.io/api`, `k8s.io/apimachinery`,
`k8s.io/klog`, a large slice of `gogo/protobuf` and a long transitive tail — tens
of megabytes of module and a meaningful slice of binary size, for a project whose
spoke is supposed to idle at about 20 MiB and whose dependency budget is
deliberately closed ([ADR-0010](0010-dependency-budget.md)).

It is worth being precise about what we actually need. Three verbs on one
resource kind, in one namespace, by name: get a Secret, create a Secret, update a
Secret with optimistic concurrency. No informers, no watches, no work queues, no
listers, no scheme registration, no CRDs, no leader election.

## Decision

Write `internal/kube`: a few hundred lines of standard library (it started at
roughly 250 and has grown with better error messages and tests, but still
touches nothing beyond the three verbs below).

* In-cluster configuration from the projected service account —
  `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` plus
  `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`.
* The token is re-read rather than cached for the process lifetime, because
  Kubernetes rotates projected tokens and a token cached at startup begins
  returning 401 about an hour later. This is the single most common bug in
  hand-rolled Kubernetes clients and it fails hours after deployment, when
  nobody is watching.
* TLS verified against the projected CA bundle. `InsecureSkipVerify` does not
  appear in the package.
* `UpdateSecret` sends `metadata.resourceVersion` and maps HTTP 409 to
  `ErrConflict`, which is the compare-and-swap the enrollment burn depends on.
* HTTP 403 is mapped to an error that names the RBAC rule the operator is
  missing, because a missing Role is the most common misconfiguration and a bare
  "403" wastes an hour.

## Consequences

**Better.** The dependency budget holds. The binaries stay small. The entire
Kubernetes interaction is one file a reviewer can read in ten minutes, which
matters when 100 platform teams are deciding whether to run the spoke.

**Worse.** We own it. Anything the API server does that we did not anticipate —
an unusual error shape, a redirect, an admission webhook returning something
strange — is ours to handle. We are also hand-rolling the JSON shapes of
`Secret` and `Status`, which are stable but not ours.

**The boundary that keeps this honest.** This is only defensible while the need
stays at three verbs on one resource kind. If the project ever wants watches,
informers, CRDs or leader election, that is the point to adopt client-go and
supersede this record — not to keep growing a homemade client until it is a bad
copy of one. The package doc says so explicitly.

## Alternatives considered

* **`k8s.io/client-go`.** The right answer for a controller. Rejected here on
  weight alone, for three verbs.
* **`kubernetes/dynamic` or the discovery client.** Same dependency tree.
* **Shell out to `kubectl`.** Rejected: it puts a binary, a version skew and a
  process spawn on the credential path, and the distroless images have no shell.
* **Mount the Secret as a volume and let the kubelet sync it.** Works for
  reading, and we would still need the API for writing. It also introduces a
  propagation delay of up to a minute, which is unacceptable for the enrollment
  burn.
