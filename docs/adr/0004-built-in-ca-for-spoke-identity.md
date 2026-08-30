# 0004. A built-in CA issues spoke identities

* Status: Accepted
* Date: 2026-08-29

## Context

A spoke must prove which cluster it is. That identity is the hinge of the whole
security model: it decides whose metrics an agent sees, and a spoke that could
claim another cluster's identity could feed an on-call engineer fabricated data
about a system it does not run.

The identity must be unforgeable by the spoke itself, must survive a pod
restart, and must be establishable by a platform team in another organisation
with one `helm install`.

We also cannot assume the 100 clusters share anything: no common SPIFFE trust
domain, no service mesh, no cert-manager, no shared identity provider. Requiring
any of those would make onboarding a project rather than a command.

## Decision

The hub runs a small internal certificate authority.

* The CA keypair is ECDSA P-256, generated on first boot, stored in a
  Kubernetes Secret the hub owns, `IsCA: true` with path length 0 so it can only
  sign leaves.
* An operator mints a **single-use enrollment token bound to one cluster ID**.
* The spoke generates a P-256 key locally and sends a CSR with that token.
* **The hub discards the CSR's requested subject and SANs entirely** and mints
  its own: `CN=spoke:<clusterID>`, a single URI SAN
  `pmf://<trustDomain>/spoke/<clusterID>`, `clientAuth` only, 14-day lifetime.
  A CSR asking for `CN=admin` gets a certificate that does not contain it.
* The enrollment token is burned atomically before the certificate is returned.
  A second redemption is refused and logged as a security event, because a
  replayed enrollment token means the install secret leaked.
* Renewal happens at half of the certificate's lifetime with jitter, using no
  enrollment token at all.
* Revocation is a hub-side denylist keyed on serial, consulted on every
  connection. A CRL is published for external auditors but nothing depends on it.

> **Amended by [ADR-0014](0014-websocket-tunnel-through-standard-ingress.md).**
> As first written, both of the last two points happened at the TLS layer: the
> spoke presented its certificate to a mutually authenticated listener and the
> denylist was consulted from `VerifyPeerCertificate`. ADR-0014 put the hub
> behind an Ingress that terminates TLS, so the hub never sees a client
> certificate. Renewal and the tunnel handshake now prove possession inside the
> connection, over a hub-issued challenge, and the denylist is consulted there.
> Nothing about the identity rules in this record changed: the cluster ID still
> comes only from the URI SAN, and the hub still discards what the CSR asks for.

`IdentityFromCert` derives the cluster ID **only** from the URI SAN, verifying
the scheme, the trust domain and the path shape. The common name is ignored for
identity purposes.

## Consequences

**Better.** Onboarding is one token. There is no dependency on cert-manager,
SPIFFE or a mesh. Identity is cryptographic and certificate-bound, so nothing a
spoke reports at runtime can override it, and a compromised spoke is confined to
its own cluster. The 14-day lifetime means a stolen certificate has a short
window even if revocation never reaches anything.

**Worse.** We are now running a CA, and a CA is a serious object. Losing the key
means every spoke keeps working until its certificate expires — at most 14 days
— and then no renewal succeeds and all 100 clusters must be re-enrolled. The
operations documentation treats backing up that Secret as a first-class task and
says exactly what the recovery costs.

**Deliberately deferred.** The council design called for an offline root with an
online intermediate, which is materially stronger: a hub compromise then cannot
forge a durable trust anchor. We ship a single online CA with a documented
rotation path and a two-certificate trust bundle, and record the two-tier design
as future work rather than implementing it badly.

**External PKI is a first-class alternative.** An operator who already has
cert-manager or SPIFFE can supply a trust bundle and an explicit
SAN-to-cluster-ID binding table instead. Trust-domain membership alone must
never confer a cluster ID, or any workload in the mesh could impersonate a
spoke.

## Alternatives considered

* **Bearer token per spoke instead of a certificate.** Rejected: a bearer token
  is replayable by anything that sees it, and it cannot bind to the TLS
  connection. A stolen spoke token would let an attacker impersonate a cluster
  from anywhere.
* **Kubernetes ServiceAccount tokens.** Rejected as the primary mechanism: the
  hub would have to trust and reach 100 different OIDC issuers, many of which are
  not publicly resolvable. Retained as an optional second binding factor where
  the issuer *is* verifiable.
* **Require cert-manager in every cluster.** Rejected: it makes onboarding a
  negotiation with each platform team.
* **Long-lived certificates.** Rejected: without short lifetimes, revocation
  becomes load-bearing, and revocation is the part of PKI that most reliably does
  not work.
