# 0015. The CA separates its active signer from its trust bundle, and rotates itself

* Status: Accepted
* Date: 2026-08-31
* Amended: 2026-08-31 — the four-state procedure below is now performed by the
  hub, not by an operator. See [Amendment: the hub rotates its own
  root](#amendment-the-hub-rotates-its-own-root).

## Context

[ADR-0004](0004-built-in-ca-for-spoke-identity.md) put a small CA inside the hub
and said, in as many words, that we ship "a single online CA with a documented
rotation path and a two-certificate trust bundle". The runbook duly documents
the path: serve both roots, roll the bundle to every spoke, let renewals migrate
the fleet, retire the old root last.

None of that was implemented. `internal/ca` held one certificate and one key.
`BundlePEM()` returned that single certificate and `Pool()` trusted exactly it,
so there was no state of the system in which two roots were both acceptable. An
operator following the runbook had two ways to try, and both were traps:

* Put old-then-new in the CA certificate file. `parseCertificatePEM` read the
  first block and discarded the rest without a word. The rotation appeared to
  have been performed and had changed nothing — the worst possible outcome,
  because the operator then proceeds to step 5 and retires a root that is still
  the only one issuing.
* Put new-then-old in the same file. The hub now signs with the new key and
  trusts only the new root, so every one of the ~100 spokes fails verification
  on its next connection, immediately, with no path back that does not involve
  minting an enrollment token per cluster by hand.

There was also nothing to *measure* a rotation with. Step 5 says "retire the old
CA only after nothing is still chained to it", and the code offered no way to
ask which root issued a given certificate. Successive roots for the same trust
domain are minted with an identical subject, so the name does not distinguish
them either.

This matters more than the size of the package suggests. The CA signs every
spoke identity across the fleet; certificates live 14 days; losing or having to
replace the root is a fleet-wide event. A rotation procedure that cannot be
executed is worse than having none, because nobody finds out until they are
already in the incident it was written for.

## Decision

**Issuance and verification stop sharing a list.**

* The **active signer** is one keypair — `CA.Certificate()` and the private half
  behind it. It signs every certificate the hub issues, and there is only ever
  one. Nothing about that changed.
* The **trust bundle** is `CA.TrustBundle()`: every root a presented
  certificate is allowed to chain to. `Pool()` is built from all of it, so
  `VerifyChain` and `VerifyChainAllowingExpiry` accept a leaf signed by any root
  in the bundle. In steady state the bundle is exactly the active signer.
* `Options.AdditionalRootsPEM` widens the bundle: zero or more concatenated PEM
  certificates, each of which must be a certificate-signing CA. It is
  **additive**, never a replacement. A field that replaced the bundle could be
  configured to omit the active signer, and an authority that does not trust its
  own signer mints certificates it will then refuse — silently, until the first
  spoke reconnects. Making that state unreachable is worth the small loss of
  expressiveness.
* `BundlePEM()` returns the whole bundle, which during a rotation is both roots.
  This is what a spoke should be configured with, and it is why a spoke keeps
  verifying the hub whichever root signed the certificate it holds. The active
  signer is emitted first, so a consumer that reads only the first block still
  lands on the root issuing today.
* `Fingerprint()` (hex SHA-256 over the DER) names a root, and
  `IssuerFingerprint()` reports which root in the bundle signed a given leaf.
  That is the instrument the runbook's last step needs: migration is finished
  when no live certificate reports the outgoing root.
* Feeding more than one certificate into the *signer* certificate file is now a
  hard `ErrInvalidCA` at load. The first trap above is the mistake the old code
  most invited, and the only place it can still be caught is where it is made.

The rotation this makes possible is four states with no re-enrollment and no
disconnection at any point. They were originally four configuration changes and
four restarts; the amendment below turns them into a controller, and the states
themselves are unchanged:

1. Mint the successor root at fresh paths. It signs nothing.
2. Keep the signer, add the successor to `AdditionalRootsPEM`. `BundlePEM()`
   now serves both; roll it to every spoke and confirm each has it.
3. Point the signer paths at the successor and move the *outgoing* root into
   `AdditionalRootsPEM`. New issuance uses the successor; every unmigrated
   spoke still verifies.
4. When `IssuerFingerprint` no longer reports the outgoing root for any live
   certificate, clear `AdditionalRootsPEM`.

## Consequences

**The runbook is now true.** The five steps it has always described map onto
four states the code can actually be put into, and each has a test that asserts
the unmigrated spoke keeps working. The one step that breaks the old
certificates is step 4, which is the point of step 4.

**Rotation costs a certificate lifetime, and there is no way to shorten it
safely.** Step 3 does not migrate anybody; ordinary renewal does, on each
spoke's own half-life-plus-jitter schedule. At the default 14-day lifetime the
overlap is a fortnight, and the honest floor is "one full certificate lifetime
after the last spoke picked up the new bundle". Forcing it faster means
re-enrolling clusters by hand, which is the thing this exists to avoid.

**Step 2 cannot be skipped, and its completion is the operator's problem.** The
hub has no way to know that all ~100 spokes have the new bundle; `hub.caBundle`
is rolled by whatever deploys the spokes. Cutting over the signer before a spoke
has the successor root disconnects that spoke as surely as the old
new-then-old trap did. The overlap is only safe in one direction.

> Superseded by the amendment. Step 2 still cannot be skipped, but it is no
> longer anybody's problem to watch: the controller holds `publishing` for a
> full certificate lifetime, which is twice the half-life at which every spoke
> renews, and renewal is what delivers the bundle.

**Readiness still tracks the active signer only.** `NotAfter()` ignores the rest
of the bundle deliberately: an outgoing root expiring during retirement is the
plan, not an incident, and what readiness must be loud about is the root that
still has to issue. The practical consequence is that
`PrometheusMCPHubCACertExpiringSoon` keeps firing through step 2 and clears at
step 3, which is the correct reading — until the signer moves, nothing has been
fixed.

**A CRL is scoped to one issuer, and this does not change that.** `CA.CRL` is
signed by the active signer, so during an overlap it does not cover serials
issued by the outgoing root. The tunnel does not consume a CRL — it consults the
live revocation store keyed on serial, regardless of issuer — so this is a gap
for external CRL consumers only. Publishing a second CRL per additional root is
the fix if anyone ever needs it; nothing in this system does.

**Rotation is still not one command.** A `CA` is immutable after construction,
which is what makes every method on it safe for concurrent use without a lock,
and we are not giving that up to make a cutover a runtime operation. Each step
is a configuration change and a restart. What is now missing is only the
convenience of a `hub ca rotate` subcommand that mints the successor and prints
the overlap bundle; the primitives it would call all exist.

> Superseded by the amendment. It is not one command either: it is no commands.
> The immutability argument was right about what it was protecting and wrong
> about where to protect it — see the amendment's first section.

**This is not the two-tier CA.** ADR-0004 deferred the offline-root/online-
intermediate design and this record does not undefer it. A hub compromise still
forges a durable trust anchor, because the root's private key is on the hub.
What changed is that replacing that root is now a planned operation instead of
an outage — which, if the root ever is compromised, is exactly the procedure the
response depends on.

## Alternatives considered

* **A single `TrustBundlePEM` that replaces the bundle outright.** Rejected: it
  admits a configuration in which the hub does not trust its own signer, and
  that failure is silent until a spoke reconnects. The extra expressiveness buys
  nothing — there is no legitimate reason to distrust the key you are signing
  with.
* **Accept a multi-certificate signer file and treat blocks 2..n as additional
  roots.** Rejected. It makes the two traps in the Context section behave
  differently from each other for reasons no operator could predict from the
  file's name, and it leaves the ordering of a file that already had a meaning
  silently load-bearing. A separate setting and a loud error is the smaller
  surprise.
* **Cut the signer over at runtime, via a reload endpoint or a file watch.**
  Rejected: it trades the immutability that makes `CA` lock-free for the removal
  of one restart from a procedure that already spans a fortnight. Wrong thing to
  optimise.

  > Revisited by the amendment, and half of it accepted. A runtime cutover is
  > now how this works, but not through a reload endpoint or a file watch: the
  > trigger is the Secret, which is the only thing the replicas share. The
  > immutability was kept, one level down.
* **Sign the successor root with the outgoing root, so old spokes chain to it
  without any bundle change.** Rejected outright. The root has `MaxPathLen 0`
  precisely so it can sign leaves and nothing else, and a cross-signed successor
  is a second-tier CA that inherits the compromise of the root it was supposed
  to replace. Cross-signing is the right answer for a public PKI with
  uncontrolled relying parties; here we control every relying party and can
  simply ship them both roots.
* **Do nothing and delete the rotation section from the runbook.** Considered
  seriously, and it would have been better than the status quo. Rejected because
  the CA's key is on the hub and the fleet needs a way to survive replacing it
  that is not "re-enroll a hundred clusters".

## Amendment: the hub rotates its own root

*2026-08-31.* Everything above is still true about the shape of a rotation.
What changed is who performs it.

### Why

The record above ends with a procedure nobody can execute, which is the same
failure it was written to fix one level up. The original Context says it
plainly: *"a rotation procedure that cannot be executed is worse than having
none, because nobody finds out until they are already in the incident it was
written for."* A four-step procedure spanning two months, with two restarts and
a measurement that has to be taken by hand at the right moment, is a procedure
that will be attempted for the first time under pressure, from a runbook nobody
has rehearsed, on the day the CA is expiring.

The root lives ten years. The chance that the person who reads step 3 is the
person who wrote it is approximately zero.

### What the hub does

A state machine, persisted in the CA Secret, one phase at a time:

```
steady ──(signer in its last fifth, or an operator annotation)──▶ publishing
publishing ──(one full spoke-certificate lifetime)──▶ signing
signing ──(a lifetime plus the renewal grace, AND no live session on the
            outgoing root anywhere in the fleet)──▶ steady
```

* **`steady`** — one root, which signs. The controller writes nothing at all.
* **`publishing`** — the successor is minted into `ca-next.crt` / `ca-next.key`
  and is trusted; the old root still signs.
* **`signing`** — the successor has been moved onto `ca.crt` / `ca.key`, the
  outgoing certificate is kept in `ca-previous.crt` and is still trusted. Its
  private key is **not** kept: a root that has stopped signing must not be able
  to start again, which also means a rotation run because a key leaked really
  does dispose of that key.
* back to **`steady`** — `ca-previous.crt` is dropped.

The set of trusted roots is `{old, new}` in both middle phases, so the
promotion — the step that changes what signs — changes nothing about what
verifies. Only the last transition narrows trust, and it is the only one with
an evidence gate as well as a clock.

### The parts that needed a decision

**The `CA` handle outlives its material.** The Consequences above defend
immutability because it makes every method lock-free. That reasoning was sound
and is preserved exactly: a `caMaterial` — signer, key, trust bundle, bundle
PEM — is still never mutated after it is published, and every method still
reads it once. What moved is the *handle*: a `*ca.CA` now holds an
`atomic.Pointer` to that snapshot, and `AdoptPEM` swaps the whole thing in one
store. The alternative was rebuilding the CA and every consumer of it — the
tunnel verifier, the enrollment and renewal handlers, `/pki/bundle` — which is
a process restart wearing a different hat.

**The Secret is the coordination primitive.** There is no database, no PVC and
no channel between replicas (ADR-0005), and the dependency budget forbids
client-go and therefore leases. What the Secret does have is a
`resourceVersion`, and `UpdateSecret` already carries it, so every transition
is a compare-and-swap and exactly one replica performs it. A replica that loses
the race does not retry: it re-reads on its next poll and adopts, because the
winner's result is by definition the one the fleet is on.

**Noticing somebody else's rotation is a poll, and five minutes is generous.**
A replica that is a poll behind is not dangerous, which is what sets the
interval. During `publishing` it serves a bundle missing the successor, which
the next renewal repairs and which nothing depends on for another fortnight;
during `signing` it keeps signing with the old root, which stays trusted for a
month and a half afterwards. Correctness is bounded by the phase gates, not by
the poll, so the interval is chosen for politeness to the API server: one GET
per replica per interval. It is configurable for the same reason it is not
important.

**`publishing` waits a full certificate lifetime, not a poll interval.** In
this architecture the strictly necessary wait is much shorter — spokes verify
the hub with the Ingress certificate, not with this root (ADR-0014), so what
`publishing` really guarantees is that no replica can still be ignorant of the
successor when another starts signing with it, and that is minutes. A full
lifetime is kept anyway. It costs nothing on a ten-year root, it is what every
external consumer of `/pki/bundle` is entitled to, and it is the bound that
stays correct if mutual TLS to the hub ever comes back.

**`signing` waits a lifetime plus the renewal grace.** Not a lifetime: a
certificate that expired yesterday can still be renewed for `--renew-grace`
afterwards, on purpose, so that a cluster switched off over a holiday is not
locked out. Dropping the outgoing root at one lifetime would take that recovery
path away from exactly the spokes it exists for. Waiting the grace out as well
means that when the root is finally dropped, every certificate chained to it is
not only expired but past the point of rescue — so the drop can no longer
disconnect anything.

**And it waits for the fleet to be quiet.** The clock is the argument; the
session check is the proof. Every replica asks its own issuer tracker how many
live sessions were admitted by the outgoing root — `IssuerFingerprint` against
the leaf, recorded at the handshake, which is the only place the leaf exists —
and publishes any sighting into `ca-rotation.last-holdout`. No replica sees the
whole fleet, but every replica writes into the same Secret, so one replica's
sighting vetoes every replica's retirement. The root is dropped only when
nobody has seen a dependant for two consecutive poll intervals. A replica that
has only just started does not get a vote: an empty session table is not
evidence.

**A trigger fraction with a floor under it.** Rotation begins in the last fifth
of the signer's life — eight years into ten, leaving two years of runway for a
job that takes two months. But a fraction alone is wrong for any shorter root:
a fifth of a 90-day CA is 18 days, and a rotation cannot finish in that. The
threshold is therefore `max(fraction × total life, 2 × spoke-cert-ttl +
renew-grace)`. Starting a rotation that cannot complete before the signer
expires is strictly worse than starting one early.

**Forcing is an annotation, not an endpoint.** `kubectl annotate secret <ca>
promfleet.io/rotate-now=<reason>` starts one immediately, for a suspected key
compromise. It needs no new authenticated surface, it works from a GitOps
change as readily as from a terminal, it touches no file, and it is available
to exactly the identity that could already read the Secret. It is edge
triggered — consumed in the same compare-and-swap that records the phase it
caused — because an annotation left in place would fire again months later for
a reason nobody remembers.

**Anything ambiguous stays where it is.** If a poll fails, a write conflicts, or
the Secret has been hand-edited into a shape that does not parse, the
controller does not advance. That is always safe, because the state it stays in
is one where both roots are trusted. What it *will* do is repair: a missing or
unreadable phase-start timestamp is rewritten to now — which can only delay a
transition, never bring one forward — a phase whose material has gone missing
falls back to `steady`, and material belonging to no phase is deleted rather
than left lying about as an unused private key.

### What this does not do

**It does not rotate a CA you supplied.** With `bootstrap.existingSecret` the
CA arrives on a read-only projected mount, and a successor written to the
Secret could not be materialised back onto that path at the next restart. The
hub declines, says so at startup, and leaves the lifecycle to whatever owns the
material.

**It does not run with the file backend.** `--state-backend=file` is a
single-process development and end-to-end mode with no compare-and-swap and no
replicas to coordinate. Rotation is off there and the reason is logged once.
The e2e suite therefore exercises the CA, not its rotation; the state machine
is covered by unit tests that drive both sides of every race.

**It does not make a compromised key safe faster.** The gates are what they are
because the fleet renews at its own pace. Forcing a rotation starts the clock;
revoking the certificates issued under the compromised root is the part that
takes effect within one revocation-cache TTL, and that is a different control.

**It does not survive losing the Secret.** The phase, the timestamps and both
roots live there and nowhere else. That is the same blast radius the CA already
had, and the runbook's answer — back it up, test the restore — is unchanged. A
backup taken mid-rotation restores mid-rotation, coherently, because it is one
object.

### Restart and scale-to-zero

**Restart mid-rotation.** Nothing is held in memory that is not in the Secret.
A starting hub reads the phase and loads the other root alongside its signer,
so it comes back trusting exactly what it trusted before. The scratch
directory is an emptyDir and is rewritten from the Secret; the phase clock is
wall-clock against a stored timestamp, so a restart neither restarts nor skips
a wait.

**Scaled to zero mid-rotation.** Nothing advances, and nothing needs to: the
phases are gated on elapsed time, and elapsed time passes whether or not a hub
is running. On scale-up the controller reads the phase and finds the gate
already open, so it advances on the first or second poll. That is correct
rather than merely tolerable — the reason the `signing` gate is a lifetime plus
the grace is precisely so that when it opens, no live certificate can still
depend on the outgoing root. The settle guard covers the remaining hazard: a
replica that has just started sees no sessions, and a zero from an empty
session table is not allowed to count as evidence until it has been up for two
poll intervals.

### Observability

`promfleet_hub_ca_trust_roots` stays and still reads 1 or 2. Beside it:

| Metric | Reads |
|---|---|
| `promfleet_hub_ca_rotation_phase{phase}` | 1 on the phase in force, 0 on the others |
| `promfleet_hub_ca_rotation_phase_start_timestamp_seconds` | when it was entered — a UNIX timestamp, unlike the `_expiry_seconds` gauges, so the age is `time() - x` |
| `promfleet_hub_ca_outgoing_root_sessions` | live sessions on THIS replica still holding a certificate from the outgoing root; sum it across replicas |
| `promfleet_hub_ca_rotation_transitions_total{to}` | advances, so "did this ever rotate" survives log rotation |

`PrometheusMCPHubCARotationStalled` alerts on a phase that has outlasted its
expected duration. It is a warning, not a page: both roots are trusted for as
long as it lasts.
