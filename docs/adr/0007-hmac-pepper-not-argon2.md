# 0007. HMAC with a pepper, not a password KDF

* Status: Accepted
* Date: 2026-08-29

## Context

Every MCP request presents a bearer API key that must be verified. The instinct
— correct for passwords — is to store a slow hash: Argon2id, scrypt or bcrypt.

Our secrets are not passwords. Each is 32 bytes straight from `crypto/rand`,
rendered as 43 base62 characters. There is no dictionary, no reuse across sites,
no human memorability, and 256 bits of entropy.

A password KDF exists to make a *low-entropy* secret expensive to brute-force
offline. Against 256 bits of CSPRNG output, offline brute force is already
infeasible, so the stretching buys nothing against the only attack it addresses.

What it does buy is a denial-of-service primitive aimed at us. Argon2id at
64 MiB and t=3, run on every request, is roughly fifteen verifications per second
per core against an exhaustible memory budget. An unauthenticated attacker
sending garbage tokens would take the hub down, and the more correctly we tuned
the KDF the easier that would be.

## Decision

Store `HMAC-SHA256(pepper, secret)`. Compare with `hmac.Equal`.

The **pepper is held outside the credential store** — its own file, mounted from
its own Secret, or supplied by a KMS. It is not in the state document, not in a
backup of that document, and not in the same blast radius.

The hot path is:

1. Parse the token and verify its CRC. A malformed token is rejected before any
   store access or crypto work, which is most of the DoS surface gone for free.
2. Look up the KID. **On a miss, still compute an HMAC against a fixed dummy
   secret** so KID existence is not a timing oracle.
3. `hmac.Equal` — constant time, never `==` or `bytes.Compare`.
4. Check class, expiry and revocation, then cache.

Argon2id is retained for exactly one thing: an interactive admin bootstrap
password, verified rarely, where the secret really is human-chosen.

## Consequences

**Better.** Verification is about half a microsecond, so authentication is not a
capacity concern and a flood of invalid tokens costs almost nothing. The pepper
gives a property per-row salting cannot: a leak of the state Secret alone, via a
backup, a misconfigured RBAC rule or an exfiltrated etcd snapshot, yields hashes
that are useless without a second secret stored somewhere else.

**Worse.** The pepper is now a single point of failure. Lose it and every issued
key is unverifiable and must be re-minted; leak it *together with* the state and
the attacker can verify offline. Rotation means re-hashing every record, which we
support but which is an operation, not a no-op.

**The thing that would make this wrong.** If we ever accept a user-chosen secret
— an admin password typed at a prompt, an operator-supplied static token — HMAC
is the wrong tool for that credential and it must go through Argon2id instead.
The code keeps them separate so that distinction cannot quietly erode.

## Alternatives considered

* **Argon2id on every request.** Rejected: no security benefit against
  high-entropy secrets, and a self-inflicted DoS primitive.
* **bcrypt.** Cheaper than Argon2id but still roughly a hundred times too slow
  for a per-request path, and it silently truncates input at 72 bytes.
* **Plain SHA-256 with a per-row salt.** Adequate against offline cracking of a
  high-entropy secret, but it gives up the out-of-database pepper, which is the
  main reason to prefer HMAC here.
* **Storing the token encrypted and comparing plaintext.** Rejected: it puts a
  recoverable secret in the store, which is precisely what we are avoiding.
