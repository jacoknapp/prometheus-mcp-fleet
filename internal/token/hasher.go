// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
)

// MinPepperBytes is the shortest pepper [NewHasher] will accept. It matches the
// output width of SHA-256: a shorter key is silently zero-extended by HMAC, so
// accepting one would quietly weaken every stored digest.
const MinPepperBytes = 32

// ErrShortPepper reports a pepper below [MinPepperBytes].
var ErrShortPepper = errors.New("pepper too short")

// decoySecret is a fixed, non-secret input used by [Hasher.Decoy]. Its value is
// irrelevant; only the cost of hashing it matters.
var decoySecret = []byte("prometheus-mcp-fleet/decoy/v1___")

// decoySink absorbs the result of the decoy comparison so that neither the
// compiler nor the linker can prove the HMAC is dead code and delete the work
// this function exists to perform.
var decoySink atomic.Uint64

// Hasher reduces a presented token secret to the digest stored in the
// database: HMAC-SHA256(pepper, secret).
//
// HMAC rather than a password KDF is deliberate. The secret is 256 bits of
// CSPRNG output, so there is no guessable keyspace for Argon2id to slow down,
// and a per-request KDF on an unauthenticated path is a CPU-exhaustion
// primitive. The pepper lives outside the database (see [LoadOrCreatePepper]),
// so a stolen database file alone does not let an attacker verify guesses
// offline.
//
// A Hasher is immutable after construction and safe for concurrent use by
// multiple goroutines.
type Hasher struct {
	pepper    []byte
	decoyHMAC []byte
}

// NewHasher returns a Hasher keyed with pepper. It copies pepper, so the
// caller may zero its own buffer afterwards. It returns [ErrShortPepper] if
// pepper is shorter than [MinPepperBytes].
func NewHasher(pepper []byte) (*Hasher, error) {
	if len(pepper) < MinPepperBytes {
		return nil, fmt.Errorf("pepper is %d bytes, need at least %d: %w",
			len(pepper), MinPepperBytes, ErrShortPepper)
	}
	h := &Hasher{pepper: bytes.Clone(pepper)}
	h.decoyHMAC = h.Sum(decoySecret)
	return h, nil
}

// Sum returns HMAC-SHA256(pepper, secret). The result is 32 bytes and is the
// value persisted as fleet.Key.SecretHMAC. It must never be logged: it is a
// verifier, and anyone holding it plus the pepper can authenticate.
func (h *Hasher) Sum(secret []byte) []byte {
	if h == nil {
		return nil
	}
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write(secret)
	return mac.Sum(nil)
}

// Equal reports whether secret hashes to storedHMAC, comparing in constant
// time with hmac.Equal.
//
// It tolerates a nil, short or over-long storedHMAC without panicking: a
// length mismatch simply compares unequal, which is the correct answer for a
// truncated or absent database field and is also what a nil Hasher returns, so
// the whole path fails closed.
func (h *Hasher) Equal(storedHMAC, secret []byte) bool {
	if h == nil {
		return false
	}
	return hmac.Equal(storedHMAC, h.Sum(secret))
}

// Decoy performs exactly the work [Equal] performs, against a fixed dummy
// digest, and discards the answer.
//
// Call it on the KID-miss branch of credential verification. Without it, a
// lookup miss returns after a map probe while a hit returns after an HMAC and
// a constant-time compare, turning response latency into an oracle for "does
// this key identifier exist". With it, both branches cost one HMAC-SHA256 over
// the presented secret plus one 32-byte constant-time compare.
func (h *Hasher) Decoy(secret []byte) {
	if h == nil {
		return
	}
	if hmac.Equal(h.decoyHMAC, h.Sum(secret)) {
		decoySink.Add(1)
	}
}
