// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// RenewChallengeTTL is how long a renewal challenge stays valid.
//
// Sixty seconds is the whole budget for a spoke to receive a challenge, build a
// CSR and post it back. It is short because it is the only bound on the window:
// the nonce is not single-use. See [server.issueRenewNonce] for why that is the
// right trade here and not at /enroll.
const RenewChallengeTTL = 60 * time.Second

// Renewal nonce layout: random || expiry || HMAC(pepper, domain||random||expiry).
const (
	// renewNonceRandomBytes makes two challenges issued in the same second
	// distinct. It is not a secret and does not have to resist guessing — the
	// HMAC is what makes a nonce unforgeable — so 128 bits is ample.
	renewNonceRandomBytes = 16
	// renewNonceExpiryBytes is a big-endian int64 of Unix seconds.
	renewNonceExpiryBytes = 8
	// renewNonceBodyBytes is the part the HMAC covers.
	renewNonceBodyBytes = renewNonceRandomBytes + renewNonceExpiryBytes
	// renewNonceLen is the whole encoded challenge.
	renewNonceLen = renewNonceBodyBytes + sha256.Size
)

// renewNonceDomain separates the nonce MAC from every other use of the pepper.
//
// The pepper also keys the digests of `pmf_` credentials. A credential secret is
// 256 bits of raw CSPRNG output, while every nonce preimage begins with these
// fixed ASCII bytes, so no nonce MAC can ever coincide with a credential digest
// and neither construction can be used as an oracle for the other.
var renewNonceDomain = []byte("prometheus-mcp-fleet/renew-nonce/v1\x00")

// Renewal challenge failures. Both are reported to the caller as 401 with a
// message telling it to fetch a fresh challenge; they are separate values so
// the hub's own log can distinguish a spoke that was merely slow from one
// presenting a nonce this fleet never issued.
var (
	// errRenewNonceInvalid means the challenge was the wrong length or its
	// authentication tag did not verify.
	errRenewNonceInvalid = errors.New("hubapi: renewal challenge was not issued by this fleet")
	// errRenewNonceExpired means the challenge verified but its window has
	// closed.
	errRenewNonceExpired = errors.New("hubapi: renewal challenge has expired")
)

// issueRenewNonce mints a self-authenticating renewal challenge.
//
// # Why there is no nonce table
//
// The hub may run several replicas behind a load balancer, and the replica that
// answers GET /renew/challenge is very often not the one that answers the
// POST /renew that follows. An in-memory nonce map would make renewal fail
// intermittently at exactly the fleet size where it matters, and a shared one
// would put a write on the hot path of the only route that must keep working
// when everything else is degraded. So the challenge carries its own proof:
// random bytes and an expiry, authenticated with the pepper every replica
// already holds. Any replica can verify what any other issued, and none has to
// remember anything.
//
// # Why it is not single-use
//
// Making a nonce single-use requires exactly the shared state the design just
// removed, so it is worth being precise about what that state would buy.
//
// Replaying a captured renewal request gets the attacker another certificate for
// the public key in the captured CSR — a key whose private half is held by the
// spoke that built it, and not by the attacker. The reply is a certificate the
// legitimate spoke could have obtained anyway, carrying an identity it already
// has. There is no privilege to escalate to and nothing to impersonate: the
// certificate is useless to anyone who cannot sign with that key. The only cost
// of a replay is a CA signature and a log line, and that is bounded by the
// sixty-second window and by the ordinary rate limits in front of the hub.
//
// This is the opposite of /enroll, where single-use is the entire security
// property: an enrollment token is a bearer credential, so a replay hands a
// second party a first-class identity for a cluster. That is why the enrollment
// burn is an atomic conditional store update and this is a MAC over an expiry.
//
// The signature the challenge protects is separately bound to the spoke's
// cluster ID and to the renewal exchange (see
// [github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof]), so a captured
// proof cannot be re-scoped to another cluster or replayed into the tunnel
// handshake either.
// It returns no error: crypto/rand.Read cannot fail (it panics if the system
// source is broken, which is not a condition a 500 would help with), and
// [Options] guarantees the hasher is present. An error return here would be two
// branches no test could ever reach.
func (s *server) issueRenewNonce(now time.Time) (nonce []byte, expiresAt time.Time) {
	expiresAt = now.Add(RenewChallengeTTL).UTC().Truncate(time.Second)

	nonce = make([]byte, renewNonceLen)
	_, _ = rand.Read(nonce[:renewNonceRandomBytes])
	//nolint:gosec // G115: expiresAt is now + RenewChallengeTTL, so its Unix seconds are positive for any clock this side of 1970.
	binary.BigEndian.PutUint64(nonce[renewNonceRandomBytes:renewNonceBodyBytes], uint64(expiresAt.Unix()))
	copy(nonce[renewNonceBodyBytes:], s.hasher.Sum(renewNonceMACInput(nonce[:renewNonceBodyBytes])))
	return nonce, expiresAt
}

// verifyRenewNonce reports whether nonce is one this fleet issued and is still
// inside its window.
//
// The tag is checked before the expiry, and in constant time, so that a caller
// cannot learn anything about the pepper from how long a rejection took or from
// which of the two refusals it received.
func (s *server) verifyRenewNonce(nonce []byte, now time.Time) error {
	if len(nonce) != renewNonceLen {
		return fmt.Errorf("%w: challenge is %d bytes, want %d", errRenewNonceInvalid, len(nonce), renewNonceLen)
	}
	body := nonce[:renewNonceBodyBytes]
	if !s.hasher.Equal(nonce[renewNonceBodyBytes:], renewNonceMACInput(body)) {
		return errRenewNonceInvalid
	}
	//nolint:gosec // G115: body is MAC-verified on the line above, so these are bytes this fleet wrote, not attacker-chosen.
	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(body[renewNonceRandomBytes:])), 0).UTC()
	if now.After(expiresAt) {
		return fmt.Errorf("%w at %s", errRenewNonceExpired, expiresAt.Format(time.RFC3339))
	}
	return nil
}

// renewNonceMACInput is the preimage the pepper authenticates.
func renewNonceMACInput(body []byte) []byte {
	return slices.Concat(renewNonceDomain, body)
}
