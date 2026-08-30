// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"math/big"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// Class is an alias for [fleet.KeyClass]. It exists so callers that only touch
// the credential format do not have to import internal/fleet for a type name.
type Class = fleet.KeyClass

// Wire-format constants. Every token of every class is exactly [Len] bytes.
const (
	// Prefix is the fixed leader shared by every credential class.
	Prefix = "pmf_"
	// ClassLen is the width of the class segment, e.g. "agt".
	ClassLen = 3
	// KIDLen is the width of the public key identifier segment.
	KIDLen = 10
	// SecretBytes is the size of the raw secret in bytes (256 bits).
	SecretBytes = 32
	// SecretLen is the fixed base62 width of the secret segment. 62^43 is the
	// smallest power of 62 above 2^256, so 43 characters represent every
	// possible secret with zero-padding and no ambiguity.
	SecretLen = 43
	// CRCLen is the fixed base62 width of the checksum segment.
	CRCLen = 6
	// Len is the total token length in bytes.
	Len = headLen + KIDLen + SecretLen + 1 + CRCLen

	headLen  = len(Prefix) + ClassLen + 1 // "pmf_agt_"
	kidEnd   = headLen + KIDLen
	crcSep   = kidEnd + SecretLen // index of the final '_'
	bodyLen  = crcSep             // bytes covered by the checksum
	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Sentinel errors returned by [Parse] and [Mint]. Callers must match with
// errors.Is; the wrapped text deliberately never contains any part of the
// token being examined.
var (
	// ErrMalformed reports that the input is not shaped like a token at all:
	// wrong length, wrong prefix, missing separator, or a character outside
	// the base62 alphabet.
	ErrMalformed = errors.New("malformed token")
	// ErrBadChecksum reports that the token is well shaped but its CRC does
	// not match, which means a typo or a truncated paste, not an attack.
	ErrBadChecksum = errors.New("token checksum mismatch")
	// ErrUnknownClass reports a class segment that is not one of the classes
	// in internal/fleet.
	ErrUnknownClass = errors.New("unknown token class")
)

// castagnoli is CRC-32C, the same polynomial used by SCTP and iSCSI. It is
// chosen over IEEE only because it has hardware support on amd64 and arm64.
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// b62Index maps a byte to its base62 digit value, or -1 if it is not a base62
// character. Indexing it is branch-free and total over all 256 byte values,
// which is what lets [Parse] avoid bounds checks on hostile input.
var b62Index = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		t[alphabet[i]] = int8(i)
	}
	return t
}()

// randRead is crypto/rand.Read, indirected so tests can exercise the
// entropy-failure paths. It is never reassigned outside tests.
var randRead = rand.Read

// Minted is the result of [Mint]: a freshly generated credential in the three
// forms its three consumers need. Raw goes to the operator exactly once, KID
// goes into the database and the audit log, and Secret is hashed by [Hasher]
// and then discarded.
//
// Minted redacts itself under fmt, log/slog and encoding/json; only KID
// survives, because KID is public by design.
type Minted struct {
	// Raw is the complete token text. It is the only copy that will ever
	// exist: the hub does not store it.
	Raw RawToken
	// KID is the public identifier, also embedded in Raw.
	KID string
	// Secret is the 32 raw secret bytes, for handing to [Hasher.Sum].
	Secret []byte
}

// String implements fmt.Stringer, exposing only the public KID.
func (m Minted) String() string {
	return fmt.Sprintf("Minted{kid:%s, raw:%s, secret:%s}", m.KID, Redacted, Redacted)
}

// GoString implements fmt.GoStringer so that %#v also redacts.
func (m Minted) GoString() string { return m.String() }

// LogValue implements slog.LogValuer, emitting only the public KID.
func (m Minted) LogValue() slog.Value { return slog.GroupValue(slog.String("kid", m.KID)) }

// MarshalJSON implements json.Marshaler, emitting only the public KID and
// [Redacted] placeholders for the two secret fields.
func (m Minted) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		KID    string `json:"kid"`
		Raw    string `json:"raw"`
		Secret string `json:"secret"`
	}{KID: m.KID, Raw: Redacted, Secret: Redacted})
}

// Mint generates a new credential of the given class. It returns
// [ErrUnknownClass] for a class internal/fleet does not recognise, and wraps
// any failure of the system CSPRNG.
//
// The returned Secret is live secret material. Hash it with [Hasher.Sum],
// store the digest, and let the slice go out of scope.
func Mint(class fleet.KeyClass) (Minted, error) {
	return mintWith(class, "", randRead)
}

// MintWithKID generates a credential whose public identifier is fixed.
//
// It exists for exactly one caller: the hub's automatically minted first admin
// credential. A well-known KID lets two hub replicas racing to bootstrap an
// empty store collide on the store's uniqueness constraint, so one wins and the
// other stays silent, instead of both minting a valid admin token and both
// printing it. The KID is public and non-secret by design -- it appears in
// audit logs -- and the secret remains 256 bits of CSPRNG output, so fixing it
// costs nothing.
//
// kid must be exactly [KIDLen] base62 characters.
func MintWithKID(class fleet.KeyClass, kid string) (Minted, error) {
	if len(kid) != KIDLen || !isBase62(kid) {
		return Minted{}, fmt.Errorf("mint kid %q: %w", kid, ErrMalformed)
	}
	return mintWith(class, kid, randRead)
}

// mintWith is Mint with an injectable entropy source. Fuzzing needs a
// deterministic Mint -- Go's fuzzing engine treats a target whose coverage
// varies between runs on the same input as unstable and stops making progress
// -- and the entropy-failure paths need to be reachable from a test.
func mintWith(class fleet.KeyClass, kid string, read func([]byte) (int, error)) (Minted, error) {
	if !class.Valid() {
		return Minted{}, fmt.Errorf("mint %q: %w", string(class), ErrUnknownClass)
	}
	if kid == "" {
		var err error
		if kid, err = randomBase62(KIDLen, read); err != nil {
			return Minted{}, fmt.Errorf("mint kid: %w", err)
		}
	}
	secret := make([]byte, SecretBytes)
	if _, err := read(secret); err != nil {
		return Minted{}, fmt.Errorf("mint secret: %w", err)
	}
	// 62^43 > 2^256, so every 32-byte secret fits by construction.
	enc, _ := encodeBase62(secret, SecretLen)

	buf := make([]byte, 0, Len)
	buf = append(buf, Prefix...)
	buf = append(buf, class...)
	buf = append(buf, '_')
	buf = append(buf, kid...)
	buf = append(buf, enc...)
	buf = append(buf, '_')
	buf = append(buf, encodeCRC(crc32.Checksum(buf[:bodyLen], castagnoli))...)

	return Minted{Raw: newRawToken(string(buf)), KID: kid, Secret: secret}, nil
}

// Parse decodes a raw token into its class, its public KID and its secret
// bytes. It is total: it returns an error for every input it cannot decode and
// panics on none, including empty, over-long, non-UTF-8 and adversarial input.
//
// Order matters. The checksum is verified before the class is interpreted and
// before the secret is decoded, so a mistyped token costs one CRC-32C over 61
// bytes rather than a database round trip. Parse performs no lookup and
// therefore cannot -- and must not be extended to -- reveal whether the KID
// exists; that is the store's job, and internal/authn pairs a miss with
// [Hasher.Decoy] to keep the timing flat.
//
// Errors are [ErrMalformed], [ErrBadChecksum] and [ErrUnknownClass]. None of
// them embed any part of the input.
func Parse(raw string) (class fleet.KeyClass, kid string, secret []byte, err error) {
	if len(raw) != Len {
		return "", "", nil, fmt.Errorf("token length %d, want %d: %w", len(raw), Len, ErrMalformed)
	}
	if raw[:len(Prefix)] != Prefix {
		return "", "", nil, fmt.Errorf("missing %q prefix: %w", Prefix, ErrMalformed)
	}
	if raw[headLen-1] != '_' || raw[crcSep] != '_' {
		return "", "", nil, fmt.Errorf("separator not found at the fixed offsets: %w", ErrMalformed)
	}
	// The class segment and every base62 segment must be in-alphabet. Checking
	// the class here as well means a byte such as 0x00 can never reach
	// fleet.KeyClass comparison.
	for i := len(Prefix); i < headLen-1; i++ {
		if b62Index[raw[i]] < 0 {
			return "", "", nil, fmt.Errorf("class segment is not base62: %w", ErrMalformed)
		}
	}
	for i := headLen; i < crcSep; i++ {
		if b62Index[raw[i]] < 0 {
			return "", "", nil, fmt.Errorf("body is not base62: %w", ErrMalformed)
		}
	}
	for i := crcSep + 1; i < Len; i++ {
		if b62Index[raw[i]] < 0 {
			return "", "", nil, fmt.Errorf("checksum is not base62: %w", ErrMalformed)
		}
	}

	// Checksum before anything else that could touch the secret.
	want := encodeCRC(crc32.Checksum([]byte(raw[:bodyLen]), castagnoli))
	if subtle.ConstantTimeCompare([]byte(want), []byte(raw[crcSep+1:])) != 1 {
		return "", "", nil, fmt.Errorf("checksum: %w", ErrBadChecksum)
	}

	class = fleet.KeyClass(raw[len(Prefix) : headLen-1])
	if !class.Valid() {
		return "", "", nil, fmt.Errorf("class %q: %w", string(class), ErrUnknownClass)
	}
	secret, ok := decodeBase62(raw[kidEnd:crcSep], SecretBytes)
	if !ok {
		// A 43-digit base62 number can exceed 2^256; such a token was never
		// produced by Mint.
		return "", "", nil, fmt.Errorf("secret out of range: %w", ErrMalformed)
	}
	return class, raw[headLen:kidEnd], secret, nil
}

// encodeCRC renders a CRC-32C value as exactly [CRCLen] base62 digits,
// left-padded with '0'. 62^6 (~5.7e10) comfortably exceeds 2^32.
func encodeCRC(sum uint32) string {
	var out [CRCLen]byte
	n := uint64(sum)
	for i := CRCLen - 1; i >= 0; i-- {
		out[i] = alphabet[n%62]
		n /= 62
	}
	return string(out[:])
}

// encodeBase62 renders b as a big-endian base62 integer of exactly width
// digits, left-padded with '0'. It reports false if b does not fit in width
// digits.
func encodeBase62(b []byte, width int) (string, bool) {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(62)
	rem := new(big.Int)
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		n.QuoRem(n, base, rem)
		out[i] = alphabet[rem.Int64()]
	}
	return string(out), n.Sign() == 0
}

// decodeBase62 is the inverse of [encodeBase62]. It reports false if s
// contains a non-base62 byte or if the value does not fit in byteLen bytes.
func decodeBase62(s string, byteLen int) ([]byte, bool) {
	n := new(big.Int)
	base := big.NewInt(62)
	digit := new(big.Int)
	for i := 0; i < len(s); i++ {
		v := b62Index[s[i]]
		if v < 0 {
			return nil, false
		}
		n.Mul(n, base)
		n.Add(n, digit.SetInt64(int64(v)))
	}
	if n.BitLen() > byteLen*8 {
		return nil, false
	}
	return n.FillBytes(make([]byte, byteLen)), true
}

// randomBase62 returns n uniformly distributed base62 characters. It uses
// rejection sampling (discarding bytes >= 248 = 62*4) rather than modulo
// reduction, which would bias the first 8 characters of the alphabet.
func randomBase62(n int, read func([]byte) (int, error)) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= 248 {
				continue
			}
			out = append(out, alphabet[b%62])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// isBase62 reports whether every byte of s is a base62 digit.
func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return len(s) > 0
}
