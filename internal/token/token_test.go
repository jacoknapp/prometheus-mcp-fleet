// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"errors"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// assemble builds a syntactically positioned token with a correct CRC, so a
// test can isolate a single downstream failure mode.
func assemble(class, kid, secret string) string {
	body := Prefix + class + "_" + kid + secret
	return body + "_" + encodeCRC(crc32.Checksum([]byte(body), castagnoli))
}

func TestMintParseRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		class fleet.KeyClass
	}{
		{"admin", fleet.ClassAdmin},
		{"agent", fleet.ClassAgent},
		{"enrollment", fleet.ClassEnrollment},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 64; i++ {
				m, err := Mint(tc.class)
				if err != nil {
					t.Fatalf("Mint(%q) = %v", tc.class, err)
				}
				raw := m.Raw.Reveal()
				if len(raw) != Len {
					t.Fatalf("token length = %d, want %d", len(raw), Len)
				}
				if got, want := raw[:headLen], Prefix+string(tc.class)+"_"; got != want {
					t.Fatalf("head = %q, want %q", got, want)
				}
				if len(m.KID) != KIDLen {
					t.Fatalf("kid length = %d, want %d", len(m.KID), KIDLen)
				}
				if len(m.Secret) != SecretBytes {
					t.Fatalf("secret length = %d, want %d", len(m.Secret), SecretBytes)
				}

				class, kid, secret, err := Parse(raw)
				if err != nil {
					t.Fatalf("Parse(Mint(%q)) = %v", tc.class, err)
				}
				if diff := cmp.Diff(tc.class, class); diff != "" {
					t.Errorf("class mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(m.KID, kid); diff != "" {
					t.Errorf("kid mismatch (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(m.Secret, secret); diff != "" {
					t.Errorf("secret mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestMintUniqueness(t *testing.T) {
	t.Parallel()
	const n = 512
	kids := make(map[string]struct{}, n)
	secrets := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		m, err := Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, dup := kids[m.KID]; dup {
			t.Fatalf("duplicate kid after %d mints", i)
		}
		kids[m.KID] = struct{}{}
		if _, dup := secrets[string(m.Secret)]; dup {
			t.Fatalf("duplicate secret after %d mints", i)
		}
		secrets[string(m.Secret)] = struct{}{}
	}
}

func TestMintRejectsUnknownClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		class fleet.KeyClass
	}{
		{"empty", ""},
		{"unknown", "xyz"},
		{"wrong case", "AGT"},
		{"too long", "agent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := Mint(tc.class)
			if !errors.Is(err, ErrUnknownClass) {
				t.Fatalf("Mint(%q) error = %v, want ErrUnknownClass", tc.class, err)
			}
			if !m.Raw.IsZero() || m.KID != "" || m.Secret != nil {
				t.Errorf("Mint returned material alongside an error: %v", m)
			}
			if strings.Contains(err.Error(), "failed to") {
				t.Errorf("error text uses banned phrasing: %v", err)
			}
		})
	}
}

func TestMintWithKID(t *testing.T) {
	t.Parallel()

	const kid = "AdminKey01"
	m, err := MintWithKID(fleet.ClassAdmin, kid)
	if err != nil {
		t.Fatalf("MintWithKID: %v", err)
	}
	if m.KID != kid {
		t.Fatalf("KID = %q, want %q", m.KID, kid)
	}
	class, parsedKID, secret, err := Parse(m.Raw.Reveal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if class != fleet.ClassAdmin || parsedKID != kid || !bytes.Equal(secret, m.Secret) {
		t.Fatalf("Parse = (%q, %q, %x), want (%q, %q, %x)", class, parsedKID, secret, fleet.ClassAdmin, kid, m.Secret)
	}

	for _, bad := range []string{"short", "toolongkid1", "contains-_", ""} {
		got, err := MintWithKID(fleet.ClassAdmin, bad)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("MintWithKID(%q) error = %v, want ErrMalformed", bad, err)
		}
		if !got.Raw.IsZero() || got.KID != "" || got.Secret != nil {
			t.Errorf("MintWithKID(%q) returned secret material with error", bad)
		}
	}
}

// TestPattern checks the regex [Pattern] returns against real minted
// credentials of every class: this is the string published to GitHub secret
// scanning (see internal/token/doc.go and SECURITY.md), so a change to the
// wire format that this regex stops matching would silently blind the
// scanner. It also checks the two documented negative cases: a string that
// merely resembles a token, and a corrupted CRC, which the pattern matches on
// shape alone by design.
func TestPattern(t *testing.T) {
	t.Parallel()

	re, err := regexp.Compile("^" + Pattern() + "$")
	if err != nil {
		t.Fatalf("Pattern() did not compile: %v", err)
	}

	for _, class := range []fleet.KeyClass{fleet.ClassAdmin, fleet.ClassAgent, fleet.ClassEnrollment} {
		m, err := Mint(class)
		if err != nil {
			t.Fatalf("Mint(%s): %v", class, err)
		}
		raw := m.Raw.Reveal()
		if !re.MatchString(raw) {
			t.Errorf("Pattern() does not match a freshly minted %s token", class)
		}
	}

	for _, bad := range []string{
		"",
		"not a token at all",
		"pmf_xyz_" + strings.Repeat("a", KIDLen+SecretLen) + "_" + strings.Repeat("a", CRCLen),
	} {
		if re.MatchString(bad) {
			t.Errorf("Pattern() matched %q, want no match (unknown class or non-token text)", bad)
		}
	}

	// The pattern matches shape, not validity: a well-formed token with a
	// deliberately wrong checksum must still match, per Pattern's doc comment.
	m, err := Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw := m.Raw.Reveal()
	corrupted := raw[:len(raw)-1] + string(flipBase62Digit(raw[len(raw)-1]))
	if !re.MatchString(corrupted) {
		t.Errorf("Pattern() did not match a shape-valid token with a corrupted checksum: %q", corrupted)
	}
	if _, _, _, err := Parse(corrupted); !errors.Is(err, ErrBadChecksum) {
		t.Fatalf("Parse(corrupted) error = %v, want ErrBadChecksum (test fixture is not exercising what it claims)", err)
	}
}

// flipBase62Digit returns a base62 digit different from b, so a test can
// corrupt exactly one character of a token without risking a no-op edit.
func flipBase62Digit(b byte) byte {
	if b == '0' {
		return '1'
	}
	return '0'
}

func TestIsBase62(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"0", "09", "AZ", "az", "0Az9"} {
		if !isBase62(s) {
			t.Errorf("isBase62(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "-", "a_", "é"} {
		if isBase62(s) {
			t.Errorf("isBase62(%q) = true, want false", s)
		}
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	valid := func() string {
		m, err := Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		return m.Raw.Reveal()
	}()
	goodKID := valid[headLen:kidEnd]
	goodSecret := valid[kidEnd:crcSep]

	swap := func(s string, i int, c byte) string {
		b := []byte(s)
		b[i] = c
		return string(b)
	}

	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"too short", valid[:Len-1], ErrMalformed},
		{"too long", valid + "x", ErrMalformed},
		{"whitespace padded", " " + valid[:Len-1], ErrMalformed},
		{"wrong prefix", "pmg_" + valid[4:], ErrMalformed},
		{"missing head separator", swap(valid, headLen-1, 'x'), ErrMalformed},
		{"missing crc separator", swap(valid, crcSep, 'x'), ErrMalformed},
		{"non base62 in class", "pmf_a-t_" + valid[headLen:], ErrMalformed},
		{"non base62 in kid", swap(valid, headLen, '-'), ErrMalformed},
		{"non base62 in secret", swap(valid, kidEnd, '/'), ErrMalformed},
		{"non base62 in crc", swap(valid, Len-1, '+'), ErrMalformed},
		{"nul byte in body", swap(valid, headLen+3, 0x00), ErrMalformed},
		{"multibyte utf8", "pmf_agt_" + strings.Repeat("é", 30), ErrMalformed},
		{"secret above 2^256", assemble("agt", goodKID, strings.Repeat("z", SecretLen)), ErrMalformed},
		{"flipped kid byte", swap(valid, headLen, flip(valid[headLen])), ErrBadChecksum},
		{"flipped secret byte", swap(valid, kidEnd+7, flip(valid[kidEnd+7])), ErrBadChecksum},
		{"flipped crc byte", swap(valid, Len-2, flip(valid[Len-2])), ErrBadChecksum},
		{"transposed body bytes", transpose(valid, headLen, headLen+1), ErrBadChecksum},
		{"unknown class, valid crc", assemble("zzz", goodKID, goodSecret), ErrUnknownClass},
		{"digit class, valid crc", assemble("000", goodKID, goodSecret), ErrUnknownClass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			class, kid, secret, err := Parse(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse error = %v, want %v", err, tc.want)
			}
			if class != "" || kid != "" || secret != nil {
				t.Errorf("Parse returned (%q, %q, %v) alongside an error", class, kid, secret)
			}
			if tc.in != "" && strings.Contains(err.Error(), tc.in) {
				t.Errorf("error text echoes the input token: %v", err)
			}
		})
	}
}

// flip returns a different in-alphabet byte, so the mutation is a checksum
// failure rather than an alphabet failure.
func flip(c byte) byte {
	if c == 'A' {
		return 'B'
	}
	return 'A'
}

func transpose(s string, i, j int) string {
	b := []byte(s)
	if b[i] == b[j] {
		b[j] = flip(b[j])
	}
	b[i], b[j] = b[j], b[i]
	return string(b)
}

func TestParseIsCanonical(t *testing.T) {
	t.Parallel()
	// Re-encoding a parsed token must reproduce it byte for byte; that is what
	// makes the fixed-width padding safe to rely on.
	for i := 0; i < 32; i++ {
		m, err := Mint(fleet.ClassEnrollment)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		class, kid, secret, err := Parse(m.Raw.Reveal())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		enc, ok := encodeBase62(secret, SecretLen)
		if !ok {
			t.Fatal("encodeBase62 overflowed a 43-digit field")
		}
		if got := assemble(string(class), kid, enc); got != m.Raw.Reveal() {
			t.Fatalf("re-encoded token = %q, want the original", got)
		}
	}
}

func TestEncodeCRCWidth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sum  uint32
		want string
	}{
		{"zero", 0, "000000"},
		{"one", 1, "000001"},
		{"sixty two", 62, "000010"},
		{"max uint32", ^uint32(0), "4gfFC3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := encodeCRC(tc.sum)
			if len(got) != CRCLen {
				t.Fatalf("encodeCRC(%d) length = %d, want %d", tc.sum, len(got), CRCLen)
			}
			if got != tc.want {
				t.Errorf("encodeCRC(%d) = %q, want %q", tc.sum, got, tc.want)
			}
		})
	}
}

func TestBase62RoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    []byte
		width int
		wantF bool // expect encode to report overflow
	}{
		{"zero", bytes.Repeat([]byte{0}, SecretBytes), SecretLen, false},
		{"max", bytes.Repeat([]byte{0xff}, SecretBytes), SecretLen, false},
		{"one", append(bytes.Repeat([]byte{0}, SecretBytes-1), 1), SecretLen, false},
		{"too narrow", bytes.Repeat([]byte{0xff}, SecretBytes), 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enc, ok := encodeBase62(tc.in, tc.width)
			if ok == tc.wantF {
				t.Fatalf("encodeBase62 ok = %v, want %v", ok, !tc.wantF)
			}
			if !ok {
				return
			}
			if len(enc) != tc.width {
				t.Fatalf("encoded width = %d, want %d", len(enc), tc.width)
			}
			dec, ok := decodeBase62(enc, len(tc.in))
			if !ok {
				t.Fatalf("decodeBase62(%q) reported overflow", enc)
			}
			if diff := cmp.Diff(tc.in, dec); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeBase62Rejects(t *testing.T) {
	t.Parallel()
	if _, ok := decodeBase62("a-b", 4); ok {
		t.Error("decodeBase62 accepted a non-base62 character")
	}
	if _, ok := decodeBase62("zz", 1); ok {
		t.Error("decodeBase62 accepted a value wider than the requested byte length")
	}
	if got, ok := decodeBase62("", 4); !ok || !bytes.Equal(got, make([]byte, 4)) {
		t.Errorf("decodeBase62(\"\") = %v, %v; want zeroes, true", got, ok)
	}
}

func TestRandomBase62Alphabet(t *testing.T) {
	t.Parallel()
	s, err := randomBase62(4096, randRead)
	if err != nil {
		t.Fatalf("randomBase62: %v", err)
	}
	if len(s) != 4096 {
		t.Fatalf("length = %d, want 4096", len(s))
	}
	seen := map[byte]bool{}
	for i := 0; i < len(s); i++ {
		if b62Index[s[i]] < 0 {
			t.Fatalf("character %q is outside the base62 alphabet", s[i])
		}
		seen[s[i]] = true
	}
	// Rejection sampling must reach every digit; modulo bias would still pass
	// this, but a broken alphabet index would not.
	if len(seen) != len(alphabet) {
		t.Errorf("saw %d distinct digits, want %d", len(seen), len(alphabet))
	}
}

// TestEntropyFailure swaps the package-level CSPRNG hook and therefore must
// not run in parallel. Go runs every non-parallel top-level test to completion
// before resuming the parallel ones, so no other test observes the swap.
func TestEntropyFailure(t *testing.T) {
	boom := errors.New("entropy exhausted")
	restore := randRead
	t.Cleanup(func() { randRead = restore })

	t.Run("kid", func(t *testing.T) {
		randRead = func([]byte) (int, error) { return 0, boom }
		if _, err := Mint(fleet.ClassAgent); !errors.Is(err, boom) {
			t.Fatalf("Mint error = %v, want %v", err, boom)
		}
		if _, err := GeneratePepper(); !errors.Is(err, boom) {
			t.Fatalf("GeneratePepper error = %v, want %v", err, boom)
		}
	})

	t.Run("pepper file", func(t *testing.T) {
		randRead = func([]byte) (int, error) { return 0, boom }
		path := filepath.Join(t.TempDir(), "sub", "pepper.key")
		if _, err := LoadOrCreatePepper(path); !errors.Is(err, boom) {
			t.Fatalf("LoadOrCreatePepper error = %v, want %v", err, boom)
		}
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Error("a pepper file was created despite the entropy failure")
		}
	})

	t.Run("secret", func(t *testing.T) {
		// Fail the secret draw and only the secret draw, so the error can
		// come from no path but mintWith's second read.
		//
		// Selecting on the buffer length rather than the call ordinal is
		// load-bearing. randomBase62 rejection-samples -- it discards bytes
		// >= 248 to keep the base62 reduction unbiased -- so a KID needs a
		// second read whenever fewer than KIDLen of its first KIDLen bytes
		// survive, which is 1-(248/256)^10 ~= 27% of runs. An ordinal gate
		// hands boom to that retry instead, and the assertion below still
		// passes because "mint kid" also wraps boom: the test stays green
		// while the statement it exists to cover goes unexecuted. The two
		// draws take distinct widths (KIDLen=10, SecretBytes=32), so the
		// width discriminates them exactly.
		read := func(b []byte) (int, error) {
			if len(b) == SecretBytes {
				return 0, boom
			}
			return restore(b)
		}
		_, err := mintWith(fleet.ClassAgent, "", read)
		if !errors.Is(err, boom) {
			t.Fatalf("mintWith error = %v, want %v", err, boom)
		}
		if !strings.Contains(err.Error(), "mint secret") {
			t.Fatalf("mintWith error = %v, want it to come from the secret draw", err)
		}
	})
}

// TestRandomBase62RejectionThreshold pins the exact byte at which rejection
// sampling starts, which no statistical test can do.
//
// 62 does not divide 256. Reducing a uniform byte modulo 62 would therefore
// make the first 256-4*62 = 8 digits of the alphabet measurably more likely,
// and every secret this package mints would carry that bias. The guard drops
// any byte >= 248 = 4*62 so that only whole cycles of the alphabet survive.
//
// TestRandomBase62Alphabet says in its own comment that modulo bias would
// still pass it, and it would: the biased digits are all still reachable.
// Feeding a fixed byte sequence is what distinguishes the two, because moving
// the threshold by one changes which bytes are consumed and therefore the
// exact output string.
func TestRandomBase62RejectionThreshold(t *testing.T) {
	t.Parallel()

	// 247 is the last accepted byte and 248 the first rejected one, so this
	// sequence straddles the edge. 249 and 255 are rejected either way, which
	// forces a second read and makes the consumed-byte count observable.
	first := []byte{247, 248, 249, 255}
	call := 0
	read := func(b []byte) (int, error) {
		call++
		if call == 1 {
			copy(b, first)
		} else {
			for i := range b {
				b[i] = byte(i)
			}
		}
		return len(b), nil
	}

	got, err := randomBase62(4, read)
	if err != nil {
		t.Fatalf("randomBase62: %v", err)
	}

	// 247 % 62 == 61 -> 'z'; 248, 249 and 255 are discarded; the second read
	// supplies 0, 1, 2 -> '0', '1', '2'.
	//
	// Accepting 248 instead would emit alphabet[248%62] == '0' in second
	// position and shift everything after it, giving "z001".
	const want = "z012"
	if got != want {
		t.Errorf("randomBase62 = %q, want %q; a byte on the wrong side of the "+
			"rejection threshold biases every minted secret", got, want)
	}
	if call != 2 {
		t.Errorf("read was called %d times, want 2", call)
	}
}
