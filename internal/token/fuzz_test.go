// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// FuzzTokenParse asserts the two properties Parse must hold for every possible
// input.
//
//  1. Totality. Parse never panics and never returns an error outside its three
//     documented sentinels. Parse runs before authentication, on bytes an
//     unauthenticated caller fully controls, so a panic here is a remote DoS.
//  2. Canonicity. Any input Parse accepts re-encodes to itself byte for byte.
//     Without this, two distinct strings could decode to the same secret and
//     the fixed-width padding would be a forgery surface rather than a
//     formatting detail.
//
// Every iteration additionally mints a fresh token and round-trips it, so the
// Mint/Parse pair is exercised against the corpus rather than only against the
// hand-written table tests.
func FuzzTokenParse(f *testing.F) {
	classes := []fleet.KeyClass{fleet.ClassAdmin, fleet.ClassAgent, fleet.ClassEnrollment}
	for _, c := range classes {
		m, err := Mint(c)
		if err != nil {
			f.Fatalf("seed Mint(%q): %v", c, err)
		}
		raw := m.Raw.Reveal()
		f.Add(raw)
		// Near-miss seeds steer the mutator at the interesting boundaries.
		f.Add(raw[:Len-1])
		f.Add(raw + "x")
		f.Add(strings.ToUpper(raw))
		f.Add(raw[:crcSep] + "_" + strings.Repeat("0", CRCLen))
	}
	f.Add("")
	f.Add("pmf_")
	f.Add("pmf_agt_")
	f.Add(strings.Repeat("\x00", Len))
	f.Add(strings.Repeat("z", Len))
	f.Add("pmf_agt_" + strings.Repeat("z", KIDLen+SecretLen) + "_" + strings.Repeat("z", CRCLen))
	f.Add("pmf_zzz_" + strings.Repeat("0", KIDLen+SecretLen) + "_" + strings.Repeat("0", CRCLen))
	f.Add("pmf_agt_" + strings.Repeat("é", 30))

	f.Fuzz(func(t *testing.T, in string) {
		// Property: minting and parsing are inverses, on every iteration.
		// The entropy source is derived from the fuzz input so that the target
		// stays deterministic; a nondeterministic target makes Go's fuzzing
		// engine treat every run as newly interesting and stall.
		class := classes[len(in)%len(classes)]
		m, err := mintWith(class, "", seededReader(in))
		if err != nil {
			t.Fatalf("mintWith(%q): %v", class, err)
		}
		gotClass, gotKID, gotSecret, err := Parse(m.Raw.Reveal())
		if err != nil {
			t.Fatalf("Parse(Mint(%q)): %v", class, err)
		}
		if gotClass != class || gotKID != m.KID || !bytes.Equal(gotSecret, m.Secret) {
			t.Fatalf("round trip mismatch: class %q/%q kid %q/%q secret equal=%v",
				class, gotClass, m.KID, gotKID, bytes.Equal(gotSecret, m.Secret))
		}

		// Property: totality over arbitrary input.
		pClass, pKID, pSecret, err := Parse(in)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBadChecksum) && !errors.Is(err, ErrUnknownClass) {
				t.Fatalf("Parse returned an undocumented error: %v", err)
			}
			if pClass != "" || pKID != "" || pSecret != nil {
				t.Fatalf("Parse returned material alongside an error")
			}
			return
		}

		// Property: canonicity of every accepted input.
		if !pClass.Valid() {
			t.Fatalf("Parse accepted an invalid class %q", pClass)
		}
		if len(pKID) != KIDLen {
			t.Fatalf("kid length = %d, want %d", len(pKID), KIDLen)
		}
		if len(pSecret) != SecretBytes {
			t.Fatalf("secret length = %d, want %d", len(pSecret), SecretBytes)
		}
		enc, ok := encodeBase62(pSecret, SecretLen)
		if !ok {
			t.Fatal("a parsed secret did not fit back into its own field width")
		}
		canonical := assemble(string(pClass), pKID, enc)
		if canonical != in {
			t.Fatalf("re-encoding is not canonical:\n got %q\nwant %q", canonical, in)
		}

		// Property: parsing is idempotent.
		again, kid2, secret2, err := Parse(canonical)
		if err != nil || again != pClass || kid2 != pKID || !bytes.Equal(secret2, pSecret) {
			t.Fatalf("second Parse disagreed with the first: %v", err)
		}
	})
}

// seededReader returns a deterministic byte source derived from seed. ChaCha8
// is used only because it is the stdlib's seedable stream generator; nothing
// here depends on its cryptographic strength.
func seededReader(seed string) func([]byte) (int, error) {
	r := rand.NewChaCha8(sha256.Sum256([]byte(seed)))
	return func(b []byte) (int, error) { return r.Read(b) }
}
