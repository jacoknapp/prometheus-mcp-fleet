// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

func newHasherForTest(t *testing.T, fill byte) *Hasher {
	t.Helper()
	h, err := NewHasher(bytes.Repeat([]byte{fill}, MinPepperBytes))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return h
}

func TestNewHasherRejectsShortPepper(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pepper  []byte
		wantErr error
	}{
		{"nil", nil, ErrShortPepper},
		{"empty", []byte{}, ErrShortPepper},
		{"one byte", []byte{0x01}, ErrShortPepper},
		{"one short", bytes.Repeat([]byte{0x01}, MinPepperBytes-1), ErrShortPepper},
		{"exact", bytes.Repeat([]byte{0x01}, MinPepperBytes), nil},
		{"long", bytes.Repeat([]byte{0x01}, 4*MinPepperBytes), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, err := NewHasher(tc.pepper)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewHasher error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				if h != nil {
					t.Error("NewHasher returned a hasher alongside an error")
				}
				return
			}
			if h == nil {
				t.Fatal("NewHasher returned nil without an error")
			}
		})
	}
}

func TestNewHasherCopiesPepper(t *testing.T) {
	t.Parallel()
	pepper := bytes.Repeat([]byte{0xa5}, MinPepperBytes)
	h, err := NewHasher(pepper)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	before := h.Sum([]byte("secret"))
	// The caller is entitled to wipe its own buffer after construction.
	for i := range pepper {
		pepper[i] = 0
	}
	after := h.Sum([]byte("secret"))
	if diff := cmp.Diff(before, after); diff != "" {
		t.Errorf("digest changed after the caller zeroed its pepper buffer (-before +after):\n%s", diff)
	}
}

func TestHasherSum(t *testing.T) {
	t.Parallel()
	h := newHasherForTest(t, 0x01)
	other := newHasherForTest(t, 0x02)

	tests := []struct {
		name   string
		secret []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short", []byte("a")},
		{"token sized", bytes.Repeat([]byte{0x7f}, SecretBytes)},
		{"long", bytes.Repeat([]byte{0x00}, 4096)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sum := h.Sum(tc.secret)
			if len(sum) != 32 {
				t.Fatalf("digest length = %d, want 32", len(sum))
			}
			if diff := cmp.Diff(sum, h.Sum(tc.secret)); diff != "" {
				t.Errorf("Sum is not deterministic (-first +second):\n%s", diff)
			}
			if bytes.Equal(sum, other.Sum(tc.secret)) {
				t.Error("two different peppers produced the same digest")
			}
			if bytes.Equal(sum, tc.secret) {
				t.Error("digest equals the input secret")
			}
		})
	}
}

func TestHasherEqual(t *testing.T) {
	t.Parallel()
	h := newHasherForTest(t, 0x01)
	other := newHasherForTest(t, 0x02)
	m, err := Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	stored := h.Sum(m.Secret)

	tests := []struct {
		name   string
		stored []byte
		secret []byte
		want   bool
	}{
		{"match", stored, m.Secret, true},
		{"wrong secret", stored, bytes.Repeat([]byte{0}, SecretBytes), false},
		{"wrong pepper", other.Sum(m.Secret), m.Secret, false},
		{"nil stored", nil, m.Secret, false},
		{"empty stored", []byte{}, m.Secret, false},
		{"truncated stored", stored[:16], m.Secret, false},
		{"over long stored", append(bytes.Clone(stored), 0), m.Secret, false},
		{"nil secret against nil stored", nil, nil, false},
		{"nil secret", stored, nil, false},
		{"single bit flip", flipBit(stored, 0), m.Secret, false},
		{"last bit flip", flipBit(stored, len(stored)*8-1), m.Secret, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := h.Equal(tc.stored, tc.secret); got != tc.want {
				t.Errorf("Equal = %v, want %v", got, tc.want)
			}
		})
	}
}

func flipBit(b []byte, bit int) []byte {
	out := bytes.Clone(b)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

func TestHasherDecoy(t *testing.T) {
	t.Parallel()
	h := newHasherForTest(t, 0x03)

	// A miss must not be distinguishable from a hit by anything observable
	// from Go: no panic, no result, no error.
	h.Decoy(nil)
	h.Decoy([]byte("whatever"))
	h.Decoy(bytes.Repeat([]byte{0xff}, SecretBytes))

	// Feeding the fixed dummy input proves the comparison really is executed
	// rather than optimised away.
	before := decoySink.Load()
	h.Decoy(decoySecret)
	if decoySink.Load() <= before {
		t.Error("Decoy did not perform the comparison it exists to perform")
	}
}

func TestNilHasherFailsClosed(t *testing.T) {
	t.Parallel()
	var h *Hasher
	if got := h.Sum([]byte("x")); got != nil {
		t.Errorf("nil Hasher Sum = %v, want nil", got)
	}
	if h.Equal([]byte("x"), []byte("x")) {
		t.Error("nil Hasher Equal returned true")
	}
	h.Decoy([]byte("x"))
}

func TestHasherIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	h := newHasherForTest(t, 0x04)
	secret := bytes.Repeat([]byte{0x5a}, SecretBytes)
	want := h.Sum(secret)

	const goroutines = 32
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < 64; j++ {
				if !h.Equal(want, secret) {
					errs <- errors.New("concurrent Equal returned false")
					return
				}
				h.Decoy(secret)
			}
			errs <- nil
		}()
	}
	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
