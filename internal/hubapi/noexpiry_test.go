// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// TestResolveExpiry covers the lifetime resolver directly, because the branch
// that matters most -- an omitted field must never mint an immortal credential
// -- is a property of this function rather than of any one route.
func TestResolveExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	const max = 90 * 24 * time.Hour

	tests := []struct {
		name     string
		want     fleet.Duration
		noExpiry bool
		class    fleet.KeyClass
		wantTime time.Time
		wantErr  string
	}{
		{
			name:     "an absent ttl takes the class default and is never immortal",
			class:    fleet.ClassAgent,
			wantTime: now.Add(max),
		},
		{
			name:     "an explicit ttl is honoured",
			want:     fleet.Duration(time.Hour),
			class:    fleet.ClassAgent,
			wantTime: now.Add(time.Hour),
		},
		{
			name:    "a ttl above the maximum is refused rather than clamped",
			want:    fleet.Duration(max + time.Hour),
			class:   fleet.ClassAgent,
			wantErr: "exceeds the configured maximum",
		},
		{
			name:     "an agent key may be minted with no expiry",
			noExpiry: true,
			class:    fleet.ClassAgent,
			wantTime: time.Time{},
		},
		{
			name:     "an admin key may not: it mints other credentials",
			noExpiry: true,
			class:    fleet.ClassAdmin,
			wantErr:  "only an agt key may be minted with no expiry",
		},
		{
			name:     "an enrollment token may not: it admits new clusters",
			noExpiry: true,
			class:    fleet.ClassEnrollment,
			wantErr:  "only an agt key may be minted with no expiry",
		},
		{
			name:     "a ttl and no-expiry together are refused, not silently ranked",
			want:     fleet.Duration(time.Hour),
			noExpiry: true,
			class:    fleet.ClassAgent,
			wantErr:  "mutually exclusive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveExpiry(tc.want, tc.noExpiry, tc.class, max, now)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("resolveExpiry() = %v, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExpiry: %v", err)
			}
			if !got.Equal(tc.wantTime) {
				t.Errorf("expiry = %v, want %v", got, tc.wantTime)
			}
		})
	}
}

// TestExpiryLabel pins the rendering the security log depends on: a zero time
// has to read as a decision, not as a missing value.
func TestExpiryLabel(t *testing.T) {
	t.Parallel()
	if got := expiryLabel(time.Time{}); got != "never" {
		t.Errorf("expiryLabel(zero) = %q, want %q", got, "never")
	}
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if got, want := expiryLabel(at), "2026-03-01T12:00:00Z"; got != want {
		t.Errorf("expiryLabel = %q, want %q", got, want)
	}
}

// TestCreateKeyNoExpiry drives the whole route, so the stored record and not
// only the resolver is checked: a key with no expiry must persist as one and
// must still authenticate long after any TTL would have lapsed.
func TestCreateKeyNoExpiry(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	var got MintedKeyResponse
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys", CreateKeyRequest{
		Class:    fleet.ClassAgent,
		Name:     "immortal-bot",
		Scope:    validScope(),
		NoExpiry: true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	decode(t, resp, &got)
	if !got.Key.ExpiresAt.IsZero() {
		t.Errorf("expiresAt = %v, want the zero time", got.Key.ExpiresAt)
	}

	// The point of the feature: still usable long after the default lifetime
	// would have run out. A key that merely reported no expiry while the auth
	// path rejected it would be worse than no feature at all.
	//
	// Asserted against the stored record rather than by replaying a request,
	// because the admin credential doing the asking has its own 90-day
	// lifetime -- advancing the clock past that would prove only that the
	// caller expired.
	stored, err := h.store.GetKey(t.Context(), got.Key.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !stored.ExpiresAt.IsZero() {
		t.Errorf("stored expiresAt = %v, want the zero time", stored.ExpiresAt)
	}
	if far := h.clock.Now().Add(10 * 365 * 24 * time.Hour); !stored.Usable(far) {
		t.Errorf("a key minted with no expiry is unusable at %v", far)
	}
}

// TestCreateKeyNoExpiryRefusedForAdmin pins the class restriction at the route.
func TestCreateKeyNoExpiryRefusedForAdmin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	resp := h.adminDo(http.MethodPost, "/admin/v1/keys", CreateKeyRequest{
		Class:    fleet.ClassAdmin,
		Name:     "root-op",
		NoExpiry: true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if env := envelopeOf(t, resp); env.Error.Code != CodeInvalidRequest {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeInvalidRequest)
	}
}

// TestRotateKeyNoExpiry covers the rotate route's own copy of the decision.
func TestRotateKeyNoExpiry(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	var minted MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys", CreateKeyRequest{
		Class: fleet.ClassAgent,
		Name:  "rotate-me",
		Scope: validScope(),
	}), &minted)
	if minted.Key.ExpiresAt.IsZero() {
		t.Fatal("test setup: the original key should have an expiry to rotate away from")
	}

	var rotated MintedKeyResponse
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+minted.Key.KID+"/rotate", rotateRequest{NoExpiry: true})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	decode(t, resp, &rotated)
	if !rotated.Key.ExpiresAt.IsZero() {
		t.Errorf("rotated expiresAt = %v, want the zero time", rotated.Key.ExpiresAt)
	}
}
