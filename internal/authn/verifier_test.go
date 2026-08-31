// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// newTestVerifier wires a verifier over a fresh fake store and clock.
func newTestVerifier(t *testing.T, tweak func(*Options)) (*Verifier, *fakeStore, *countingMetrics, *fakeClock) {
	t.Helper()
	store := newFakeStore()
	metrics := newCountingMetrics()
	clock := newFakeClock()
	opts := Options{
		Store:   store,
		Hasher:  newTestHasher(t),
		Metrics: metrics,
		Clock:   clock.Now,
	}
	if tweak != nil {
		tweak(&opts)
	}
	v, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(v.Close)
	return v, store, metrics, clock
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()
	h, err := token.NewHasher(testPepper)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{name: "no store", opts: Options{Hasher: h}, want: "Store is required"},
		{name: "no hasher", opts: Options{Store: newFakeStore()}, want: "Hasher is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()
	v, err := New(Options{Store: newFakeStore(), Hasher: newTestHasher(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(v.Close)
	if got, want := v.cacheTTL, DefaultCacheTTL; got != want {
		t.Errorf("cacheTTL = %s, want %s", got, want)
	}
	if got, want := v.negativeTTL, DefaultNegativeTTL; got != want {
		t.Errorf("negativeTTL = %s, want %s", got, want)
	}
	if got, want := v.realm, DefaultRealm; got != want {
		t.Errorf("realm = %q, want %q", got, want)
	}
	if v.clock == nil || v.metrics == nil || v.log == nil || v.decoy == nil {
		t.Fatal("New left a defaulted field nil")
	}
	if got := len(v.pos.m); got != 0 {
		t.Errorf("fresh cache holds %d entries, want 0", got)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the raw credential to present and the class to demand.
		setup   func(t *testing.T, f *fakeStore, h *token.Hasher, c *fakeClock) (string, fleet.KeyClass)
		wantErr error
		// wantReason is the metric reason expected, when wantErr is non-nil.
		wantReason string
		check      func(t *testing.T, p *fleet.Principal)
	}{
		{
			name: "agent key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw, fleet.ClassAgent
			},
			check: func(t *testing.T, p *fleet.Principal) {
				if p.Class != fleet.ClassAgent {
					t.Errorf("class = %q, want %q", p.Class, fleet.ClassAgent)
				}
				if p.Role != fleet.RoleViewer {
					t.Errorf("role = %q, want %q", p.Role, fleet.RoleViewer)
				}
				if p.Scope == nil {
					t.Error("principal carries no scope")
				}
			},
		},
		{
			name: "admin key is always role admin",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAdmin, nil)
				return raw, fleet.ClassAdmin
			},
			check: func(t *testing.T, p *fleet.Principal) {
				if p.Role != fleet.RoleAdmin {
					t.Errorf("role = %q, want %q", p.Role, fleet.RoleAdmin)
				}
			},
		},
		{
			name: "enrollment key carries no role",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassEnrollment, func(k *fleet.Key) {
					k.Enrollment = &fleet.EnrollmentGrant{ClusterID: "prod-eu"}
				})
				return raw, fleet.ClassEnrollment
			},
			check: func(t *testing.T, p *fleet.Principal) {
				if p.Role != "" {
					t.Errorf("role = %q, want empty", p.Role)
				}
			},
		},
		{
			name: "empty token",
			setup: func(*testing.T, *fakeStore, *token.Hasher, *fakeClock) (string, fleet.KeyClass) {
				return "", fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonMalformed,
		},
		{
			name: "truncated token",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw[:len(raw)-1], fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonMalformed,
		},
		{
			name: "corrupted checksum",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				flipped := []byte(raw)
				if flipped[len(flipped)-1] == 'A' {
					flipped[len(flipped)-1] = 'B'
				} else {
					flipped[len(flipped)-1] = 'A'
				}
				return string(flipped), fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonMalformed,
		},
		{
			name: "agent key presented to the admin listener",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw, fleet.ClassAdmin
			},
			wantErr:    ErrWrongClass,
			wantReason: ReasonWrongClass,
		},
		{
			name: "agent key presented to the enrollment endpoint",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw, fleet.ClassEnrollment
			},
			wantErr:    ErrWrongClass,
			wantReason: ReasonWrongClass,
		},
		{
			name: "admin key cannot enroll",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAdmin, nil)
				return raw, fleet.ClassEnrollment
			},
			wantErr:    ErrWrongClass,
			wantReason: ReasonWrongClass,
		},
		{
			name: "class segment rewritten to admin",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return retagClass(t, raw, fleet.ClassAdmin), fleet.ClassAdmin
			},
			wantErr:    ErrWrongClass,
			wantReason: ReasonWrongClass,
		},
		{
			name: "unknown key id",
			setup: func(t *testing.T, _ *fakeStore, _ *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				m, err := token.Mint(fleet.ClassAgent)
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return m.Raw.Reveal(), fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonUnknownKey,
		},
		{
			name: "wrong secret for a real key id",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, key := mintKey(t, f, h, fleet.ClassAgent, nil)
				f.mutate(key.KID, func(k *fleet.Key) { k.SecretHMAC = h.Sum([]byte("someone else")) })
				return raw, fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonBadSecret,
		},
		{
			name: "stored class disagrees with the token",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, key := mintKey(t, f, h, fleet.ClassAdmin, nil)
				f.mutate(key.KID, func(k *fleet.Key) { k.Class = fleet.ClassAgent })
				return raw, fleet.ClassAdmin
			},
			wantErr:    ErrWrongClass,
			wantReason: ReasonWrongClass,
		},
		{
			name: "expired key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, c *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, func(k *fleet.Key) {
					k.ExpiresAt = testNow.Add(time.Minute)
				})
				c.advance(2 * time.Minute)
				return raw, fleet.ClassAgent
			},
			wantErr:    ErrExpired,
			wantReason: ReasonExpired,
		},
		{
			name: "revoked key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, key := mintKey(t, f, h, fleet.ClassAgent, nil)
				at := testNow
				f.mutate(key.KID, func(k *fleet.Key) { k.RevokedAt = &at; k.RevokedReason = "laptop lost" })
				return raw, fleet.ClassAgent
			},
			wantErr:    ErrRevoked,
			wantReason: ReasonRevoked,
		},
		{
			name: "store unavailable denies rather than serving stale",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				f.setErrs(errors.New("secret unreadable"), nil)
				return raw, fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonStoreError,
		},
		{
			name: "epoch unreadable denies",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) (string, fleet.KeyClass) {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				f.setErrs(nil, errors.New("api server unreachable"))
				return raw, fleet.ClassAgent
			},
			wantErr:    ErrUnauthenticated,
			wantReason: ReasonStoreError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, store, metrics, clock := newTestVerifier(t, nil)
			raw, want := tc.setup(t, store, v.hasher, clock)

			p, err := v.Verify(context.Background(), raw, want)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Verify() error = %v, want one matching %v", err, tc.wantErr)
				}
				if p != nil {
					t.Errorf("Verify() returned a principal alongside an error: %v", p)
				}
				if got := metrics.failure(tc.wantReason); got != 1 {
					t.Errorf("metric %q = %d, want 1", tc.wantReason, got)
				}
				if strings.Contains(err.Error(), raw) && raw != "" {
					t.Error("error message echoes the presented credential")
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v, want nil", err)
			}
			if p == nil {
				t.Fatal("Verify() returned no principal")
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

// retagClass rewrites a token's class segment and repairs its CRC, which is
// exactly what an attacker holding the token text can do: the checksum is
// public, unkeyed and cheap to recompute. It exists to prove the verifier
// trusts the stored class rather than the one in the token.
func retagClass(t *testing.T, raw string, class fleet.KeyClass) string {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := []byte(raw)
	copy(b[len(token.Prefix):len(token.Prefix)+token.ClassLen], class)
	bodyEnd := len(b) - token.CRCLen - 1 // everything before the final '_'
	sum := crc32.Checksum(b[:bodyEnd], crc32.MakeTable(crc32.Castagnoli))
	n := uint64(sum)
	for i := len(b) - 1; i >= bodyEnd+1; i-- {
		b[i] = alphabet[n%62]
		n /= 62
	}
	return string(b)
}

func TestVerifyCachesAndHonoursEpochBump(t *testing.T) {
	t.Parallel()
	v, store, metrics, clock := newTestVerifier(t, func(o *Options) {
		o.CacheTTL = time.Minute
	})
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	ctx := context.Background()

	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	first := store.gets()
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if got := store.gets(); got != first {
		t.Errorf("cached verification still called GetKey: %d then %d", first, got)
	}
	if metrics.hitCount() == 0 {
		t.Error("no cache hit recorded")
	}

	// A revocation bumps the epoch, which must invalidate the cached entry
	// well inside the cache TTL.
	at := clock.Now()
	store.mutate(key.KID, func(k *fleet.Key) { k.RevokedAt = &at })
	clock.advance(time.Second) // still far inside CacheTTL

	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after epoch bump Verify() error = %v, want %v", err, ErrRevoked)
	}
	if got := store.gets(); got <= first {
		t.Errorf("epoch bump did not force a fresh lookup: %d then %d", first, got)
	}
}

func TestVerifyCacheExpiresWithTTL(t *testing.T) {
	t.Parallel()
	v, store, _, clock := newTestVerifier(t, func(o *Options) { o.CacheTTL = 30 * time.Second })
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	ctx := context.Background()

	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	before := store.gets()
	clock.advance(31 * time.Second)
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify after ttl: %v", err)
	}
	if got := store.gets(); got != before+1 {
		t.Errorf("GetKey calls = %d, want %d after the cache entry expired", got, before+1)
	}
}

func TestVerifyCachedEntryExpiryAndClass(t *testing.T) {
	t.Parallel()
	v, store, _, clock := newTestVerifier(t, func(o *Options) { o.CacheTTL = time.Hour })
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, func(k *fleet.Key) {
		k.ExpiresAt = testNow.Add(10 * time.Minute)
	})
	ctx := context.Background()
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A cached principal must still be refused for the wrong listener class.
	if _, err := v.Verify(ctx, raw, fleet.ClassAdmin); !errors.Is(err, ErrWrongClass) {
		t.Fatalf("cached entry, wrong class: error = %v, want %v", err, ErrWrongClass)
	}

	// And the cached entry must not outlive the credential itself.
	clock.advance(11 * time.Minute)
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); !errors.Is(err, ErrExpired) {
		t.Fatalf("cached entry past expiry: error = %v, want %v", err, ErrExpired)
	}
}

func TestVerifyNegativeCache(t *testing.T) {
	t.Parallel()
	v, store, metrics, clock := newTestVerifier(t, func(o *Options) { o.NegativeTTL = 5 * time.Second })
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	store.mutate(key.KID, func(k *fleet.Key) { k.SecretHMAC = v.hasher.Sum([]byte("wrong")) })
	ctx := context.Background()

	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Verify: %v", err)
	}
	before := store.gets()
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("second Verify: %v", err)
	}
	if got := store.gets(); got != before {
		t.Errorf("negative cache did not prevent a lookup: %d then %d", before, got)
	}
	if metrics.failure(ReasonBadSecret) != 2 {
		t.Errorf("bad_secret failures = %d, want 2", metrics.failure(ReasonBadSecret))
	}

	clock.advance(6 * time.Second)
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("third Verify: %v", err)
	}
	if got := store.gets(); got != before+1 {
		t.Errorf("expired negative entry did not force a lookup: %d then %d", before, got)
	}
}

func TestVerifyTouchesKeyAsynchronously(t *testing.T) {
	t.Parallel()
	v, store, _, clock := newTestVerifier(t, nil)
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)

	if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	v.Close()
	at, ok := store.touchedAt(key.KID)
	if !ok {
		t.Fatal("TouchKey was never called")
	}
	if !at.Equal(clock.Now()) {
		t.Errorf("TouchKey at = %s, want %s", at, clock.Now())
	}
}

func TestVerifyTouchFailureNeverFailsTheRequest(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	store.mu.Lock()
	store.touchErr = errors.New("state secret is read-only")
	store.mu.Unlock()

	if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	v.Close()
}

func TestVerifyTouchSurvivesRequestCancellation(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	cancel() // the client hangs up the instant the response is written
	v.Close()
	if _, ok := store.touchedAt(key.KID); !ok {
		t.Error("a cancelled request dropped the best-effort last-used write")
	}
}

func TestVerifyIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	raws := make([]string, 8)
	for i := range raws {
		raws[i], _ = mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	}

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), raws[i%len(raws)], fleet.ClassAgent); err != nil {
				t.Errorf("Verify: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestVerifyRateLimitsFailuresPerSource(t *testing.T) {
	t.Parallel()
	v, _, metrics, clock := newTestVerifier(t, nil)
	ctx := ContextWithSourceIP(context.Background(), "203.0.113.9")

	var limited bool
	for range failureBurst + 3 {
		m, err := token.Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, err := v.Verify(ctx, m.Raw.Reveal(), fleet.ClassAgent); errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
		clock.advance(time.Millisecond)
	}
	if !limited {
		t.Fatal("a source producing more than the failure burst was never rate limited")
	}
	if metrics.failure(ReasonRateLimited) == 0 {
		t.Error("rate_limited failure was not counted")
	}

	// A successful verification from a different source is unaffected.
	other := ContextWithSourceIP(context.Background(), "198.51.100.4")
	store := v.store.(*fakeStore)
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	if _, err := v.Verify(other, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("unrelated source was throttled: %v", err)
	}
}

func TestVerifyRateLimitRecoversAndClearsOnSuccess(t *testing.T) {
	t.Parallel()
	v, store, _, clock := newTestVerifier(t, nil)
	ip := "203.0.113.10"
	ctx := ContextWithSourceIP(context.Background(), ip)
	for range failureBurst + 1 {
		m, _ := token.Mint(fleet.ClassAgent)
		_, _ = v.Verify(ctx, m.Raw.Reveal(), fleet.ClassAgent)
	}
	if v.limiter.Allow(ip, clock.Now()) {
		t.Fatal("source should be in backoff")
	}
	clock.advance(2 * time.Second)
	if !v.limiter.Allow(ip, clock.Now()) {
		t.Fatal("backoff never expired")
	}
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify after backoff: %v", err)
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	t.Parallel()
	if got := PrincipalFrom(context.Background()); got != nil {
		t.Fatalf("PrincipalFrom(empty) = %v, want nil", got)
	}
	want := &fleet.Principal{KID: "abc", Class: fleet.ClassAgent, Name: "bot"}
	got := PrincipalFrom(ContextWithPrincipal(context.Background(), want))
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("principal round trip (-want +got):\n%s", diff)
	}
	if got := SourceIPFrom(context.Background()); got != "" {
		t.Errorf("SourceIPFrom(empty) = %q, want empty", got)
	}
	if got := SourceIPFrom(ContextWithSourceIP(context.Background(), "10.1.2.3")); got != "10.1.2.3" {
		t.Errorf("SourceIPFrom = %q, want 10.1.2.3", got)
	}
}

func TestNopMetricsDoesNothing(t *testing.T) {
	t.Parallel()
	var m Metrics = NopMetrics{}
	m.AuthSuccess(fleet.ClassAgent)
	m.AuthFailure(ReasonExpired)
	m.CacheHit()
	m.CacheMiss()
}

func TestScopeNameIsAClosedMapping(t *testing.T) {
	t.Parallel()
	tests := map[fleet.KeyClass]string{
		fleet.ClassAdmin:      "admin",
		fleet.ClassAgent:      "mcp",
		fleet.ClassEnrollment: "enroll",
		fleet.KeyClass("xyz"): "mcp",
	}
	for class, want := range tests {
		if got := ScopeName(class); got != want {
			t.Errorf("ScopeName(%q) = %q, want %q", class, got, want)
		}
	}
}

func TestScopesOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		p    *fleet.Principal
		want []string
	}{
		{name: "nil principal", p: nil, want: nil},
		{
			name: "agent with tools",
			p: &fleet.Principal{
				Class: fleet.ClassAgent,
				Role:  fleet.RoleViewer,
				Scope: &fleet.Scope{Tools: fleet.ToolScope{Allow: []string{"prom.query", "prom.range"}}},
			},
			want: []string{"class:agt", "role:viewer", "tool:prom.query", "tool:prom.range"},
		},
		{
			name: "enrollment token has no role",
			p:    &fleet.Principal{Class: fleet.ClassEnrollment},
			want: []string{"class:enr"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, ScopesOf(tc.p)); diff != "" {
				t.Errorf("ScopesOf (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSlogNeverSeesACredential(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	v, store, _, _ := newTestVerifier(t, func(o *Options) {
		o.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	ctx := context.Background()
	if _, err := v.Verify(ctx, raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	store.mutate(key.KID, func(k *fleet.Key) { k.SecretHMAC = v.hasher.Sum([]byte("no")) })
	_, _ = v.Verify(ctx, raw, fleet.ClassAgent)
	v.Close()

	logged := buf.String()
	if strings.Contains(logged, raw) {
		t.Error("the raw credential reached the log")
	}
	if strings.Contains(logged, raw[len(token.Prefix)+token.ClassLen+1+token.KIDLen:]) {
		t.Error("the secret segment reached the log")
	}
	// Nor the stored digest, nor the pepper, in any encoding a formatter might
	// reach for.
	stored, err := store.GetKey(ctx, key.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	for what, secret := range map[string][]byte{"stored hmac": stored.SecretHMAC, "pepper": testPepper} {
		for enc, rendered := range map[string]string{
			"raw":       string(secret),
			"hex":       hex.EncodeToString(secret),
			"base64":    base64.StdEncoding.EncodeToString(secret),
			"base64raw": base64.RawStdEncoding.EncodeToString(secret),
		} {
			if strings.Contains(logged, rendered) {
				t.Errorf("the %s reached the log (%s encoded)", what, enc)
			}
		}
	}
}

// syncBuffer is an io.Writer safe for concurrent use, for capturing slog
// output from the verifier's background goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestParseHappensBeforeAnyStoreAccess pins the order of the hot path. A
// malformed or mis-checksummed paste must cost a few hundred nanoseconds, not
// a lookup, or an unauthenticated caller can turn garbage into store load.
func TestParseHappensBeforeAnyStoreAccess(t *testing.T) {
	t.Parallel()

	good, err := token.Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw := good.Raw.Reveal()

	tests := []struct {
		name  string
		token string
		want  fleet.KeyClass
	}{
		{name: "empty", token: "", want: fleet.ClassAgent},
		{name: "wrong prefix", token: "ghp_" + raw[4:], want: fleet.ClassAgent},
		{name: "truncated", token: raw[:len(raw)-1], want: fleet.ClassAgent},
		{name: "one byte too long", token: raw + "a", want: fleet.ClassAgent},
		{name: "separator moved", token: raw[:7] + "x" + raw[8:], want: fleet.ClassAgent},
		{name: "non base62 body", token: raw[:20] + "!" + raw[21:], want: fleet.ClassAgent},
		{name: "bad checksum", token: raw[:len(raw)-1] + flip(raw[len(raw)-1]), want: fleet.ClassAgent},
		{name: "unknown class", token: mustRetag(t, raw, "xyz"), want: fleet.ClassAgent},
		// A well-formed token of the wrong class is rejected on the plaintext
		// class segment, which is also before any lookup.
		{name: "wrong class", token: raw, want: fleet.ClassAdmin},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, store, _, _ := newTestVerifier(t, nil)
			if _, err := v.Verify(context.Background(), tc.token, tc.want); err == nil {
				t.Fatal("Verify() succeeded, want an error")
			}
			if got := store.gets(); got != 0 {
				t.Errorf("GetKey called %d times before the token was parsed", got)
			}
			if got := store.epochs(); got != 0 {
				t.Errorf("Epoch read %d times before the token was parsed", got)
			}
		})
	}
}

// flip returns a different base62 character.
func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// mustRetag rewrites the class segment and repairs the checksum.
func mustRetag(t *testing.T, raw, class string) string {
	t.Helper()
	return retagClass(t, raw, fleet.KeyClass(class))
}

// TestTouchIsBestEffortAndDoesNotBumpTheEpoch proves the last-used write is
// off the request path in all three senses that matter: it does not delay the
// response, it does not fail the request, and it does not invalidate the
// verifier's cache -- which it would if it bumped the revocation epoch, since
// it runs on every authenticated request.
func TestTouchIsBestEffortAndDoesNotBumpTheEpoch(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)

	gate := make(chan struct{})
	store.mu.Lock()
	store.touchGate = gate
	before := store.epoch
	store.mu.Unlock()

	// The response is produced while TouchKey is still blocked, which is the
	// non-blocking property stated without measuring a wall clock.
	if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, ok := store.touchedAt(key.KID); ok {
		t.Fatal("TouchKey completed synchronously; it must not be on the request path")
	}
	close(gate)
	v.Close()
	if _, ok := store.touchedAt(key.KID); !ok {
		t.Error("the best-effort last-used write never happened")
	}
	if got := store.currentEpoch(); got != before {
		t.Errorf("epoch = %d, want %d: recording last use must not invalidate every cache", got, before)
	}

	// And the cached decision survives it: a second verification is served
	// without touching the store.
	gets := store.gets()
	if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if got := store.gets(); got != gets {
		t.Errorf("GetKey calls = %d, want %d: the cache was invalidated by a touch", got, gets)
	}
}

// TestTouchIsDroppedWhenTheWorkerBudgetIsExhausted proves the bounded
// goroutine count, not an unbounded one: past the budget the update is
// discarded rather than queued.
func TestTouchIsDroppedWhenTheWorkerBudgetIsExhausted(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	gate := make(chan struct{})
	store.mu.Lock()
	store.touchGate = gate
	store.mu.Unlock()

	raws := make([]string, touchConcurrency+8)
	kids := make([]string, len(raws))
	for i := range raws {
		var key *fleet.Key
		raws[i], key = mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
		kids[i] = key.KID
	}
	for _, raw := range raws {
		if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	close(gate)
	v.Close()

	var touched int
	for _, kid := range kids {
		if _, ok := store.touchedAt(kid); ok {
			touched++
		}
	}
	if touched > touchConcurrency {
		t.Errorf("%d last-used writes ran, want at most the %d-goroutine budget", touched, touchConcurrency)
	}
	if touched == 0 {
		t.Error("no last-used write ran at all")
	}
}

// TestVerifiedCacheIsBoundedAndEvicts proves the positive cache cannot grow
// with the number of credentials presented.
func TestVerifiedCacheIsBoundedAndEvicts(t *testing.T) {
	t.Parallel()
	const size = 4
	v, store, _, _ := newTestVerifier(t, func(o *Options) { o.CacheSize = size })

	raws := make([]string, size*3)
	for i := range raws {
		raws[i], _ = mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
		if _, err := v.Verify(context.Background(), raws[i], fleet.ClassAgent); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	if got := len(v.pos.m); got > size {
		t.Errorf("positive cache holds %d entries, want at most %d", got, size)
	}
	// The oldest entry was evicted, so re-presenting it costs a lookup.
	before := store.gets()
	if _, err := v.Verify(context.Background(), raws[0], fleet.ClassAgent); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := store.gets(); got != before+1 {
		t.Errorf("GetKey calls = %d, want %d: the evicted entry was served from cache", got, before+1)
	}

	// The negative cache is bounded the same way, so presenting garbage cannot
	// evict every verified credential's neighbours without limit.
	for range size * 3 {
		m, err := token.Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, err := v.Verify(context.Background(), m.Raw.Reveal(), fleet.ClassAgent); err == nil {
			t.Fatal("an unknown key identifier authenticated")
		}
	}
	if got := len(v.neg.m); got > size {
		t.Errorf("negative cache holds %d entries, want at most %d", got, size)
	}
}
