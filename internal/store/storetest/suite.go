// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"strings"
)

// OpenFunc creates a store for one subtest. It must return an independent,
// empty store on every call and register its own cleanup, because the suite
// runs its subtests in parallel.
type OpenFunc func(t *testing.T) store.Store

// Reference timestamps. Fixed values keep every comparison deterministic and,
// because they carry no monotonic reading, survive a serialisation round trip
// unchanged.
var (
	tBase    = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tExpires = tBase.Add(720 * time.Hour)
)

// RunSuite runs the full conformance suite against the store returned by open.
//
// Each named case gets its own store, and the cases run in parallel, so open
// must hand out an independent empty store every time.
func RunSuite(t *testing.T, open OpenFunc) {
	t.Helper()
	tests := []struct {
		name string
		run  func(t *testing.T, s store.Store)
	}{
		{"KeyRoundTrip", testKeyRoundTrip},
		{"KeySecretHMACSurvives", testKeySecretHMACSurvives},
		{"GetKeyReturnsCopies", testGetKeyReturnsCopies},
		{"PutKeyRejectsDuplicate", testPutKeyRejectsDuplicate},
		{"PutKeyValidates", testPutKeyValidates},
		{"PutKeyIfNoUsable", testPutKeyIfNoUsable},
		{"GetKeyNotFound", testGetKeyNotFound},
		{"ListKeysOrdering", testListKeysOrdering},
		{"ListKeysEmpty", testListKeysEmpty},
		{"RevokeKey", testRevokeKey},
		{"Prune", testPrune},
		{"PruneKeepsWhatStillDecides", testPruneKeepsWhatStillDecides},
		{"PruneRejectsNegativeRetention", testPruneRejectsNegativeRetention},
		{"ReplaceKey", testReplaceKey},
		{"ReplaceKeyRefusesRevoked", testReplaceKeyRefusesRevoked},
		{"ReplaceKeyNotFound", testReplaceKeyNotFound},
		{"ReplaceKeyAtomicOnCollision", testReplaceKeyAtomicOnCollision},
		{"RevokeKeyIsIdempotent", testRevokeKeyIsIdempotent},
		{"RevokeKeyNotFound", testRevokeKeyNotFound},
		{"DeleteKey", testDeleteKey},
		{"DeleteKeyNotFound", testDeleteKeyNotFound},
		{"TouchKey", testTouchKey},
		{"TouchKeyDoesNotBumpEpoch", testTouchKeyDoesNotBumpEpoch},
		{"TouchKeyNotFound", testTouchKeyNotFound},
		{"BurnEnrollment", testBurnEnrollment},
		{"BurnEnrollmentTwice", testBurnEnrollmentTwice},
		{"BurnEnrollmentRejects", testBurnEnrollmentRejects},
		{"BurnEnrollmentConcurrent", testBurnEnrollmentConcurrent},
		{"BurnEnrollmentReusableUnlimited", testBurnEnrollmentReusableUnlimited},
		{"BurnEnrollmentReusableCapped", testBurnEnrollmentReusableCapped},
		{"RevokedCerts", testRevokedCerts},
		{"RevokedCertsOrdering", testRevokedCertsOrdering},
		{"RevokedCertValidates", testRevokedCertValidates},
		{"EpochMonotonic", testEpochMonotonic},
		{"ContextCancellation", testContextCancellation},
		{"ClosedStore", testClosedStore},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, open(t))
		})
	}
}

// --- fixtures ------------------------------------------------------------

// agentKey builds an agent credential record.
func agentKey(kid string, createdAt time.Time) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassAgent,
		Name:       "key-" + kid,
		Owner:      "sre@example.test",
		SecretHMAC: []byte("hmac-" + kid),
		Scope: &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"prod-eu-1"}},
			Tools:    fleet.ToolScope{Allow: []string{"prom.query"}},
			Limits:   fleet.Limits{MaxPoints: 500, Timeout: fleet.Duration(30 * time.Second)},
		},
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(720 * time.Hour),
	}
}

// adminKey builds an admin credential record.
func adminKey(kid string, createdAt time.Time) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassAdmin,
		Name:       "admin-" + kid,
		SecretHMAC: []byte("hmac-" + kid),
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(720 * time.Hour),
	}
}

// enrollmentKey builds a single-use enrollment token record.
func enrollmentKey(kid string, createdAt time.Time) *fleet.Key {
	const clusterID = "prod-eu-1"
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassEnrollment,
		Name:       "enroll-" + clusterID,
		SecretHMAC: []byte("hmac-" + kid),
		Enrollment: &fleet.EnrollmentGrant{
			ClusterID: clusterID,
			Labels:    map[string]string{"env": "prod"},
		},
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(15 * time.Minute),
	}
}

// reusableEnrollmentKey is enrollmentKey with Reusable set and an optional
// redemption cap; maxRedemptions of 0 means unlimited.
func reusableEnrollmentKey(kid string, createdAt time.Time, maxRedemptions int) *fleet.Key {
	k := enrollmentKey(kid, createdAt)
	k.Enrollment.Reusable = true
	k.Enrollment.MaxRedemptions = maxRedemptions
	return k
}

func mustPut(t *testing.T, s store.Store, k *fleet.Key) {
	t.Helper()
	if err := s.PutKey(t.Context(), k); err != nil {
		t.Fatalf("PutKey(%s): %v", k.KID, err)
	}
}

func mustEpoch(t *testing.T, s store.Store) uint64 {
	t.Helper()
	e, err := s.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	return e
}

func kidsOf(keys []*fleet.Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.KID)
	}
	return out
}

// --- keys ----------------------------------------------------------------

func testKeyRoundTrip(t *testing.T, s store.Store) {
	ctx := t.Context()
	tests := []struct {
		name string
		key  *fleet.Key
	}{
		{"agent with scope", agentKey("agent0001", tBase)},
		{"admin without scope", adminKey("admin0001", tBase)},
		{"enrollment with grant", enrollmentKey("enrol0001", tBase)},
	}
	for _, tc := range tests {
		mustPut(t, s, tc.key)
	}
	for _, tc := range tests {
		got, err := s.GetKey(ctx, tc.key.KID)
		if err != nil {
			t.Fatalf("%s: GetKey: %v", tc.name, err)
		}
		if diff := cmp.Diff(tc.key, got); diff != "" {
			t.Errorf("%s: round trip mismatch (-want +got):\n%s", tc.name, diff)
		}
	}
}

func testKeySecretHMACSurvives(t *testing.T, s store.Store) {
	// fleet.Key tags SecretHMAC `json:"-"`, so a backend that serialises the
	// domain type directly loses it and every credential becomes unverifiable
	// at the next restart, silently. This is the regression test for that.
	ctx := t.Context()
	k := agentKey("agent0002", tBase)
	k.SecretHMAC = []byte{0x00, 0x01, 0xfe, 0xff, 0x7f, 0x80}
	mustPut(t, s, k)

	got, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if diff := cmp.Diff(k.SecretHMAC, got.SecretHMAC); diff != "" {
		t.Fatalf("SecretHMAC did not survive persistence (-want +got):\n%s", diff)
	}

	listed, err := s.ListKeys(ctx, fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListKeys returned %d keys, want 1", len(listed))
	}
	if diff := cmp.Diff(k.SecretHMAC, listed[0].SecretHMAC); diff != "" {
		t.Errorf("ListKeys dropped SecretHMAC (-want +got):\n%s", diff)
	}
}

func testGetKeyReturnsCopies(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0003", tBase)
	mustPut(t, s, k)

	first, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	first.Name = "mutated"
	first.SecretHMAC[0] = 0xff
	first.Scope.Clusters.Allow[0] = "mutated"

	second, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey (second): %v", err)
	}
	if diff := cmp.Diff(k, second); diff != "" {
		t.Errorf("mutating a returned key changed stored state (-want +got):\n%s", diff)
	}

	// The value handed to PutKey must also be independent of stored state.
	k.Name = "mutated after put"
	third, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey (third): %v", err)
	}
	if third.Name == "mutated after put" {
		t.Error("mutating the caller's key after PutKey changed stored state")
	}
}

func testPutKeyRejectsDuplicate(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0004", tBase)
	mustPut(t, s, k)
	before := mustEpoch(t, s)

	dup := adminKey("agent0004", tBase.Add(time.Hour))
	if err := s.PutKey(ctx, dup); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("PutKey (duplicate) error = %v, want ErrAlreadyExists", err)
	}
	got, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if diff := cmp.Diff(k, got); diff != "" {
		t.Errorf("rejected duplicate modified the stored key (-want +got):\n%s", diff)
	}
	if after := mustEpoch(t, s); after != before {
		t.Errorf("epoch moved %d -> %d on a rejected write", before, after)
	}
}

func testPutKeyValidates(t *testing.T, s store.Store) {
	ctx := t.Context()
	tests := []struct {
		name string
		key  *fleet.Key
	}{
		{"nil", nil},
		{"empty kid", &fleet.Key{Class: fleet.ClassAgent, CreatedAt: tBase}},
		{"empty class", &fleet.Key{KID: "agent0005", CreatedAt: tBase}},
		{"unknown class", &fleet.Key{KID: "agent0006", Class: "xyz", CreatedAt: tBase}},
	}
	for _, tc := range tests {
		if err := s.PutKey(ctx, tc.key); err == nil {
			t.Errorf("PutKey(%s) = nil, want an error", tc.name)
		}
	}
	keys, err := s.ListKeys(ctx, "")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("rejected writes left %d keys behind", len(keys))
	}
}

func testPutKeyIfNoUsable(t *testing.T, s store.Store) {
	ctx := t.Context()
	first := adminKey("bootstrap0", tBase)
	stored, err := s.PutKeyIfNoUsable(ctx, first, tBase)
	if err != nil || !stored {
		t.Fatalf("first PutKeyIfNoUsable = (%v, %v), want (true, nil)", stored, err)
	}

	replacement := adminKey("bootstrap0", tBase.Add(time.Hour))
	replacement.SecretHMAC = []byte("replacement")
	stored, err = s.PutKeyIfNoUsable(ctx, replacement, tBase.Add(time.Hour))
	if err != nil || stored {
		t.Fatalf("usable PutKeyIfNoUsable = (%v, %v), want (false, nil)", stored, err)
	}
	got, err := s.GetKey(ctx, first.KID)
	if err != nil || string(got.SecretHMAC) != string(first.SecretHMAC) {
		t.Fatalf("usable key was replaced: key=%+v err=%v", got, err)
	}

	stored, err = s.PutKeyIfNoUsable(ctx, replacement, tExpires.Add(time.Second))
	if err != nil || !stored {
		t.Fatalf("expired PutKeyIfNoUsable = (%v, %v), want (true, nil)", stored, err)
	}
	got, err = s.GetKey(ctx, first.KID)
	if err != nil || string(got.SecretHMAC) != string(replacement.SecretHMAC) {
		t.Fatalf("expired key was not replaced: key=%+v err=%v", got, err)
	}

	if _, err := s.PutKeyIfNoUsable(ctx, nil, tBase); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("nil PutKeyIfNoUsable error = %v, want ErrInvalid", err)
	}

	// A zero timestamp is resolved by the backend's clock. The far-future
	// expiry keeps this assertion valid for both real-time and fixed clocks.
	future := adminKey("bootstrap1", tBase)
	future.ExpiresAt = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	if stored, err := s.PutKeyIfNoUsable(ctx, future, time.Time{}); err != nil || !stored {
		t.Fatalf("zero-time PutKeyIfNoUsable = (%v, %v), want (true, nil)", stored, err)
	}
}

func testGetKeyNotFound(t *testing.T, s store.Store) {
	for _, kid := range []string{"", "missing", "\x00", "a very long identifier that was never issued"} {
		got, err := s.GetKey(t.Context(), kid)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetKey(%q) error = %v, want ErrNotFound", kid, err)
		}
		if got != nil {
			t.Errorf("GetKey(%q) returned a key alongside an error", kid)
		}
	}
}

func testListKeysOrdering(t *testing.T, s store.Store) {
	ctx := t.Context()
	// Insert out of order, with a deliberate CreatedAt tie so the KID
	// tie-break is exercised rather than accidentally satisfied.
	mustPut(t, s, agentKey("agentZZZZ", tBase.Add(2*time.Hour)))
	mustPut(t, s, agentKey("agentBBBB", tBase))
	mustPut(t, s, agentKey("agentAAAA", tBase))
	mustPut(t, s, adminKey("adminCCCC", tBase.Add(time.Hour)))
	mustPut(t, s, adminKey("adminAAAA", tBase.Add(3*time.Hour)))
	mustPut(t, s, enrollmentKey("enrolAAAA", tBase.Add(4*time.Hour)))

	tests := []struct {
		name  string
		class fleet.KeyClass
		want  []string
	}{
		{"agent", fleet.ClassAgent, []string{"agentAAAA", "agentBBBB", "agentZZZZ"}},
		{"admin", fleet.ClassAdmin, []string{"adminCCCC", "adminAAAA"}},
		{"enrollment", fleet.ClassEnrollment, []string{"enrolAAAA"}},
		{"all", "", []string{"agentAAAA", "agentBBBB", "adminCCCC", "agentZZZZ", "adminAAAA", "enrolAAAA"}},
	}
	for _, tc := range tests {
		got, err := s.ListKeys(ctx, tc.class)
		if err != nil {
			t.Fatalf("ListKeys(%q): %v", tc.class, err)
		}
		if diff := cmp.Diff(tc.want, kidsOf(got)); diff != "" {
			t.Errorf("ListKeys(%q) order (-want +got):\n%s", tc.class, diff)
		}
		// Repeating the call must produce the same order, not merely a
		// correct set.
		again, err := s.ListKeys(ctx, tc.class)
		if err != nil {
			t.Fatalf("ListKeys(%q) repeat: %v", tc.class, err)
		}
		if diff := cmp.Diff(kidsOf(got), kidsOf(again)); diff != "" {
			t.Errorf("ListKeys(%q) is not stable across calls (-first +second):\n%s", tc.class, diff)
		}
		for _, k := range got {
			if tc.class != "" && k.Class != tc.class {
				t.Errorf("ListKeys(%q) returned a %q key", tc.class, k.Class)
			}
		}
	}
}

func testListKeysEmpty(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, class := range []fleet.KeyClass{"", fleet.ClassAgent, fleet.ClassAdmin, fleet.ClassEnrollment, "nope"} {
		got, err := s.ListKeys(ctx, class)
		if err != nil {
			t.Fatalf("ListKeys(%q): %v", class, err)
		}
		if len(got) != 0 {
			t.Errorf("ListKeys(%q) returned %d keys from an empty store", class, len(got))
		}
		if got == nil {
			t.Errorf("ListKeys(%q) returned nil, want an empty slice", class)
		}
	}
	mustPut(t, s, agentKey("agent0007", tBase))
	got, err := s.ListKeys(ctx, "nope")
	if err != nil {
		t.Fatalf("ListKeys(unknown class): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListKeys(unknown class) returned %d keys", len(got))
	}
}

// testReplaceKey proves the rotation primitive: one call, and afterwards the
// fresh key is live while the old one is revoked with the given reason.
// testPrune covers what a prune is for: records that stopped mattering more
// than the retention window ago are gone, and the epoch does NOT move,
// because nothing removed could have changed an answer.
func testPrune(t *testing.T, s store.Store) {
	ctx := t.Context()
	const retain = 24 * time.Hour

	// Long expired: prunable.
	stale := agentKey("agent0050", tBase.Add(-90*24*time.Hour))
	stale.ExpiresAt = tBase.Add(-60 * 24 * time.Hour)
	mustPut(t, s, stale)
	// Expired, but inside the retention window: kept for the investigator.
	recent := agentKey("agent0051", tBase.Add(-90*24*time.Hour))
	recent.ExpiresAt = tBase.Add(-time.Hour)
	mustPut(t, s, recent)
	// Live.
	live := agentKey("agent0052", tBase)
	live.ExpiresAt = tBase.Add(90 * 24 * time.Hour)
	mustPut(t, s, live)

	// A revocation whose certificate expired long ago, and one still current.
	if err := s.RevokeCert(ctx, store.RevokedCert{
		Serial: "0a", RevokedAt: tBase.Add(-60 * 24 * time.Hour), NotAfter: tBase.Add(-50 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("RevokeCert(stale): %v", err)
	}
	if err := s.RevokeCert(ctx, store.RevokedCert{
		Serial: "0b", RevokedAt: tBase, NotAfter: tBase.Add(14 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("RevokeCert(current): %v", err)
	}

	before := mustEpoch(t, s)
	res, err := s.Prune(ctx, retain)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if res.Keys != 1 || res.RevokedCerts != 1 {
		t.Fatalf("Prune() = %+v, want exactly one key and one revocation", res)
	}
	if _, err := s.GetKey(ctx, "agent0050"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the long-expired key survived: %v", err)
	}
	for _, kid := range []string{"agent0051", "agent0052"} {
		if _, err := s.GetKey(ctx, kid); err != nil {
			t.Errorf("GetKey(%s) after prune: %v", kid, err)
		}
	}
	certs, err := s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if len(certs) != 1 || certs[0].Serial != "0b" {
		t.Errorf("revocations after prune = %+v, want only the current one", certs)
	}
	// The epoch is the signal that tells every replica to re-read. Nothing
	// pruned can change an answer, so making them re-read would be pure noise.
	if after := mustEpoch(t, s); after != before {
		t.Errorf("epoch moved %d -> %d; a prune must not invalidate every replica's cache", before, after)
	}

	// Idempotent: a second pass finds nothing and must not write.
	again, err := s.Prune(ctx, retain)
	if err != nil {
		t.Fatalf("Prune (second): %v", err)
	}
	if !again.Empty() {
		t.Errorf("second prune removed %+v, want nothing", again)
	}
}

// testPruneKeepsWhatStillDecides is the safety half, and the most important
// case is the last one: a revoked credential with NO expiry must survive,
// because its record is the only thing refusing it.
func testPruneKeepsWhatStillDecides(t *testing.T, s store.Store) {
	ctx := t.Context()

	// Revoked, not yet expired: the revocation is doing the refusing.
	revoked := agentKey("agent0060", tBase)
	revoked.ExpiresAt = tBase.Add(90 * 24 * time.Hour)
	mustPut(t, s, revoked)
	if err := s.RevokeKey(ctx, revoked.KID, "leaked", tBase); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	// No expiry at all, and revoked. Pruning this hands a revoked immortal
	// key its access back: there is no expiry underneath to catch it.
	immortal := agentKey("agent0061", tBase.Add(-365*24*time.Hour))
	immortal.ExpiresAt = time.Time{}
	mustPut(t, s, immortal)
	if err := s.RevokeKey(ctx, immortal.KID, "leaked", tBase.Add(-300*24*time.Hour)); err != nil {
		t.Fatalf("RevokeKey(immortal): %v", err)
	}
	// A revocation entry with no recorded expiry: unknown, so never dropped.
	if err := s.RevokeCert(ctx, store.RevokedCert{Serial: "0c", RevokedAt: tBase.Add(-365 * 24 * time.Hour)}); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	res, err := s.Prune(ctx, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if !res.Empty() {
		t.Fatalf("Prune removed %+v, want nothing: every record here still decides something", res)
	}
	got, err := s.GetKey(ctx, "agent0061")
	if err != nil {
		t.Fatalf("the revoked no-expiry key was pruned, restoring its access: %v", err)
	}
	if !got.Revoked() {
		t.Error("the surviving record lost its revocation")
	}
}

// testPruneRejectsNegativeRetention: a negative window would prune records
// that have not stopped mattering yet.
func testPruneRejectsNegativeRetention(t *testing.T, s store.Store) {
	if _, err := s.Prune(t.Context(), -time.Hour); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Prune(negative) = %v, want ErrInvalid", err)
	}
}

func testReplaceKey(t *testing.T, s store.Store) {
	ctx := t.Context()
	old := agentKey("agent0030", tBase)
	mustPut(t, s, old)
	fresh := agentKey("agent0031", tBase.Add(time.Hour))
	before := mustEpoch(t, s)

	at := tBase.Add(time.Hour)
	if err := s.ReplaceKey(ctx, fresh, old.KID, "rotated (replaced by agent0031)", at); err != nil {
		t.Fatalf("ReplaceKey: %v", err)
	}

	gotFresh, err := s.GetKey(ctx, fresh.KID)
	if err != nil {
		t.Fatalf("GetKey(fresh): %v", err)
	}
	if gotFresh.Revoked() {
		t.Error("the replacement key is revoked")
	}
	gotOld, err := s.GetKey(ctx, old.KID)
	if err != nil {
		t.Fatalf("GetKey(old): %v", err)
	}
	if gotOld.RevokedAt == nil || !gotOld.RevokedAt.Equal(at) {
		t.Errorf("old RevokedAt = %v, want %s", gotOld.RevokedAt, at)
	}
	if gotOld.RevokedReason != "rotated (replaced by agent0031)" {
		t.Errorf("old RevokedReason = %q", gotOld.RevokedReason)
	}
	if after := mustEpoch(t, s); after <= before {
		t.Errorf("epoch = %d after ReplaceKey, want > %d", after, before)
	}
}

// testReplaceKeyRefusesRevoked pins the replay contract: an already-revoked
// source fails with an error that is NOT the create-collision sentinel, so a
// caller retrying identifier collisions cannot loop on a finished rotation.
func testReplaceKeyRefusesRevoked(t *testing.T, s store.Store) {
	ctx := t.Context()
	old := agentKey("agent0032", tBase)
	mustPut(t, s, old)
	if err := s.RevokeKey(ctx, old.KID, "rotated (replaced by agent0033)", tBase.Add(time.Hour)); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	fresh := agentKey("agent0034", tBase)
	err := s.ReplaceKey(ctx, fresh, old.KID, "rotated again", tBase.Add(2*time.Hour))
	if err == nil {
		t.Fatal("ReplaceKey accepted a revoked source key")
	}
	if !errors.Is(err, store.ErrRevoked) {
		t.Errorf("err = %v, want it to wrap store.ErrRevoked", err)
	}
	if errors.Is(err, store.ErrAlreadyExists) {
		t.Error("the refusal wraps ErrAlreadyExists, which a collision-retrying caller would replay")
	}
	if !strings.Contains(err.Error(), "agent0033") {
		t.Errorf("err = %q, want it to carry the recorded reason naming the replacement", err)
	}
	if _, err := s.GetKey(ctx, fresh.KID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetKey(fresh) err = %v, want ErrNotFound: the refused replacement was stored", err)
	}
}

// testReplaceKeyNotFound: a missing source is ErrNotFound and stores nothing.
func testReplaceKeyNotFound(t *testing.T, s store.Store) {
	ctx := t.Context()
	fresh := agentKey("agent0035", tBase)
	err := s.ReplaceKey(ctx, fresh, "agent-none", "rotated", tBase)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetKey(ctx, fresh.KID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetKey(fresh) err = %v, want ErrNotFound: a failed replace stored the fresh key", err)
	}
}

// testReplaceKeyAtomicOnCollision: when the fresh KID is taken, NOTHING
// changes -- in particular the old key is not revoked. This is the atomicity
// the primitive exists for.
func testReplaceKeyAtomicOnCollision(t *testing.T, s store.Store) {
	ctx := t.Context()
	old := agentKey("agent0036", tBase)
	taken := agentKey("agent0037", tBase)
	mustPut(t, s, old)
	mustPut(t, s, taken)

	dup := agentKey("agent0037", tBase.Add(time.Hour))
	err := s.ReplaceKey(ctx, dup, old.KID, "rotated", tBase.Add(time.Hour))
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
	gotOld, err := s.GetKey(ctx, old.KID)
	if err != nil {
		t.Fatalf("GetKey(old): %v", err)
	}
	if gotOld.Revoked() {
		t.Error("the old key was revoked by a ReplaceKey that failed: the mutation is not atomic")
	}
}

func testRevokeKey(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0008", tBase)
	mustPut(t, s, k)
	before := mustEpoch(t, s)

	at := tBase.Add(time.Hour)
	if err := s.RevokeKey(ctx, k.KID, "leaked in a build log", at); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	got, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("RevokedAt is nil after RevokeKey")
	}
	if !got.RevokedAt.Equal(at) {
		t.Errorf("RevokedAt = %s, want %s", got.RevokedAt, at)
	}
	if got.RevokedReason != "leaked in a build log" {
		t.Errorf("RevokedReason = %q", got.RevokedReason)
	}
	if !got.Revoked() || got.Usable(at) {
		t.Error("revoked key still reports itself usable")
	}
	if after := mustEpoch(t, s); after <= before {
		t.Errorf("epoch = %d after revocation, want > %d", after, before)
	}

	// A revoked key is still listed: revocation preserves the audit trail.
	listed, err := s.ListKeys(ctx, fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if diff := cmp.Diff([]string{k.KID}, kidsOf(listed)); diff != "" {
		t.Errorf("revoked key disappeared from ListKeys (-want +got):\n%s", diff)
	}
}

func testRevokeKeyIsIdempotent(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0009", tBase)
	mustPut(t, s, k)

	first := tBase.Add(time.Hour)
	if err := s.RevokeKey(ctx, k.KID, "first", first); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	epochAfterFirst := mustEpoch(t, s)

	if err := s.RevokeKey(ctx, k.KID, "second", first.Add(time.Hour)); err != nil {
		t.Fatalf("RevokeKey (repeat) = %v, want nil", err)
	}
	got, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !got.RevokedAt.Equal(first) || got.RevokedReason != "first" {
		t.Errorf("second revocation overwrote the audit record: at=%s reason=%q",
			got.RevokedAt, got.RevokedReason)
	}
	if after := mustEpoch(t, s); after != epochAfterFirst {
		t.Errorf("epoch moved %d -> %d on a repeated revocation", epochAfterFirst, after)
	}
}

func testRevokeKeyNotFound(t *testing.T, s store.Store) {
	before := mustEpoch(t, s)
	if err := s.RevokeKey(t.Context(), "missing", "why", tBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeKey error = %v, want ErrNotFound", err)
	}
	if after := mustEpoch(t, s); after != before {
		t.Errorf("epoch moved %d -> %d on a failed revocation", before, after)
	}
}

func testDeleteKey(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0010", tBase)
	mustPut(t, s, k)
	before := mustEpoch(t, s)

	if err := s.DeleteKey(ctx, k.KID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := s.GetKey(ctx, k.KID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetKey after delete error = %v, want ErrNotFound", err)
	}
	listed, err := s.ListKeys(ctx, fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(listed) != 0 {
		// A backend that forgets to clean its class index leaves a dangling
		// entry here, which then fails the lookup on the next list.
		t.Errorf("ListKeys returned %v after delete, want none", kidsOf(listed))
	}
	if after := mustEpoch(t, s); after <= before {
		t.Errorf("epoch = %d after delete, want > %d", after, before)
	}

	// The identifier must be reusable, which also proves the index entry was
	// removed rather than merely orphaned.
	mustPut(t, s, agentKey(k.KID, tBase.Add(time.Hour)))
	listed, err = s.ListKeys(ctx, fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if diff := cmp.Diff([]string{k.KID}, kidsOf(listed)); diff != "" {
		t.Errorf("re-created key (-want +got):\n%s", diff)
	}
}

func testDeleteKeyNotFound(t *testing.T, s store.Store) {
	before := mustEpoch(t, s)
	if err := s.DeleteKey(t.Context(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteKey error = %v, want ErrNotFound", err)
	}
	if after := mustEpoch(t, s); after != before {
		t.Errorf("epoch moved %d -> %d on a failed delete", before, after)
	}
}

func testTouchKey(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0011", tBase)
	mustPut(t, s, k)

	at := tBase.Add(90 * time.Minute)
	if err := s.TouchKey(ctx, k.KID, at); err != nil {
		t.Fatalf("TouchKey: %v", err)
	}
	got, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.LastUsed == nil {
		t.Fatal("LastUsed is nil after TouchKey")
	}
	if !got.LastUsed.Equal(at) {
		t.Errorf("LastUsed = %s, want %s", got.LastUsed, at)
	}

	later := at.Add(time.Hour)
	if err := s.TouchKey(ctx, k.KID, later); err != nil {
		t.Fatalf("TouchKey (second): %v", err)
	}
	got, err = s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !got.LastUsed.Equal(later) {
		t.Errorf("LastUsed = %s, want the most recent use %s", got.LastUsed, later)
	}

	// Touching must not disturb anything else about the record.
	want := agentKey(k.KID, tBase)
	want.LastUsed = &later
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TouchKey changed more than LastUsed (-want +got):\n%s", diff)
	}

	// A zero timestamp means "now", which must still record something.
	if err := s.TouchKey(ctx, k.KID, time.Time{}); err != nil {
		t.Fatalf("TouchKey (zero time): %v", err)
	}
	got, err = s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.LastUsed == nil || got.LastUsed.IsZero() {
		t.Error("TouchKey with a zero timestamp did not substitute the clock")
	}
}

func testTouchKeyDoesNotBumpEpoch(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := agentKey("agent0012", tBase)
	mustPut(t, s, k)
	before := mustEpoch(t, s)

	// TouchKey runs on every authenticated request. If it bumped the epoch,
	// every verifier cache in the fleet would be invalidated continuously and
	// the cache would become a pure cost.
	for i := 0; i < 16; i++ {
		if err := s.TouchKey(ctx, k.KID, tBase.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("TouchKey: %v", err)
		}
	}
	if after := mustEpoch(t, s); after != before {
		t.Errorf("epoch moved %d -> %d across 16 touches", before, after)
	}
}

func testTouchKeyNotFound(t *testing.T, s store.Store) {
	if err := s.TouchKey(t.Context(), "missing", tBase); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("TouchKey error = %v, want ErrNotFound", err)
	}
}

// --- enrollment ----------------------------------------------------------

func testBurnEnrollment(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := enrollmentKey("enrol0002", tBase)
	mustPut(t, s, k)
	before := mustEpoch(t, s)

	at := tBase.Add(5 * time.Minute)
	got, err := s.BurnEnrollment(ctx, k.KID, "serial-01", at)
	if err != nil {
		t.Fatalf("BurnEnrollment: %v", err)
	}
	if got.Enrollment == nil || got.Enrollment.UsedAt == nil {
		t.Fatal("BurnEnrollment returned a key with no UsedAt")
	}
	if !got.Enrollment.UsedAt.Equal(at) {
		t.Errorf("UsedAt = %s, want %s", got.Enrollment.UsedAt, at)
	}
	if got.Enrollment.CertSerial != "serial-01" {
		t.Errorf("CertSerial = %q, want %q", got.Enrollment.CertSerial, "serial-01")
	}
	if got.Enrollment.ClusterID != "prod-eu-1" {
		t.Errorf("burning changed ClusterID to %q", got.Enrollment.ClusterID)
	}
	if diff := cmp.Diff(k.SecretHMAC, got.SecretHMAC); diff != "" {
		t.Errorf("BurnEnrollment returned a key without its SecretHMAC (-want +got):\n%s", diff)
	}
	if after := mustEpoch(t, s); after <= before {
		t.Errorf("epoch = %d after burn, want > %d", after, before)
	}

	// The returned key must match what a subsequent read sees.
	reread, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if diff := cmp.Diff(got, reread); diff != "" {
		t.Errorf("returned key differs from the stored key (-returned +stored):\n%s", diff)
	}
}

func testBurnEnrollmentTwice(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := enrollmentKey("enrol0003", tBase)
	mustPut(t, s, k)

	first, err := s.BurnEnrollment(ctx, k.KID, "serial-01", tBase.Add(time.Minute))
	if err != nil {
		t.Fatalf("BurnEnrollment: %v", err)
	}
	epochAfterFirst := mustEpoch(t, s)

	second, err := s.BurnEnrollment(ctx, k.KID, "serial-02", tBase.Add(2*time.Minute))
	if !errors.Is(err, store.ErrEnrollmentUsed) {
		t.Fatalf("second BurnEnrollment error = %v, want ErrEnrollmentUsed", err)
	}
	if second != nil {
		t.Error("second BurnEnrollment returned a key alongside an error")
	}

	stored, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if diff := cmp.Diff(first, stored); diff != "" {
		t.Errorf("the rejected second burn changed stored state (-want +got):\n%s", diff)
	}
	if after := mustEpoch(t, s); after != epochAfterFirst {
		t.Errorf("epoch moved %d -> %d on a rejected burn", epochAfterFirst, after)
	}
}

func testBurnEnrollmentRejects(t *testing.T, s store.Store) {
	ctx := t.Context()

	agent := agentKey("agent0013", tBase)
	mustPut(t, s, agent)

	noGrant := &fleet.Key{
		KID:       "enrol0004",
		Class:     fleet.ClassEnrollment,
		CreatedAt: tBase,
		ExpiresAt: tBase.Add(time.Hour),
	}
	mustPut(t, s, noGrant)

	revoked := enrollmentKey("enrol0005", tBase)
	mustPut(t, s, revoked)
	if err := s.RevokeKey(ctx, revoked.KID, "operator error", tBase.Add(time.Minute)); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	expired := enrollmentKey("enrol0006", tBase)
	mustPut(t, s, expired)

	valid := enrollmentKey("enrol0007", tBase)
	mustPut(t, s, valid)

	tests := []struct {
		name   string
		kid    string
		serial string
		at     time.Time
		want   error
	}{
		{"unknown kid", "missing", "serial-01", tBase, store.ErrNotFound},
		{"wrong class", agent.KID, "serial-01", tBase, store.ErrWrongClass},
		{"no enrollment grant", noGrant.KID, "serial-01", tBase, store.ErrWrongClass},
		{"revoked", revoked.KID, "serial-01", tBase.Add(2 * time.Minute), store.ErrNotUsable},
		{"expired", expired.KID, "serial-01", tBase.Add(time.Hour), store.ErrNotUsable},
		{"empty serial", valid.KID, "", tBase, nil},
	}
	for _, tc := range tests {
		got, err := s.BurnEnrollment(ctx, tc.kid, tc.serial, tc.at)
		if err == nil {
			t.Errorf("%s: BurnEnrollment = %v, want an error", tc.name, got)
			continue
		}
		if got != nil {
			t.Errorf("%s: BurnEnrollment returned a key alongside an error", tc.name)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v, want %v", tc.name, err, tc.want)
		}
	}

	// None of the above may have consumed the still-valid token.
	if _, err := s.BurnEnrollment(ctx, valid.KID, "serial-99", tBase.Add(time.Minute)); err != nil {
		t.Fatalf("a rejected burn consumed an unrelated token: %v", err)
	}
}

func testBurnEnrollmentConcurrent(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := enrollmentKey("enrol0008", tBase)
	mustPut(t, s, k)

	const racers = 24
	type outcome struct {
		serial string
		err    error
	}
	results := make([]outcome, racers)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer done.Done()
			serial := fmt.Sprintf("serial-%02d", i)
			start.Wait()
			_, err := s.BurnEnrollment(ctx, k.KID, serial, tBase.Add(time.Minute))
			results[i] = outcome{serial: serial, err: err}
		}()
	}
	start.Done()
	done.Wait()

	var winners []string
	for _, r := range results {
		switch {
		case r.err == nil:
			winners = append(winners, r.serial)
		case errors.Is(r.err, store.ErrEnrollmentUsed):
			// Expected loss.
		default:
			t.Errorf("racer %s: error = %v, want nil or ErrEnrollmentUsed", r.serial, r.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded, want exactly 1: %v",
			len(winners), racers, winners)
	}

	stored, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if stored.Enrollment.CertSerial != winners[0] {
		t.Errorf("stored CertSerial = %q, want the winner's %q",
			stored.Enrollment.CertSerial, winners[0])
	}
}

// testBurnEnrollmentReusableUnlimited proves a reusable grant with no cap
// (MaxRedemptions == 0) may be redeemed any number of times, each redemption
// incrementing Redemptions and overwriting CertSerial and UsedAt, for every
// backend.
func testBurnEnrollmentReusableUnlimited(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := reusableEnrollmentKey("enrol0009", tBase, 0)
	mustPut(t, s, k)

	for i, serial := range []string{"serial-01", "serial-02", "serial-03"} {
		at := tBase.Add(time.Duration(i) * time.Minute)
		got, err := s.BurnEnrollment(ctx, k.KID, serial, at)
		if err != nil {
			t.Fatalf("redemption %d: BurnEnrollment: %v", i, err)
		}
		if got.Enrollment.Redemptions != i+1 {
			t.Errorf("redemption %d: Redemptions = %d, want %d", i, got.Enrollment.Redemptions, i+1)
		}
		if got.Enrollment.CertSerial != serial {
			t.Errorf("redemption %d: CertSerial = %q, want %q", i, got.Enrollment.CertSerial, serial)
		}
		if !got.Enrollment.UsedAt.Equal(at) {
			t.Errorf("redemption %d: UsedAt = %s, want %s", i, got.Enrollment.UsedAt, at)
		}
		if got.Enrollment.ClusterID != "prod-eu-1" {
			t.Errorf("redemption %d: ClusterID changed to %q", i, got.Enrollment.ClusterID)
		}

		reread, err := s.GetKey(ctx, k.KID)
		if err != nil {
			t.Fatalf("redemption %d: GetKey: %v", i, err)
		}
		if diff := cmp.Diff(got, reread); diff != "" {
			t.Errorf("redemption %d: returned key differs from the stored key (-returned +stored):\n%s", i, diff)
		}
	}
}

// testBurnEnrollmentReusableCapped proves a reusable grant refuses
// redemption once Redemptions reaches MaxRedemptions, without disturbing the
// state left by the redemptions that already succeeded, for every backend.
func testBurnEnrollmentReusableCapped(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := reusableEnrollmentKey("enrol0010", tBase, 2)
	mustPut(t, s, k)

	for i, serial := range []string{"serial-01", "serial-02"} {
		if _, err := s.BurnEnrollment(ctx, k.KID, serial, tBase.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("redemption %d: BurnEnrollment: %v", i, err)
		}
	}
	epochAfterCap := mustEpoch(t, s)

	got, err := s.BurnEnrollment(ctx, k.KID, "serial-03", tBase.Add(3*time.Minute))
	if !errors.Is(err, store.ErrEnrollmentUsed) {
		t.Fatalf("redemption over the cap: error = %v, want ErrEnrollmentUsed", err)
	}
	if got != nil {
		t.Error("a redemption over the cap returned a key alongside an error")
	}
	if after := mustEpoch(t, s); after != epochAfterCap {
		t.Errorf("epoch moved %d -> %d on a redemption over the cap", epochAfterCap, after)
	}

	stored, err := s.GetKey(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if stored.Enrollment.Redemptions != 2 {
		t.Errorf("Redemptions = %d after a refused redemption over the cap, want 2", stored.Enrollment.Redemptions)
	}
	if stored.Enrollment.CertSerial != "serial-02" {
		t.Errorf("CertSerial = %q after a refused redemption over the cap, want the last successful one",
			stored.Enrollment.CertSerial)
	}
}

// --- revoked certificates ------------------------------------------------

func testRevokedCerts(t *testing.T, s store.Store) {
	ctx := t.Context()
	before := mustEpoch(t, s)

	rc := store.RevokedCert{
		Serial:    "0a1b2c",
		RevokedAt: tBase,
		NotAfter:  tExpires,
		Reason:    "spoke decommissioned",
	}
	if err := s.RevokeCert(ctx, rc); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	got, err := s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if diff := cmp.Diff([]store.RevokedCert{rc}, got); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
	if after := mustEpoch(t, s); after <= before {
		t.Errorf("epoch = %d after RevokeCert, want > %d", after, before)
	}

	// Re-revoking the same serial replaces rather than duplicates, so a
	// repeated decommission is not an error.
	updated := rc
	updated.Reason = "key compromise"
	if err := s.RevokeCert(ctx, updated); err != nil {
		t.Fatalf("RevokeCert (repeat): %v", err)
	}
	got, err = s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if diff := cmp.Diff([]store.RevokedCert{updated}, got); diff != "" {
		t.Errorf("re-revocation mismatch (-want +got):\n%s", diff)
	}

	// Entries past NotAfter are still returned; pruning is the caller's call.
	old := store.RevokedCert{
		Serial:    "0000ff",
		RevokedAt: tBase.Add(-48 * time.Hour),
		NotAfter:  tBase.Add(-24 * time.Hour),
	}
	if err := s.RevokeCert(ctx, old); err != nil {
		t.Fatalf("RevokeCert (expired): %v", err)
	}
	got, err = s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListRevokedCerts returned %d entries, want 2 including the expired one", len(got))
	}
}

func testRevokedCertsOrdering(t *testing.T, s store.Store) {
	ctx := t.Context()
	for _, serial := range []string{"ff", "0a", "zz", "01", "b0"} {
		if err := s.RevokeCert(ctx, store.RevokedCert{
			Serial:    serial,
			RevokedAt: tBase,
			NotAfter:  tExpires,
		}); err != nil {
			t.Fatalf("RevokeCert(%s): %v", serial, err)
		}
	}
	want := []string{"01", "0a", "b0", "ff", "zz"}
	for i := 0; i < 3; i++ {
		got, err := s.ListRevokedCerts(ctx)
		if err != nil {
			t.Fatalf("ListRevokedCerts: %v", err)
		}
		serials := make([]string, 0, len(got))
		for _, rc := range got {
			serials = append(serials, rc.Serial)
		}
		if diff := cmp.Diff(want, serials); diff != "" {
			t.Fatalf("ListRevokedCerts order (-want +got):\n%s", diff)
		}
	}
}

func testRevokedCertValidates(t *testing.T, s store.Store) {
	ctx := t.Context()
	if err := s.RevokeCert(ctx, store.RevokedCert{}); err == nil {
		t.Error("RevokeCert(empty serial) = nil, want an error")
	}
	got, err := s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("rejected revocation left %d entries behind", len(got))
	}
	if got == nil {
		t.Error("ListRevokedCerts returned nil, want an empty slice")
	}

	// A zero RevokedAt must be filled in, not stored as the zero time: a CRL
	// entry with no timestamp cannot be audited.
	if err := s.RevokeCert(ctx, store.RevokedCert{Serial: "aa", NotAfter: tExpires}); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	got, err = s.ListRevokedCerts(ctx)
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if len(got) != 1 || got[0].RevokedAt.IsZero() {
		t.Errorf("RevokeCert did not substitute the clock for a zero RevokedAt: %+v", got)
	}
}

// --- epoch ---------------------------------------------------------------

func testEpochMonotonic(t *testing.T, s store.Store) {
	ctx := t.Context()
	k := enrollmentKey("enrol0009", tBase)
	agent := agentKey("agent0014", tBase)

	steps := []struct {
		name     string
		op       func() error
		wantBump bool
	}{
		{"put enrollment", func() error { return s.PutKey(ctx, k) }, true},
		{"put agent", func() error { return s.PutKey(ctx, agent) }, true},
		{"touch", func() error { return s.TouchKey(ctx, agent.KID, tBase) }, false},
		{"burn", func() error {
			_, err := s.BurnEnrollment(ctx, k.KID, "serial-01", tBase.Add(time.Minute))
			return err
		}, true},
		{"revoke cert", func() error {
			return s.RevokeCert(ctx, store.RevokedCert{Serial: "aa", RevokedAt: tBase, NotAfter: tExpires})
		}, true},
		{"revoke key", func() error { return s.RevokeKey(ctx, agent.KID, "rotation", tBase) }, true},
		{"revoke key again", func() error { return s.RevokeKey(ctx, agent.KID, "rotation", tBase) }, false},
		{"delete key", func() error { return s.DeleteKey(ctx, agent.KID) }, true},
	}

	prev := mustEpoch(t, s)
	for _, step := range steps {
		if err := step.op(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		got := mustEpoch(t, s)
		switch {
		case got < prev:
			t.Fatalf("%s: epoch went backwards, %d -> %d", step.name, prev, got)
		case step.wantBump && got <= prev:
			t.Errorf("%s: epoch = %d, want > %d", step.name, got, prev)
		case !step.wantBump && got != prev:
			t.Errorf("%s: epoch moved %d -> %d, want no change", step.name, prev, got)
		}
		prev = got
	}
}

// --- lifecycle -----------------------------------------------------------

// allOps names every Store method and calls it, so the context and closed
// checks are proven for the whole surface rather than for a sample of it.
func allOps(ctx context.Context, s store.Store) []struct {
	name string
	err  func() error
} {
	return []struct {
		name string
		err  func() error
	}{
		{"PutKey", func() error { return s.PutKey(ctx, agentKey("agent0015", tBase)) }},
		{"GetKey", func() error { _, err := s.GetKey(ctx, "agent0015"); return err }},
		{"ListKeys", func() error { _, err := s.ListKeys(ctx, ""); return err }},
		{"ListKeys by class", func() error { _, err := s.ListKeys(ctx, fleet.ClassAgent); return err }},
		{"RevokeKey", func() error { return s.RevokeKey(ctx, "agent0015", "r", tBase) }},
		{"DeleteKey", func() error { return s.DeleteKey(ctx, "agent0015") }},
		{"TouchKey", func() error { return s.TouchKey(ctx, "agent0015", tBase) }},
		{"BurnEnrollment", func() error { _, err := s.BurnEnrollment(ctx, "enrol0010", "s", tBase); return err }},
		{"RevokeCert", func() error {
			return s.RevokeCert(ctx, store.RevokedCert{Serial: "aa", RevokedAt: tBase, NotAfter: tExpires})
		}},
		{"ListRevokedCerts", func() error { _, err := s.ListRevokedCerts(ctx); return err }},
		{"Epoch", func() error { _, err := s.Epoch(ctx); return err }},
	}
}

func testContextCancellation(t *testing.T, s store.Store) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, op := range allOps(ctx, s) {
		if err := op.err(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a cancelled context: error = %v, want context.Canceled", op.name, err)
		}
	}
	// Nothing may have been written despite the cancellation.
	keys, err := s.ListKeys(t.Context(), "")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("a cancelled call wrote %d keys", len(keys))
	}
}

func testClosedStore(t *testing.T, s store.Store) {
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close (repeat) = %v, want nil", err)
	}
	for _, op := range allOps(context.Background(), s) {
		if err := op.err(); !errors.Is(err, store.ErrClosed) {
			t.Errorf("%s after Close: error = %v, want ErrClosed", op.name, err)
		}
	}
}
