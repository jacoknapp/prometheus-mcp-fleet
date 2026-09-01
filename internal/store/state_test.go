// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

var (
	tBase    = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tExpires = tBase.Add(720 * time.Hour)
)

func clockAt(t time.Time) func() time.Time { return func() time.Time { return t } }

func agentKey(kid string, createdAt time.Time) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassAgent,
		Name:       "key-" + kid,
		SecretHMAC: []byte{0x00, 0xff, 0x7f},
		Scope: &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"prod-eu-1"}, Deny: []string{"dev-1"}, MatchLabels: map[string]string{"env": "prod"}},
			Tools:    fleet.ToolScope{Allow: []string{"prom.query"}, Deny: []string{"admin.*"}},
		},
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(720 * time.Hour),
	}
}

func enrollmentKey(kid string, createdAt time.Time) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassEnrollment,
		SecretHMAC: []byte("hmac"),
		Enrollment: &fleet.EnrollmentGrant{ClusterID: "prod-eu-1", Labels: map[string]string{"env": "prod"}},
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(15 * time.Minute),
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

func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    error
		wantVer int
	}{
		{name: "empty input is an empty document", in: "", wantVer: SchemaVersion},
		{name: "explicit version", in: `{"schemaVersion":1,"epoch":3}`, wantVer: 1},
		{name: "absent version reads as version 1", in: `{"epoch":3}`, wantVer: SchemaVersion},
		{name: "corrupt", in: "{not json", want: ErrCorrupt},
		{name: "wrong shape", in: `{"keys":[]}`, want: ErrCorrupt},
		{name: "newer schema", in: `{"schemaVersion":99}`, want: ErrSchemaTooNew},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Decode([]byte(tc.in))
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("Decode error = %v, want %v", err, tc.want)
				}
				if got != nil {
					t.Error("Decode returned a document alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got.SchemaVersion != tc.wantVer {
				t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, tc.wantVer)
			}
			if got.Keys == nil || got.RevokedCerts == nil {
				t.Error("Decode left a nil map, which would panic on the first write")
			}
		})
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	t.Parallel()
	s := NewState()
	for _, kid := range []string{"zzz", "aaa", "mmm"} {
		if _, err := s.PutKey(agentKey(kid, tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
	}
	first, err := s.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for range 5 {
		again, err := s.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if string(first) != string(again) {
			t.Fatal("Encode is not deterministic; every no-op write would look like a change")
		}
	}
	// A round trip through the wire must preserve everything, SecretHMAC
	// included -- the field fleet.Key deliberately hides from JSON.
	decoded, err := Decode(first)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if diff := cmp.Diff(s, decoded); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
}

func TestEncodeWithin(t *testing.T) {
	t.Parallel()
	s := NewState()
	for i := range 4 {
		if _, err := s.PutKey(agentKey(string(rune('a'+i)), tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
	}
	if _, err := s.RevokeCert(RevokedCert{Serial: "0a", RevokedAt: tBase, NotAfter: tExpires}, time.Now); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	full, err := s.EncodeWithin(0)
	if err != nil {
		t.Fatalf("EncodeWithin(0): %v", err)
	}
	if _, err := s.EncodeWithin(-1); err != nil {
		t.Errorf("EncodeWithin(-1) = %v, want unbounded", err)
	}
	if _, err := s.EncodeWithin(len(full)); err != nil {
		t.Errorf("EncodeWithin(exact size) = %v, want it to fit", err)
	}
	_, err = s.EncodeWithin(len(full) - 1)
	if !errors.Is(err, ErrStateTooLarge) {
		t.Fatalf("EncodeWithin(too small) = %v, want ErrStateTooLarge", err)
	}
	for _, want := range []string{"4 keys", "1 revoked certificates", "delete expired or revoked keys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestMigrationHook(t *testing.T) {
	// Not parallel: it registers a migration in the package-level table.
	original := migrations
	t.Cleanup(func() { migrations = original })

	t.Run("runs each step in order", func(t *testing.T) {
		var steps []int
		migrations = map[int]func(*State) error{
			1: func(s *State) error { steps = append(steps, 1); s.Epoch++; return nil },
			2: func(s *State) error { steps = append(steps, 2); s.Epoch++; return nil },
		}
		s := &State{SchemaVersion: 1, Keys: map[string]KeyRecord{}, RevokedCerts: map[string]RevokedCert{}}
		if err := s.migrateTo(3); err != nil {
			t.Fatalf("migrateTo: %v", err)
		}
		if diff := cmp.Diff([]int{1, 2}, steps); diff != "" {
			t.Errorf("migration order (-want +got):\n%s", diff)
		}
		if s.SchemaVersion != 3 || s.Epoch != 2 {
			t.Errorf("after migration: version %d epoch %d, want 3 and 2", s.SchemaVersion, s.Epoch)
		}
	})

	t.Run("a missing step is corruption, not a silent skip", func(t *testing.T) {
		migrations = map[int]func(*State) error{}
		s := &State{SchemaVersion: 1}
		if err := s.migrateTo(2); !errors.Is(err, ErrCorrupt) {
			t.Errorf("migrateTo error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("a failing step aborts", func(t *testing.T) {
		sentinel := errors.New("boom")
		migrations = map[int]func(*State) error{1: func(*State) error { return sentinel }}
		s := &State{SchemaVersion: 1}
		err := s.migrateTo(2)
		if !errors.Is(err, sentinel) {
			t.Fatalf("migrateTo error = %v, want the step's own error", err)
		}
		if !strings.Contains(err.Error(), "migrate schema 1 to 2") {
			t.Errorf("error %q does not name the step (from 1 to 2)", err)
		}
		if s.SchemaVersion != 1 {
			t.Errorf("SchemaVersion = %d after a failed step, want it left at 1", s.SchemaVersion)
		}
	})
}

func TestPutKeyValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  *fleet.Key
		want error
	}{
		{"nil", nil, ErrInvalid},
		{"no kid", &fleet.Key{Class: fleet.ClassAgent}, ErrInvalid},
		{"unknown class", &fleet.Key{KID: "k", Class: "xyz"}, ErrInvalid},
		{"empty class", &fleet.Key{KID: "k"}, ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := NewState()
			changed, err := s.PutKey(tc.key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("PutKey error = %v, want %v", err, tc.want)
			}
			if changed {
				t.Error("a rejected write reported a change")
			}
			if len(s.Keys) != 0 {
				t.Errorf("a rejected write stored %d keys", len(s.Keys))
			}
		})
	}
}

func TestPutKeyIfNoUsable(t *testing.T) {
	t.Parallel()

	s := NewState()
	first := agentKey("bootstrap0", tBase)
	changed, err := s.PutKeyIfNoUsable(first, tBase)
	if err != nil || !changed {
		t.Fatalf("first put = (%v, %v), want (true, nil)", changed, err)
	}

	replacement := agentKey("bootstrap0", tBase.Add(time.Hour))
	replacement.SecretHMAC = []byte("replacement")
	changed, err = s.PutKeyIfNoUsable(replacement, tBase.Add(time.Hour))
	if err != nil || changed {
		t.Fatalf("usable put = (%v, %v), want (false, nil)", changed, err)
	}

	changed, err = s.PutKeyIfNoUsable(replacement, tExpires.Add(time.Second))
	if err != nil || !changed {
		t.Fatalf("expired put = (%v, %v), want (true, nil)", changed, err)
	}
	got, err := s.GetKey(first.KID)
	if err != nil || string(got.SecretHMAC) != "replacement" {
		t.Fatalf("replacement = %+v, err %v", got, err)
	}

	if _, err := s.PutKeyIfNoUsable(nil, tBase); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil put error = %v, want ErrInvalid", err)
	}
}

func TestPutKeyDeepCopiesTheCaller(t *testing.T) {
	t.Parallel()
	s := NewState()
	k := agentKey("agent0001", tBase)
	if _, err := s.PutKey(k); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	k.SecretHMAC[0] = 0x11
	k.Scope.Clusters.Allow[0] = "mutated"

	got, err := s.GetKey("agent0001")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.SecretHMAC[0] == 0x11 {
		t.Error("the stored SecretHMAC aliases the caller's slice")
	}
	if got.Scope.Clusters.Allow[0] == "mutated" {
		t.Error("the stored scope aliases the caller's slice")
	}

	// And a returned value must not alias stored state either.
	got.Scope.Clusters.MatchLabels["env"] = "mutated"
	got.Enrollment = nil
	again, err := s.GetKey("agent0001")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if again.Scope.Clusters.MatchLabels["env"] != "prod" {
		t.Error("mutating a returned key changed stored state")
	}
}

func TestGetKeyNotFound(t *testing.T) {
	t.Parallel()
	s := NewState()
	got, err := s.GetKey("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetKey error = %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Error("GetKey returned a key alongside an error")
	}
}

func TestListKeysCopiesEnrollmentGrants(t *testing.T) {
	t.Parallel()
	s := NewState()
	if _, err := s.PutKey(enrollmentKey("enrol0001", tBase)); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	listed := s.ListKeys(fleet.ClassEnrollment)
	if len(listed) != 1 {
		t.Fatalf("ListKeys returned %d keys, want 1", len(listed))
	}
	listed[0].Enrollment.Labels["env"] = "mutated"
	again := s.ListKeys("")
	if again[0].Enrollment.Labels["env"] != "prod" {
		t.Error("mutating a listed enrollment grant changed stored state")
	}
}

// TestReplaceKeyState drives the document-level rotation primitive directly,
// including the branches the shared backend suite reaches only through a
// backend: the zero revocation time falling back to the clock, and the exact
// field mutations on the outgoing record.
func TestReplaceKeyState(t *testing.T) {
	t.Parallel()

	t.Run("replaces and revokes as one mutation", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		at := tBase.Add(time.Hour)
		changed, err := s.ReplaceKey(agentKey("agent0002", at), "agent0001", "rotated (replaced by agent0002)", at, clockAt(tBase))
		if err != nil || !changed {
			t.Fatalf("ReplaceKey = %v, %v; want a change", changed, err)
		}
		old, err := s.GetKey("agent0001")
		if err != nil {
			t.Fatalf("GetKey(old): %v", err)
		}
		if old.RevokedAt == nil || !old.RevokedAt.Equal(at) || old.RevokedReason != "rotated (replaced by agent0002)" {
			t.Errorf("old record = revokedAt %v reason %q, want %s and the rotation reason", old.RevokedAt, old.RevokedReason, at)
		}
		if fresh, err := s.GetKey("agent0002"); err != nil || fresh.Revoked() {
			t.Errorf("fresh record = %v, %v; want live", fresh, err)
		}
	})

	t.Run("a zero revocation time takes the clock", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		now := tBase.Add(2 * time.Hour)
		if _, err := s.ReplaceKey(agentKey("agent0002", tBase), "agent0001", "rotated", time.Time{}, clockAt(now)); err != nil {
			t.Fatalf("ReplaceKey: %v", err)
		}
		old, err := s.GetKey("agent0001")
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		if old.RevokedAt == nil || !old.RevokedAt.Equal(now) {
			t.Errorf("RevokedAt = %v, want the clock's %s", old.RevokedAt, now)
		}
	})

	t.Run("missing source is ErrNotFound", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.ReplaceKey(agentKey("agent0002", tBase), "agent-none", "rotated", tBase, clockAt(tBase)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("revoked source is ErrRevoked, never ErrAlreadyExists", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.RevokeKey("agent0001", "rotated (replaced by agent0009)", tBase, clockAt(tBase)); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		_, err := s.ReplaceKey(agentKey("agent0002", tBase), "agent0001", "rotated", tBase, clockAt(tBase))
		if !errors.Is(err, ErrRevoked) || errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v, want ErrRevoked and not ErrAlreadyExists", err)
		}
		if !strings.Contains(err.Error(), "agent0009") {
			t.Errorf("err = %q, want the recorded reason naming the replacement", err)
		}
	})

	t.Run("a taken fresh KID changes nothing", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.PutKey(agentKey("agent0002", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.ReplaceKey(agentKey("agent0002", tBase), "agent0001", "rotated", tBase, clockAt(tBase)); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("err = %v, want ErrAlreadyExists", err)
		}
		old, err := s.GetKey("agent0001")
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		if old.Revoked() {
			t.Error("the old key was revoked by a failed ReplaceKey")
		}
	})

	t.Run("an invalid fresh key changes nothing", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.ReplaceKey(&fleet.Key{}, "agent0001", "rotated", tBase, clockAt(tBase)); err == nil {
			t.Fatal("ReplaceKey accepted an invalid fresh key")
		}
		if old, _ := s.GetKey("agent0001"); old.Revoked() {
			t.Error("the old key was revoked by a failed ReplaceKey")
		}
	})
}

func TestRevokeKeyIdempotence(t *testing.T) {
	t.Parallel()
	s := NewState()
	if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	epochAfterPut := s.Epoch

	changed, err := s.RevokeKey("agent0001", "leaked", time.Time{}, clockAt(tBase))
	if err != nil || !changed {
		t.Fatalf("RevokeKey = %v, %v; want a change", changed, err)
	}
	if s.Epoch != epochAfterPut+1 {
		t.Errorf("epoch = %d, want %d", s.Epoch, epochAfterPut+1)
	}
	k, err := s.GetKey("agent0001")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if k.RevokedAt == nil || !k.RevokedAt.Equal(tBase) {
		t.Errorf("RevokedAt = %v, want the clock's %v for a zero timestamp", k.RevokedAt, tBase)
	}

	changed, err = s.RevokeKey("agent0001", "second", tBase.Add(time.Hour), clockAt(tBase))
	if err != nil {
		t.Fatalf("RevokeKey (repeat): %v", err)
	}
	if changed {
		t.Error("a repeated revocation reported a change, which would rewrite the audit record")
	}
	if s.Epoch != epochAfterPut+1 {
		t.Errorf("epoch moved to %d on a repeated revocation", s.Epoch)
	}
}

func TestKeyNotFoundMutations(t *testing.T) {
	t.Parallel()
	s := NewState()
	tests := []struct {
		name string
		run  func() (bool, error)
	}{
		{"RevokeKey", func() (bool, error) { return s.RevokeKey("missing", "r", tBase, time.Now) }},
		{"DeleteKey", func() (bool, error) { return s.DeleteKey("missing") }},
		{"TouchKey", func() (bool, error) { return s.TouchKey("missing", tBase, time.Now) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			changed, err := tc.run()
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want ErrNotFound", err)
			}
			if changed {
				t.Error("a failed mutation reported a change")
			}
		})
	}
}

func TestPutKeyRejectsADuplicate(t *testing.T) {
	t.Parallel()
	s := NewState()
	if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	before := s.Epoch
	changed, err := s.PutKey(agentKey("agent0001", tBase.Add(time.Hour)))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("error = %v, want ErrAlreadyExists", err)
	}
	if changed || s.Epoch != before {
		t.Error("a rejected duplicate changed the document")
	}
}

func TestTouchKeyUsesTheClock(t *testing.T) {
	t.Parallel()
	s := NewState()
	if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	before := s.Epoch
	changed, err := s.TouchKey("agent0001", time.Time{}, clockAt(tExpires))
	if err != nil || !changed {
		t.Fatalf("TouchKey = %v, %v", changed, err)
	}
	if s.Epoch != before {
		t.Errorf("TouchKey bumped the epoch to %d; every verifier cache in the fleet would be invalidated per request", s.Epoch)
	}
	k, err := s.GetKey("agent0001")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if k.LastUsed == nil || !k.LastUsed.Equal(tExpires) {
		t.Errorf("LastUsed = %v, want the clock's %v", k.LastUsed, tExpires)
	}
}

func TestBurnEnrollment(t *testing.T) {
	t.Parallel()

	newWith := func(t *testing.T, keys ...*fleet.Key) *State {
		t.Helper()
		s := NewState()
		for _, k := range keys {
			if _, err := s.PutKey(k); err != nil {
				t.Fatalf("PutKey: %v", err)
			}
		}
		return s
	}

	t.Run("records the serial and the time", func(t *testing.T) {
		t.Parallel()
		s := newWith(t, enrollmentKey("enrol0001", tBase))
		before := s.Epoch
		got, changed, err := s.BurnEnrollment("enrol0001", "serial-01", time.Time{}, clockAt(tBase))
		if err != nil || !changed {
			t.Fatalf("BurnEnrollment = %v, %v", changed, err)
		}
		if got.Enrollment.CertSerial != "serial-01" || !got.Enrollment.UsedAt.Equal(tBase) {
			t.Errorf("grant = %+v, want the serial and the clock's time", got.Enrollment)
		}
		if s.Epoch != before+1 {
			t.Errorf("epoch = %d, want %d", s.Epoch, before+1)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		t.Parallel()
		revoked := enrollmentKey("enrol0002", tBase)
		expired := enrollmentKey("enrol0003", tBase)
		noGrant := &fleet.Key{KID: "enrol0004", Class: fleet.ClassEnrollment, CreatedAt: tBase, ExpiresAt: tExpires}
		burned := enrollmentKey("enrol0005", tBase)
		s := newWith(t, agentKey("agent0001", tBase), revoked, expired, noGrant, burned)
		if _, err := s.RevokeKey(revoked.KID, "operator error", tBase, time.Now); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		if _, _, err := s.BurnEnrollment(burned.KID, "serial-01", tBase, time.Now); err != nil {
			t.Fatalf("BurnEnrollment: %v", err)
		}
		epochBefore := s.Epoch

		tests := []struct {
			name   string
			kid    string
			serial string
			at     time.Time
			want   error
		}{
			{"empty serial", "enrol0003", "", tBase, ErrInvalid},
			{"unknown kid", "missing", "serial-01", tBase, ErrNotFound},
			{"wrong class", "agent0001", "serial-01", tBase, ErrWrongClass},
			{"no grant", noGrant.KID, "serial-01", tBase, ErrWrongClass},
			{"revoked", revoked.KID, "serial-01", tBase, ErrNotUsable},
			{"expired", expired.KID, "serial-01", tExpires, ErrNotUsable},
			{"already used", burned.KID, "serial-02", tBase, ErrEnrollmentUsed},
		}
		for _, tc := range tests {
			got, changed, err := s.BurnEnrollment(tc.kid, tc.serial, tc.at, time.Now)
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: error = %v, want %v", tc.name, err, tc.want)
			}
			if got != nil || changed {
				t.Errorf("%s: a rejected burn reported a change", tc.name)
			}
		}
		if s.Epoch != epochBefore {
			t.Errorf("epoch moved to %d across rejected burns", s.Epoch)
		}
		if k, err := s.GetKey(expired.KID); err != nil || k.Enrollment.UsedAt != nil {
			t.Error("a rejected burn consumed the token")
		}
	})

	t.Run("the second attempt names the first", func(t *testing.T) {
		t.Parallel()
		s := newWith(t, enrollmentKey("enrol0001", tBase))
		if _, _, err := s.BurnEnrollment("enrol0001", "serial-01", tBase, time.Now); err != nil {
			t.Fatalf("BurnEnrollment: %v", err)
		}
		_, _, err := s.BurnEnrollment("enrol0001", "serial-02", tBase, time.Now)
		if !errors.Is(err, ErrEnrollmentUsed) {
			t.Fatalf("error = %v, want ErrEnrollmentUsed", err)
		}
		// A second redemption is a security event, so the message has to
		// carry enough to investigate it.
		for _, want := range []string{"serial-01", "2026-03-01"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
	})

	t.Run("reusable", func(t *testing.T) {
		t.Parallel()

		t.Run("unlimited: repeated redemption increments Redemptions and never fails", func(t *testing.T) {
			t.Parallel()
			s := newWith(t, reusableEnrollmentKey("enrol0006", tBase, 0))
			for i, serial := range []string{"serial-01", "serial-02", "serial-03"} {
				got, changed, err := s.BurnEnrollment("enrol0006", serial, tBase.Add(time.Duration(i)*time.Minute), time.Now)
				if err != nil || !changed {
					t.Fatalf("redemption %d: BurnEnrollment = %v, %v", i, changed, err)
				}
				if got.Enrollment.Redemptions != i+1 {
					t.Errorf("redemption %d: Redemptions = %d, want %d", i, got.Enrollment.Redemptions, i+1)
				}
				if got.Enrollment.CertSerial != serial {
					t.Errorf("redemption %d: CertSerial = %q, want %q", i, got.Enrollment.CertSerial, serial)
				}
				if got.Enrollment.ClusterID != "prod-eu-1" {
					t.Errorf("redemption %d: ClusterID changed to %q", i, got.Enrollment.ClusterID)
				}
			}
		})

		t.Run("capped: redemptions beyond MaxRedemptions are refused", func(t *testing.T) {
			t.Parallel()
			s := newWith(t, reusableEnrollmentKey("enrol0007", tBase, 2))

			for i, serial := range []string{"serial-01", "serial-02"} {
				got, changed, err := s.BurnEnrollment("enrol0007", serial, tBase.Add(time.Duration(i)*time.Minute), time.Now)
				if err != nil || !changed {
					t.Fatalf("redemption %d: BurnEnrollment = %v, %v", i, changed, err)
				}
				if got.Enrollment.Redemptions != i+1 {
					t.Errorf("redemption %d: Redemptions = %d, want %d", i, got.Enrollment.Redemptions, i+1)
				}
			}

			before := s.Epoch
			got, changed, err := s.BurnEnrollment("enrol0007", "serial-03", tBase.Add(3*time.Minute), time.Now)
			if !errors.Is(err, ErrEnrollmentUsed) {
				t.Fatalf("third redemption: error = %v, want ErrEnrollmentUsed", err)
			}
			if got != nil || changed {
				t.Error("a redemption over the cap reported a change")
			}
			if s.Epoch != before {
				t.Errorf("epoch moved to %d on a redemption over the cap", s.Epoch)
			}
			stored, err := s.GetKey("enrol0007")
			if err != nil {
				t.Fatalf("GetKey: %v", err)
			}
			if stored.Enrollment.Redemptions != 2 {
				t.Errorf("Redemptions = %d after a refused third attempt, want 2", stored.Enrollment.Redemptions)
			}
		})

		t.Run("single-use is unaffected: a second attempt still fails", func(t *testing.T) {
			t.Parallel()
			// Not reusable, MaxRedemptions irrelevant: this is the ordinary
			// single-use path, pinned here beside the reusable cases so a
			// regression that made every grant reusable would be caught next
			// to the behaviour it must not disturb.
			s := newWith(t, enrollmentKey("enrol0008", tBase))
			if _, _, err := s.BurnEnrollment("enrol0008", "serial-01", tBase, time.Now); err != nil {
				t.Fatalf("BurnEnrollment: %v", err)
			}
			_, _, err := s.BurnEnrollment("enrol0008", "serial-02", tBase, time.Now)
			if !errors.Is(err, ErrEnrollmentUsed) {
				t.Fatalf("second attempt: error = %v, want ErrEnrollmentUsed", err)
			}
		})
	})
}

func TestRevokeCert(t *testing.T) {
	t.Parallel()
	s := NewState()
	changed, err := s.RevokeCert(RevokedCert{}, time.Now)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("RevokeCert(no serial) = %v, want ErrInvalid", err)
	}
	if changed || len(s.RevokedCerts) != 0 {
		t.Error("a rejected revocation changed the document")
	}

	if _, err := s.RevokeCert(RevokedCert{Serial: "0a", NotAfter: tExpires}, clockAt(tBase)); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	got := s.ListRevokedCerts()
	if len(got) != 1 || !got[0].RevokedAt.Equal(tBase) {
		t.Fatalf("entries = %+v, want a clock-filled RevokedAt", got)
	}

	// Re-revoking replaces rather than duplicating.
	if _, err := s.RevokeCert(RevokedCert{Serial: "0a", RevokedAt: tBase, NotAfter: tExpires, Reason: "key compromise"}, time.Now); err != nil {
		t.Fatalf("RevokeCert (repeat): %v", err)
	}
	if got = s.ListRevokedCerts(); len(got) != 1 || got[0].Reason != "key compromise" {
		t.Errorf("entries = %+v, want the one replaced entry", got)
	}
}

func TestClock(t *testing.T) {
	t.Parallel()
	if Clock(nil) == nil {
		t.Error("Clock(nil) returned nil, want time.Now")
	}
	if got := Clock(clockAt(tBase))(); !got.Equal(tBase) {
		t.Errorf("Clock returned %v, want the injected %v", got, tBase)
	}
}

func TestCheckContext(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		closed bool
		want   error
	}{
		{"open", context.Background(), false, nil},
		{"closed", context.Background(), true, ErrClosed},
		{"cancelled", cancelled, false, context.Canceled},
		{"cancelled and closed reports the context first", cancelled, true, context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckContext(tc.ctx, tc.closed)
			if tc.want == nil && err != nil {
				t.Fatalf("CheckContext = %v, want nil", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("CheckContext = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestListKeys(t *testing.T) {
	t.Parallel()
	s := NewState()
	// Inserted out of order, with a deliberate CreatedAt tie so the KID
	// tie-break is exercised rather than accidentally satisfied.
	for _, k := range []*fleet.Key{
		agentKey("agentZZZZ", tBase.Add(2*time.Hour)),
		agentKey("agentBBBB", tBase),
		agentKey("agentAAAA", tBase),
		enrollmentKey("enrolAAAA", tBase.Add(time.Hour)),
	} {
		if _, err := s.PutKey(k); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
	}
	tests := []struct {
		name  string
		class fleet.KeyClass
		want  []string
	}{
		{"all", "", []string{"agentAAAA", "agentBBBB", "enrolAAAA", "agentZZZZ"}},
		{"agent", fleet.ClassAgent, []string{"agentAAAA", "agentBBBB", "agentZZZZ"}},
		{"enrollment", fleet.ClassEnrollment, []string{"enrolAAAA"}},
		{"admin", fleet.ClassAdmin, nil},
		{"unknown class", "nope", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := s.ListKeys(tc.class)
			if got == nil {
				t.Fatal("ListKeys returned nil, want an empty slice")
			}
			kids := make([]string, 0, len(got))
			for _, k := range got {
				kids = append(kids, k.KID)
			}
			if len(tc.want) == 0 && len(kids) != 0 {
				t.Fatalf("ListKeys(%q) = %v, want none", tc.class, kids)
			}
			if len(tc.want) != 0 {
				if diff := cmp.Diff(tc.want, kids); diff != "" {
					t.Errorf("ListKeys(%q) order (-want +got):\n%s", tc.class, diff)
				}
			}
		})
	}
}

func TestDeleteKey(t *testing.T) {
	t.Parallel()
	s := NewState()
	if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	before := s.Epoch
	changed, err := s.DeleteKey("agent0001")
	if err != nil || !changed {
		t.Fatalf("DeleteKey = %v, %v", changed, err)
	}
	if s.Epoch != before+1 {
		t.Errorf("epoch = %d, want %d", s.Epoch, before+1)
	}
	if _, err := s.GetKey("agent0001"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetKey after delete = %v, want ErrNotFound", err)
	}
	// The identifier must be reusable afterwards.
	if _, err := s.PutKey(agentKey("agent0001", tBase)); err != nil {
		t.Errorf("PutKey after delete: %v", err)
	}
}

func TestListRevokedCertsOrdering(t *testing.T) {
	t.Parallel()
	s := NewState()
	for _, serial := range []string{"ff", "0a", "zz", "01", "b0"} {
		if _, err := s.RevokeCert(RevokedCert{Serial: serial, RevokedAt: tBase, NotAfter: tExpires}, time.Now); err != nil {
			t.Fatalf("RevokeCert(%s): %v", serial, err)
		}
	}
	want := []string{"01", "0a", "b0", "ff", "zz"}
	for range 3 {
		got := s.ListRevokedCerts()
		serials := make([]string, 0, len(got))
		for _, rc := range got {
			serials = append(serials, rc.Serial)
		}
		if diff := cmp.Diff(want, serials); diff != "" {
			t.Fatalf("ListRevokedCerts order (-want +got):\n%s", diff)
		}
	}
	if got := NewState().ListRevokedCerts(); got == nil {
		t.Error("ListRevokedCerts returned nil for an empty document, want an empty slice")
	}
}

// TestStatePrune drives the document-level prune directly, including the
// branches the shared backend suite reaches only through a backend.
func TestStatePrune(t *testing.T) {
	t.Parallel()

	now := tBase.Add(365 * 24 * time.Hour)
	const retain = 24 * time.Hour

	newSeeded := func(t *testing.T) *State {
		t.Helper()
		s := NewState()
		expired := agentKey("agent0001", tBase)
		expired.ExpiresAt = now.Add(-48 * time.Hour)
		if _, err := s.PutKey(expired); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.RevokeCert(RevokedCert{
			Serial: "0a", RevokedAt: tBase, NotAfter: now.Add(-48 * time.Hour),
		}, clockAt(now)); err != nil {
			t.Fatalf("RevokeCert: %v", err)
		}
		return s
	}

	t.Run("removes what stopped mattering", func(t *testing.T) {
		t.Parallel()
		s := newSeeded(t)
		res, changed, err := s.Prune(now, retain)
		if err != nil || !changed {
			t.Fatalf("Prune() = %+v, %v, %v; want a change", res, changed, err)
		}
		if res.Keys != 1 || res.RevokedCerts != 1 {
			t.Errorf("Prune() = %+v, want one of each", res)
		}
	})

	t.Run("retention holds a record back", func(t *testing.T) {
		t.Parallel()
		s := newSeeded(t)
		// Both records lapsed 48h ago; a 72h window keeps them.
		res, changed, err := s.Prune(now, 72*time.Hour)
		if err != nil {
			t.Fatalf("Prune: %v", err)
		}
		if changed || !res.Empty() {
			t.Errorf("Prune() = %+v, changed=%v; the retention window must hold both back", res, changed)
		}
	})

	t.Run("an unknown certificate expiry is never dropped", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, err := s.RevokeCert(RevokedCert{Serial: "0b", RevokedAt: tBase}, clockAt(now)); err != nil {
			t.Fatalf("RevokeCert: %v", err)
		}
		res, _, err := s.Prune(now, 0)
		if err != nil {
			t.Fatalf("Prune: %v", err)
		}
		if res.RevokedCerts != 0 {
			t.Error("a revocation with no recorded expiry was dropped; nothing proves that certificate is dead")
		}
	})

	t.Run("a key with no expiry is never dropped", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		immortal := agentKey("agent0002", tBase)
		immortal.ExpiresAt = time.Time{}
		if _, err := s.PutKey(immortal); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
		if _, err := s.RevokeKey(immortal.KID, "leaked", tBase, clockAt(now)); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		res, changed, err := s.Prune(now, 0)
		if err != nil {
			t.Fatalf("Prune: %v", err)
		}
		if changed || res.Keys != 0 {
			t.Fatal("a revoked key with no expiry was pruned; its record is the only thing refusing it")
		}
	})

	t.Run("negative retention is refused", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		if _, _, err := s.Prune(now, -time.Second); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Prune(negative) = %v, want ErrInvalid", err)
		}
	})

	// The hub reads a cluster's operator labels from its newest non-revoked
	// enrollment record on every attach. Tokens expire in minutes, so the
	// first release of Prune deleted that record retain after the install and
	// the cluster silently fell back to whatever labels the spoke reported --
	// the self-relabelling that record exists to prevent.
	t.Run("the newest enrollment record per cluster survives, older and revoked ones do not", func(t *testing.T) {
		t.Parallel()
		s := NewState()
		put := func(k *fleet.Key) {
			t.Helper()
			if _, err := s.PutKey(k); err != nil {
				t.Fatalf("PutKey(%s): %v", k.KID, err)
			}
		}
		// Three tokens for prod-eu-1 across its life: the original install,
		// a rebuild, and one minted by mistake and revoked. Plus one for a
		// second cluster, so the rule is visibly per cluster.
		first := enrollmentKey("enrol001", tBase)
		rebuild := enrollmentKey("enrol002", tBase.Add(30*24*time.Hour))
		mistake := enrollmentKey("enrol003", tBase.Add(60*24*time.Hour))
		other := enrollmentKey("enrol004", tBase)
		other.Enrollment.ClusterID = "prod-us-1"
		for _, k := range []*fleet.Key{first, rebuild, mistake, other} {
			put(k)
		}
		if _, err := s.RevokeKey(mistake.KID, "wrong cluster", tBase.Add(61*24*time.Hour), clockAt(now)); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		// Two tokens minted in the same instant: the tie goes to the lower
		// KID, exactly as hub.enrollmentLabels resolves it, so the record
		// kept is the record read.
		tieA := enrollmentKey("tie00002", tBase.Add(time.Hour))
		tieB := enrollmentKey("tie00001", tBase.Add(time.Hour))
		tieA.Enrollment.ClusterID, tieB.Enrollment.ClusterID = "prod-ap-1", "prod-ap-1"
		put(tieA)
		put(tieB)

		res, changed, err := s.Prune(now, 0)
		if err != nil || !changed {
			t.Fatalf("Prune() = %+v, %v, %v; want a change", res, changed, err)
		}
		if res.Keys != 3 {
			t.Errorf("Prune() dropped %d keys, want 3 (the superseded original, the revoked mistake, the tie loser)", res.Keys)
		}
		for _, want := range []string{rebuild.KID, other.KID, tieB.KID} {
			if _, ok := s.Keys[want]; !ok {
				t.Errorf("%s was pruned; it carries its cluster's operator labels", want)
			}
		}
		for _, gone := range []string{first.KID, mistake.KID, tieA.KID} {
			if _, ok := s.Keys[gone]; ok {
				t.Errorf("%s survived; it is not any cluster's label authority", gone)
			}
		}
	})
}
