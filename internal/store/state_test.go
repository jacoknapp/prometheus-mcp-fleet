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
