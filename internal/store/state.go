// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// SchemaVersion is the document format this build writes.
const SchemaVersion = 1

// MaxStateBytes is the largest encoded document a backend will write.
//
// A Kubernetes Secret is hard-capped at 1 MiB by the API server. 700 KiB
// leaves room for base64 expansion of any sibling keys and for the object
// metadata, and leaves the operator a wide margin in which the exported size
// gauge can fire an alert before a write actually fails.
const MaxStateBytes = 700 << 10

// State is the entire persisted document: every credential record, the
// certificate revocation list and the revocation epoch.
//
// It is exported because the two shipped backends are separate packages that
// must agree on the format byte for byte, and because keeping the mutations
// here means the burn-once rule, the epoch rules and the ordering guarantees
// are written once and inherited by every backend rather than reimplemented
// per backend. A backend's job is reduced to load bytes, apply, store bytes.
//
// A State is not safe for concurrent use; backends own the synchronisation
// and hand each operation its own decoded copy.
type State struct {
	// SchemaVersion is the format version of this document.
	SchemaVersion int `json:"schemaVersion"`
	// Epoch is the revocation epoch. See [Store.Epoch].
	Epoch uint64 `json:"epoch"`
	// Keys is keyed by KID. A JSON object rather than an array keeps the
	// encoding deterministic (encoding/json sorts map keys) and makes the
	// uniqueness of a KID a property of the document rather than of the code
	// that walks it.
	Keys map[string]KeyRecord `json:"keys,omitempty"`
	// RevokedCerts is keyed by certificate serial.
	RevokedCerts map[string]RevokedCert `json:"revokedCerts,omitempty"`
}

// KeyRecord is the stored form of a credential.
//
// It exists for one reason: fleet.Key.SecretHMAC is tagged `json:"-"` so that
// the admin API cannot leak a verifier by accident. Marshalling a fleet.Key
// directly would therefore persist every field except the only one that makes
// the key verifiable, and every credential in the fleet would stop
// authenticating at the next restart -- with no error at write time, no error
// at read time, and no error until a user's request is rejected. The digest is
// carried here, outside the domain type's own tag set, and reattached on load.
//
// Any future field the domain type hides from the wire must be added here the
// same way.
type KeyRecord struct {
	// V is the schema version of this record, stored per record as well as
	// per document so that a partially migrated state is detectable rather
	// than silently mixed.
	V int `json:"v"`
	// Key is the domain value, minus the fields it hides.
	Key fleet.Key `json:"key"`
	// SecretHMAC is fleet.Key.SecretHMAC, persisted because the domain type
	// refuses to serialise it.
	SecretHMAC []byte `json:"secretHmac,omitempty"`
}

// NewState returns an empty document at the current schema version.
func NewState() *State {
	return &State{SchemaVersion: SchemaVersion, Keys: map[string]KeyRecord{}, RevokedCerts: map[string]RevokedCert{}}
}

// Decode parses a persisted document. Empty input yields an empty document,
// which is what a first start and an operator-created but unpopulated Secret
// both look like.
//
// It returns [ErrSchemaTooNew] for a document written by a later build and
// [ErrCorrupt] for anything that is not the expected JSON.
func Decode(b []byte) (*State, error) {
	if len(b) == 0 {
		return NewState(), nil
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode state: %w: %w", ErrCorrupt, err)
	}
	if s.Keys == nil {
		s.Keys = map[string]KeyRecord{}
	}
	if s.RevokedCerts == nil {
		s.RevokedCerts = map[string]RevokedCert{}
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// migrations upgrades a document one version at a time: migrations[n]
// converts version n to version n+1.
//
// It is empty because version 1 is the first released format. The hook is
// present, and exercised by the tests, so that adding version 2 is a map entry
// rather than a redesign.
var migrations = map[int]func(*State) error{}

// migrate brings a decoded document up to [SchemaVersion].
func (s *State) migrate() error { return s.migrateTo(SchemaVersion) }

// migrateTo is migrate with an explicit target, so that the hook and its
// failure modes are testable while [SchemaVersion] is still 1 and the loop
// below would otherwise never run.
func (s *State) migrateTo(target int) error {
	// A document with no schemaVersion at all predates nothing -- version 1 is
	// the first format -- so it is read as version 1 rather than rejected.
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	if s.SchemaVersion > target {
		return fmt.Errorf("state schema version %d, this build writes %d: %w",
			s.SchemaVersion, target, ErrSchemaTooNew)
	}
	for v := s.SchemaVersion; v < target; v++ {
		up, ok := migrations[v]
		if !ok {
			return fmt.Errorf("no migration registered from schema version %d: %w", v, ErrCorrupt)
		}
		if err := up(s); err != nil {
			return fmt.Errorf("migrate schema %d to %d: %w", v, v+1, err)
		}
		s.SchemaVersion = v + 1
	}
	return nil
}

// Encode renders the document for storage. The output is deterministic for a
// given document, so an unchanged state produces identical bytes and a
// diffing operator sees only real changes.
func (s *State) Encode() ([]byte, error) {
	s.SchemaVersion = SchemaVersion
	b, _ := json.Marshal(s) // State contains only JSON-native field types.
	return b, nil
}

// EncodeWithin is [State.Encode] bounded by max bytes, returning
// [ErrStateTooLarge] with the record counts and a pruning hint when the
// document would not fit. A max of zero or less is unbounded.
func (s *State) EncodeWithin(max int) ([]byte, error) {
	b, _ := s.Encode()
	if max > 0 && len(b) > max {
		return nil, fmt.Errorf(
			"state document is %d bytes against a %d byte limit, holding %d keys and %d revoked certificates; "+
				"delete expired or revoked keys and drop revocation entries whose notAfter has passed: %w",
			len(b), max, len(s.Keys), len(s.RevokedCerts), ErrStateTooLarge)
	}
	return b, nil
}

// bump advances the revocation epoch. It is called by exactly those mutations
// that can change an authorization outcome.
func (s *State) bump() { s.Epoch++ }

// --- keys ----------------------------------------------------------------

// validateKey rejects a record that could never be looked up or verified.
func validateKey(k *fleet.Key) error {
	switch {
	case k == nil:
		return fmt.Errorf("key is nil: %w", ErrInvalid)
	case k.KID == "":
		return fmt.Errorf("key has no kid: %w", ErrInvalid)
	case !k.Class.Valid():
		return fmt.Errorf("key %s has class %q: %w", k.KID, k.Class, ErrInvalid)
	default:
		return nil
	}
}

// PutKey inserts k. It reports whether the document changed, which is always
// true on success. See [Store.PutKey].
func (s *State) PutKey(k *fleet.Key) (bool, error) {
	if err := validateKey(k); err != nil {
		return false, err
	}
	if _, ok := s.Keys[k.KID]; ok {
		return false, fmt.Errorf("key %s: %w", k.KID, ErrAlreadyExists)
	}
	s.putKey(k)
	s.bump()
	return true, nil
}

// PutKeyIfNoUsable stores k when the current record is absent or unusable at
// at. The check and replacement occur within the backend's single mutation.
func (s *State) PutKeyIfNoUsable(k *fleet.Key, at time.Time) (bool, error) {
	if err := validateKey(k); err != nil {
		return false, err
	}
	if rec, ok := s.Keys[k.KID]; ok && rec.value().Usable(at) {
		return false, nil
	}
	s.putKey(k)
	s.bump()
	return true, nil
}

func (s *State) putKey(k *fleet.Key) {
	rec := KeyRecord{V: SchemaVersion, Key: cloneKey(*k), SecretHMAC: slices.Clone(k.SecretHMAC)}
	// The digest lives in exactly one place, the record's own field. Leaving a
	// copy on the embedded domain value would make the in-memory document and
	// the decoded one differ -- the embedded copy does not survive JSON -- and
	// that difference is the kind that shows up as a bug months later.
	rec.Key.SecretHMAC = nil
	s.Keys[k.KID] = rec
}

// GetKey returns the key with the given KID. See [Store.GetKey].
func (s *State) GetKey(kid string) (*fleet.Key, error) {
	rec, ok := s.Keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %s: %w", kid, ErrNotFound)
	}
	return rec.value(), nil
}

// value reassembles the domain key, reattaching the digest the domain type
// refuses to serialise. The result shares nothing with the record.
func (r KeyRecord) value() *fleet.Key {
	k := cloneKey(r.Key)
	k.SecretHMAC = slices.Clone(r.SecretHMAC)
	return &k
}

// cloneKey deep-copies every part of a key that lives behind a pointer, so
// that neither a caller's later mutation nor a caller's mutation of a
// returned value can reach stored state. A shallow copy would leave the
// scope, the enrollment grant and the timestamps shared, which is the classic
// way an authorization document silently changes under a verifier.
func cloneKey(k fleet.Key) fleet.Key {
	out := k
	out.SecretHMAC = slices.Clone(k.SecretHMAC)
	if k.Scope != nil {
		scope := *k.Scope
		scope.Clusters.Allow = slices.Clone(k.Scope.Clusters.Allow)
		scope.Clusters.Deny = slices.Clone(k.Scope.Clusters.Deny)
		scope.Clusters.MatchLabels = maps.Clone(k.Scope.Clusters.MatchLabels)
		scope.Tools.Allow = slices.Clone(k.Scope.Tools.Allow)
		scope.Tools.Deny = slices.Clone(k.Scope.Tools.Deny)
		out.Scope = &scope
	}
	if k.Enrollment != nil {
		grant := *k.Enrollment
		grant.Labels = maps.Clone(k.Enrollment.Labels)
		if k.Enrollment.UsedAt != nil {
			used := *k.Enrollment.UsedAt
			grant.UsedAt = &used
		}
		out.Enrollment = &grant
	}
	if k.LastUsed != nil {
		used := *k.LastUsed
		out.LastUsed = &used
	}
	if k.RevokedAt != nil {
		revoked := *k.RevokedAt
		out.RevokedAt = &revoked
	}
	return out
}

// ListKeys returns the keys of the given class, or all of them when class is
// empty, in ascending CreatedAt then KID order. See [Store.ListKeys].
func (s *State) ListKeys(class fleet.KeyClass) []*fleet.Key {
	out := make([]*fleet.Key, 0, len(s.Keys))
	for _, rec := range s.Keys {
		if class != "" && rec.Key.Class != class {
			continue
		}
		out = append(out, rec.value())
	}
	slices.SortFunc(out, func(a, b *fleet.Key) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.KID, b.KID)
	})
	return out
}

// RevokeKey marks a key revoked, reporting whether anything changed. See
// [Store.RevokeKey].
func (s *State) RevokeKey(kid, reason string, at time.Time, now func() time.Time) (bool, error) {
	rec, ok := s.Keys[kid]
	if !ok {
		return false, fmt.Errorf("key %s: %w", kid, ErrNotFound)
	}
	if rec.Key.RevokedAt != nil {
		// Idempotent: the first revocation's timestamp and reason are the
		// audit record, and a repeat must not rewrite them or move the epoch.
		return false, nil
	}
	when := at
	if when.IsZero() {
		when = now()
	}
	rec.Key.RevokedAt = &when
	rec.Key.RevokedReason = reason
	s.Keys[kid] = rec
	s.bump()
	return true, nil
}

// DeleteKey removes a key. See [Store.DeleteKey].
func (s *State) DeleteKey(kid string) (bool, error) {
	if _, ok := s.Keys[kid]; !ok {
		return false, fmt.Errorf("key %s: %w", kid, ErrNotFound)
	}
	delete(s.Keys, kid)
	s.bump()
	return true, nil
}

// TouchKey records a use. It deliberately does not bump the epoch. See
// [Store.TouchKey].
func (s *State) TouchKey(kid string, at time.Time, now func() time.Time) (bool, error) {
	rec, ok := s.Keys[kid]
	if !ok {
		return false, fmt.Errorf("key %s: %w", kid, ErrNotFound)
	}
	when := at
	if when.IsZero() {
		when = now()
	}
	rec.Key.LastUsed = &when
	s.Keys[kid] = rec
	return true, nil
}

// BurnEnrollment redeems a single-use enrollment token. See
// [Store.BurnEnrollment].
func (s *State) BurnEnrollment(kid, certSerial string, at time.Time, now func() time.Time) (*fleet.Key, bool, error) {
	if certSerial == "" {
		// Checked before anything else so that a caller which forgot the
		// serial cannot consume the token: a burn with no serial records
		// which token was spent but not what it bought, which is exactly the
		// audit trail the single-use rule exists to produce.
		return nil, false, fmt.Errorf("enrollment %s: certificate serial is empty: %w", kid, ErrInvalid)
	}
	rec, ok := s.Keys[kid]
	if !ok {
		return nil, false, fmt.Errorf("enrollment %s: %w", kid, ErrNotFound)
	}
	if rec.Key.Class != fleet.ClassEnrollment || rec.Key.Enrollment == nil {
		return nil, false, fmt.Errorf("key %s is class %q, not an enrollment token: %w",
			kid, rec.Key.Class, ErrWrongClass)
	}
	when := at
	if when.IsZero() {
		when = now()
	}
	if !rec.Key.Usable(when) {
		return nil, false, fmt.Errorf("enrollment %s: %w", kid, ErrNotUsable)
	}
	if rec.Key.Enrollment.UsedAt != nil {
		return nil, false, fmt.Errorf("enrollment %s was redeemed at %s for certificate %q: %w",
			kid, rec.Key.Enrollment.UsedAt.UTC(), rec.Key.Enrollment.CertSerial, ErrEnrollmentUsed)
	}
	grant := *rec.Key.Enrollment
	grant.UsedAt = &when
	grant.CertSerial = certSerial
	rec.Key.Enrollment = &grant
	s.Keys[kid] = rec
	s.bump()
	return rec.value(), true, nil
}

// --- revoked certificates ------------------------------------------------

// RevokeCert adds or replaces a revocation list entry. See
// [Store.RevokeCert].
func (s *State) RevokeCert(rc RevokedCert, now func() time.Time) (bool, error) {
	if rc.Serial == "" {
		return false, fmt.Errorf("revoked certificate has no serial: %w", ErrInvalid)
	}
	if rc.RevokedAt.IsZero() {
		rc.RevokedAt = now()
	}
	s.RevokedCerts[rc.Serial] = rc
	s.bump()
	return true, nil
}

// ListRevokedCerts returns every entry in ascending serial order. See
// [Store.ListRevokedCerts].
func (s *State) ListRevokedCerts() []RevokedCert {
	out := make([]RevokedCert, 0, len(s.RevokedCerts))
	for _, rc := range s.RevokedCerts {
		out = append(out, rc)
	}
	slices.SortFunc(out, func(a, b RevokedCert) int { return cmp.Compare(a.Serial, b.Serial) })
	return out
}

// --- backend helpers -----------------------------------------------------

// Clock returns now, or time.Now when now is nil. Backends use it to
// normalise an injected clock exactly once, at construction.
func Clock(now func() time.Time) func() time.Time {
	if now == nil {
		return time.Now
	}
	return now
}

// CheckContext is the ctx-then-closed guard every backend method runs before
// touching state, so that a cancelled call never writes and a closed store
// never lies about having done work.
func CheckContext(ctx context.Context, closed bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if closed {
		return ErrClosed
	}
	return nil
}
