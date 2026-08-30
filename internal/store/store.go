// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// Sentinel errors. Every one of them is returned wrapped with context
// identifying the record involved, so callers must match with errors.Is.
var (
	// ErrNotFound reports that no record exists under the given identifier.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists reports an attempt to create a record whose identifier
	// is already taken.
	ErrAlreadyExists = errors.New("already exists")
	// ErrEnrollmentUsed reports a second attempt to redeem a single-use
	// enrollment token. It is a security event, not a retryable condition:
	// either the token leaked or a spoke is misbehaving.
	ErrEnrollmentUsed = errors.New("enrollment token already used")
	// ErrClosed reports use of a store after Close.
	ErrClosed = errors.New("store is closed")
	// ErrStateTooLarge reports a write that would push the state document
	// past [MaxStateBytes]. A Kubernetes Secret is hard-capped at 1 MiB by
	// the API server, and a hub that only discovers this at the moment it
	// tries to record a revocation has already lost the revocation, so the
	// limit is enforced early and with a message naming what to prune.
	ErrStateTooLarge = errors.New("state document too large")
	// ErrWrongClass reports an operation applied to a key of the wrong
	// fleet.KeyClass, such as burning an agent key as if it were an
	// enrollment token.
	ErrWrongClass = errors.New("wrong key class")
	// ErrNotUsable reports that a key exists but is revoked or expired.
	ErrNotUsable = errors.New("key is not usable")
	// ErrInvalid reports a record that is malformed on its face: a nil key, an
	// empty KID, an unknown class, an empty certificate serial.
	ErrInvalid = errors.New("invalid record")
	// ErrCorrupt reports that the persisted document is not decodable.
	ErrCorrupt = errors.New("state document is corrupt")
	// ErrSchemaTooNew reports a document written by a newer build. Refusing to
	// read it is deliberate: an older build that ignored unknown fields could
	// drop revocations, and a dropped revocation is a live credential.
	ErrSchemaTooNew = errors.New("state schema is newer than this build")
)

// RevokedCert is one entry of the hub's certificate revocation list.
type RevokedCert struct {
	// Serial is the certificate serial number in the hub CA's own notation.
	// It is the primary key and must be non-empty.
	Serial string `json:"serial"`
	// RevokedAt is when the revocation took effect.
	RevokedAt time.Time `json:"revokedAt"`
	// NotAfter is the certificate's own expiry. Once it has passed, the
	// revocation carries no information -- the certificate is invalid on its
	// own terms -- so callers may prune the entry. The store never prunes on
	// its own, because deciding when a CRL entry may be dropped depends on
	// clock skew tolerance the store does not know about.
	NotAfter time.Time `json:"notAfter"`
	// Reason is a short audit string, e.g. "spoke decommissioned".
	Reason string `json:"reason,omitempty"`
}

// Store is the hub's persistence boundary for credential material.
//
// There are deliberately no cluster methods. The registry is self-registering:
// spokes reconnect and re-publish their facts, so it is derivable and lives
// purely in memory (see internal/registry). Persisting it would only create
// the opportunity to serve an agent a stale cluster that no longer exists.
//
// Implementations are safe for concurrent use. Every method checks ctx for
// cancellation before it does any work and returns [ErrClosed] after Close.
// Returned pointers are freshly decoded copies: mutating one never affects
// stored state, and a second Get returns an independent value.
type Store interface {
	// PutKey stores a new key. It returns [ErrAlreadyExists] if the KID is
	// taken; there is deliberately no upsert, because silently replacing a
	// credential record is never a legitimate operation. Bumps the epoch.
	PutKey(ctx context.Context, k *fleet.Key) error

	// GetKey returns the key with the given KID, including its SecretHMAC.
	// It returns [ErrNotFound] if there is none.
	GetKey(ctx context.Context, kid string) (*fleet.Key, error)

	// ListKeys returns the keys of the given class, or every key when class is
	// empty. The order is stable: ascending CreatedAt, then ascending KID. An
	// unrecognised class yields an empty slice rather than an error.
	ListKeys(ctx context.Context, class fleet.KeyClass) ([]*fleet.Key, error)

	// RevokeKey marks a key revoked at the given time with the given reason,
	// and bumps the epoch. It is idempotent: revoking an already revoked key
	// succeeds, changes nothing, and does not bump the epoch again, so the
	// first revocation's timestamp and reason survive. A zero at means now.
	RevokeKey(ctx context.Context, kid, reason string, at time.Time) error

	// DeleteKey removes a key entirely and bumps the epoch. Prefer RevokeKey:
	// deletion destroys the audit trail. Returns [ErrNotFound] if absent.
	DeleteKey(ctx context.Context, kid string) error

	// TouchKey records that the key was used at the given time. It does not
	// bump the epoch: it runs on every authenticated request, and bumping
	// would invalidate every verifier cache continuously. A zero at means now.
	TouchKey(ctx context.Context, kid string, at time.Time) error

	// BurnEnrollment atomically redeems a single-use enrollment token for the
	// certificate with the given serial and returns the updated key.
	//
	// The load, the four checks and the write are one compare-and-swap
	// against the persisted document, so concurrent redemptions -- including
	// redemptions arriving at different hub replicas -- are serialized and
	// exactly one wins. The losers get [ErrEnrollmentUsed] and the stored
	// record is unchanged. Other failures are [ErrNotFound], [ErrWrongClass]
	// for a key that is not an enrollment token, [ErrNotUsable] for one that
	// is revoked or expired, and [ErrInvalid] for an empty certSerial, which
	// would spend the token without recording what it bought. Bumps the epoch
	// on success only.
	BurnEnrollment(ctx context.Context, kid, certSerial string, at time.Time) (*fleet.Key, error)

	// RevokeCert adds or replaces a certificate revocation list entry and
	// bumps the epoch. Replacing rather than rejecting a duplicate serial
	// keeps re-revocation from failing an otherwise correct decommission.
	RevokeCert(ctx context.Context, rc RevokedCert) error

	// ListRevokedCerts returns every revocation entry in ascending serial
	// order, including entries whose NotAfter has passed. Callers may prune
	// those; see [RevokedCert].
	ListRevokedCerts(ctx context.Context) ([]RevokedCert, error)

	// Epoch returns the current revocation epoch. It increases monotonically
	// and never resets for the life of the state document.
	Epoch(ctx context.Context) (uint64, error)

	// Close releases the backend. It is idempotent and returns nil on a
	// second call. Every other method returns [ErrClosed] afterwards.
	Close() error
}
