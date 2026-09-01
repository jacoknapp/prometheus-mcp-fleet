// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"fmt"
	"time"
)

// KeyClass distinguishes the credential classes the hub issues. Each class has
// a separate issuance path, a separate verification path, and a separate blast
// radius; an agent key must never enroll a spoke, and an enrollment token must
// never run a query.
type KeyClass string

const (
	// ClassAdmin administers the hub: key CRUD, enrollment minting, revocation.
	// Presented only to the admin listener, never to the MCP listener.
	ClassAdmin KeyClass = "adm"
	// ClassAgent authenticates an AI agent to the MCP endpoint.
	ClassAgent KeyClass = "agt"
	// ClassEnrollment is single-use and buys exactly one spoke certificate.
	ClassEnrollment KeyClass = "enr"
)

// Valid reports whether c is a known credential class.
func (c KeyClass) Valid() bool {
	switch c {
	case ClassAdmin, ClassAgent, ClassEnrollment:
		return true
	default:
		return false
	}
}

// Role is a coarse capability tier attached to a key. Roles only ever remove
// capability relative to the next tier up; they never grant across classes.
type Role string

const (
	// RoleViewer may read metrics through the MCP tools it is scoped to. A
	// viewer's "*" tool wildcard excludes the operational surfaces (scrape
	// targets, runtime and TSDB internals); naming such a tool in the allow
	// list grants it regardless of role, because writing the name is the
	// deliberate act the tier exists to require.
	RoleViewer Role = "viewer"
	// RoleOperator additionally receives the operational surfaces through a
	// "*" wildcard: scrape targets, Alertmanager discovery, TSDB statistics,
	// runtime configuration and per-target metadata.
	RoleOperator Role = "operator"
	// RoleAdmin administers the hub. Only ever held by a ClassAdmin key.
	RoleAdmin Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// Key is the stored, non-secret record of an issued credential. The secret
// itself is never persisted: only SecretHMAC, which is
// HMAC-SHA256(pepper, secret) with the pepper held outside the database.
type Key struct {
	// KID is the public, non-secret identifier embedded in the token. It is
	// the primary lookup key and is safe to write to audit logs.
	KID string `json:"kid"`
	// Class fixes what the credential is allowed to be used for.
	Class KeyClass `json:"class"`
	// Name is an operator-chosen label, e.g. "sre-oncall-bot".
	Name string `json:"name"`
	// Owner is free-form contact information for the key's holder.
	Owner string `json:"owner,omitempty"`
	// SecretHMAC is HMAC-SHA256(pepper, secret). Never logged, never returned
	// by the admin API.
	SecretHMAC []byte `json:"-"`
	// Scope is the authorization document. Nil for admin and enrollment keys.
	Scope *Scope `json:"scope,omitempty"`
	// Enrollment carries the enrollment-specific fields. Nil unless
	// Class is ClassEnrollment.
	Enrollment *EnrollmentGrant `json:"enrollment,omitempty"`

	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	LastUsed  *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// RevokedReason is recorded for the audit trail.
	RevokedReason string `json:"revokedReason,omitempty"`
}

// Expired reports whether the key is past its expiry at time now.
func (k *Key) Expired(now time.Time) bool { return !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt) }

// Revoked reports whether the key has been revoked.
func (k *Key) Revoked() bool { return k.RevokedAt != nil }

// Usable reports whether the key may authenticate a request at time now.
func (k *Key) Usable(now time.Time) bool { return !k.Revoked() && !k.Expired(now) }

// EnrollmentGrant is the payload of a single-use spoke enrollment token. It
// binds the token to exactly one cluster identity so a leaked token cannot be
// redeemed for a different cluster's certificate.
type EnrollmentGrant struct {
	// ClusterID the resulting certificate will be bound to.
	ClusterID string `json:"clusterId"`
	// Labels are stamped onto the cluster registry entry at enrollment so the
	// hub can route by selector before the spoke reports anything itself.
	Labels map[string]string `json:"labels,omitempty"`
	// UsedAt is the moment of redemption. For a single-use grant it is set
	// exactly once, by an atomic conditional update, and a second attempt is a
	// security event rather than a retry. For a reusable grant it is the most
	// recent redemption.
	UsedAt *time.Time `json:"usedAt,omitempty"`
	// CertSerial records which certificate the token was burned for. For a
	// reusable grant it is the most recently issued one.
	CertSerial string `json:"certSerial,omitempty"`

	// Reusable allows this grant to be redeemed more than once.
	//
	// Single use is the default and remains right for an imperative install,
	// where a human mints a token and hands it straight to one cluster. It does
	// not survive contact with GitOps: the chart is reconciled from git
	// continuously, so a credential that is valid for fifteen minutes and dies
	// on first use cannot be committed, and a cluster rebuilt six months later
	// finds its token burned with nobody minting a replacement.
	//
	// What a reusable grant deliberately does NOT give up: it is still bound to
	// exactly one ClusterID, so a leak compromises one cluster and not the
	// fleet; it is still revocable; it still expires; and the hub still ignores
	// what the CSR asks for and mints its own subject and SAN.
	Reusable bool `json:"reusable,omitempty"`
	// Redemptions counts successful redemptions. It is meaningful only for a
	// reusable grant, where it is the audit trail that a single-use grant gets
	// from UsedAt being set at most once.
	Redemptions int `json:"redemptions,omitempty"`
	// MaxRedemptions caps a reusable grant. Zero means no cap, which is the
	// sensible default for a cluster that may be rebuilt any number of times.
	MaxRedemptions int `json:"maxRedemptions,omitempty"`
}

// Principal is the authenticated caller attached to a request context. It is
// derived from a verified credential and carries no secret material.
type Principal struct {
	KID   string   `json:"kid"`
	Name  string   `json:"name"`
	Class KeyClass `json:"class"`
	Role  Role     `json:"role"`
	Scope *Scope   `json:"scope,omitempty"`
	// Epoch is the revocation epoch the principal was verified against.
	Epoch uint64 `json:"-"`
}

// String renders the principal for logs. It deliberately contains no secret.
func (p *Principal) String() string {
	if p == nil {
		return "anonymous"
	}
	return fmt.Sprintf("%s/%s(%s)", p.Class, p.KID, p.Name)
}
