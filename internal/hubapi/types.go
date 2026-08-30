// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// TokenOnceNotice is the text every mint response carries. It is a field
// rather than a documentation note because the single most expensive operator
// mistake this API allows is closing the terminal before copying the token.
const TokenOnceNotice = "This is the only time this token will ever be shown. " +
	"The hub stores a keyed hash, not the token, so it cannot be recovered or resent. " +
	"Store it now; if you lose it, rotate the key."

// CreateKeyRequest is the body of POST /admin/v1/keys.
type CreateKeyRequest struct {
	// Class is "agt" or "adm". Enrollment tokens are minted by
	// POST /admin/v1/enrollments instead, because they need a cluster binding.
	Class fleet.KeyClass `json:"class"`
	// Name is an operator-chosen label such as "sre-oncall-bot". Required.
	Name string `json:"name"`
	// Owner is free-form contact information for the holder.
	Owner string `json:"owner,omitempty"`
	// TTL is a Go duration string. Empty means the class default; a value
	// above the configured maximum is refused rather than silently clamped, so
	// an operator is never surprised by a credential that expires early.
	TTL fleet.Duration `json:"ttl,omitempty"`
	// Scope is the authorization document. Required for an agent key and
	// refused for an admin key, whose authority is not scope-evaluated.
	Scope *fleet.Scope `json:"scope,omitempty"`
}

// CreateEnrollmentRequest is the body of POST /admin/v1/enrollments.
type CreateEnrollmentRequest struct {
	// ClusterID binds the token to exactly one cluster identity. It must match
	// ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$: this value becomes the URI SAN of
	// a certificate, so it is validated before it is stored, not at issuance.
	ClusterID string `json:"clusterId"`
	// Labels are stamped onto the cluster registry entry at enrollment.
	Labels map[string]string `json:"labels,omitempty"`
	// Name is an optional operator label for the token itself.
	Name string `json:"name,omitempty"`
	// Owner is free-form contact information.
	Owner string `json:"owner,omitempty"`
	// TTL is a Go duration string. Empty means the configured default.
	TTL fleet.Duration `json:"ttl,omitempty"`
}

// MintedKeyResponse is returned by every route that creates a credential.
type MintedKeyResponse struct {
	// Key is the stored, non-secret record.
	Key KeyView `json:"key"`
	// Token is the complete credential. This is the only time it is ever
	// returned.
	Token string `json:"token"`
	// TokenShownOnce is always true. It exists so that a client scripting
	// against this API has a machine-readable signal, not just prose.
	TokenShownOnce bool `json:"tokenShownOnce"`
	// Warning restates that in words; see [TokenOnceNotice].
	Warning string `json:"warning"`
}

// KeyView is the public projection of a stored credential.
//
// It is a distinct type from [fleet.Key] on purpose. fleet.Key holds
// SecretHMAC, and although that field is tagged json:"-" today, a projection
// that has no field for it cannot start leaking one because someone changed a
// tag. Nothing in this struct is secret.
type KeyView struct {
	KID           string          `json:"kid"`
	Class         fleet.KeyClass  `json:"class"`
	Name          string          `json:"name"`
	Owner         string          `json:"owner,omitempty"`
	Scope         *fleet.Scope    `json:"scope,omitempty"`
	Enrollment    *EnrollmentView `json:"enrollment,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	LastUsedAt    *time.Time      `json:"lastUsedAt,omitempty"`
	RevokedAt     *time.Time      `json:"revokedAt,omitempty"`
	RevokedReason string          `json:"revokedReason,omitempty"`
	// Expired and Revoked are computed for the operator's convenience so a UI
	// does not have to reimplement the clock comparison.
	Expired bool `json:"expired"`
	Revoked bool `json:"revoked"`
}

// EnrollmentView is the public projection of an enrollment grant.
type EnrollmentView struct {
	ClusterID  string            `json:"clusterId"`
	Labels     map[string]string `json:"labels,omitempty"`
	UsedAt     *time.Time        `json:"usedAt,omitempty"`
	CertSerial string            `json:"certSerial,omitempty"`
}

// KeyListResponse is the body of the list routes.
type KeyListResponse struct {
	Keys []KeyView `json:"keys"`
	// Count is len(Keys), so a client can assert it read the whole page. This
	// API does not paginate: the credential set is operator-sized.
	Count int `json:"count"`
}

// RevokeCertRequest is the body of POST /admin/v1/certs/{serial}/revoke.
type RevokeCertRequest struct {
	// Reason is a short audit string. Required.
	Reason string `json:"reason"`
	// NotAfter is the certificate's own expiry, after which the entry may be
	// pruned. Zero means the configured spoke certificate lifetime from now,
	// which is the longest a certificate issued by this hub can still be
	// valid.
	NotAfter time.Time `json:"notAfter,omitzero"`
}

// RevokedCertListResponse is the body of GET /admin/v1/certs/revoked.
type RevokedCertListResponse struct {
	Revoked []RevokedCert `json:"revoked"`
	Count   int           `json:"count"`
}

// EnrollRequest is the body of POST /enroll.
//
// POST /renew takes [RenewRequest] instead: it carries the proof of possession
// that route needs, and the two are separate types because this package decodes
// strictly and an unknown field is an error rather than a silently ignored one.
type EnrollRequest struct {
	// CSR is a base64 (standard encoding) DER certificate signing request.
	//
	// Everything it asks for except the public key is discarded. The subject,
	// the SANs and the extensions of the issued certificate are decided by the
	// hub from the identity it already bound to the enrollment token or read
	// from the certificate the caller proved it holds.
	CSR string `json:"csr"`
}

// RenewChallengeResponse is the body of GET /renew/challenge.
type RenewChallengeResponse struct {
	// Nonce is the challenge to sign, base64 encoded on the wire. It is
	// self-authenticating rather than remembered, so the replica that verifies
	// it need not be the one that issued it; see [server.issueRenewNonce].
	Nonce []byte `json:"nonce"`
	// ExpiresAt is when the challenge stops being accepted. A spoke that misses
	// the window fetches another; there is no penalty for doing so.
	ExpiresAt time.Time `json:"expiresAt"`
}

// RenewRequest is the body of POST /renew.
//
// There is deliberately no cluster field. The identity is read from the URI SAN
// of the verified certificate in Chain and from nowhere else, so a spoke cannot
// renew its way into being a different cluster, and the strict decoder turns any
// attempt to name one into a 400 rather than a value somebody has to remember to
// ignore.
type RenewRequest struct {
	// CSR is a base64 (standard encoding) DER certificate signing request, as
	// on [EnrollRequest]. Only its public key is used.
	CSR string `json:"csr"`
	// Chain is the spoke's current certificate followed by any intermediates,
	// DER encoded, leaf first. encoding/json renders each entry as base64.
	//
	// It is the credential this route accepts, and on its own it proves
	// nothing: a certificate is public. Signature is what turns it into one.
	Chain [][]byte `json:"chain"`
	// Signature is over the transcript binding Nonce, the renewal protocol
	// version and the cluster ID the hub derives from the leaf. See
	// [github.com/jacoknapp/prometheus-mcp-fleet/internal/certproof].
	Signature []byte `json:"signature"`
	// Nonce is the challenge from GET /renew/challenge, echoed back unchanged.
	Nonce []byte `json:"nonce"`
}

// EnrollResponse is the body returned by POST /enroll and POST /renew.
type EnrollResponse struct {
	// Certificate is the issued client certificate, PEM encoded.
	Certificate string `json:"certificate"`
	// CABundle is the trust anchor for the hub's tunnel listener, PEM encoded.
	CABundle string `json:"caBundle"`
	// NotAfter is when the certificate expires. Renew well before it.
	NotAfter time.Time `json:"notAfter"`
	// ClusterID is the identity actually bound into the certificate. A spoke
	// should compare it with its own configuration and refuse to start on a
	// mismatch.
	ClusterID string `json:"clusterId"`
	// Serial is the certificate serial in lowercase hexadecimal.
	Serial string `json:"serial"`
}

// CABundleResponse is the JSON form of the CA bundle, returned by
// GET /admin/v1/ca.
type CABundleResponse struct {
	// CABundle is the CA certificate, PEM encoded.
	CABundle string `json:"caBundle"`
	// NotAfter is when the CA certificate expires. Rotating it is a fleet-wide
	// re-enrollment, so it is worth alerting on well in advance.
	NotAfter time.Time `json:"notAfter"`
	// TrustDomain is the authority of every spoke URI SAN.
	TrustDomain string `json:"trustDomain"`
}

// ProtectedResourceMetadata is the RFC 9728 protected-resource document served
// at /.well-known/oauth-protected-resource/mcp.
//
// This hub does not implement OAuth. It authenticates with static bearer keys
// minted by an operator through the admin API, and there is no authorization
// server to redirect a client to. The document is served anyway, and
// AuthorizationServers is deliberately an empty array rather than absent,
// because a spec-compliant MCP client that receives a 401 will fetch this URL
// and deserves a well-formed answer that says "there is nowhere to go" instead
// of a 404 it has to guess about. PMFAuth is the extension that tells such a
// client what actually is expected.
type ProtectedResourceMetadata struct {
	// Resource is the canonical external MCP URL.
	Resource string `json:"resource,omitempty"`
	// AuthorizationServers is always empty: see the type documentation.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported is ["header"]: the credential goes in
	// Authorization, never in a query parameter, where it would land in access
	// logs.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	// ScopesSupported lists the scope strings this hub emits.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ResourceName is a human-readable name.
	ResourceName string `json:"resource_name,omitempty"`
	// ResourceDocumentation points at the project.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
	// PMFAuth is a non-standard extension naming the authentication schemes
	// this resource really accepts. It is "static-bearer": an operator-minted
	// `pmf_agt_` key presented as a bearer credential.
	PMFAuth []string `json:"x-pmf-auth"`
}

// viewKey projects a stored key for the API.
func viewKey(k *fleet.Key, now time.Time) KeyView {
	v := KeyView{
		KID:           k.KID,
		Class:         k.Class,
		Name:          k.Name,
		Owner:         k.Owner,
		Scope:         k.Scope,
		CreatedAt:     k.CreatedAt,
		ExpiresAt:     k.ExpiresAt,
		LastUsedAt:    k.LastUsed,
		RevokedAt:     k.RevokedAt,
		RevokedReason: k.RevokedReason,
		Expired:       k.Expired(now),
		Revoked:       k.Revoked(),
	}
	if k.Enrollment != nil {
		v.Enrollment = &EnrollmentView{
			ClusterID:  k.Enrollment.ClusterID,
			Labels:     k.Enrollment.Labels,
			UsedAt:     k.Enrollment.UsedAt,
			CertSerial: k.Enrollment.CertSerial,
		}
	}
	return v
}

// viewKeys projects a slice of stored keys.
func viewKeys(keys []*fleet.Key, now time.Time) []KeyView {
	out := make([]KeyView, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		out = append(out, viewKey(k, now))
	}
	return out
}
