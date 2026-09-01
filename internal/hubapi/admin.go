// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"errors"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// kidRE is the public key identifier grammar: exactly token.KIDLen base62
// characters. Validating it in the path keeps an arbitrary string from
// reaching the store as a lookup key or an audit line as a field.
var kidRE = regexp.MustCompile(`^[0-9A-Za-z]{` + strconv.Itoa(token.KIDLen) + `}$`)

// mintRetries is how many times a KID collision is retried before the request
// fails. 62^10 identifiers make one collision astronomically unlikely and two
// in a row impossible in practice, so this only exists so that the theoretical
// case is a retry rather than a 500.
const mintRetries = 3

// NewAdminMux returns the handler for the hub's admin listener.
//
// Every route it serves requires a `pmf_adm_` credential, enforced by one
// middleware wrapped around the whole mux rather than per route, so a route
// added later cannot accidentally be left unauthenticated. The listener itself
// is expected to be ClusterIP-only; this authentication is the second lock,
// not the first.
//
// Routes:
//
//	POST   /admin/v1/keys                  mint an agent or admin credential
//	GET    /admin/v1/keys                  list credentials, optional ?class=
//	GET    /admin/v1/keys/{kid}            read one credential record
//	DELETE /admin/v1/keys/{kid}            revoke (?reason=, optional ?purge=true)
//	POST   /admin/v1/keys/{kid}/rotate     mint a replacement and revoke the old
//	POST   /admin/v1/enrollments           mint a single-use enrollment token
//	GET    /admin/v1/enrollments           list enrollment tokens
//	DELETE /admin/v1/enrollments/{kid}     revoke an unredeemed enrollment token
//	POST   /admin/v1/certs/{serial}/revoke revoke a spoke certificate
//	GET    /admin/v1/certs/revoked         list revoked certificates
//	GET    /admin/v1/ca                    the CA bundle
func NewAdminMux(opts Options) (http.Handler, error) {
	s, err := newServer(opts)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/keys", s.handleCreateKey)
	mux.HandleFunc("GET /admin/v1/keys", s.handleListKeys)
	mux.HandleFunc("GET /admin/v1/keys/{kid}", s.handleGetKey)
	mux.HandleFunc("DELETE /admin/v1/keys/{kid}", s.handleRevokeKey)
	mux.HandleFunc("POST /admin/v1/keys/{kid}/rotate", s.handleRotateKey)
	mux.HandleFunc("POST /admin/v1/enrollments", s.handleCreateEnrollment)
	mux.HandleFunc("GET /admin/v1/enrollments", s.handleListEnrollments)
	mux.HandleFunc("DELETE /admin/v1/enrollments/{kid}", s.handleRevokeEnrollment)
	mux.HandleFunc("POST /admin/v1/certs/{serial}/revoke", s.handleRevokeCert)
	mux.HandleFunc("GET /admin/v1/certs/revoked", s.handleListRevokedCerts)
	mux.HandleFunc("GET /admin/v1/ca", s.handleCABundle)
	mux.HandleFunc("/", s.handleAdminNotFound)
	return s.verifier.Middleware(fleet.ClassAdmin)(mux), nil
}

// handleAdminNotFound answers any unrouted admin path with the standard
// envelope rather than the standard library's plain-text 404.
func (s *server) handleAdminNotFound(w http.ResponseWriter, r *http.Request) {
	s.fail(w, r, CodeNotFound, "no such admin route")
}

// handleCreateKey mints an agent or admin credential.
func (s *server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var req CreateKeyRequest
	if !s.readBody(w, r, &req) {
		return
	}

	var maxTTL time.Duration
	switch req.Class {
	case fleet.ClassAgent:
		maxTTL = s.agentKeyTTL
	case fleet.ClassAdmin:
		maxTTL = s.adminKeyTTL
	case fleet.ClassEnrollment:
		s.fail(w, r, CodeInvalidRequest,
			"enrollment tokens are minted by POST /admin/v1/enrollments, which binds them to a cluster")
		return
	default:
		s.fail(w, r, CodeInvalidRequest, fmt.Sprintf("class must be %q or %q", fleet.ClassAgent, fleet.ClassAdmin))
		return
	}
	if err := validateName(req.Name); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	if err := validateOwner(req.Owner); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	switch req.Class {
	case fleet.ClassAgent:
		if err := req.Scope.Validate(); err != nil {
			s.fail(w, r, CodeInvalidRequest, "scope: "+err.Error())
			return
		}
	case fleet.ClassAdmin:
		if req.Scope != nil {
			s.fail(w, r, CodeInvalidRequest,
				"an admin key carries no scope: its authority is the admin listener, not a scope document")
			return
		}
	case fleet.ClassEnrollment:
		// Unreachable: the maxTTL switch above already refused this class.
		// The case is not decoration -- `exhaustive` is enabled and this
		// switch has no default, so omitting it is a lint failure and, more
		// to the point, a fourth KeyClass would then be accepted silently.
	}
	expiresAt, err := resolveExpiry(req.TTL, req.NoExpiry, req.Class, maxTTL, s.clock())
	if err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}

	key, raw, err := s.mintKey(r.Context(), req.Class, req.Name, req.Owner, expiresAt, req.Scope, nil)
	if err != nil {
		s.failInternal(w, r, "mint key", err)
		return
	}
	s.security(r, EventKeyMinted,
		slog.String("kid", key.KID),
		slog.String("class", string(key.Class)),
		slog.String("name", key.Name),
		slog.String("expires_at", expiryLabel(key.ExpiresAt)))
	s.writeJSON(w, r, http.StatusCreated, mintedResponse(key, raw, s.clock()))
}

// handleListKeys lists stored credentials, optionally filtered by class.
func (s *server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	class := fleet.KeyClass(r.URL.Query().Get("class"))
	if class != "" && !class.Valid() {
		s.fail(w, r, CodeInvalidRequest, "class must be one of adm, agt, enr")
		return
	}
	keys, err := s.store.ListKeys(r.Context(), class)
	if err != nil {
		s.failInternal(w, r, "list keys", err)
		return
	}
	views := viewKeys(keys, s.clock())
	s.writeJSON(w, r, http.StatusOK, KeyListResponse{Keys: views, Count: len(views)})
}

// handleGetKey reads one credential record.
func (s *server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	kid, ok := s.pathKID(w, r)
	if !ok {
		return
	}
	key, ok := s.loadKey(w, r, kid, "")
	if !ok {
		return
	}
	s.writeJSON(w, r, http.StatusOK, viewKey(key, s.clock()))
}

// handleRevokeKey revokes, or with ?purge=true deletes, one credential.
func (s *server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	kid, ok := s.pathKID(w, r)
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	if err := validateReason(reason); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	purge, err := boolParam(r, "purge")
	if err != nil {
		s.fail(w, r, CodeInvalidRequest, "purge must be true or false")
		return
	}
	if _, ok := s.loadKey(w, r, kid, ""); !ok {
		return
	}

	if purge {
		// Deliberately separate from revocation and never the default:
		// deleting a record destroys the evidence that the credential ever
		// existed, which is exactly what an attacker with admin access wants.
		if err := s.store.DeleteKey(r.Context(), kid); err != nil {
			s.failInternal(w, r, "delete key", err)
			return
		}
		s.security(r, EventKeyDeleted, slog.String("kid", kid), slog.String("reason", reason))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.store.RevokeKey(r.Context(), kid, reason, s.clock()); err != nil {
		s.failInternal(w, r, "revoke key", err)
		return
	}
	s.security(r, EventKeyRevoked, slog.String("kid", kid), slog.String("reason", reason))
	w.WriteHeader(http.StatusNoContent)
}

// rotateRequest is the optional body of the rotate route.
type rotateRequest struct {
	// TTL overrides the replacement credential's lifetime. Empty reuses the
	// class default.
	TTL fleet.Duration `json:"ttl,omitempty"`
	// NoExpiry mints the replacement with no expiry. Agent keys only. It is
	// not inherited from the credential being replaced: rotating a key is the
	// moment to restate that choice, not to carry it forward silently.
	NoExpiry bool `json:"noExpiry,omitempty"`
	// Reason is recorded against the credential being replaced.
	Reason string `json:"reason,omitempty"`
}

// handleRotateKey mints a replacement credential with the same identity and
// scope, then revokes the original.
//
// The mint and the revocation commit as ONE store mutation (ReplaceKey), so a
// rotation can never half-happen: before this, a revoke failing after the mint
// succeeded left a live replacement credential whose raw token was already
// unrecoverable, because the token exists only in the response body.
func (s *server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	kid, ok := s.pathKID(w, r)
	if !ok {
		return
	}
	var req rotateRequest
	if !s.readOptionalBody(w, r, &req) {
		return
	}
	old, ok := s.loadKey(w, r, kid, "")
	if !ok {
		return
	}
	if old.Class == fleet.ClassEnrollment {
		s.fail(w, r, CodeInvalidRequest,
			"an enrollment token is single use and is not rotated: mint a new one")
		return
	}
	if old.Revoked() {
		// Rotating a revoked credential would mint it back into life under a
		// routine-looking audit event -- and a replayed rotation would strand
		// a second replacement whose raw token nobody ever saw. The recorded
		// reason names the replacement when this revocation was itself a
		// rotation. ReplaceKey enforces the same refusal atomically for the
		// race this check cannot see.
		s.fail(w, r, CodeConflict,
			fmt.Sprintf("key %s is revoked (%s) and cannot be rotated: mint a new key instead", old.KID, old.RevokedReason))
		return
	}
	maxTTL := s.agentKeyTTL
	if old.Class == fleet.ClassAdmin {
		maxTTL = s.adminKeyTTL
	}
	expiresAt, err := resolveExpiry(req.TTL, req.NoExpiry, old.Class, maxTTL, s.clock())
	if err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "rotated"
	}
	if err := validateReason(reason); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}

	fresh, raw, err := s.mintKeyWith(r.Context(), old.Class, old.Name, old.Owner, expiresAt, old.Scope, nil,
		func(ctx context.Context, k *fleet.Key) error {
			return s.store.ReplaceKey(ctx, k, old.KID, reason+" (replaced by "+k.KID+")", s.clock())
		})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrRevoked):
		// The race the pre-flight check above cannot see: the key was revoked
		// between loading it and committing the replacement. The same 409 as
		// the pre-flight, not a 500 -- the caller did nothing internal-error
		// about, and the recorded reason names any replacement.
		s.fail(w, r, CodeConflict,
			fmt.Sprintf("key %s was revoked while rotating: %s", old.KID, err.Error()))
		return
	case s.isNotFound(err):
		// Deleted in the same window. Gone is gone.
		s.fail(w, r, CodeNotFound, fmt.Sprintf("key %s no longer exists", old.KID))
		return
	default:
		s.failInternal(w, r, "rotate key", err)
		return
	}
	s.security(r, EventKeyRotated,
		slog.String("kid", fresh.KID),
		slog.String("replaces_kid", old.KID),
		slog.String("class", string(fresh.Class)),
		slog.String("reason", reason))
	s.writeJSON(w, r, http.StatusCreated, mintedResponse(fresh, raw, s.clock()))
}

// handleCreateEnrollment mints a single-use enrollment token bound to one
// cluster identity.
func (s *server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	var req CreateEnrollmentRequest
	if !s.readBody(w, r, &req) {
		return
	}
	// The cluster ID ends up in a certificate URI SAN, so it is validated at
	// the point an operator introduces it rather than at issuance time.
	if !ca.ValidClusterID(req.ClusterID) {
		s.fail(w, r, CodeInvalidRequest,
			`clusterId must match ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
		return
	}
	if err := validateLabels(req.Labels); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	name := req.Name
	if name == "" {
		name = "enroll:" + req.ClusterID
	}
	if err := validateName(name); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	if err := validateOwner(req.Owner); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	ttl, err := resolveTTL(req.TTL, s.enrollmentTTL)
	if err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}

	if req.MaxRedemptions < 0 {
		s.fail(w, r, CodeInvalidRequest, "maxRedemptions cannot be negative")
		return
	}
	if req.MaxRedemptions > 0 && !req.Reusable {
		// Silently ignoring the cap would leave an operator believing a
		// single-use token had a limit of their choosing.
		s.fail(w, r, CodeInvalidRequest,
			"maxRedemptions requires reusable: a single-use token is already capped at one")
		return
	}
	grant := &fleet.EnrollmentGrant{
		ClusterID:      req.ClusterID,
		Labels:         req.Labels,
		Reusable:       req.Reusable,
		MaxRedemptions: req.MaxRedemptions,
	}
	key, raw, err := s.mintKey(r.Context(), fleet.ClassEnrollment, name, req.Owner, s.clock().Add(ttl), nil, grant)
	if err != nil {
		s.failInternal(w, r, "mint enrollment", err)
		return
	}
	s.security(r, EventEnrollmentMinted,
		slog.String("kid", key.KID),
		slog.String("cluster", req.ClusterID),
		slog.String("ttl", ttl.String()))
	s.writeJSON(w, r, http.StatusCreated, mintedResponse(key, raw, s.clock()))
}

// handleListEnrollments lists enrollment tokens.
func (s *server) handleListEnrollments(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListKeys(r.Context(), fleet.ClassEnrollment)
	if err != nil {
		s.failInternal(w, r, "list enrollments", err)
		return
	}
	views := viewKeys(keys, s.clock())
	s.writeJSON(w, r, http.StatusOK, KeyListResponse{Keys: views, Count: len(views)})
}

// handleRevokeEnrollment revokes an enrollment token that has not been
// redeemed.
func (s *server) handleRevokeEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	kid, ok := s.pathKID(w, r)
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "enrollment window closed"
	}
	if err := validateReason(reason); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	key, ok := s.loadKey(w, r, kid, fleet.ClassEnrollment)
	if !ok {
		return
	}
	if err := s.store.RevokeKey(r.Context(), key.KID, reason, s.clock()); err != nil {
		s.failInternal(w, r, "revoke enrollment", err)
		return
	}
	cluster := ""
	if key.Enrollment != nil {
		cluster = key.Enrollment.ClusterID
	}
	s.security(r, EventKeyRevoked,
		slog.String("kid", key.KID),
		slog.String("class", string(fleet.ClassEnrollment)),
		slog.String("cluster", cluster),
		slog.String("reason", reason))
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeCert adds a certificate serial to the revocation list.
func (s *server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	serial := r.PathValue("serial")
	if !validSerial(serial) {
		s.fail(w, r, CodeInvalidRequest, "serial must be non-zero lowercase hexadecimal")
		return
	}
	var req RevokeCertRequest
	if !s.readOptionalBody(w, r, &req) {
		return
	}
	if err := validateReason(req.Reason); err != nil {
		s.fail(w, r, CodeInvalidRequest, err.Error())
		return
	}
	now := s.clock()
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = now.Add(s.spokeCertTTL)
	}
	// A notAfter already in the past is refused rather than recorded. The
	// tunnel's revocation cache drops entries past their notAfter as moot --
	// an expired certificate cannot complete a handshake anyway -- so an
	// operator who mistyped the year, or copied the expiry of the wrong
	// certificate, would get a 204 and a revocation that blocks nothing
	// while the certificate it was meant for connects on. Omitting the field
	// records the longest lifetime this hub can have issued, which is always
	// safe.
	if notAfter.Before(now) {
		s.fail(w, r, CodeInvalidRequest,
			"notAfter is in the past; omit it to cover the longest possible certificate lifetime, or supply the certificate's real expiry")
		return
	}
	if err := s.store.RevokeCert(r.Context(), RevokedCert{
		Serial:    serial,
		RevokedAt: now,
		NotAfter:  notAfter,
		Reason:    req.Reason,
	}); err != nil {
		s.failInternal(w, r, "revoke certificate", err)
		return
	}
	s.security(r, EventCertRevoked, slog.String("serial", serial), slog.String("reason", req.Reason))
	// After the store, never before: the list is the durable record, and a
	// session closed against a revocation that was not persisted would come
	// straight back on the spoke's next reconnect.
	s.closeRevokedSessions(r, serial)
	w.WriteHeader(http.StatusNoContent)
}

// closeRevokedSessions tears down any live tunnel the just-revoked certificate
// admitted on this replica, and records it.
//
// This is the half of revocation that the revocation list cannot do on its
// own. The list is consulted at the tunnel handshake, so without this a
// revoked spoke keeps serving the connection it already holds until its
// certificate expires -- which during a compromise is the whole of the window
// that matters.
//
// Only this replica's sessions are reachable from here: a session is pinned to
// the hub that accepted it and there is deliberately no hub-to-hub forwarding.
// The other replicas close theirs from [RevocationEnforcer], off the same
// revocation list.
func (s *server) closeRevokedSessions(r *http.Request, serial string) {
	if s.sessions == nil {
		return
	}
	closed := s.sessions.CloseRevoked(serial)
	if len(closed) == 0 {
		// Nothing was connected here. That is the common case -- the spoke may
		// be on another replica or already gone -- and it is not an event.
		return
	}
	s.security(r, EventSessionRevoked,
		slog.String("serial", serial),
		slog.Int("sessions", len(closed)),
		slog.String("clusters", strings.Join(uniqueSorted(closed), ",")))
}

// handleListRevokedCerts lists the revocation entries.
func (s *server) handleListRevokedCerts(w http.ResponseWriter, r *http.Request) {
	revoked, err := s.store.ListRevokedCerts(r.Context())
	if err != nil {
		s.failInternal(w, r, "list revoked certificates", err)
		return
	}
	if revoked == nil {
		revoked = []RevokedCert{}
	}
	s.writeJSON(w, r, http.StatusOK, RevokedCertListResponse{Revoked: revoked, Count: len(revoked)})
}

// handleCABundle returns the CA certificate for an authenticated operator. The
// same material is served unauthenticated at /pki/bundle on the public
// listener; this route exists so an admin tool needs only one base URL.
func (s *server) handleCABundle(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, CABundleResponse{
		CABundle:    string(s.ca.BundlePEM()),
		NotAfter:    s.ca.NotAfter(),
		TrustDomain: s.ca.TrustDomain(),
	})
}

// mintKey generates a credential, stores its record and returns the record
// together with the one and only copy of the raw token.
//
// The secret exists in this function and in the response body, and nowhere
// else: what reaches the store is HMAC-SHA256(pepper, secret).
func (s *server) mintKey(
	ctx context.Context,
	class fleet.KeyClass,
	name, owner string,
	expiresAt time.Time,
	scope *fleet.Scope,
	grant *fleet.EnrollmentGrant,
) (*fleet.Key, string, error) {
	return s.mintKeyWith(ctx, class, name, owner, expiresAt, scope, grant, s.store.PutKey)
}

// mintKeyWith is mintKey with the caller choosing how the record is committed,
// so a rotation can commit its mint and its revocation as one store mutation
// rather than two -- the gap between two was a real failure mode, in which the
// revocation failed after the mint succeeded and the caller received an error
// for a rotation that had half-happened.
func (s *server) mintKeyWith(
	ctx context.Context,
	class fleet.KeyClass,
	name, owner string,
	expiresAt time.Time,
	scope *fleet.Scope,
	grant *fleet.EnrollmentGrant,
	commit func(context.Context, *fleet.Key) error,
) (*fleet.Key, string, error) {
	// The zero expiresAt means the credential never expires, and only an
	// agent key is ever allowed that. resolveExpiry enforces this for every
	// route; asserting it here too makes the invariant structural, so a
	// future caller cannot mint an immortal admin credential by passing the
	// zero value directly.
	if expiresAt.IsZero() && class != fleet.ClassAgent {
		return nil, "", fmt.Errorf("a %s credential must carry an expiry", class)
	}
	now := s.clock()
	var lastErr error
	for attempt := range mintRetries {
		minted, err := token.Mint(class)
		if err != nil {
			return nil, "", fmt.Errorf("mint %s credential: %w", class, err)
		}
		key := &fleet.Key{
			KID:        minted.KID,
			Class:      class,
			Name:       name,
			Owner:      owner,
			SecretHMAC: s.hasher.Sum(minted.Secret),
			Scope:      scope,
			Enrollment: grant,
			CreatedAt:  now,
			ExpiresAt:  expiresAt,
		}
		if err := commit(ctx, key); err != nil {
			lastErr = err
			if s.isConflict(err) {
				// A key identifier collision. Retrying is correct; the
				// alternative would be overwriting an existing credential.
				s.log.LogAttrs(ctx, slog.LevelWarn, "key identifier collision, retrying",
					slog.Int("attempt", attempt+1))
				continue
			}
			return nil, "", fmt.Errorf("store %s credential: %w", class, err)
		}
		return key, minted.Raw.Reveal(), nil
	}
	return nil, "", fmt.Errorf("store %s credential after %d attempts: %w", class, mintRetries, lastErr)
}

// mintedResponse assembles the one-time token response.
func mintedResponse(key *fleet.Key, raw string, now time.Time) MintedKeyResponse {
	return MintedKeyResponse{
		Key:            viewKey(key, now),
		Token:          raw,
		TokenShownOnce: true,
		Warning:        TokenOnceNotice,
	}
}

// pathKID reads and validates the {kid} path segment.
func (s *server) pathKID(w http.ResponseWriter, r *http.Request) (string, bool) {
	kid := r.PathValue("kid")
	if !kidRE.MatchString(kid) {
		s.fail(w, r, CodeInvalidRequest, fmt.Sprintf("kid must be %d base62 characters", token.KIDLen))
		return "", false
	}
	return kid, true
}

// loadKey fetches a key and writes the appropriate error response when it is
// absent or of the wrong class. An empty want accepts any class.
func (s *server) loadKey(w http.ResponseWriter, r *http.Request, kid string, want fleet.KeyClass) (*fleet.Key, bool) {
	key, err := s.store.GetKey(r.Context(), kid)
	switch {
	case err != nil && s.isNotFound(err):
		s.fail(w, r, CodeNotFound, "no credential with that key id")
		return nil, false
	case err != nil:
		s.failInternal(w, r, "get key", err)
		return nil, false
	case key == nil:
		s.fail(w, r, CodeNotFound, "no credential with that key id")
		return nil, false
	case want != "" && key.Class != want:
		// Answering 404 rather than 400 keeps this route from confirming that
		// a key id exists in another class.
		s.fail(w, r, CodeNotFound, "no credential with that key id")
		return nil, false
	}
	return key, true
}

// readOptionalBody decodes a body that may legitimately be absent.
func (s *server) readOptionalBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return true
	}
	return s.readBody(w, r, dst)
}

// boolParam reads an optional boolean query parameter.
func boolParam(r *http.Request, name string) (bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return false, nil
	}
	return strconv.ParseBool(v)
}
