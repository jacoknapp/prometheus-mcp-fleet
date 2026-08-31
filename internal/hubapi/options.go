// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// Defaults applied by the constructors when the corresponding [Options] field
// is zero.
const (
	// DefaultAgentKeyTTL matches the PMF_AGENT_KEY_TTL default of 30 days.
	DefaultAgentKeyTTL = 720 * time.Hour
	// DefaultAdminKeyTTL is 90 days. Admin credentials are the highest-value
	// secret the hub issues, so they expire sooner than an agent key would be
	// convenient.
	DefaultAdminKeyTTL = 90 * 24 * time.Hour
	// DefaultEnrollmentTTL matches the PMF_ENROLLMENT_TOKEN_TTL default. An
	// enrollment token is handed to an installer and redeemed within seconds;
	// a long window is a long exposure.
	DefaultEnrollmentTTL = 15 * time.Minute
	// DefaultSpokeCertTTL matches ca.DefaultSpokeCertTTL.
	DefaultSpokeCertTTL = ca.DefaultSpokeCertTTL
	// DefaultCRLValidity is how long a published CRL claims to be current.
	DefaultCRLValidity = 24 * time.Hour
	// MaxBodyBytes bounds every request body this package reads. Every
	// document it accepts -- a key request, a label map, a base64 CSR -- is a
	// few kilobytes at most, so the limit exists purely to keep an
	// unauthenticated caller from spending the hub's memory.
	MaxBodyBytes = 64 << 10
)

// RevokedCert is one entry of the hub's certificate revocation list.
//
// It is an alias for [store.RevokedCert] rather than a lookalike struct. The
// two were separate types once, and the result was that the real store did not
// satisfy [AdminStore] -- Go interface satisfaction is by type identity, not by
// shape -- so the composition root could not wire the two together without an
// adapter that existed only to rename a field set. Aliasing keeps the API's
// JSON shape stable while making the satisfaction real; see the compile-time
// assertion below.
//
// Serial is the certificate serial in lowercase hexadecimal, as
// [ca.SerialHex] renders it.
type RevokedCert = store.RevokedCert

// AdminStore is the persistence this package requires.
//
// It is deliberately wider than [authn.KeyStore]: the admin API mutates what
// the verifier only reads. It is declared here rather than imported so that
// the HTTP layer depends on eleven method signatures instead of on a
// particular backend, and so the tests can run the real mux against a map.
//
// Implementations must be safe for concurrent use. Every mutating method
// except TouchKey must bump the revocation epoch, which is what bounds how
// long internal/authn will keep serving a revoked credential from cache.
type AdminStore interface {
	// PutKey stores a new key. It returns an error satisfying
	// [Options.IsConflict] if the KID is already taken. There is no upsert.
	PutKey(ctx context.Context, k *fleet.Key) error
	// GetKey returns the key with the given KID, or an error satisfying
	// [Options.IsNotFound].
	GetKey(ctx context.Context, kid string) (*fleet.Key, error)
	// ListKeys returns the keys of the given class, or every key when class is
	// empty, in a stable order.
	ListKeys(ctx context.Context, class fleet.KeyClass) ([]*fleet.Key, error)
	// RevokeKey marks a key revoked. It is idempotent.
	RevokeKey(ctx context.Context, kid, reason string, at time.Time) error
	// DeleteKey removes a key entirely, destroying its audit trail.
	DeleteKey(ctx context.Context, kid string) error
	// BurnEnrollment atomically redeems a single-use enrollment token for the
	// certificate with the given serial. Exactly one concurrent caller wins;
	// the losers get an error satisfying [Options.IsConflict].
	BurnEnrollment(ctx context.Context, kid, certSerial string, at time.Time) (*fleet.Key, error)
	// RevokeCert adds or replaces a certificate revocation entry.
	RevokeCert(ctx context.Context, rc RevokedCert) error
	// ListRevokedCerts returns every revocation entry in a stable order.
	ListRevokedCerts(ctx context.Context) ([]RevokedCert, error)
	// Epoch returns the current monotonic revocation epoch.
	Epoch(ctx context.Context) (uint64, error)
}

// Compile-time proof that the production [store.Store] satisfies [AdminStore]
// and [authn.KeyStore]. The hub composition root passes one value to both, and
// a drift in either interface must break the build here rather than in the
// composition root at the end of a long refactor.
var (
	_ AdminStore     = (store.Store)(nil)
	_ authn.KeyStore = (store.Store)(nil)
)

// Metrics is the narrow counter surface this package needs. Implementations
// must be safe for concurrent use.
//
// Cardinality: result is one of the Result constants and event is one of the
// Event constants, both closed sets. A cluster identifier, a key identifier or
// a remote address must never be passed as a label value.
type Metrics interface {
	// Enrollment records the outcome of one /enroll or /renew attempt.
	Enrollment(result string)
	// SecurityEvent records one credential mint, revocation or burn.
	SecurityEvent(event string)
}

// NopMetrics is a [Metrics] that records nothing.
type NopMetrics struct{}

// Enrollment implements [Metrics] and does nothing.
func (NopMetrics) Enrollment(string) {}

// SecurityEvent implements [Metrics] and does nothing.
func (NopMetrics) SecurityEvent(string) {}

var _ Metrics = NopMetrics{}

// Options configures [NewAdminMux] and [NewPublicMux]. Store, Hasher, CA and
// Verifier are required; every other field has a documented default.
type Options struct {
	// Store is credential and revocation persistence. Required.
	Store AdminStore
	// Hasher turns a freshly minted secret into the digest that is stored.
	// Required.
	Hasher *token.Hasher
	// CA issues and revokes spoke certificates and publishes the trust
	// anchor. Required.
	CA *ca.CA
	// Verifier authenticates the admin and enrollment credentials. Required.
	Verifier *authn.Verifier
	// Logger receives request and security-event logs. Nil discards them.
	Logger *slog.Logger
	// Metrics counts enrollments and security events. Nil means [NopMetrics].
	Metrics Metrics
	// Clock supplies the current time. Nil means time.Now.
	Clock func() time.Time

	// AgentKeyTTL is both the default and the maximum lifetime of an agent
	// key. Zero means [DefaultAgentKeyTTL].
	AgentKeyTTL time.Duration
	// AdminKeyTTL is both the default and the maximum lifetime of an admin
	// key. Zero means [DefaultAdminKeyTTL].
	AdminKeyTTL time.Duration
	// EnrollmentTTL is both the default and the maximum lifetime of an
	// enrollment token. Zero means [DefaultEnrollmentTTL].
	EnrollmentTTL time.Duration
	// SpokeCertTTL is reported to a spoke as the lifetime it should expect.
	// The authoritative value is the CA's own configuration, which clamps the
	// certificate; this field exists so the admin API can describe it. Zero
	// means [DefaultSpokeCertTTL].
	SpokeCertTTL time.Duration
	// CRLValidity sets the published CRL's NextUpdate. Zero means
	// [DefaultCRLValidity].
	CRLValidity time.Duration
	// RenewGrace is how long after expiry a spoke certificate may still be
	// renewed, given proof the spoke still holds the matching private key.
	// Zero requires an unexpired certificate. See
	// [ca.CA.VerifyChainAllowingExpiry] for why this exists.
	RenewGrace time.Duration

	// EnrollmentEnabled gates /enroll. When false the route answers 503, which
	// lets an operator close the enrollment window for a fleet that is fully
	// provisioned without redeploying.
	EnrollmentEnabled bool
	// Draining reports whether the process is shutting down. While it returns
	// true every mutating route answers 503, so no credential is minted or
	// burned in a process that is about to exit. Nil means never draining.
	Draining func() bool

	// PublicURL is the canonical external MCP URL, published as the "resource"
	// field of the protected-resource document. Empty omits the field.
	PublicURL string

	// IsNotFound reports whether an [AdminStore] error means "no such record".
	// Nil matches this package's [ErrNotFound] and the production store's
	// [store.ErrNotFound], so the shipped backend needs no wiring and a
	// different one only has to supply this func.
	IsNotFound func(error) bool
	// IsConflict reports whether an [AdminStore] error means "this record is
	// already taken or already burned". It is what turns a losing
	// BurnEnrollment into a 409 and a security event rather than a 500, so a
	// wrong answer here downgrades a replayed enrollment token from a security
	// event to an internal error. Nil matches this package's
	// [ErrEnrollmentUsed] and [ErrAlreadyExists] and the production store's
	// [store.ErrEnrollmentUsed] and [store.ErrAlreadyExists].
	IsConflict func(error) bool
}

// server is the shared state behind both muxes.
type server struct {
	store    AdminStore
	hasher   *token.Hasher
	ca       *ca.CA
	verifier *authn.Verifier
	log      *slog.Logger
	metrics  Metrics
	clock    func() time.Time

	agentKeyTTL   time.Duration
	adminKeyTTL   time.Duration
	enrollmentTTL time.Duration
	spokeCertTTL  time.Duration
	crlValidity   time.Duration
	renewGrace    time.Duration

	enrollmentEnabled bool
	draining          func() bool
	publicURL         string

	isNotFound func(error) bool
	isConflict func(error) bool
}

// newServer validates opts and applies every default.
func newServer(opts Options) (*server, error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("hubapi: Options.Store is required")
	case opts.Hasher == nil:
		return nil, errors.New("hubapi: Options.Hasher is required")
	case opts.CA == nil:
		return nil, errors.New("hubapi: Options.CA is required")
	case opts.Verifier == nil:
		return nil, errors.New("hubapi: Options.Verifier is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Metrics == nil {
		opts.Metrics = NopMetrics{}
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.AgentKeyTTL <= 0 {
		opts.AgentKeyTTL = DefaultAgentKeyTTL
	}
	if opts.AdminKeyTTL <= 0 {
		opts.AdminKeyTTL = DefaultAdminKeyTTL
	}
	if opts.EnrollmentTTL <= 0 {
		opts.EnrollmentTTL = DefaultEnrollmentTTL
	}
	if opts.SpokeCertTTL <= 0 {
		opts.SpokeCertTTL = DefaultSpokeCertTTL
	}
	if opts.CRLValidity <= 0 {
		opts.CRLValidity = DefaultCRLValidity
	}
	if opts.Draining == nil {
		opts.Draining = func() bool { return false }
	}
	if opts.IsNotFound == nil {
		opts.IsNotFound = func(err error) bool {
			return errors.Is(err, ErrNotFound) || errors.Is(err, store.ErrNotFound)
		}
	}
	if opts.IsConflict == nil {
		// The store sentinels are matched as well as this package's own,
		// because a composition root that forgets to wire these turns a
		// replayed enrollment token -- a security event -- into a generic 500,
		// and a missing key into a 500 instead of a 404. Defaulting to the one
		// backend that exists is worth more than the purity of not naming it.
		opts.IsConflict = func(err error) bool {
			return errors.Is(err, ErrEnrollmentUsed) || errors.Is(err, ErrAlreadyExists) ||
				errors.Is(err, store.ErrEnrollmentUsed) || errors.Is(err, store.ErrAlreadyExists)
		}
	}
	return &server{
		store:             opts.Store,
		hasher:            opts.Hasher,
		ca:                opts.CA,
		verifier:          opts.Verifier,
		log:               opts.Logger,
		metrics:           opts.Metrics,
		clock:             opts.Clock,
		agentKeyTTL:       opts.AgentKeyTTL,
		adminKeyTTL:       opts.AdminKeyTTL,
		enrollmentTTL:     opts.EnrollmentTTL,
		spokeCertTTL:      opts.SpokeCertTTL,
		renewGrace:        opts.RenewGrace,
		crlValidity:       opts.CRLValidity,
		enrollmentEnabled: opts.EnrollmentEnabled,
		draining:          opts.Draining,
		publicURL:         opts.PublicURL,
		isNotFound:        opts.IsNotFound,
		isConflict:        opts.IsConflict,
	}, nil
}
