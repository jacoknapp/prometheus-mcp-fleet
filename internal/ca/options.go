// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"regexp"
	"time"
)

// Default lifetimes. They are exported so the config layer can present them as
// flag defaults without duplicating the numbers.
const (
	// DefaultTrustDomain is the trust domain used when Options.TrustDomain is
	// empty. It matches the PMF_TRUST_DOMAIN default.
	DefaultTrustDomain = "fleet.local"
	// DefaultSpokeCertTTL is 14 days. Spoke certificates are deliberately
	// short-lived: renewal is cheap and a stolen key stops being useful fast.
	DefaultSpokeCertTTL = 14 * 24 * time.Hour
	// DefaultCATTL is 10 years. Rotating the root is a fleet-wide
	// re-enrollment, so it is set long enough that it is a planned event and
	// not an incident.
	DefaultCATTL = 10 * 365 * 24 * time.Hour
	// clockSkew is how far every certificate's NotBefore is backdated so that
	// a freshly issued certificate is usable on a peer whose clock is a little
	// behind the hub's.
	clockSkew = 5 * time.Minute
)

// clusterIDRE is the cluster ID grammar from the spec. It is applied to the
// value taken out of the URI SAN, never to anything a spoke self-reports.
var clusterIDRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// trustDomainRE constrains the trust domain to a lowercase DNS-shaped label
// set. Anything else would let a caller smuggle a path, a port or userinfo
// into the URI SAN authority and defeat the host comparison in
// CA.IdentityFromCert.
var trustDomainRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// ValidClusterID reports whether id matches the fleet-wide cluster ID grammar
// ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$.
func ValidClusterID(id string) bool { return clusterIDRE.MatchString(id) }

// Options configures a CA. The zero value is usable: every field falls back to
// the documented default.
type Options struct {
	// TrustDomain names the fleet and forms the authority of every spoke URI
	// SAN, "pmf://<TrustDomain>/spoke/<clusterID>". Defaults to
	// DefaultTrustDomain. Changing it invalidates every issued certificate.
	TrustDomain string
	// SpokeCertTTL is the lifetime of an issued spoke client certificate.
	// Defaults to DefaultSpokeCertTTL.
	SpokeCertTTL time.Duration
	// CATTL is the lifetime of a newly created root certificate. It is only
	// consulted by Create; loading an existing CA uses whatever is on disk.
	// Defaults to DefaultCATTL.
	CATTL time.Duration
	// Clock supplies the current time. It exists so tests can drive expiry
	// boundaries deterministically. Defaults to time.Now.
	Clock func() time.Time
	// AdditionalRootsPEM names roots that must be trusted alongside the active
	// signer, as one or more concatenated PEM CERTIFICATE blocks. Unset or
	// blank means the active signer is the only trust anchor, which is the
	// steady state; the field exists so that during a root rotation the
	// outgoing and incoming roots can both be accepted while the fleet
	// migrates. See docs/adr/0015-ca-rotation.md.
	//
	// It is additive on purpose. A field that replaced the trust bundle
	// outright could be set to a list that omits the active signer, and an
	// authority that does not trust its own signer issues certificates it will
	// then refuse -- silently, until the first spoke reconnects. Adding the
	// signer unconditionally makes that state unreachable.
	//
	// Order does not matter and repeats are ignored, so pointing this at a
	// bundle file that already contains the active signer is safe.
	AdditionalRootsPEM []byte
}

// withDefaults returns a copy of o with every unset field filled in.
func (o Options) withDefaults() Options {
	if o.TrustDomain == "" {
		o.TrustDomain = DefaultTrustDomain
	}
	if o.SpokeCertTTL == 0 {
		o.SpokeCertTTL = DefaultSpokeCertTTL
	}
	if o.CATTL == 0 {
		o.CATTL = DefaultCATTL
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return o
}

// additionalRoots parses [Options.AdditionalRootsPEM]. A blank value is not an
// error: it is the steady state in which the active signer is the only root.
// Anything else must parse into at least one certificate-signing CA, because a
// value that was set and yields no roots is a truncated file or the wrong
// ConfigMap key, never an intention.
func (o Options) additionalRoots() ([]*x509.Certificate, error) {
	if len(bytes.TrimSpace(o.AdditionalRootsPEM)) == 0 {
		return nil, nil
	}
	return ParseTrustBundlePEM(o.AdditionalRootsPEM)
}

// validate reports whether o, after defaulting, describes a usable CA.
func (o Options) validate() error {
	if !trustDomainRE.MatchString(o.TrustDomain) {
		return fmt.Errorf("%w: trust domain %q", ErrInvalidOptions, o.TrustDomain)
	}
	if o.SpokeCertTTL <= 0 {
		return fmt.Errorf("%w: spoke cert ttl %s", ErrInvalidOptions, o.SpokeCertTTL)
	}
	if o.CATTL <= 0 {
		return fmt.Errorf("%w: ca ttl %s", ErrInvalidOptions, o.CATTL)
	}
	return nil
}
