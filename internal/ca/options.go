// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
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
