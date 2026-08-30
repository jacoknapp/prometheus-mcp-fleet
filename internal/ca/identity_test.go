// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

func TestIdentityFromIssuedCertificate(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	c := mustCA(t, Options{TrustDomain: "fleet.local", SpokeCertTTL: 14 * 24 * time.Hour, Clock: clock.Now})
	csrDER, _ := simpleCSR(t)
	_, cert, err := c.IssueSpokeFromCSR(csrDER, "prod-us-east-1")
	if err != nil {
		t.Fatalf("IssueSpokeFromCSR: %v", err)
	}

	got, err := c.IdentityFromCert(cert)
	if err != nil {
		t.Fatalf("IdentityFromCert: %v", err)
	}
	want := tunnel.Identity{
		ClusterID:    "prod-us-east-1",
		CertSerial:   SerialHex(cert.SerialNumber),
		CertNotAfter: cert.NotAfter,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Identity (-want +got):\n%s", diff)
	}
	if got.RemoteAddr != "" {
		t.Errorf("RemoteAddr = %q, want empty (the transport fills it in)", got.RemoteAddr)
	}
	if strings.ContainsAny(got.CertSerial, "ABCDEF:- ") {
		t.Errorf("CertSerial %q is not lowercase hex without separators", got.CertSerial)
	}
	if !got.CertNotAfter.Equal(testTime.Add(14 * 24 * time.Hour)) {
		t.Errorf("CertNotAfter = %s", got.CertNotAfter)
	}
}

func TestIdentityIgnoresCommonName(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{TrustDomain: "fleet.local"})
	// The CN claims one cluster, the SAN another. The SAN wins, always.
	cert := certWithURIs(t, []*url.URL{mustURL(t, "pmf://fleet.local/spoke/real")}, "spoke:impostor")
	got, err := c.IdentityFromCert(cert)
	if err != nil {
		t.Fatalf("IdentityFromCert: %v", err)
	}
	if got.ClusterID != "real" {
		t.Errorf("ClusterID = %q, want %q; the CN must never be consulted", got.ClusterID, "real")
	}

	// A certificate whose only claim is in the CN has no identity at all.
	cnOnly := certWithURIs(t, nil, "spoke:prod")
	if _, err := c.IdentityFromCert(cnOnly); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("CN-only certificate: got %v, want ErrNoIdentity", err)
	}
}

func TestIdentityFromCertMalformed(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{TrustDomain: "fleet.local"})

	tests := []struct {
		name    string
		uris    []string
		wantErr error
		alsoIs  error
	}{
		{
			name:    "no san at all",
			wantErr: ErrNoIdentity,
		},
		{
			name:    "two uri sans",
			uris:    []string{"pmf://fleet.local/spoke/a", "pmf://fleet.local/spoke/b"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "duplicate identical uri sans",
			uris:    []string{"pmf://fleet.local/spoke/a", "pmf://fleet.local/spoke/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "wrong scheme spiffe",
			uris:    []string{"spiffe://fleet.local/spoke/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "wrong scheme https",
			uris:    []string{"https://fleet.local/spoke/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "uppercase scheme is normalised by url parsing",
			uris:    []string{"PMF://fleet.local/spoke/a"},
			wantErr: nil,
		},
		{
			name:    "opaque uri",
			uris:    []string{"pmf:spoke/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "userinfo",
			uris:    []string{"pmf://admin@fleet.local/spoke/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "query string",
			uris:    []string{"pmf://fleet.local/spoke/a?as=admin"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "fragment",
			uris:    []string{"pmf://fleet.local/spoke/a#admin"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "wrong trust domain",
			uris:    []string{"pmf://other.local/spoke/a"},
			wantErr: ErrWrongTrustDomain,
		},
		{
			name:    "trust domain with port",
			uris:    []string{"pmf://fleet.local:8443/spoke/a"},
			wantErr: ErrWrongTrustDomain,
		},
		{
			name:    "trust domain as suffix",
			uris:    []string{"pmf://evil.fleet.local/spoke/a"},
			wantErr: ErrWrongTrustDomain,
		},
		{
			name:    "empty host",
			uris:    []string{"pmf:///spoke/a"},
			wantErr: ErrWrongTrustDomain,
		},
		{
			name:    "wrong path prefix",
			uris:    []string{"pmf://fleet.local/agent/a"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "root path",
			uris:    []string{"pmf://fleet.local/"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "no path",
			uris:    []string{"pmf://fleet.local"},
			wantErr: ErrNoIdentity,
		},
		{
			name:    "nested path",
			uris:    []string{"pmf://fleet.local/spoke/a/b"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "trailing slash",
			uris:    []string{"pmf://fleet.local/spoke/a/"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "empty cluster id",
			uris:    []string{"pmf://fleet.local/spoke/"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "uppercase cluster id",
			uris:    []string{"pmf://fleet.local/spoke/PROD"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "cluster id with dot",
			uris:    []string{"pmf://fleet.local/spoke/prod.eu"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "cluster id traversal",
			uris:    []string{"pmf://fleet.local/spoke/..%2fadmin"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "cluster id too long",
			uris:    []string{"pmf://fleet.local/spoke/" + strings.Repeat("a", 64)},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
		{
			name:    "cluster id trailing dash",
			uris:    []string{"pmf://fleet.local/spoke/prod-"},
			wantErr: ErrNoIdentity,
			alsoIs:  ErrInvalidClusterID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			uris := make([]*url.URL, 0, len(tc.uris))
			for _, raw := range tc.uris {
				uris = append(uris, mustURL(t, raw))
			}
			cert := certWithURIs(t, uris, "spoke:whatever")
			id, err := c.IdentityFromCert(cert)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("IdentityFromCert: unexpected error %v", err)
				}
				if id.ClusterID != "a" {
					t.Errorf("ClusterID = %q, want %q", id.ClusterID, "a")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("IdentityFromCert: got %v, want %v", err, tc.wantErr)
			}
			if tc.alsoIs != nil && !errors.Is(err, tc.alsoIs) {
				t.Errorf("IdentityFromCert: %v does not also match %v", err, tc.alsoIs)
			}
			if diff := cmp.Diff(tunnel.Identity{}, id); diff != "" {
				t.Errorf("identity returned alongside an error (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIdentityFromNilCert(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{})
	if _, err := c.IdentityFromCert(nil); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("got %v, want ErrNoIdentity", err)
	}
}

func TestIdentityRoundTripsEveryTrustDomain(t *testing.T) {
	t.Parallel()

	for _, td := range []string{"fleet.local", "f", "a-b.c-d.example.internal"} {
		t.Run(td, func(t *testing.T) {
			t.Parallel()
			c := mustCA(t, Options{TrustDomain: td})
			csrDER, _ := simpleCSR(t)
			_, cert, err := c.IssueSpokeFromCSR(csrDER, "prod")
			if err != nil {
				t.Fatalf("IssueSpokeFromCSR: %v", err)
			}
			id, err := c.IdentityFromCert(cert)
			if err != nil {
				t.Fatalf("IdentityFromCert: %v", err)
			}
			if id.ClusterID != "prod" {
				t.Errorf("ClusterID = %q", id.ClusterID)
			}
			// A CA for a different trust domain must reject the same cert.
			other := mustCA(t, Options{TrustDomain: "elsewhere.test"})
			if _, err := other.IdentityFromCert(cert); !errors.Is(err, ErrWrongTrustDomain) {
				t.Errorf("cross-domain: got %v, want ErrWrongTrustDomain", err)
			}
		})
	}
}
