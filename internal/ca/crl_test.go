// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestCRL(t *testing.T) {
	t.Parallel()
	clock := newFakeClock(testTime)
	c := mustCA(t, Options{Clock: clock.Now})
	explicitRevocation := testTime.Add(-2 * time.Hour).In(time.FixedZone("test", -6*60*60))

	der, err := c.CRL([]RevokedEntry{
		{Serial: "01"},
		{Serial: "deadBEEF", RevokedAt: explicitRevocation},
	}, time.Time{}, 6*time.Hour)
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
	if !crl.ThisUpdate.Equal(testTime) || !crl.NextUpdate.Equal(testTime.Add(6*time.Hour)) {
		t.Errorf("validity = %s..%s, want %s..%s", crl.ThisUpdate, crl.NextUpdate, testTime, testTime.Add(6*time.Hour))
	}
	if got, want := crl.Number.Int64(), testTime.UnixNano(); got != want {
		t.Errorf("CRL number = %d, want %d", got, want)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("entries = %d, want 2", len(crl.RevokedCertificateEntries))
	}
	if got := SerialHex(crl.RevokedCertificateEntries[0].SerialNumber); got != "1" {
		t.Errorf("first serial = %q, want 1", got)
	}
	if !crl.RevokedCertificateEntries[0].RevocationTime.Equal(testTime) {
		t.Errorf("default revocation time = %s, want %s", crl.RevokedCertificateEntries[0].RevocationTime, testTime)
	}
	if got := SerialHex(crl.RevokedCertificateEntries[1].SerialNumber); got != "deadbeef" {
		t.Errorf("second serial = %q, want deadbeef", got)
	}
	if !crl.RevokedCertificateEntries[1].RevocationTime.Equal(explicitRevocation) || crl.RevokedCertificateEntries[1].RevocationTime.Location() != time.UTC {
		t.Errorf("explicit revocation time = %s, want %s UTC", crl.RevokedCertificateEntries[1].RevocationTime, explicitRevocation)
	}
}

func TestCRLRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	c := mustCA(t, Options{})
	for _, validity := range []time.Duration{0, -time.Nanosecond} {
		if der, err := c.CRL(nil, testTime, validity); !errors.Is(err, ErrInvalidOptions) || der != nil {
			t.Errorf("CRL validity %s = (%x, %v), want nil ErrInvalidOptions", validity, der, err)
		}
	}
	for _, serial := range []string{"", "xyz", "0", "-1"} {
		if der, err := c.CRL([]RevokedEntry{{Serial: serial}}, testTime, time.Hour); !errors.Is(err, ErrInvalidOptions) || der != nil {
			t.Errorf("CRL serial %q = (%x, %v), want nil ErrInvalidOptions", serial, der, err)
		}
	}
}
