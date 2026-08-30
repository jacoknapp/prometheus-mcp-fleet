// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"time"
)

// RSA key sizes accepted in a spoke CSR.
//
// P-256 is the fleet standard and what the spoke generates. RSA is accepted
// only because some clusters mint their key inside an HSM or a KMS that has no
// EC support; 2048 is the floor because anything smaller is below the current
// public-key strength floor, and 8192 is the ceiling because verifying a
// signature from an arbitrarily large modulus is unbounded work handed to us
// by an unauthenticated-at-parse-time party. Ed25519 and non-P-256 curves are
// refused outright so the fleet has exactly one leaf profile to reason about.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// SpokeURI renders the canonical URI SAN for a cluster ID,
// "pmf://<trust-domain>/spoke/<clusterID>". It does not validate clusterID;
// callers that accept operator or spoke input must run ValidClusterID first.
func (c *CA) SpokeURI(clusterID string) *url.URL {
	return &url.URL{
		Scheme: uriScheme,
		Host:   c.opts.TrustDomain,
		Path:   "/spoke/" + clusterID,
	}
}

// IssueSpokeFromCSR validates a DER certificate signing request and issues a
// client certificate for clusterID.
//
// Everything the CSR asks for except the public key is discarded. The subject
// becomes "CN=spoke:<clusterID>", the only SAN is the URI from SpokeURI, the
// only extended key usage is clientAuth, and the key usage is
// digitalSignature. A CSR that asks for "CN=admin", a DNS SAN, or a URI SAN
// naming another cluster therefore receives a certificate that grants exactly
// the identity the hub already decided on when it issued the enrollment token.
//
// The CSR's self-signature is checked, which proves the requester holds the
// private key. This package does not remember which public keys it has already
// certified: single-use is enforced by the caller burning the enrollment token
// atomically, not here.
//
// The returned certificate never outlives the CA certificate; its NotAfter is
// clamped to the CA's.
func (c *CA) IssueSpokeFromCSR(csrDER []byte, clusterID string) (certPEM []byte, cert *x509.Certificate, err error) {
	if !ValidClusterID(clusterID) {
		return nil, nil, fmt.Errorf("%w: %q", ErrInvalidClusterID, clusterID)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse: %s", ErrCSRInvalid, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("%w: signature: %s", ErrCSRInvalid, err)
	}
	if err := checkCSRPublicKey(csr.PublicKey); err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "spoke:" + clusterID},
		URIs:                  []*url.URL{c.SpokeURI(clusterID)},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, leaf, err := c.sign(tmpl, csr.PublicKey, c.opts.SpokeCertTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("issue spoke %s: %w", clusterID, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der}), leaf, nil
}

// IssueServer issues the hub tunnel listener's server certificate with a
// freshly generated P-256 key, and returns it ready to hand to crypto/tls. At
// least one DNS name or IP address is required: a certificate with no SAN
// cannot be verified by any modern client.
//
// The private key exists only inside the returned tls.Certificate and is never
// written to disk by this package.
func (c *CA) IssueServer(dnsNames []string, ipAddrs []net.IP) (tls.Certificate, error) {
	if len(dnsNames) == 0 && len(ipAddrs) == 0 {
		return tls.Certificate{}, fmt.Errorf("%w: server certificate needs at least one dns name or ip", ErrInvalidOptions)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}
	cn := "prometheus-mcp-fleet hub"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, leaf, err := c.sign(tmpl, key.Public(), c.opts.ServerCertTTL)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue server certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// sign fills in the parts of tmpl that are never the caller's business
// (serial, validity window, issuer) and signs it.
func (c *CA) sign(tmpl *x509.Certificate, pub any, ttl time.Duration) ([]byte, *x509.Certificate, error) {
	now := c.now()
	if !now.Before(c.cert.NotAfter) {
		return nil, nil, fmt.Errorf("%w at %s", ErrCAExpired, c.cert.NotAfter.UTC().Format(time.RFC3339))
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(ttl)
	if notAfter.After(c.cert.NotAfter) {
		// A leaf that outlives its issuer is unverifiable for the remainder of
		// its nominal life, which is worse than a short one.
		notAfter = c.cert.NotAfter
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = notBefore
	tmpl.NotAfter = notAfter

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	return der, leaf, nil
}

// checkCSRPublicKey enforces the accepted key profile described on minRSABits.
func checkCSRPublicKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ecdsa curve %s, only P-256 is accepted", ErrCSRInvalid, k.Curve.Params().Name)
		}
		return nil
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < minRSABits || bits > maxRSABits {
			return fmt.Errorf("%w: rsa key is %d bits, accepted range is %d-%d", ErrCSRInvalid, bits, minRSABits, maxRSABits)
		}
		return nil
	default:
		return fmt.Errorf("%w: key type %T, want ecdsa P-256 or rsa", ErrCSRInvalid, pub)
	}
}
