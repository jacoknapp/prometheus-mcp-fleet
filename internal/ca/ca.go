// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// serialBits is the entropy of every serial number this package mints. Serials
// are drawn from crypto/rand and are never sequential and never derived from a
// clock: a predictable serial lets an attacker who can influence issuance
// correlate or pre-compute certificates, and RFC 5280 requires uniqueness that
// a counter cannot guarantee across a restored backup.
const serialBits = 128

// pemTypeCertificate and pemTypePrivateKey are the PEM block types this
// package writes.
const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypePrivateKey  = "PRIVATE KEY"
	pemTypeECKeyLegacy = "EC PRIVATE KEY"
)

type durableFile interface {
	io.Writer
	Name() string
	Sync() error
	Chmod(fs.FileMode) error
	Close() error
}

type syncCloser interface {
	Sync() error
	Close() error
}

// These are the narrow process and filesystem boundaries whose failures must
// be handled safely. Tests replace one at a time to exercise error paths that
// otherwise depend on root privileges, filesystem type, or CSPRNG failure.
var (
	caGenerateKey       = ecdsa.GenerateKey
	caRandomInt         = rand.Int
	caCreateCertificate = x509.CreateCertificate
	caReadFile          = os.ReadFile
	caStat              = os.Stat
	caRemove            = os.Remove
	caCreateTemp        = func(dir, pattern string) (durableFile, error) { return os.CreateTemp(dir, pattern) }
	caLink              = os.Link
	caOpenDir           = func(path string) (syncCloser, error) { return os.Open(path) }
)

// CA is the hub's certificate authority. It is immutable after construction
// and safe for concurrent use. It deliberately has no String, GoString or
// MarshalJSON method: the private key must not be reachable through any
// formatting verb, panic trace or log field.
type CA struct {
	opts    Options
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// now returns the current time according to the configured clock.
func (c *CA) now() time.Time { return c.opts.Clock() }

// Timing of the creation-race retry. Generating a P-256 key and writing two
// small files takes on the order of a millisecond, so a few hundred
// milliseconds of patience is enough to let a racing process finish while
// still failing fast on a genuinely half-present CA.
const (
	initPollAttempts = 20
	initPollInterval = 10 * time.Millisecond
)

var loadOrCreateCreate = Create

// LoadOrCreate loads the CA at certPath and keyPath, creating a new one
// atomically if neither file exists.
//
// If exactly one of the two files exists it returns ErrCAIncomplete rather
// than regenerating: a half-present CA almost always means a partially
// restored backup or a bad mount, and quietly minting a fresh root there would
// orphan every enrolled spoke.
//
// Concurrent callers racing to initialise the same paths are safe. Exactly one
// wins the exclusive creation of the key file; the others observe the
// intermediate states and retry briefly before loading what the winner wrote,
// which is why a transient half-present state is re-checked rather than
// reported immediately.
func LoadOrCreate(certPath, keyPath string, opts Options) (*CA, error) {
	var lastIncomplete error
	for attempt := range initPollAttempts + 1 {
		if attempt > 0 {
			time.Sleep(initPollInterval)
		}
		certExists, err := regularFileExists(certPath)
		if err != nil {
			return nil, err
		}
		keyExists, err := regularFileExists(keyPath)
		if err != nil {
			return nil, err
		}
		switch {
		case certExists && keyExists:
			return Load(certPath, keyPath, opts)
		case certExists != keyExists:
			present, missing := certPath, keyPath
			if keyExists {
				present, missing = keyPath, certPath
			}
			lastIncomplete = fmt.Errorf("%w: %s present but %s missing", ErrCAIncomplete, present, missing)
			continue
		}
		c, err := loadOrCreateCreate(certPath, keyPath, opts)
		if errors.Is(err, ErrCAExists) {
			// Another process won the creation race. Its material is
			// authoritative; loop round and load it once both files land.
			continue
		}
		return c, err
	}
	if lastIncomplete != nil {
		return nil, lastIncomplete
	}
	return nil, fmt.Errorf("%w: concurrent initialisation of %s did not settle", ErrCAExists, certPath)
}

// Load loads an existing CA keypair. It never creates one.
//
// It refuses a key file that is group- or world-readable, a key that is not
// ECDSA P-256, a key that does not match the certificate, and a certificate
// that is not a CA with the certificate-signing key usage.
func Load(certPath, keyPath string, opts Options) (*CA, error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	certPEM, err := caReadFile(certPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCANotFound, certPath)
		}
		return nil, fmt.Errorf("read ca certificate %s: %w", certPath, err)
	}

	info, err := caStat(keyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCANotFound, keyPath)
		}
		return nil, fmt.Errorf("stat ca key %s: %w", keyPath, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrInsecureKeyMode, keyPath, mode)
	}
	keyPEM, err := caReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key %s: %w", keyPath, err)
	}

	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca certificate %s: %w", certPath, err)
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		// keyPEM is never included in the message: it is the key.
		return nil, fmt.Errorf("ca key %s: %w", keyPath, err)
	}
	if err := checkCAUsable(cert, key); err != nil {
		return nil, err
	}
	return newCA(opts, cert, key), nil
}

// Create writes a brand new self-signed CA to certPath and keyPath.
//
// It returns ErrCAExists if either path is already present. A CA is never
// overwritten: doing so would orphan every enrolled spoke, so the commit step
// uses link(2) rather than rename(2). Renaming would silently replace an
// existing name, and reserving the name up front with O_EXCL would publish a
// zero-length file that a concurrent reader could load. Linking a fully
// written temporary file into place is atomic and refuses to replace anything,
// which gives both properties at once.
//
// The key file is committed first. If the process dies between the two
// commits the surviving state is "key present, certificate absent", which
// LoadOrCreate reports as ErrCAIncomplete instead of silently regenerating.
func Create(certPath, keyPath string, opts Options) (*CA, error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	// Fast path: refuse before spending a key generation. This is advisory
	// only; the link below is the authoritative exclusion.
	for _, p := range []string{certPath, keyPath} {
		exists, err := regularFileExists(p)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: %s", ErrCAExists, p)
		}
	}

	key, err := caGenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := opts.Clock()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"prometheus-mcp-fleet"},
			CommonName:   "prometheus-mcp-fleet ca " + opts.TrustDomain,
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(opts.CATTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Path length 0: this root may sign leaves and nothing else. There is
		// no intermediate tier in this design and there must be no way to
		// grow one.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := caCreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca certificate: %w", err)
	}
	// x509.CreateCertificate's successful output and this supported key type
	// are valid by construction; neither standard-library conversion can fail.
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: keyDER})

	if err := linkFileExclusive(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := linkFileExclusive(certPath, certPEM, 0o644); err != nil {
		// Do not leave a key behind with no certificate.
		_ = caRemove(keyPath)
		return nil, err
	}
	return newCA(opts, cert, key), nil
}

// newCA assembles a CA from already-validated material.
func newCA(opts Options, cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		opts:    opts,
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: cert.Raw}),
	}
}

// Certificate returns the CA's own certificate. The returned value is shared;
// callers must treat it as read-only.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// BundlePEM returns the PEM encoding of the CA certificate, which is what a
// spoke is handed at enrollment so it can verify the hub's tunnel listener. It
// contains no private material. Each call returns a fresh copy.
func (c *CA) BundlePEM() []byte { return bytes.Clone(c.certPEM) }

// Pool returns a certificate pool trusting only this CA. A fresh pool is built
// on every call so that a caller adding roots to it cannot widen the trust of
// anything else.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// NotAfter returns the CA certificate's expiry. The hub reports itself not
// ready once this is less than 24h away.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// TrustDomain returns the trust domain this CA issues for.
func (c *CA) TrustDomain() string { return c.opts.TrustDomain }

// SerialHex renders a certificate serial number as lowercase hexadecimal with
// no separators and no leading zeroes. It is the canonical key for revocation
// lookups, and both issuance and verification go through it so the two sides
// can never disagree on spelling.
func SerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.TrimPrefix(n.Text(16), "-")
}

// newSerial draws a fresh 128-bit serial from crypto/rand. The draw is over
// [0, 2^128-1) and then incremented, so the result is always strictly
// positive as RFC 5280 requires, without a retry loop or a branch that can
// never be exercised.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), serialBits), big.NewInt(1))
	n, err := caRandomInt(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// parseCertificatePEM decodes the first PEM block and requires it to be a
// certificate.
func parseCertificatePEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidCA)
	}
	if blk.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: PEM block is %q, want %q", ErrInvalidCA, blk.Type, pemTypeCertificate)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCA, err)
	}
	return cert, nil
}

// parsePrivateKeyPEM decodes a PKCS#8 or SEC1 EC private key and requires it to
// be ECDSA on P-256. Error messages never carry key bytes.
func parsePrivateKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidCA)
	}
	var key *ecdsa.PrivateKey
	switch blk.Type {
	case pemTypePrivateKey:
		parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: pkcs#8 parse failed", ErrInvalidCA)
		}
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is %T, want ecdsa", ErrInvalidCA, parsed)
		}
		key = ec
	case pemTypeECKeyLegacy:
		ec, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: sec1 parse failed", ErrInvalidCA)
		}
		key = ec
	default:
		return nil, fmt.Errorf("%w: PEM block is %q", ErrInvalidCA, blk.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: curve is %s, want P-256", ErrInvalidCA, key.Curve.Params().Name)
	}
	return key, nil
}

// checkCAUsable verifies that cert really is a signing CA and that key is its
// private half.
func checkCAUsable(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if !cert.IsCA {
		return fmt.Errorf("%w: certificate is not a CA", ErrInvalidCA)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: certificate lacks the certSign key usage", ErrInvalidCA)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: certificate key is %T, want ecdsa", ErrInvalidCA, cert.PublicKey)
	}
	if !pub.Equal(key.Public()) {
		return fmt.Errorf("%w: private key does not match certificate", ErrInvalidCA)
	}
	return nil
}

// regularFileExists reports whether path names an existing file. A path that
// exists but is not a regular file is an error, because renaming over a
// directory or a device node is not something to paper over.
func regularFileExists(path string) (bool, error) {
	info, err := caStat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return true, nil
	case err == nil:
		return false, fmt.Errorf("%w: %s is not a regular file", ErrInvalidCA, path)
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}

// linkFileExclusive atomically creates path containing data, and fails with
// ErrCAExists if path already exists.
//
// The content goes to a 0600 temporary file in the same directory, is fsynced
// and chmodded, and is then hard-linked into place. link(2) is atomic and, in
// contrast to rename(2), refuses to replace an existing name, so no partially
// written or zero-length file is ever visible under the final name and an
// existing CA can never be clobbered. The directory is fsynced afterwards so
// the new name itself is durable.
func linkFileExclusive(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := caCreateTemp(dir, ".ca-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() { _ = caRemove(tmp) }()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := caLink(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrCAExists, path)
		}
		return fmt.Errorf("link %s to %s: %w", tmp, path, err)
	}
	d, err := caOpenDir(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
