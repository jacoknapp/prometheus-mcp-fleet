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
	"slices"
	"strings"
	"sync/atomic"
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
	opts Options
	// material is the signer and the trust bundle, published as one
	// immutable snapshot behind an atomic pointer.
	//
	// A CA used to be immutable outright, which is what made every method on
	// it safe for concurrent use without a lock. That property is kept, one
	// level down: a [caMaterial] is never mutated after it is published, every
	// method reads it exactly once, and a rotation swaps the whole snapshot in
	// a single store. What changes is that the *handle* now outlives the
	// material, so a rotation reaches everything holding a *CA without any of
	// them being rebuilt -- which is the difference between rotating the root
	// and restarting the process to rotate the root. See
	// [CA.AdoptPEM] and docs/adr/0015-ca-rotation.md.
	material atomic.Pointer[caMaterial]
}

// caMaterial is one immutable snapshot of what a CA signs with and what it
// trusts. Nothing here is written after [newMaterial] returns.
type caMaterial struct {
	// cert and key are the active signer: the one keypair that signs every
	// certificate this authority issues.
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// roots is the trust bundle: every root a presented certificate may chain
	// to, active signer first. During a rotation it holds the outgoing root as
	// well, which is the whole reason issuance and verification are separate
	// fields rather than one.
	roots     []*x509.Certificate
	bundlePEM []byte
}

// current returns the snapshot in force. Callers that need two fields to agree
// -- the signer certificate and the key that must match it, above all -- must
// call this once and read both from the result, never call it twice.
func (c *CA) current() *caMaterial { return c.material.Load() }

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

	cert, key, additional, err := parseMaterial(certPEM, keyPEM, opts)
	if err != nil {
		// Neither certPEM nor keyPEM is included in the message: one of them
		// is the private key. The paths are, because they are what the
		// operator has to go and look at.
		return nil, fmt.Errorf("ca at %s and %s: %w", certPath, keyPath, err)
	}
	return newCA(opts, cert, key, additional), nil
}

// Parse builds a CA from PEM material already in memory.
//
// It is [Load] without the filesystem: the same certificate, key and trust
// bundle checks, applied to bytes that came from somewhere other than a file.
// The hub's durable state is a Kubernetes Secret (ADR-0005), so a rotation
// reads and writes PEM and never wants a path; the key-file permission check
// [Load] performs has no meaning here and is the only thing missing.
func Parse(certPEM, keyPEM []byte, opts Options) (*CA, error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	cert, key, additional, err := parseMaterial(certPEM, keyPEM, opts)
	if err != nil {
		return nil, err
	}
	return newCA(opts, cert, key, additional), nil
}

// parseMaterial validates a signer keypair and the additional roots in opts.
func parseMaterial(certPEM, keyPEM []byte, opts Options) (*x509.Certificate, *ecdsa.PrivateKey, []*x509.Certificate, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ca certificate: %w", err)
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		// keyPEM is never included in the message: it is the key.
		return nil, nil, nil, fmt.Errorf("ca key: %w", err)
	}
	if err := checkCAUsable(cert, key); err != nil {
		return nil, nil, nil, err
	}
	additional, err := opts.additionalRoots()
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, additional, nil
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
	additional, err := opts.additionalRoots()
	if err != nil {
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

	cert, key, certPEM, keyPEM, err := mintRoot(opts)
	if err != nil {
		return nil, err
	}

	if err := linkFileExclusive(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := linkFileExclusive(certPath, certPEM, 0o644); err != nil {
		// Do not leave a key behind with no certificate.
		_ = caRemove(keyPath)
		return nil, err
	}
	return newCA(opts, cert, key, additional), nil
}

// mintRoot generates one self-signed root and returns it both parsed and PEM
// encoded. It touches no filesystem, which is what lets a rotation mint a
// successor straight into the Secret that is the only durable state this
// system has (ADR-0005).
func mintRoot(opts Options) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := caGenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, nil, nil, err
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
		return nil, nil, nil, nil, fmt.Errorf("self-sign ca certificate: %w", err)
	}
	// x509.CreateCertificate's successful output and this supported key type
	// are valid by construction; neither standard-library conversion can fail.
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return cert,
		key,
		pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: keyDER}),
		nil
}

// newCA assembles a CA from already-validated material.
//
// The active signer is always the first root in the trust bundle and can never
// be dropped from it, which is why the additional roots are additive rather
// than a replacement list: an authority that could be configured not to trust
// its own signer would issue certificates it then refuses, and would do so
// silently until the first spoke reconnected.
//
// Duplicates are dropped rather than rejected. Concatenating the outgoing and
// incoming roots into one bundle file and pointing both hub settings at it is
// the obvious way to run a rotation, and it necessarily names the active
// signer twice.
func newCA(opts Options, cert *x509.Certificate, key *ecdsa.PrivateKey, additional []*x509.Certificate) *CA {
	c := &CA{opts: opts}
	c.material.Store(newMaterial(cert, key, additional))
	return c
}

// newMaterial assembles one immutable snapshot. It is shared by construction
// and by [CA.AdoptPEM] so a rotated authority is assembled by exactly the same
// rules as a freshly loaded one.
func newMaterial(cert *x509.Certificate, key *ecdsa.PrivateKey, additional []*x509.Certificate) *caMaterial {
	roots := make([]*x509.Certificate, 0, 1+len(additional))
	var bundle bytes.Buffer
	appendRoot := func(root *x509.Certificate) {
		if slices.ContainsFunc(roots, func(have *x509.Certificate) bool { return bytes.Equal(have.Raw, root.Raw) }) {
			return
		}
		roots = append(roots, root)
		bundle.Write(pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: root.Raw}))
	}
	appendRoot(cert)
	for _, root := range additional {
		appendRoot(root)
	}
	return &caMaterial{cert: cert, key: key, roots: roots, bundlePEM: bundle.Bytes()}
}

// Certificate returns the active signer's certificate -- the issuer of every
// certificate this authority mints from now on, which during a rotation is not
// the only root it trusts. The returned value is shared; callers must treat it
// as read-only. Use [CA.TrustBundle] for what is trusted.
func (c *CA) Certificate() *x509.Certificate { return c.current().cert }

// BundlePEM returns the PEM trust bundle a spoke should be configured with:
// every root this authority accepts, active signer first, and no private
// material. Each call returns a fresh copy.
//
// During a rotation this is both roots, which is the point. A spoke holding
// this bundle keeps verifying the hub whichever root signed the certificate it
// is presented, so the fleet can be moved across without a flag day. The
// active signer comes first so that a consumer which reads only the first
// block still lands on the root that is issuing today.
func (c *CA) BundlePEM() []byte { return bytes.Clone(c.current().bundlePEM) }

// Pool returns a certificate pool trusting every root in this authority's
// trust bundle. A fresh pool is built on every call so that a caller adding
// roots to it cannot widen the trust of anything else.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	for _, root := range c.current().roots {
		p.AddCert(root)
	}
	return p
}

// NotAfter returns the active signer's expiry. The hub reports itself not
// ready once this is less than 24h away.
//
// It deliberately ignores the rest of the trust bundle. An outgoing root that
// is being retired may well expire first, and that is the plan, not an
// incident; what matters for readiness is the root that has to keep issuing.
func (c *CA) NotAfter() time.Time { return c.current().cert.NotAfter }

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

// parseCertificatePEM decodes exactly one PEM certificate block.
//
// More than one block is refused rather than ignored. The signer certificate
// file is the file an operator reaches for when told to "serve both roots", and
// before this check a concatenated old-and-new file loaded cleanly while
// everything after the first block was silently discarded -- the rotation would
// appear to have been performed and would have changed nothing. Additional
// roots belong in Options.AdditionalRootsPEM, and saying so loudly here is the
// only place that mistake can still be caught.
func parseCertificatePEM(b []byte) (*x509.Certificate, error) {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidCA)
	}
	if blk.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: PEM block is %q, want %q", ErrInvalidCA, blk.Type, pemTypeCertificate)
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, fmt.Errorf("%w: holds more than one PEM block; the active signer certificate is exactly one certificate and further trust anchors belong in the trust bundle", ErrInvalidCA)
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

// caSigningDefect describes why cert cannot serve as a trust anchor for this
// fleet, or returns "" if it can. It is shared by the active signer's checks
// and the trust bundle's so the two can never drift into disagreeing about
// what counts as a root.
func caSigningDefect(cert *x509.Certificate) string {
	switch {
	case !cert.IsCA:
		return "certificate is not a CA"
	case cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return "certificate lacks the certSign key usage"
	default:
		return ""
	}
}

// checkCAUsable verifies that cert really is a signing CA and that key is its
// private half.
func checkCAUsable(cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	if defect := caSigningDefect(cert); defect != "" {
		return fmt.Errorf("%w: %s", ErrInvalidCA, defect)
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
