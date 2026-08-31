// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
)

// Errors returned while establishing or loading the spoke's identity.
var (
	// ErrNoIdentity means no usable key and certificate were found and none
	// could be obtained.
	ErrNoIdentity = errors.New("spoke: no client identity available")
	// ErrEnrollmentRequired means the spoke must redeem an enrollment token
	// before it can connect.
	ErrEnrollmentRequired = errors.New("spoke: enrollment required")
)

// These are the narrow process and cryptographic boundaries whose failures the
// spoke must survive but cannot provoke: a CSPRNG that fails, a key the
// standard library declines to marshal, a signer that refuses. Tests replace
// one at a time, as [github.com/jacoknapp/prometheus-mcp-fleet/internal/ca]
// does for the same reason.
var (
	spokeGenerateKey = ecdsa.GenerateKey
	spokeCreateCSR   = x509.CreateCertificateRequest
	spokeInCluster   = kube.InCluster
)

// Keys in the identity Secret and in the file backend.
const (
	keyClientKey  = "tls.key"
	keyClientCert = "tls.crt"
	keyCABundle   = "ca.crt"
)

// Identity is the spoke's client key, its issued certificate, and the trust
// bundle for the hub.
type Identity struct {
	// Certificate is ready to hand to crypto/tls.
	Certificate tls.Certificate
	// Leaf is the parsed issued certificate.
	Leaf *x509.Certificate
	// CABundle is the PEM trust bundle the hub returned at enrollment.
	CABundle []byte
	// KeyPEM and CertPEM are the encoded forms, kept so the identity can be
	// written back to its store unchanged.
	KeyPEM, CertPEM []byte
}

// NeedsRenewal reports whether the certificate has passed the given fraction of
// its lifetime. Renewing at half life with jitter keeps 100 spokes from
// stampeding the hub in the same minute.
func (id *Identity) NeedsRenewal(now time.Time, fraction float64) bool {
	if id == nil || id.Leaf == nil {
		return true
	}
	total := id.Leaf.NotAfter.Sub(id.Leaf.NotBefore)
	if total <= 0 {
		return true
	}
	return now.After(id.Leaf.NotBefore.Add(time.Duration(float64(total) * fraction)))
}

// Expired reports whether the certificate is no longer valid.
func (id *Identity) Expired(now time.Time) bool {
	return id == nil || id.Leaf == nil || now.After(id.Leaf.NotAfter)
}

// identityStore persists the spoke's identity between restarts. Without one,
// every pod restart would need a fresh single-use enrollment token.
type identityStore interface {
	// Load returns ErrNoIdentity when nothing is stored yet.
	Load(ctx context.Context) (keyPEM, certPEM, caPEM []byte, err error)
	Save(ctx context.Context, keyPEM, certPEM, caPEM []byte) error
	// Describe names the backend for logs.
	Describe() string
}

// newIdentityStore resolves the configured backend. "auto" selects the Secret
// backend when a projected service account is present and the file backend
// otherwise, so the same binary works in a cluster and on a laptop.
func newIdentityStore(cfg *config.Spoke, logger *slog.Logger) (identityStore, error) {
	backend := cfg.IdentityBackend
	if backend == config.IdentityBackendAuto {
		if _, err := spokeInCluster(); err == nil {
			backend = config.IdentityBackendSecret
		} else {
			backend = config.IdentityBackendFile
		}
		logger.Info("resolved identity backend", "backend", backend)
	}

	switch backend {
	case config.IdentityBackendSecret:
		client, err := spokeInCluster()
		if err != nil {
			return nil, fmt.Errorf("identity backend %q: %w", backend, err)
		}
		return &secretIdentityStore{client: client, name: cfg.IdentitySecretName}, nil
	case config.IdentityBackendFile:
		return &fileIdentityStore{dir: cfg.DataDir}, nil
	case config.IdentityBackendMemory:
		// Nothing survives a restart, which is why this mode needs a
		// multi-use enrollment token. See docs/spoke-enrollment.md.
		return &memoryIdentityStore{}, nil
	default:
		return nil, fmt.Errorf("identity backend %q is not supported", backend)
	}
}

// secretIdentityStore keeps the identity in a Kubernetes Secret. It is the
// reason the spoke holds get/create/update on exactly one Secret by name.
type secretIdentityStore struct {
	client *kube.Client
	name   string
}

// Describe names the Secret the identity lives in.
func (s *secretIdentityStore) Describe() string {
	return fmt.Sprintf("secret %s/%s", s.client.Namespace(), s.name)
}

// Load reads the identity from the Secret, returning [ErrNoIdentity] when the
// Secret is absent or carries no key and certificate yet.
func (s *secretIdentityStore) Load(ctx context.Context) (key, cert, ca []byte, err error) {
	sec, err := s.client.GetSecret(ctx, s.name)
	if errors.Is(err, kube.ErrNotFound) {
		return nil, nil, nil, ErrNoIdentity
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read identity secret: %w", err)
	}
	key, cert, ca = sec.Data[keyClientKey], sec.Data[keyClientCert], sec.Data[keyCABundle]
	if len(key) == 0 || len(cert) == 0 {
		return nil, nil, nil, ErrNoIdentity
	}
	return key, cert, ca, nil
}

// Save writes the identity to the Secret, creating it if another replica has
// not already done so.
func (s *secretIdentityStore) Save(ctx context.Context, key, cert, ca []byte) error {
	data := map[string][]byte{keyClientKey: key, keyClientCert: cert, keyCABundle: ca}

	existing, err := s.client.GetSecret(ctx, s.name)
	switch {
	case errors.Is(err, kube.ErrNotFound):
		_, err = s.client.CreateSecret(ctx, &kube.Secret{Name: s.name, Data: data})
		// Another replica of this spoke may have created it in the gap. There
		// is only ever one spoke per cluster, but a rolling update briefly
		// overlaps, so treat the race as recoverable.
		if errors.Is(err, kube.ErrAlreadyExists) {
			return s.Save(ctx, key, cert, ca)
		}
		if err != nil {
			return fmt.Errorf("create identity secret: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("read identity secret: %w", err)
	}

	existing.Data = data
	if _, err := s.client.UpdateSecret(ctx, existing); err != nil {
		return fmt.Errorf("update identity secret: %w", err)
	}
	return nil
}

// fileIdentityStore keeps the identity on local disk, for development and for
// running outside Kubernetes.
type fileIdentityStore struct{ dir string }

// Describe names the directory the identity files live in.
func (f *fileIdentityStore) Describe() string { return "files in " + f.dir }

// Load reads the identity files, returning [ErrNoIdentity] when the key or the
// certificate is missing.
func (f *fileIdentityStore) Load(context.Context) (key, cert, ca []byte, err error) {
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(f.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return b, err
	}
	if key, err = read(keyClientKey); err != nil {
		return nil, nil, nil, err
	}
	if cert, err = read(keyClientCert); err != nil {
		return nil, nil, nil, err
	}
	if ca, err = read(keyCABundle); err != nil {
		return nil, nil, nil, err
	}
	if len(key) == 0 || len(cert) == 0 {
		return nil, nil, nil, ErrNoIdentity
	}
	return key, cert, ca, nil
}

// Save writes each file through a temporary name and renames it into place, so
// a crash mid-write cannot leave a half file that looks loadable.
func (f *fileIdentityStore) Save(_ context.Context, key, cert, ca []byte) error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	for name, data := range map[string][]byte{
		keyClientKey: key, keyClientCert: cert, keyCABundle: ca,
	} {
		if len(data) == 0 {
			continue
		}
		// Write and rename so a crash mid-write cannot leave a half file that
		// looks loadable.
		tmp := filepath.Join(f.dir, "."+name+".tmp")
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := os.Rename(tmp, filepath.Join(f.dir, name)); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}

// memoryIdentityStore discards the identity on exit. It exists for operators
// who will grant no RBAC at all.
type memoryIdentityStore struct{ key, cert, ca []byte }

// Describe reports that nothing is persisted.
func (m *memoryIdentityStore) Describe() string { return "memory (not persisted)" }

// Load returns the identity held in memory, or [ErrNoIdentity] before the first
// enrollment of this process.
func (m *memoryIdentityStore) Load(context.Context) (key, cert, ca []byte, err error) {
	if len(m.key) == 0 {
		return nil, nil, nil, ErrNoIdentity
	}
	return m.key, m.cert, m.ca, nil
}

// Save holds the identity for the lifetime of the process only.
func (m *memoryIdentityStore) Save(_ context.Context, key, cert, ca []byte) error {
	m.key, m.cert, m.ca = key, cert, ca
	return nil
}

// generateKey creates the spoke's private key. It is ECDSA P-256 to match what
// the hub's CA will sign, and it is generated here so that it never crosses the
// network: only a certificate signing request does.
func generateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := spokeGenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// buildCSR produces a certificate signing request for clusterID.
//
// The subject here is advisory only: the hub discards every requested subject
// and SAN and mints its own, which is what makes a CSR asking for CN=admin
// harmless. We fill it in anyway so the request is readable in a packet capture
// and in the hub's audit log.
func buildCSR(key *ecdsa.PrivateKey, clusterID string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkixName("spoke:" + clusterID),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := spokeCreateCSR(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return der, nil
}

// loadIdentity assembles an Identity from stored PEM material.
//
// It does not re-parse the leaf: crypto/tls parses it during X509KeyPair and
// stores it on the result, so a certificate that got past the line above is
// already a *x509.Certificate. There used to be a fallback that parsed it
// again when Leaf was nil, which no build of Go since 1.23 can reach.
func loadIdentity(keyPEM, certPEM, caPEM []byte) (*Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse stored identity: %w", err)
	}
	return &Identity{
		Certificate: cert,
		Leaf:        cert.Leaf,
		CABundle:    caPEM,
		KeyPEM:      keyPEM,
		CertPEM:     certPEM,
	}, nil
}
