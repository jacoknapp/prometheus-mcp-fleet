// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
)

// TestNeedsRenewalAtHalfLife pins the renewal point. Half life is not a round
// number chosen for tidiness: it leaves a full half-lifetime of failed retries
// before a spoke actually falls off the fleet.
func TestNeedsRenewalAtHalfLife(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	id := &Identity{Leaf: &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(14 * 24 * time.Hour),
	}}

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{name: "just issued", now: issued.Add(time.Minute), want: false},
		{name: "a minute before half life", now: issued.Add(7*24*time.Hour - time.Minute), want: false},
		{name: "exactly at half life", now: issued.Add(7 * 24 * time.Hour), want: false},
		{name: "a minute after half life", now: issued.Add(7*24*time.Hour + time.Minute), want: true},
		{name: "past expiry", now: issued.Add(20 * 24 * time.Hour), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := id.NeedsRenewal(tc.now, renewAtFraction); got != tc.want {
				t.Errorf("NeedsRenewal(%s) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}
}

// TestNeedsRenewalOnAnIdentityItCannotReasonAbout errs towards renewing.
//
// Every one of these means the spoke cannot work out when its certificate
// expires. Answering "no renewal needed" would mean sitting there until the
// certificate lapsed; answering "renew" costs one request.
func TestNeedsRenewalOnAnIdentityItCannotReasonAbout(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name string
		id   *Identity
	}{
		{name: "no identity at all", id: nil},
		{name: "an identity with no parsed certificate", id: &Identity{}},
		{
			name: "a certificate with no lifetime",
			id: &Identity{Leaf: &x509.Certificate{
				NotBefore: now, NotAfter: now,
			}},
		},
		{
			name: "a certificate whose dates are inverted",
			id: &Identity{Leaf: &x509.Certificate{
				NotBefore: now, NotAfter: now.Add(-time.Hour),
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.id.NeedsRenewal(now, renewAtFraction) {
				t.Error("NeedsRenewal = false; an unreadable lifetime must renew, not wait")
			}
		})
	}
}

// TestExpired pins the check establishIdentity uses to decide whether a stored
// certificate is worth loading at all.
func TestExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		id   *Identity
		want bool
	}{
		{name: "no identity", id: nil, want: true},
		{name: "no parsed certificate", id: &Identity{}, want: true},
		{
			name: "still valid",
			id:   &Identity{Leaf: &x509.Certificate{NotAfter: now.Add(time.Second)}},
			want: false,
		},
		{
			name: "exactly at notAfter is not yet expired",
			id:   &Identity{Leaf: &x509.Certificate{NotAfter: now}},
			want: false,
		},
		{
			name: "a second past notAfter",
			id:   &Identity{Leaf: &x509.Certificate{NotAfter: now.Add(-time.Second)}},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.id.Expired(now); got != tc.want {
				t.Errorf("Expired(%s) = %v, want %v", now, got, tc.want)
			}
		})
	}
}

// TestNewIdentityStoreResolvesTheBackend covers every posture in
// docs/spoke-enrollment.md, including "auto", which is what makes one binary
// work both in a cluster and on a laptop.
//
// It is not parallel: it replaces the in-cluster detector, which is a package
// boundary rather than a parameter, following internal/ca.
func TestNewIdentityStoreResolvesTheBackend(t *testing.T) {
	original := spokeInCluster
	t.Cleanup(func() { spokeInCluster = original })

	_, client := newFakeAPIServer(t)
	inCluster := func() (*kube.Client, error) { return client, nil }
	notInCluster := func() (*kube.Client, error) {
		return nil, errors.New("kube: no projected service account: " + kube.ErrNotInCluster.Error())
	}

	tests := []struct {
		name      string
		backend   string
		detector  func() (*kube.Client, error)
		wantDescr string
		wantErr   string
	}{
		{
			name: "auto in a cluster picks the Secret", backend: config.IdentityBackendAuto,
			detector: inCluster, wantDescr: "secret " + testNamespace + "/pmf-spoke-identity",
		},
		{
			name: "auto on a laptop falls back to files", backend: config.IdentityBackendAuto,
			detector: notInCluster, wantDescr: "files in /var/lib/pmf",
		},
		{
			name: "an explicit Secret backend", backend: config.IdentityBackendSecret,
			detector: inCluster, wantDescr: "secret " + testNamespace + "/pmf-spoke-identity",
		},
		{
			// This is the misconfiguration an operator hits by setting the
			// backend explicitly and then running outside a cluster, and it
			// must fail loudly rather than silently downgrading to files.
			name: "an explicit Secret backend outside a cluster", backend: config.IdentityBackendSecret,
			detector: notInCluster, wantErr: `identity backend "secret"`,
		},
		{
			name: "files", backend: config.IdentityBackendFile,
			detector: notInCluster, wantDescr: "files in /var/lib/pmf",
		},
		{
			name: "memory", backend: config.IdentityBackendMemory,
			detector: notInCluster, wantDescr: "memory (not persisted)",
		},
		{
			name: "anything else", backend: "vault",
			detector: notInCluster, wantErr: `identity backend "vault" is not supported`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spokeInCluster = tc.detector
			store, err := newIdentityStore(&config.Spoke{
				IdentityBackend:    tc.backend,
				IdentitySecretName: "pmf-spoke-identity",
				DataDir:            "/var/lib/pmf",
			}, quiet())

			if tc.wantErr != "" {
				errContains(t, err, tc.wantErr)
				if store != nil {
					t.Error("a failed backend resolution still returned a store")
				}
				return
			}
			if err != nil {
				t.Fatalf("newIdentityStore: %v", err)
			}
			if got := store.Describe(); got != tc.wantDescr {
				t.Errorf("Describe() = %q, want %q", got, tc.wantDescr)
			}
		})
	}
}

// TestSecretStoreRoundTrip drives the Secret backend against a real
// kube.Client and a real API server: create on first write, compare-and-swap
// update on the second, and read back what a restart would see.
func TestSecretStoreRoundTrip(t *testing.T) {
	t.Parallel()

	api, client := newFakeAPIServer(t)
	store := &secretIdentityStore{client: client, name: "pmf-spoke-identity"}

	if _, _, _, err := store.Load(t.Context()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Load before enrollment = %v, want ErrNoIdentity", err)
	}
	if err := store.Save(t.Context(), []byte("key-1"), []byte("cert-1"), []byte("ca-1")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(t.Context(), []byte("key-2"), []byte("cert-2"), []byte("ca-2")); err != nil {
		t.Fatalf("Save again: %v", err)
	}

	key, cert, ca, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(key) != "key-2" || string(cert) != "cert-2" || string(ca) != "ca-2" {
		t.Errorf("Load = (%s, %s, %s), want the second write", key, cert, ca)
	}
	creates, updates := api.counts()
	if creates != 1 || updates != 1 {
		t.Errorf("creates=%d updates=%d, want one of each: the second Save must "+
			"update the existing Secret, not recreate it", creates, updates)
	}
}

// TestSecretStoreTreatsAHalfWrittenSecretAsNoIdentity covers the Secret that
// exists but carries no usable material — a hand-created placeholder, or a
// write that lost the key. Loading it would produce a confusing TLS error
// later; treating it as "not enrolled yet" produces a new certificate.
func TestSecretStoreTreatsAHalfWrittenSecretAsNoIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data map[string][]byte
	}{
		{name: "empty", data: map[string][]byte{}},
		{name: "certificate but no key", data: map[string][]byte{keyClientCert: []byte("c")}},
		{name: "key but no certificate", data: map[string][]byte{keyClientKey: []byte("k")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			api, client := newFakeAPIServer(t)
			api.seed("pmf-spoke-identity", tc.data)
			store := &secretIdentityStore{client: client, name: "pmf-spoke-identity"}

			if _, _, _, err := store.Load(t.Context()); !errors.Is(err, ErrNoIdentity) {
				t.Errorf("Load = %v, want ErrNoIdentity", err)
			}
		})
	}
}

// TestSecretStoreRetriesTheCreateRace pins the rolling-update overlap: two
// processes both see no Secret, both create, one loses. The loser must re-read
// and update rather than fail, or a rollout leaves a spoke with an identity it
// never persisted.
func TestSecretStoreRetriesTheCreateRace(t *testing.T) {
	t.Parallel()

	api, client := newFakeAPIServer(t)
	store := &secretIdentityStore{client: client, name: "pmf-spoke-identity"}
	// The create is refused exactly once, as though another replica won it,
	// and the object it "created" is already there to be read back.
	api.seed("pmf-spoke-identity", map[string][]byte{keyClientKey: []byte("theirs")})
	api.failCreate = &apiFailure{status: http.StatusConflict, reason: "AlreadyExists", once: true}
	api.failGet = &apiFailure{status: http.StatusNotFound, reason: "NotFound", once: true}

	if err := store.Save(t.Context(), []byte("mine"), []byte("cert"), []byte("ca")); err != nil {
		t.Fatalf("Save through the create race: %v", err)
	}
	if got := string(api.stored("pmf-spoke-identity")[keyClientKey]); got != "mine" {
		t.Errorf("stored key = %q, want the retry to have written through", got)
	}
	if creates, updates := api.counts(); creates != 1 || updates != 1 {
		t.Errorf("creates=%d updates=%d, want the losing create to become an update", creates, updates)
	}
}

// TestSecretStoreSurfacesAPIFailures. Every one of these is an RBAC or
// connectivity problem an operator has to fix, so none of them may be
// swallowed into "no identity" and silently re-enrolled.
func TestSecretStoreSurfacesAPIFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arrange func(*fakeAPIServer)
		load    bool
		wantIs  error
		wantMsg string
	}{
		{
			name:    "a forbidden read",
			arrange: func(f *fakeAPIServer) { f.failGet = &apiFailure{status: http.StatusForbidden, reason: "Forbidden"} },
			load:    true, wantIs: kube.ErrForbidden, wantMsg: "read identity secret",
		},
		{
			name:    "a forbidden read while saving",
			arrange: func(f *fakeAPIServer) { f.failGet = &apiFailure{status: http.StatusForbidden, reason: "Forbidden"} },
			wantIs:  kube.ErrForbidden, wantMsg: "read identity secret",
		},
		{
			name: "a refused create",
			arrange: func(f *fakeAPIServer) {
				f.failCreate = &apiFailure{status: http.StatusForbidden, reason: "Forbidden"}
			},
			wantIs: kube.ErrForbidden, wantMsg: "create identity secret",
		},
		{
			name: "a refused update",
			arrange: func(f *fakeAPIServer) {
				f.seed("pmf-spoke-identity", map[string][]byte{keyClientKey: []byte("k")})
				f.failUpdate = &apiFailure{status: http.StatusForbidden, reason: "Forbidden"}
			},
			wantIs: kube.ErrForbidden, wantMsg: "update identity secret",
		},
		{
			name: "a lost compare-and-swap",
			arrange: func(f *fakeAPIServer) {
				f.seed("pmf-spoke-identity", map[string][]byte{keyClientKey: []byte("k")})
				f.failUpdate = &apiFailure{status: http.StatusConflict, reason: "Conflict"}
			},
			wantIs: kube.ErrConflict, wantMsg: "update identity secret",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			api, client := newFakeAPIServer(t)
			tc.arrange(api)
			store := &secretIdentityStore{client: client, name: "pmf-spoke-identity"}

			var err error
			if tc.load {
				_, _, _, err = store.Load(t.Context())
			} else {
				err = store.Save(t.Context(), []byte("k"), []byte("c"), []byte("a"))
			}
			if errors.Is(err, ErrNoIdentity) {
				t.Fatalf("%v was reported as ErrNoIdentity, which would re-enroll over a "+
					"cluster problem and burn a token doing it", err)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("error = %v, want it to wrap %v", err, tc.wantIs)
			}
			errContains(t, err, tc.wantMsg)
		})
	}
}

// TestFileStoreRoundTrip is the development and outside-Kubernetes posture.
func TestFileStoreRoundTrip(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "nested", "data")
	store := &fileIdentityStore{dir: dir}

	if got := store.Describe(); got != "files in "+dir {
		t.Errorf("Describe() = %q", got)
	}
	if _, _, _, err := store.Load(t.Context()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Load on an empty directory = %v, want ErrNoIdentity", err)
	}
	if err := store.Save(t.Context(), []byte("key"), []byte("cert"), []byte("ca")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	key, cert, ca, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(key) != "key" || string(cert) != "cert" || string(ca) != "ca" {
		t.Errorf("Load = (%s, %s, %s), want what was saved", key, cert, ca)
	}
	// Nothing may be left behind: a leftover .tls.key.tmp is a private key on
	// disk under a name nothing cleans up.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("Save left %s behind", e.Name())
		}
	}
}

// TestFileStoreSaveSkipsEmptyMaterial. A hub that returned no CA bundle must
// not cause an empty ca.crt to overwrite a good one.
func TestFileStoreSaveSkipsEmptyMaterial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := &fileIdentityStore{dir: dir}
	if err := store.Save(t.Context(), []byte("key"), []byte("cert"), []byte("good-ca")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(t.Context(), []byte("key2"), []byte("cert2"), nil); err != nil {
		t.Fatalf("Save without a CA bundle: %v", err)
	}
	_, _, ca, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(ca) != "good-ca" {
		t.Errorf("ca.crt = %q, want the previous bundle left intact", ca)
	}
}

// TestFileStoreSurfacesFilesystemFailures. A read that fails for a reason
// other than "not there" is not "not enrolled": re-enrolling would burn a
// single-use token over a mount problem.
func TestFileStoreSurfacesFilesystemFailures(t *testing.T) {
	t.Parallel()

	t.Run("loading", func(t *testing.T) {
		t.Parallel()
		for _, unreadable := range []string{keyClientKey, keyClientCert, keyCABundle} {
			t.Run(unreadable, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				// Everything before the unreadable entry has to be present, or
				// Load stops early for a different reason.
				for _, name := range []string{keyClientKey, keyClientCert, keyCABundle} {
					if name == unreadable {
						mkdir(t, dir, name)
						break
					}
					writeFile(t, dir, name, "material")
				}
				_, _, _, err := (&fileIdentityStore{dir: dir}).Load(t.Context())
				if errors.Is(err, ErrNoIdentity) || err == nil {
					t.Fatalf("Load = %v, want the filesystem error surfaced", err)
				}
				errContains(t, err, "is a directory")
			})
		}
	})

	t.Run("creating the data directory", func(t *testing.T) {
		t.Parallel()
		base := t.TempDir()
		writeFile(t, base, "blocked", "not a directory")
		store := &fileIdentityStore{dir: filepath.Join(base, "blocked", "data")}
		errContains(t, store.Save(t.Context(), []byte("k"), []byte("c"), []byte("a")), "create data dir")
	})

	t.Run("writing the temporary file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		for _, name := range []string{keyClientKey, keyClientCert, keyCABundle} {
			mkdir(t, dir, "."+name+".tmp")
		}
		store := &fileIdentityStore{dir: dir}
		errContains(t, store.Save(t.Context(), []byte("k"), []byte("c"), []byte("a")), "write ")
	})

	t.Run("committing the rename", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		// A non-empty directory under the final name: the temporary write
		// succeeds and only the rename fails, which is the half-written case
		// the rename exists to prevent.
		for _, name := range []string{keyClientKey, keyClientCert, keyCABundle} {
			occupied := mkdir(t, dir, name)
			writeFile(t, occupied, "occupant", "x")
		}
		store := &fileIdentityStore{dir: dir}
		errContains(t, store.Save(t.Context(), []byte("k"), []byte("c"), []byte("a")), "commit ")
	})
}

// TestMemoryStoreLosesTheIdentityOnRestart pins the documented trade-off of
// the "no RBAC at all" posture: the identity survives the process and nothing
// more, which is why that mode needs a multi-use enrollment token.
func TestMemoryStoreLosesTheIdentityOnRestart(t *testing.T) {
	t.Parallel()

	store := &memoryIdentityStore{}
	if got := store.Describe(); got != "memory (not persisted)" {
		t.Errorf("Describe() = %q, want it to say nothing is persisted", got)
	}
	if _, _, _, err := store.Load(t.Context()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Load before enrollment = %v, want ErrNoIdentity", err)
	}
	if err := store.Save(t.Context(), []byte("key"), []byte("cert"), []byte("ca")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	key, cert, ca, err := store.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(key) != "key" || string(cert) != "cert" || string(ca) != "ca" {
		t.Errorf("Load = (%s, %s, %s), want what was saved", key, cert, ca)
	}

	// The restart. A new process gets a new store, and the previous identity
	// is gone: this is the cost documented in docs/spoke-enrollment.md, not a
	// bug to be fixed by caching it somewhere.
	restarted := &memoryIdentityStore{}
	if _, _, _, err := restarted.Load(t.Context()); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("a restarted memory store returned %v, want ErrNoIdentity: if this "+
			"ever persists, the documented reason for needing a multi-use token is gone", err)
	}
}

// TestGenerateKeyProducesAP256KeyThatNeverLeaves checks the shape the hub's CA
// will sign, and that the PEM is a PKCS#8 private key rather than anything
// else that happens to parse.
func TestGenerateKeyProducesAP256Key(t *testing.T) {
	t.Parallel()

	key, keyPEM, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256: the hub's CA signs P-256", key.Curve)
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("key PEM starts %q, want a PKCS#8 block", string(keyPEM[:32]))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pemBlock(t, keyPEM))
	if err != nil {
		t.Fatalf("the encoded key does not parse back: %v", err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(key) {
		t.Error("the encoded key is not the key that was generated")
	}

	other, _, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if other.Equal(key) {
		t.Error("two calls produced the same key")
	}
}

// unusableCurve is an elliptic.Curve the standard library has no object
// identifier for, so a key on it cannot be marshalled. The embedded interface
// is nil and is never called: MarshalPKCS8PrivateKey rejects the curve before
// it asks it anything.
type unusableCurve struct{ elliptic.Curve }

// TestGenerateKeyFailures covers the two ways key generation can fail. Neither
// is reachable from a healthy process — that is the point of handling them:
// enrollment must report a CSPRNG or encoding failure, not proceed with a key
// it does not have.
func TestGenerateKeyFailures(t *testing.T) {
	original := spokeGenerateKey
	t.Cleanup(func() { spokeGenerateKey = original })

	boom := errors.New("the CSPRNG failed")
	t.Run("the CSPRNG fails", func(t *testing.T) {
		spokeGenerateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, boom }
		_, _, err := generateKey()
		if !errors.Is(err, boom) {
			t.Fatalf("generateKey = %v, want it to wrap the CSPRNG failure", err)
		}
		errContains(t, err, "generate key")
	})

	t.Run("the key cannot be encoded", func(t *testing.T) {
		spokeGenerateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) {
			return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: unusableCurve{}}}, nil
		}
		_, _, err := generateKey()
		errContains(t, err, "marshal key")
	})
}

// TestBuildCSRAsksForNothingThatMatters. The subject is decoration: the hub
// discards every requested subject and SAN and mints its own, which is what
// makes a CSR asking for CN=admin harmless. We still fill it in so the request
// is readable in a packet capture and in the hub's audit log.
func TestBuildCSRAsksForNothingThatMatters(t *testing.T) {
	t.Parallel()

	key, _, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	der, err := buildCSR(key, "prod-eu-1")
	if err != nil {
		t.Fatalf("buildCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("the CSR does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the CSR is not self-signed by the key: %v", err)
	}
	if csr.Subject.CommonName != "spoke:prod-eu-1" {
		t.Errorf("subject CN = %q, want spoke:prod-eu-1", csr.Subject.CommonName)
	}
	if len(csr.URIs) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 {
		t.Errorf("the CSR requests SANs (%v, %v, %v); it must ask for nothing the "+
			"hub could be tempted to honour", csr.URIs, csr.DNSNames, csr.IPAddresses)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Error("the CSR does not carry the generated public key")
	}
}

// TestBuildCSRFailure covers the signing failure. It cannot happen with a key
// this package generated, which is exactly why the error is returned rather
// than ignored.
func TestBuildCSRFailure(t *testing.T) {
	original := spokeCreateCSR
	t.Cleanup(func() { spokeCreateCSR = original })

	boom := errors.New("the signer refused")
	spokeCreateCSR = func(io.Reader, *x509.CertificateRequest, any) ([]byte, error) { return nil, boom }

	key, _, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	if _, err := buildCSR(key, "prod-eu-1"); !errors.Is(err, boom) {
		t.Fatalf("buildCSR = %v, want it to wrap the signing failure", err)
	}
}

// TestLoadIdentity assembles what a store handed back, and refuses material
// that is not a matching key and certificate.
func TestLoadIdentity(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	key, keyPEM, err := generateKey()
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}
	certPEM := ca.issue(t, "prod-eu-1", key.Public())

	t.Run("a stored identity", func(t *testing.T) {
		t.Parallel()
		id, err := loadIdentity(keyPEM, certPEM, ca.pem)
		if err != nil {
			t.Fatalf("loadIdentity: %v", err)
		}
		if id.Leaf == nil {
			t.Fatal("the leaf certificate was not populated, so nothing can read the expiry")
		}
		if got := clusterIDFromCert(id.Leaf); got != "prod-eu-1" {
			t.Errorf("cluster from the leaf = %q, want prod-eu-1", got)
		}
		if string(id.KeyPEM) != string(keyPEM) || string(id.CertPEM) != string(certPEM) {
			t.Error("the encoded forms were not kept, so the identity cannot be written back unchanged")
		}
		if string(id.CABundle) != string(ca.pem) {
			t.Error("the trust bundle was not kept")
		}
	})

	t.Run("unusable material", func(t *testing.T) {
		t.Parallel()
		_, otherKeyPEM, err := generateKey()
		if err != nil {
			t.Fatalf("generateKey: %v", err)
		}
		for _, tc := range []struct {
			name             string
			keyPEM, certPEM  []byte
			wantErrSubstring string
		}{
			{name: "nothing at all", wantErrSubstring: "parse stored identity"},
			{name: "not PEM", keyPEM: []byte("garbage"), certPEM: []byte("garbage"),
				wantErrSubstring: "parse stored identity"},
			{name: "a key that does not match the certificate", keyPEM: otherKeyPEM, certPEM: certPEM,
				wantErrSubstring: "parse stored identity"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				id, err := loadIdentity(tc.keyPEM, tc.certPEM, nil)
				if id != nil {
					t.Error("a broken identity was still returned")
				}
				errContains(t, err, tc.wantErrSubstring)
			})
		}
	})
}

// pemBlock decodes the first PEM block's bytes.
func pemBlock(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %q", data)
	}
	return block.Bytes
}
