// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type faultDurableFile struct {
	name string
	fail string
	err  error
}

func (f *faultDurableFile) Name() string { return f.name }
func (f *faultDurableFile) Write(p []byte) (int, error) {
	if f.fail == "write" {
		return 0, f.err
	}
	return len(p), nil
}
func (f *faultDurableFile) Sync() error {
	if f.fail == "sync" {
		return f.err
	}
	return nil
}
func (f *faultDurableFile) Chmod(fs.FileMode) error {
	if f.fail == "chmod" {
		return f.err
	}
	return nil
}
func (f *faultDurableFile) Close() error {
	if f.fail == "close" {
		return f.err
	}
	return nil
}

type faultSyncCloser struct{ err error }

func (f *faultSyncCloser) Sync() error  { return f.err }
func (f *faultSyncCloser) Close() error { return nil }

func TestOptionsDefaults(t *testing.T) {
	t.Parallel()

	got := Options{}.withDefaults()
	if got.TrustDomain != DefaultTrustDomain {
		t.Errorf("TrustDomain = %q, want %q", got.TrustDomain, DefaultTrustDomain)
	}
	if got.SpokeCertTTL != DefaultSpokeCertTTL {
		t.Errorf("SpokeCertTTL = %s, want %s", got.SpokeCertTTL, DefaultSpokeCertTTL)
	}
	if got.CATTL != DefaultCATTL {
		t.Errorf("CATTL = %s, want %s", got.CATTL, DefaultCATTL)
	}
	if got.Clock == nil {
		t.Fatal("Clock is nil after defaulting")
	}
	if d := time.Since(got.Clock()); d > time.Minute || d < -time.Minute {
		t.Errorf("default clock is not time.Now: off by %s", d)
	}

	explicit := Options{
		TrustDomain:  "other.test",
		SpokeCertTTL: time.Hour,
		CATTL:        2 * time.Hour,
		Clock:        func() time.Time { return testTime },
	}.withDefaults()
	if diff := cmp.Diff("other.test", explicit.TrustDomain); diff != "" {
		t.Errorf("TrustDomain (-want +got):\n%s", diff)
	}
	if explicit.SpokeCertTTL != time.Hour || explicit.CATTL != 2*time.Hour {
		t.Errorf("explicit TTLs were overwritten: %+v", explicit)
	}
	if !explicit.Clock().Equal(testTime) {
		t.Errorf("explicit clock was overwritten")
	}
}

// TestValidateRejectsZeroTTLDirectly calls validate without withDefaults
// first. Every production caller defaults before validating, so a zero TTL
// never reaches validate() in the running binary -- but validate's own job is
// to reject a non-positive TTL outright, and the only way to put a literal 0
// in front of it is to call the unexported method directly, which a
// same-package test can do.
func TestValidateRejectsZeroTTLDirectly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts Options
	}{
		{name: "zero spoke ttl", opts: Options{TrustDomain: "fleet.local", SpokeCertTTL: 0, CATTL: time.Hour}},
		{name: "zero ca ttl", opts: Options{TrustDomain: "fleet.local", SpokeCertTTL: time.Hour, CATTL: 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.opts.validate(); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("validate() = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts Options
		ok   bool
	}{
		{name: "defaults", opts: Options{}, ok: true},
		{name: "dotted trust domain", opts: Options{TrustDomain: "fleet.example.internal"}, ok: true},
		{name: "single label trust domain", opts: Options{TrustDomain: "f"}, ok: true},
		{name: "uppercase trust domain", opts: Options{TrustDomain: "Fleet.local"}},
		{name: "trust domain with port", opts: Options{TrustDomain: "fleet.local:8443"}},
		{name: "trust domain with path", opts: Options{TrustDomain: "fleet.local/x"}},
		{name: "trust domain with userinfo", opts: Options{TrustDomain: "a@fleet.local"}},
		{name: "trust domain leading dash", opts: Options{TrustDomain: "-fleet.local"}},
		{name: "negative spoke ttl", opts: Options{SpokeCertTTL: -time.Hour}},
		{name: "negative ca ttl", opts: Options{CATTL: -time.Hour}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.opts.withDefaults().validate()
			if tc.ok {
				if err != nil {
					t.Fatalf("validate: unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("validate: got %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func TestCreateProducesConservativeRoot(t *testing.T) {
	t.Parallel()

	clock := newFakeClock(testTime)
	certPath, keyPath := paths(t)
	c, err := Create(certPath, keyPath, Options{TrustDomain: "unit.test", CATTL: 24 * time.Hour, Clock: clock.Now})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cert := c.Certificate()
	if !cert.IsCA {
		t.Error("root is not a CA")
	}
	if !cert.BasicConstraintsValid {
		t.Error("root has no basic constraints")
	}
	if !cert.MaxPathLenZero || cert.MaxPathLen != 0 {
		t.Errorf("root path length = %d (zero=%v), want 0/true", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %b, want %b", cert.KeyUsage, want)
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("root carries extended key usage %v/%v, want none", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("root key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if got := cert.PublicKey.(*ecdsa.PublicKey).Curve; got != elliptic.P256() {
		t.Errorf("root curve = %s, want P-256", got.Params().Name)
	}
	if got, want := cert.NotBefore.UTC(), testTime.Add(-clockSkew); !got.Equal(want) {
		t.Errorf("NotBefore = %s, want %s", got, want)
	}
	if got, want := c.NotAfter().UTC(), testTime.Add(24*time.Hour); !got.Equal(want) {
		t.Errorf("NotAfter = %s, want %s", got, want)
	}
	if got := c.TrustDomain(); got != "unit.test" {
		t.Errorf("TrustDomain = %q, want %q", got, "unit.test")
	}
	if n := cert.SerialNumber; n.Sign() <= 0 || n.BitLen() > serialBits {
		t.Errorf("serial %s has bitlen %d, want 1..%d and positive", n, n.BitLen(), serialBits)
	}
	if len(cert.URIs)+len(cert.DNSNames)+len(cert.IPAddresses) != 0 {
		t.Error("root carries SANs, want none")
	}
}

func TestCreateFilePermissions(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	if _, err := Create(certPath, keyPath, Options{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("key mode = %04o, want 0600", got)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if got := certInfo.Mode().Perm(); got&0o077 != 0o044 {
		t.Errorf("cert mode = %04o, want world readable", got)
	}
	// No temp files may survive a successful create.
	entries, err := os.ReadDir(filepath.Dir(certPath))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s survived", e.Name())
		}
	}
}

func TestCreateThenLoadRoundTrip(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	opts := Options{TrustDomain: "round.trip", Clock: newFakeClock(testTime).Now}
	created, err := Create(certPath, keyPath, opts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	loaded, err := Load(certPath, keyPath, opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if diff := cmp.Diff(created.Certificate().Raw, loaded.Certificate().Raw); diff != "" {
		t.Errorf("certificate DER differs after reload (-created +loaded):\n%s", diff)
	}
	if diff := cmp.Diff(created.BundlePEM(), loaded.BundlePEM()); diff != "" {
		t.Errorf("bundle differs after reload (-created +loaded):\n%s", diff)
	}
	if !created.current().key.PublicKey.Equal(&loaded.current().key.PublicKey) {
		t.Error("loaded key does not match created key")
	}
	// LoadOrCreate on an existing pair must load, not recreate.
	again, err := LoadOrCreate(certPath, keyPath, opts)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if diff := cmp.Diff(created.Certificate().Raw, again.Certificate().Raw); diff != "" {
		t.Errorf("LoadOrCreate regenerated the root (-created +again):\n%s", diff)
	}
}

func TestBundleAndPoolAreDefensiveCopies(t *testing.T) {
	t.Parallel()

	c := mustCA(t, Options{})
	b1 := c.BundlePEM()
	b1[0] ^= 0xff
	if diff := cmp.Diff(c.BundlePEM(), c.current().bundlePEM); diff != "" {
		t.Errorf("mutating BundlePEM changed the CA (-got +want):\n%s", diff)
	}
	p1, p2 := c.Pool(), c.Pool()
	if p1 == p2 {
		t.Error("Pool returned the same pool twice; a caller could widen shared trust")
	}
	if got := len(p1.Subjects()); got != 1 { //nolint:staticcheck // system pool is never used here
		t.Errorf("pool has %d subjects, want 1", got)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		preCert    bool
		preKey     bool
		wantExists bool
	}{
		{name: "both present", preCert: true, preKey: true, wantExists: true},
		{name: "only cert present", preCert: true, wantExists: true},
		{name: "only key present", preKey: true, wantExists: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPath, keyPath := paths(t)
			if tc.preCert {
				if err := os.WriteFile(certPath, []byte("existing"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.preKey {
				if err := os.WriteFile(keyPath, []byte("existing"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Create(certPath, keyPath, Options{})
			if !errors.Is(err, ErrCAExists) {
				t.Fatalf("Create: got %v, want ErrCAExists", err)
			}
			if tc.preCert {
				b, readErr := os.ReadFile(certPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(b) != "existing" {
					t.Error("existing certificate was overwritten")
				}
			}
			if tc.preKey {
				b, readErr := os.ReadFile(keyPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(b) != "existing" {
					t.Error("existing key was overwritten")
				}
			}
			if !tc.preCert {
				if _, statErr := os.Stat(certPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Error("failed Create left a reservation behind at the certificate path")
				}
			}
			if !tc.preKey {
				if _, statErr := os.Stat(keyPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Error("failed Create left a reservation behind at the key path")
				}
			}
		})
	}
}

func TestLoadOrCreateHalfPresent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		preCert bool
		preKey  bool
	}{
		{name: "cert without key", preCert: true},
		{name: "key without cert", preKey: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPath, keyPath := paths(t)
			if tc.preCert {
				if err := os.WriteFile(certPath, []byte("half"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.preKey {
				if err := os.WriteFile(keyPath, []byte("half"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := LoadOrCreate(certPath, keyPath, Options{})
			if !errors.Is(err, ErrCAIncomplete) {
				t.Fatalf("LoadOrCreate: got %v, want ErrCAIncomplete", err)
			}
		})
	}
}

func TestLoadOrCreateCreatesWhenAbsent(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	c, err := LoadOrCreate(certPath, keyPath, Options{TrustDomain: "made.up"})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if c.TrustDomain() != "made.up" {
		t.Errorf("TrustDomain = %q", c.TrustDomain())
	}
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("stat %s: %v", p, err)
		}
	}
}

// TestLoadOrCreateFirstAttemptDoesNotPoll proves attempt 0 never pays the
// poll delay: that budget exists for retries after a losing race, not for the
// common case where nothing else is contending for these paths.
//
// It cannot use t.Parallel: it overrides the package-level caStat hook that
// every regularFileExists call in the suite goes through.
//
// Timing the whole LoadOrCreate call would be flaky under load, since key
// generation and a cert write can occasionally take longer than
// initPollInterval when the machine is busy. Instead this times only the gap
// between entering the loop and the first existence check, which is where an
// attempt-0 sleep would show up; that isolates the signal from the unrelated
// crypto and I/O cost that follows it, leaving a wide margin (initPollInterval
// versus microseconds) between "slept" and "didn't."
func TestLoadOrCreateFirstAttemptDoesNotPoll(t *testing.T) {
	origStat := caStat
	t.Cleanup(func() { caStat = origStat })

	certPath, keyPath := paths(t)
	var firstStatAt time.Time
	caStat = func(name string) (os.FileInfo, error) {
		if firstStatAt.IsZero() {
			firstStatAt = time.Now()
		}
		return origStat(name)
	}
	start := time.Now()
	if _, err := LoadOrCreate(certPath, keyPath, Options{TrustDomain: "made.up"}); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if firstStatAt.IsZero() {
		t.Fatal("regularFileExists never reached caStat")
	}
	if gap := firstStatAt.Sub(start); gap >= initPollInterval/2 {
		t.Errorf("LoadOrCreate waited %v before its first existence check, want near-zero (< %v): attempt 0 appears to sleep before trying anything",
			gap, initPollInterval/2)
	}
}

func TestLoadOrCreateConcurrent(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	const n = 8
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		serls []string
	)
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			c, err := LoadOrCreate(certPath, keyPath, Options{})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("LoadOrCreate: %v", err)
				return
			}
			serls = append(serls, SerialHex(c.Certificate().SerialNumber))
		}()
	}
	wg.Wait()
	if len(serls) != n {
		t.Fatalf("got %d results, want %d", len(serls), n)
	}
	for _, s := range serls {
		if s != serls[0] {
			t.Fatalf("racing callers saw different roots: %v", serls)
		}
	}
}

func TestLoadOrCreateRejectsNonRegularPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(sub, filepath.Join(dir, "k"), Options{}); !errors.Is(err, ErrInvalidCA) {
		t.Errorf("directory as cert path: got %v, want ErrInvalidCA", err)
	}
	if _, err := LoadOrCreate(filepath.Join(dir, "c"), sub, Options{}); !errors.Is(err, ErrInvalidCA) {
		t.Errorf("directory as key path: got %v, want ErrInvalidCA", err)
	}

	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	notADir := filepath.Join(file, "nested")
	if _, err := LoadOrCreate(notADir, filepath.Join(dir, "k2"), Options{}); err == nil {
		t.Error("stat through a non-directory: got nil error")
	} else if errors.Is(err, ErrCANotFound) || errors.Is(err, ErrCAExists) {
		t.Errorf("stat through a non-directory: got %v, want a raw stat error", err)
	}
	if _, err := LoadOrCreate(filepath.Join(dir, "c2"), notADir, Options{}); err == nil {
		t.Error("stat through a non-directory (key): got nil error")
	}
}

func TestLoadOrCreateInvalidOptions(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	if _, err := LoadOrCreate(certPath, keyPath, Options{TrustDomain: "NOPE"}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("got %v, want ErrInvalidOptions", err)
	}
}

func TestCreateUnwritableDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "missing")
	_, err := Create(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), Options{})
	if err == nil {
		t.Fatal("Create into a missing directory: got nil error")
	}
	if errors.Is(err, ErrCAExists) {
		t.Fatalf("got %v, want a raw create error", err)
	}
}

func TestLoadMissing(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	if _, err := Load(certPath, keyPath, Options{}); !errors.Is(err, ErrCANotFound) {
		t.Errorf("missing cert: got %v, want ErrCANotFound", err)
	}
	if _, err := Create(certPath, keyPath, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPath, keyPath, Options{}); !errors.Is(err, ErrCANotFound) {
		t.Errorf("missing key: got %v, want ErrCANotFound", err)
	}
}

func TestLoadInvalidOptions(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	if _, err := Load(certPath, keyPath, Options{CATTL: -1}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("got %v, want ErrInvalidOptions", err)
	}
}

func TestLoadRefusesLooseKeyPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{name: "0600", mode: 0o600, ok: true},
		{name: "0400", mode: 0o400, ok: true},
		{name: "0640 group readable", mode: 0o640},
		{name: "0604 world readable", mode: 0o604},
		{name: "0660 group writable", mode: 0o660},
		{name: "0666", mode: 0o666},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPath, keyPath := paths(t)
			if _, err := Create(certPath, keyPath, Options{}); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := Load(certPath, keyPath, Options{})
			switch {
			case tc.ok && err != nil:
				t.Fatalf("Load: unexpected error %v", err)
			case !tc.ok && !errors.Is(err, ErrInsecureKeyMode):
				t.Fatalf("Load: got %v, want ErrInsecureKeyMode", err)
			}
		})
	}
}

func TestLoadRejectsBadMaterial(t *testing.T) {
	t.Parallel()

	// A well-formed but wrong keypair to reuse across cases.
	otherKey := newKey(t)
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalECPrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}

	selfSigned := func(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) []byte {
		t.Helper()
		tmpl.SerialNumber = big.NewInt(7)
		tmpl.NotBefore = testTime
		tmpl.NotAfter = testTime.Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return pemBlock(pemTypeCertificate, der)
	}

	tests := []struct {
		name    string
		cert    func(t *testing.T) []byte
		key     func(t *testing.T) []byte
		wantErr error
	}{
		{
			name:    "cert not pem",
			cert:    func(*testing.T) []byte { return []byte("not pem at all") },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "cert wrong pem type",
			cert:    func(*testing.T) []byte { return pemBlock("PRIVATE KEY", otherKeyDER) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "cert pem holds garbage",
			cert:    func(*testing.T) []byte { return pemBlock(pemTypeCertificate, []byte{1, 2, 3}) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key not pem",
			key:     func(*testing.T) []byte { return []byte("nope") },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key wrong pem type",
			key:     func(*testing.T) []byte { return pemBlock("CERTIFICATE", otherKeyDER) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key pkcs8 garbage",
			key:     func(*testing.T) []byte { return pemBlock(pemTypePrivateKey, []byte{9, 9}) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key sec1 garbage",
			key:     func(*testing.T) []byte { return pemBlock(pemTypeECKeyLegacy, []byte{9, 9}) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key is rsa",
			key:     func(*testing.T) []byte { return pemBlock(pemTypePrivateKey, rsaDER) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key is p384",
			key:     func(*testing.T) []byte { return pemBlock(pemTypeECKeyLegacy, p384DER) },
			wantErr: ErrInvalidCA,
		},
		{
			name:    "key does not match cert",
			key:     func(*testing.T) []byte { return pemBlock(pemTypePrivateKey, otherKeyDER) },
			wantErr: ErrInvalidCA,
		},
		{
			name: "cert is not a ca",
			cert: func(t *testing.T) []byte {
				return selfSigned(t, &x509.Certificate{
					Subject:               pkix.Name{CommonName: "leaf"},
					BasicConstraintsValid: true,
					KeyUsage:              x509.KeyUsageDigitalSignature,
				}, otherKey)
			},
			key:     func(*testing.T) []byte { return pemBlock(pemTypePrivateKey, otherKeyDER) },
			wantErr: ErrInvalidCA,
		},
		{
			name: "ca without certsign",
			cert: func(t *testing.T) []byte {
				return selfSigned(t, &x509.Certificate{
					Subject:               pkix.Name{CommonName: "ca"},
					BasicConstraintsValid: true,
					IsCA:                  true,
					KeyUsage:              x509.KeyUsageCRLSign,
				}, otherKey)
			},
			key:     func(*testing.T) []byte { return pemBlock(pemTypePrivateKey, otherKeyDER) },
			wantErr: ErrInvalidCA,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			certPath, keyPath := paths(t)
			if _, err := Create(certPath, keyPath, Options{}); err != nil {
				t.Fatal(err)
			}
			if tc.cert != nil {
				if err := os.WriteFile(certPath, tc.cert(t), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.key != nil {
				if err := os.WriteFile(keyPath, tc.key(t), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Load(certPath, keyPath, Options{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Load: got %v, want %v", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "MII") || strings.Contains(err.Error(), "BEGIN") {
				t.Errorf("error message may contain key material: %v", err)
			}
		})
	}
}

func TestLoadAcceptsRSACACertificate(t *testing.T) {
	t.Parallel()

	// An RSA-keyed CA certificate paired with an EC key must be rejected at
	// the public-key type check rather than panicking.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "rsa ca"},
		NotBefore:             testTime,
		NotAfter:              testTime.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := paths(t)
	if _, err := Create(certPath, keyPath, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pemBlock(pemTypeCertificate, der), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPath, keyPath, Options{}); !errors.Is(err, ErrInvalidCA) {
		t.Fatalf("got %v, want ErrInvalidCA", err)
	}
}

func TestLoadAcceptsSEC1Key(t *testing.T) {
	t.Parallel()

	certPath, keyPath := paths(t)
	c, err := Create(certPath, keyPath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(c.current().key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pemBlock(pemTypeECKeyLegacy, sec1), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(certPath, keyPath, Options{})
	if err != nil {
		t.Fatalf("Load with SEC1 key: %v", err)
	}
	if !loaded.current().key.PublicKey.Equal(&c.current().key.PublicKey) {
		t.Error("SEC1 key round trip produced a different key")
	}
}

func TestLoadCertificatePathIsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := Load(dir, filepath.Join(dir, "k"), Options{}); err == nil {
		t.Fatal("Load with a directory as the certificate path: got nil error")
	}
}

func TestSerialHex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   *big.Int
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "zero", in: big.NewInt(0), want: "0"},
		{name: "small", in: big.NewInt(255), want: "ff"},
		{name: "lowercase", in: big.NewInt(0xdeadbeef), want: "deadbeef"},
		{name: "negative loses sign", in: big.NewInt(-255), want: "ff"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, SerialHex(tc.in)); diff != "" {
				t.Errorf("SerialHex (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewSerialIsRandomAndBounded(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 64)
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	for range 64 {
		n, err := newSerial()
		if err != nil {
			t.Fatalf("newSerial: %v", err)
		}
		if n.Sign() <= 0 {
			t.Fatalf("serial %s is not positive", n)
		}
		if n.Cmp(limit) >= 0 {
			t.Fatalf("serial %s exceeds %d bits", n, serialBits)
		}
		if n.BitLen() < 96 {
			t.Errorf("serial %s has only %d bits; entropy source looks wrong", n, n.BitLen())
		}
		s := SerialHex(n)
		if seen[s] {
			t.Fatalf("duplicate serial %s", s)
		}
		seen[s] = true
	}
}

func TestValidClusterID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "simple", id: "prod", want: true},
		{name: "with dashes", id: "prod-us-east-1", want: true},
		{name: "single char", id: "a", want: true},
		{name: "digits", id: "0", want: true},
		{name: "max length", id: "a" + strings.Repeat("b", 61) + "c", want: true},
		{name: "empty", id: ""},
		{name: "too long", id: strings.Repeat("a", 64)},
		{name: "uppercase", id: "Prod"},
		{name: "leading dash", id: "-prod"},
		{name: "trailing dash", id: "prod-"},
		{name: "dot", id: "prod.us"},
		{name: "underscore", id: "prod_us"},
		{name: "slash", id: "prod/us"},
		{name: "newline", id: "prod\n"},
		{name: "space", id: "prod us"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidClusterID(tc.id); got != tc.want {
				t.Errorf("ValidClusterID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

func TestLinkFileExclusive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := linkFileExclusive(target, []byte("hello"), 0o600); err != nil {
		t.Fatalf("linkFileExclusive: %v", err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff("hello", string(b)); diff != "" {
		t.Errorf("content (-want +got):\n%s", diff)
	}
	// A second link to the same name must not replace it.
	if err := linkFileExclusive(target, []byte("clobbered"), 0o600); !errors.Is(err, ErrCAExists) {
		t.Fatalf("second link: got %v, want ErrCAExists", err)
	}
	b, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Errorf("content was replaced: %q", b)
	}
	// No temp files may survive either outcome.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s survived", e.Name())
		}
	}
	if err := linkFileExclusive(filepath.Join(dir, "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Error("linkFileExclusive into a missing directory: got nil error")
	}
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := linkFileExclusive(sub, []byte("x"), 0o600); !errors.Is(err, ErrCAExists) {
		t.Errorf("linkFileExclusive over a directory: got %v, want ErrCAExists", err)
	}
}

// TestCAOperationalFailures drives the process boundaries that fail only under
// unusual kernel, filesystem, or entropy conditions. It is deliberately
// non-parallel because each case temporarily replaces one package operation.
func TestCAOperationalFailures(t *testing.T) {
	boom := errors.New("injected operational failure")
	origGenerateKey, origRandomInt := caGenerateKey, caRandomInt
	origCreateCert, origCreateCRL := caCreateCertificate, caCreateRevocationList
	origRead, origStat, origRemove := caReadFile, caStat, caRemove
	origCreateTemp, origLink, origOpenDir := caCreateTemp, caLink, caOpenDir
	origLoadOrCreateCreate := loadOrCreateCreate
	t.Cleanup(func() {
		caGenerateKey, caRandomInt = origGenerateKey, origRandomInt
		caCreateCertificate, caCreateRevocationList = origCreateCert, origCreateCRL
		caReadFile, caStat, caRemove = origRead, origStat, origRemove
		caCreateTemp, caLink, caOpenDir = origCreateTemp, origLink, origOpenDir
		loadOrCreateCreate = origLoadOrCreateCreate
	})

	assertBoom := func(t *testing.T, got *CA, err error) {
		t.Helper()
		if got != nil || !errors.Is(err, boom) {
			t.Fatalf("result = (%v, %v), want (nil, wrapped injected error)", got, err)
		}
	}

	t.Run("load certificate read", func(t *testing.T) {
		caReadFile = func(string) ([]byte, error) { return nil, boom }
		got, err := Load("certificate", "key", Options{})
		assertBoom(t, got, err)
		caReadFile = origRead
	})

	t.Run("load key stat", func(t *testing.T) {
		certPath, keyPath := paths(t)
		if _, err := Create(certPath, keyPath, Options{}); err != nil {
			t.Fatal(err)
		}
		caStat = func(string) (fs.FileInfo, error) { return nil, boom }
		got, err := Load(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		caStat = origStat
	})

	t.Run("load key read", func(t *testing.T) {
		certPath, keyPath := paths(t)
		if _, err := Create(certPath, keyPath, Options{}); err != nil {
			t.Fatal(err)
		}
		caReadFile = func(path string) ([]byte, error) {
			if path == keyPath {
				return nil, boom
			}
			return origRead(path)
		}
		got, err := Load(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		caReadFile = origRead
	})

	t.Run("invalid create options", func(t *testing.T) {
		got, err := Create("certificate", "key", Options{CATTL: -1})
		if got != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("Create = (%v, %v), want nil ErrInvalidOptions", got, err)
		}
	})

	t.Run("create path stat", func(t *testing.T) {
		dir := t.TempDir()
		got, err := Create(dir, filepath.Join(dir, "key"), Options{})
		if got != nil || !errors.Is(err, ErrInvalidCA) {
			t.Fatalf("Create = (%v, %v), want nil ErrInvalidCA", got, err)
		}
	})

	t.Run("key generation", func(t *testing.T) {
		caGenerateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, boom }
		certPath, keyPath := paths(t)
		got, err := Create(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		caGenerateKey = origGenerateKey
	})

	// NewRootPEM mints the successor a rotation begins with. A CSPRNG failure
	// there must surface as an error and no material, because the caller is
	// about to write whatever it is handed into the Secret the whole fleet
	// reads.
	t.Run("successor root key generation", func(t *testing.T) {
		caGenerateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, boom }
		certPEM, keyPEM, err := NewRootPEM(Options{})
		if !errors.Is(err, boom) {
			t.Fatalf("NewRootPEM() error = %v, want one wrapping boom", err)
		}
		if certPEM != nil || keyPEM != nil {
			t.Error("NewRootPEM returned material alongside an error")
		}
		caGenerateKey = origGenerateKey
	})

	t.Run("serial generation", func(t *testing.T) {
		caRandomInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, boom }
		if serial, err := newSerial(); serial != nil || !errors.Is(err, boom) {
			t.Fatalf("newSerial = (%v, %v), want nil wrapped error", serial, err)
		}
		certPath, keyPath := paths(t)
		got, err := Create(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		caRandomInt = origRandomInt
	})

	t.Run("leaf serial generation", func(t *testing.T) {
		c := mustCA(t, Options{})
		csrDER, _ := simpleCSR(t)
		caRandomInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, boom }
		pemBytes, leaf, err := c.IssueSpokeFromCSR(csrDER, "prod")
		if pemBytes != nil || leaf != nil || !errors.Is(err, boom) {
			t.Fatalf("IssueSpokeFromCSR = (%x, %v, %v), want nils and wrapped error", pemBytes, leaf, err)
		}
		caRandomInt = origRandomInt
	})

	t.Run("certificate signing", func(t *testing.T) {
		c := mustCA(t, Options{})
		caCreateCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
			return nil, boom
		}
		certPath, keyPath := paths(t)
		got, err := Create(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		csrDER, _ := simpleCSR(t)
		pemBytes, leaf, err := c.IssueSpokeFromCSR(csrDER, "prod")
		if pemBytes != nil || leaf != nil || !errors.Is(err, boom) {
			t.Fatalf("IssueSpokeFromCSR = (%x, %v, %v), want nils and wrapped error", pemBytes, leaf, err)
		}
		caCreateCertificate = origCreateCert
	})

	t.Run("crl signing", func(t *testing.T) {
		c := mustCA(t, Options{})
		caCreateRevocationList = func(io.Reader, *x509.RevocationList, *x509.Certificate, crypto.Signer) ([]byte, error) {
			return nil, boom
		}
		der, err := c.CRL(nil, testTime, time.Hour)
		if der != nil || !errors.Is(err, boom) {
			t.Fatalf("CRL = (%x, %v), want nil wrapped error", der, err)
		}
		caCreateRevocationList = origCreateCRL
	})

	t.Run("creation race never settles", func(t *testing.T) {
		// The real delay is the budget itself; nothing here is waiting on
		// another goroutine, so spending it would only slow the suite.
		origSleep := caSleep
		caSleep = func(time.Duration) {}
		defer func() { caSleep = origSleep }()
		loadOrCreateCreate = func(string, string, Options) (*CA, error) { return nil, ErrCAExists }
		certPath, keyPath := paths(t)
		got, err := LoadOrCreate(certPath, keyPath, Options{})
		if got != nil || !errors.Is(err, ErrCAExists) || !strings.Contains(err.Error(), "did not settle") {
			t.Fatalf("LoadOrCreate = (%v, %v), want nil unsettled ErrCAExists", got, err)
		}
		loadOrCreateCreate = origLoadOrCreateCreate
	})

	// LoadOrCreate polls initPollAttempts+1 times in total (the initial try
	// plus initPollAttempts retries) before giving up. A race that resolves
	// on the very last permitted attempt must still succeed; a budget that is
	// one attempt short of that would report the race as never having
	// settled instead.
	t.Run("creation race settles on the last permitted attempt", func(t *testing.T) {
		origSleep := caSleep
		caSleep = func(time.Duration) {}
		defer func() { caSleep = origSleep }()
		certPath, keyPath := paths(t)
		calls := 0
		loadOrCreateCreate = func(cp, kp string, o Options) (*CA, error) {
			calls++
			if calls <= initPollAttempts {
				return nil, ErrCAExists
			}
			return origLoadOrCreateCreate(cp, kp, o)
		}
		got, err := LoadOrCreate(certPath, keyPath, Options{})
		if err != nil {
			t.Fatalf("LoadOrCreate: %v, want success on attempt %d of the %d-attempt budget",
				err, calls, initPollAttempts+1)
		}
		if got == nil {
			t.Fatal("LoadOrCreate returned a nil CA with no error")
		}
		if calls != initPollAttempts+1 {
			t.Errorf("loadOrCreateCreate was called %d times, want exactly %d (the full budget)",
				calls, initPollAttempts+1)
		}
		loadOrCreateCreate = origLoadOrCreateCreate
	})

	t.Run("certificate commit cleans key", func(t *testing.T) {
		certPath, keyPath := paths(t)
		caLink = func(old, new string) error {
			if new == certPath {
				return boom
			}
			return origLink(old, new)
		}
		got, err := Create(certPath, keyPath, Options{})
		assertBoom(t, got, err)
		if _, err := os.Stat(keyPath); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("failed certificate commit left key behind: %v", err)
		}
		caLink = origLink
	})
}

func TestLinkFileExclusiveOperationalFailures(t *testing.T) {
	boom := errors.New("injected filesystem failure")
	origCreateTemp, origLink, origOpenDir := caCreateTemp, caLink, caOpenDir
	t.Cleanup(func() { caCreateTemp, caLink, caOpenDir = origCreateTemp, origLink, origOpenDir })

	t.Run("create temp", func(t *testing.T) {
		caCreateTemp = func(string, string) (durableFile, error) { return nil, boom }
		if err := linkFileExclusive("target", []byte("data"), 0o600); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want wrapped injected error", err)
		}
		caCreateTemp = origCreateTemp
	})

	for _, stage := range []string{"write", "sync", "chmod", "close"} {
		t.Run(stage, func(t *testing.T) {
			caCreateTemp = func(string, string) (durableFile, error) {
				return &faultDurableFile{name: filepath.Join(t.TempDir(), "temp"), fail: stage, err: boom}, nil
			}
			if err := linkFileExclusive("target", []byte("data"), 0o600); !errors.Is(err, boom) {
				t.Fatalf("error = %v, want wrapped injected error", err)
			}
			caCreateTemp = origCreateTemp
		})
	}

	t.Run("link", func(t *testing.T) {
		caCreateTemp = func(string, string) (durableFile, error) {
			return &faultDurableFile{name: filepath.Join(t.TempDir(), "temp")}, nil
		}
		caLink = func(string, string) error { return boom }
		if err := linkFileExclusive("target", []byte("data"), 0o600); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want wrapped injected error", err)
		}
		caCreateTemp, caLink = origCreateTemp, origLink
	})

	t.Run("open directory", func(t *testing.T) {
		caCreateTemp = func(string, string) (durableFile, error) {
			return &faultDurableFile{name: filepath.Join(t.TempDir(), "temp")}, nil
		}
		caLink = func(string, string) error { return nil }
		caOpenDir = func(string) (syncCloser, error) { return nil, boom }
		if err := linkFileExclusive("target", []byte("data"), 0o600); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want wrapped injected error", err)
		}
		caCreateTemp, caLink, caOpenDir = origCreateTemp, origLink, origOpenDir
	})

	t.Run("sync directory", func(t *testing.T) {
		caCreateTemp = func(string, string) (durableFile, error) {
			return &faultDurableFile{name: filepath.Join(t.TempDir(), "temp")}, nil
		}
		caLink = func(string, string) error { return nil }
		caOpenDir = func(string) (syncCloser, error) { return &faultSyncCloser{err: boom}, nil }
		if err := linkFileExclusive("target", []byte("data"), 0o600); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want wrapped injected error", err)
		}
		caCreateTemp, caLink, caOpenDir = origCreateTemp, origLink, origOpenDir
	})
}
