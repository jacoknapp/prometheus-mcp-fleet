// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// newBootstrapper builds a bootstrapper for cfg, with client set only when one
// is supplied.
func newBootstrapper(t *testing.T, cfg *config.Hub, api *fakeAPI) (*bootstrapper, *logSink) {
	t.Helper()
	logger, sink := newLogSink()
	b := &bootstrapper{secret: cfg.CASecretName, dir: cfg.DataDir, logger: logger}
	if api != nil {
		b.client = api.client(t)
	}
	return b, sink
}

// sameHasher reports whether two hashers are keyed with the same pepper, which
// is the only externally visible property that matters: two hubs that disagree
// cannot verify each other's credentials.
func sameHasher(a, b *token.Hasher) bool {
	probe := []byte("probe")
	return bytes.Equal(a.Sum(probe), b.Sum(probe))
}

func hasherFor(t *testing.T, pepper []byte) *token.Hasher {
	t.Helper()
	h, err := token.NewHasher(pepper)
	if err != nil {
		t.Fatalf("build hasher: %v", err)
	}
	return h
}

func TestPrepareGeneratesMaterialWithoutKubernetes(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	b, sink := newBootstrapper(t, cfg, nil)

	authority, hasher, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if authority.TrustDomain() != cfg.TrustDomain {
		t.Fatalf("trust domain = %q, want %q", authority.TrustDomain(), cfg.TrustDomain)
	}
	for _, path := range []string{cfg.CACertFile, cfg.CAKeyFile, cfg.PepperFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}
	// The pepper on disk must be the one the returned hasher is keyed with,
	// or a restart would stop verifying every credential this process minted.
	pepper, err := os.ReadFile(cfg.PepperFile)
	if err != nil {
		t.Fatalf("read pepper: %v", err)
	}
	if !sameHasher(hasher, hasherFor(t, pepper)) {
		t.Fatal("the returned hasher is not keyed with the pepper on disk")
	}
	sink.mustNotFind(t, "adopted existing CA material from the secret")
}

func TestPrepareFailsWhenTheScratchDirectoryCannotBeCreated(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	b, _ := newBootstrapper(t, cfg, nil)
	b.dir = filepath.Join(blocker, "scratch")

	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "create scratch dir") {
		t.Fatalf("error = %v, want a create scratch dir failure", err)
	}
}

func TestPrepareFailsOnAnUnloadableCA(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cfg.CACertFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(cfg.CAKeyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	b, _ := newBootstrapper(t, cfg, nil)

	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "load or create the CA") {
		t.Fatalf("error = %v, want a CA load failure", err)
	}
}

func TestPrepareFailsOnAnUnloadablePepper(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	b, _ := newBootstrapper(t, cfg, nil)
	cfg.PepperFile = ""

	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "load or create the pepper") {
		t.Fatalf("error = %v, want a pepper load failure", err)
	}
}

func TestPrepareAdoptsACompleteSecretAndWritesNothingBack(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, fix.secretData())

	b, sink := newBootstrapper(t, cfg, api)
	authority, hasher, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// The whole point of reading the Secret first: this hub must be signing
	// with the fleet's CA, not one it just made up.
	if got, want := authority.Certificate().SerialNumber, fix.ca.Certificate().SerialNumber; got.Cmp(want) != 0 {
		t.Fatalf("adopted CA serial = %s, want the stored one %s", got, want)
	}
	if !sameHasher(hasher, hasherFor(t, fix.pepper)) {
		t.Fatal("the hasher is not keyed with the stored pepper")
	}
	if _, creates, updates := api.counts(); creates != 0 || updates != 0 {
		t.Fatalf("creates=%d updates=%d, want a complete secret to be left alone", creates, updates)
	}
	sink.mustFind(t, "adopted existing CA material from the secret")
}

func TestPrepareReportsASecretReadFailure(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	api.onGet = func(string, int) *fault {
		return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "etcd is unhappy"}
	}
	b, _ := newBootstrapper(t, cfg, api)

	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "read CA secret") {
		t.Fatalf("error = %v, want a secret read failure", err)
	}
}

func TestMaterialiseSkipsAWriteWhenTheFileAlreadyHoldsThoseBytes(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	m := caMaterial{certPEM: fix.certPEM, keyPEM: fix.keyPEM, pepper: fix.pepper}
	paths := map[string][]byte{
		cfg.CACertFile: fix.certPEM,
		cfg.CAKeyFile:  fix.keyPEM,
		cfg.PepperFile: fix.pepper,
	}
	pinned := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for path, data := range paths {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		if err := os.Chtimes(path, pinned, pinned); err != nil {
			t.Fatalf("chtimes %s: %v", path, err)
		}
	}

	b, _ := newBootstrapper(t, cfg, nil)
	if err := b.materialise(m, cfg); err != nil {
		t.Fatalf("materialise: %v", err)
	}
	// Untouched, byte for byte: a projected Secret mount is read-only, so a
	// rewrite of identical content would be a startup failure rather than a
	// wasted syscall.
	for path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !info.ModTime().Equal(pinned) {
			t.Fatalf("%s was rewritten (mtime %s, want %s)", path, info.ModTime(), pinned)
		}
	}

	// And it does write when the bytes differ, or adoption would never work.
	other := newCAFixture(t, cfg.TrustDomain)
	if err := b.materialise(caMaterial{certPEM: other.certPEM}, cfg); err != nil {
		t.Fatalf("materialise (changed): %v", err)
	}
	got, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !bytes.Equal(got, other.certPEM) {
		t.Fatal("differing bytes were not written")
	}
}

func TestMaterialiseIgnoresAbsentValuesAndUnsetPaths(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg.CACertFile = "" // an unset path must not be written to
	b, sink := newBootstrapper(t, cfg, nil)

	if err := b.materialise(caMaterial{}, cfg); err != nil {
		t.Fatalf("materialise: %v", err)
	}
	for _, path := range []string{cfg.CAKeyFile, cfg.PepperFile} {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s was created from empty material", path)
		}
	}
	// Nothing was stored, so nothing was adopted and nothing is claimed.
	sink.mustNotFind(t, "adopted existing CA material from the secret")
}

func TestMaterialiseReportsWhichFileItCouldNotWrite(t *testing.T) {
	t.Parallel()

	fix := newCAFixture(t, config.DefaultTrustDomain)
	m := caMaterial{certPEM: fix.certPEM, keyPEM: fix.keyPEM, pepper: fix.pepper}

	for _, tc := range []struct {
		name  string
		spoil func(*config.Hub, string)
		want  string
	}{
		{"cert", func(c *config.Hub, p string) { c.CACertFile = p }, "write CA certificate"},
		{"key", func(c *config.Hub, p string) { c.CAKeyFile = p }, "write CA key"},
		{"pepper", func(c *config.Hub, p string) { c.PepperFile = p }, "write pepper"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := newHubConfig(t)
			if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			blocker := filepath.Join(cfg.DataDir, "blocker")
			if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
				t.Fatalf("write blocker: %v", err)
			}
			tc.spoil(cfg, filepath.Join(blocker, "nested", "file"))

			b, _ := newBootstrapper(t, cfg, nil)
			err := b.materialise(m, cfg)
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPersistCreatesTheSecretOnFirstBoot(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	b, sink := newBootstrapper(t, cfg, api)

	if _, _, err := b.prepare(context.Background(), cfg); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	stored := api.get(cfg.CASecretName)
	if stored == nil {
		t.Fatal("the CA secret was not created")
	}
	for _, key := range []string{secretKeyCACert, secretKeyCAKey, secretKeyPepper} {
		if len(stored[key]) == 0 {
			t.Fatalf("secret is missing %s", key)
		}
	}
	// What was published must be exactly what is on disk, or the next replica
	// adopts material this one is not using.
	onDisk, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !bytes.Equal(stored[secretKeyCACert], onDisk) {
		t.Fatal("the published CA certificate is not the one on disk")
	}
	if got := api.labelsOf(cfg.CASecretName)["app.kubernetes.io/managed-by"]; got != "prometheus-mcp-hub" {
		t.Fatalf("managed-by label = %q", got)
	}
	sink.mustFind(t, "generated and stored a new CA")
}

func TestPersistCompletesAPartialSecretWithoutOverwritingIt(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: fix.certPEM,
		secretKeyCAKey:  fix.keyPEM,
	})

	b, sink := newBootstrapper(t, cfg, api)
	authority, hasher, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	stored := api.get(cfg.CASecretName)
	// The live CA survived untouched. Overwriting it would orphan the fleet.
	if !bytes.Equal(stored[secretKeyCACert], fix.certPEM) {
		t.Fatal("the stored CA certificate was overwritten")
	}
	if !bytes.Equal(stored[secretKeyCAKey], fix.keyPEM) {
		t.Fatal("the stored CA key was overwritten")
	}
	if len(stored[secretKeyPepper]) == 0 {
		t.Fatal("the missing pepper was not filled in")
	}
	if !sameHasher(hasher, hasherFor(t, stored[secretKeyPepper])) {
		t.Fatal("the published pepper is not the one this hub is using")
	}
	if got, want := authority.Certificate().SerialNumber, fix.ca.Certificate().SerialNumber; got.Cmp(want) != 0 {
		t.Fatalf("CA serial = %s, want the stored one %s", got, want)
	}
	if _, _, updates := api.counts(); updates != 1 {
		t.Fatalf("updates = %d, want exactly one completion", updates)
	}
	rec := sink.mustFind(t, "completed a partially populated CA secret")
	if filled, ok := rec["filled"].([]any); !ok || len(filled) != 1 || filled[0] != secretKeyPepper {
		t.Fatalf("filled = %v, want [%s]", rec["filled"], secretKeyPepper)
	}
}

func TestPersistLeavesAValueThatAppearedDuringTheReadAlone(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: fix.certPEM,
		secretKeyCAKey:  fix.keyPEM,
	})
	// Another replica fills the pepper in between our read and our
	// read-modify-write. Its value must win: two replicas with different
	// peppers cannot verify each other's credentials.
	// The second GET is the read-modify-write inside complete; by then the
	// other replica's value is there.
	api.onGet = func(name string, n int) *fault {
		if n == 2 {
			api.put(name, map[string][]byte{
				secretKeyCACert: fix.certPEM,
				secretKeyCAKey:  fix.keyPEM,
				secretKeyPepper: fix.pepper,
			})
		}
		return nil
	}

	b, sink := newBootstrapper(t, cfg, api)
	if _, _, err := b.prepare(context.Background(), cfg); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	if got := api.get(cfg.CASecretName)[secretKeyPepper]; !bytes.Equal(got, fix.pepper) {
		t.Fatal("the pepper another replica wrote was replaced")
	}
	if _, _, updates := api.counts(); updates != 0 {
		t.Fatalf("updates = %d, want none: every field was already populated", updates)
	}
	sink.mustNotFind(t, "completed a partially populated CA secret")
}

func TestPersistAdoptsTheWinnerOfTheCreateRaceAndReloads(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	winner := newCAFixture(t, cfg.TrustDomain)
	// The winner's Secret appears only after we have read (and found nothing)
	// and generated our own material, which is exactly the race.
	api.onCreate = func(name string, _ int) *fault {
		api.put(name, winner.secretData())
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}

	b, sink := newBootstrapper(t, cfg, api)
	authority, hasher, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// The loser must be signing with the winner's CA. Continuing with its own
	// would mean issuing certificates nobody else in the fleet trusts.
	if got, want := authority.Certificate().SerialNumber, winner.ca.Certificate().SerialNumber; got.Cmp(want) != 0 {
		t.Fatalf("CA serial = %s, want the winner's %s", got, want)
	}
	if !sameHasher(hasher, hasherFor(t, winner.pepper)) {
		t.Fatal("the hasher is not keyed with the winner's pepper")
	}
	onDisk, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !bytes.Equal(onDisk, winner.certPEM) {
		t.Fatal("the scratch directory still holds the loser's CA")
	}
	sink.mustFind(t, "another replica created the CA secret first; adopting its material")
}

func TestPersistRefusesAnEmptyWinningSecret(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	api.onCreate = func(name string, _ int) *fault {
		api.put(name, map[string][]byte{})
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "exists but is empty") {
		t.Fatalf("error = %v, want a refusal to adopt an empty secret", err)
	}
}

func TestPersistReportsALoadFailureAfterLosingTheRace(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	api.onCreate = func(string, int) *fault {
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}
	api.onGet = func(_ string, n int) *fault {
		if n == 1 {
			return nil // first boot: no secret yet
		}
		return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "read CA secret") {
		t.Fatalf("error = %v, want the failed re-read of the winner's secret", err)
	}
}

func TestPersistReportsAMaterialiseFailureAfterLosingTheRace(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	winner := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, winner.secretData())
	api.onCreate = func(string, int) *fault {
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}

	// persist is called directly so the scratch paths can be made unwritable
	// after the CA was loaded from them, which is what a read-only mount that
	// changes underneath a running pod looks like.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	own := newCAFixture(t, cfg.TrustDomain)
	if err := os.WriteFile(cfg.CACertFile, own.certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(cfg.CAKeyFile, own.keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg.PepperFile = filepath.Join(cfg.CACertFile, "nested", "pepper.key")

	b, _ := newBootstrapper(t, cfg, api)
	_, err := b.persist(context.Background(), caMaterial{}, cfg, own.pepper)
	if err == nil || !contains(err.Error(), "write pepper") {
		t.Fatalf("error = %v, want the failed write of the winner's pepper", err)
	}
}

func TestPrepareReportsAFailedReloadAfterAdoption(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	pepper, err := token.GeneratePepper()
	if err != nil {
		t.Fatalf("generate pepper: %v", err)
	}
	api.onCreate = func(name string, _ int) *fault {
		api.put(name, map[string][]byte{
			secretKeyCACert: []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"),
			secretKeyCAKey:  []byte("also not a key"),
			secretKeyPepper: pepper,
		})
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err = b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "reload the adopted CA") {
		t.Fatalf("error = %v, want a reload failure", err)
	}
}

func TestPrepareReportsAFailedPepperReloadAfterAdoption(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	winner := newCAFixture(t, cfg.TrustDomain)
	api.onCreate = func(name string, _ int) *fault {
		api.put(name, map[string][]byte{
			secretKeyCACert: winner.certPEM,
			secretKeyCAKey:  winner.keyPEM,
			secretKeyPepper: []byte("too short"),
		})
		return &fault{code: http.StatusConflict, reason: "AlreadyExists", message: "already exists"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "reload the adopted pepper") {
		t.Fatalf("error = %v, want a pepper reload failure", err)
	}
}

func TestPersistNamesTheMissingRoleOnAForbiddenCreate(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	api.onCreate = func(string, int) *fault {
		return &fault{code: http.StatusForbidden, reason: "Forbidden", message: "secrets is forbidden"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected a forbidden create to fail startup")
	}
	// A bare 403 costs an operator an hour; the error has to name the rule.
	for _, want := range []string{"cannot create the CA secret", "Role granting create on secrets"} {
		if !contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestPersistReportsAnUnexpectedCreateFailure(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	api.onCreate = func(string, int) *fault {
		return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "create CA secret") {
		t.Fatalf("error = %v, want a create failure", err)
	}
}

func TestPersistReportsUnreadableGeneratedMaterial(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		writeCA bool
		want    string
	}{
		{"certificate", false, "read generated CA certificate"},
		{"key", true, "read generated CA key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := newHubConfig(t)
			api := newFakeAPI(t)
			if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if tc.writeCA {
				fix := newCAFixture(t, cfg.TrustDomain)
				if err := os.WriteFile(cfg.CACertFile, fix.certPEM, 0o600); err != nil {
					t.Fatalf("write cert: %v", err)
				}
			}
			b, _ := newBootstrapper(t, cfg, api)
			_, err := b.persist(context.Background(), caMaterial{}, cfg, nil)
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompleteReportsAFailedReRead(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: fix.certPEM,
		secretKeyCAKey:  fix.keyPEM,
	})
	api.onGet = func(_ string, n int) *fault {
		if n < 2 {
			return nil
		}
		return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "read CA secret") {
		t.Fatalf("error = %v, want the failed re-read inside complete", err)
	}
}

func TestCompleteAdoptsWhenAnotherReplicaCompletedItFirst(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: fix.certPEM,
		secretKeyCAKey:  fix.keyPEM,
		// The pepper this replica would have filled in is written to disk by
		// materialise below, so the reload after the conflict finds it there.
	})
	api.onUpdate = func(string, int) *fault {
		return &fault{code: http.StatusConflict, reason: "Conflict", message: "modified"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	authority, hasher, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// Losing the completion race is not a failure: the CA is still the fleet's.
	if got, want := authority.Certificate().SerialNumber, fix.ca.Certificate().SerialNumber; got.Cmp(want) != 0 {
		t.Fatalf("CA serial = %s, want the stored one %s", got, want)
	}
	pepper, err := os.ReadFile(cfg.PepperFile)
	if err != nil {
		t.Fatalf("read pepper: %v", err)
	}
	if !sameHasher(hasher, hasherFor(t, pepper)) {
		t.Fatal("the hasher is not keyed with the pepper on disk")
	}
}

func TestCompleteReportsAnUpdateFailure(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: fix.certPEM,
		secretKeyCAKey:  fix.keyPEM,
	})
	api.onUpdate = func(string, int) *fault {
		return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
	}

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	if err == nil || !contains(err.Error(), "complete CA secret") {
		t.Fatalf("error = %v, want a completion failure", err)
	}
}

func TestCAMaterialEmptinessAndCompleteness(t *testing.T) {
	t.Parallel()

	if !(caMaterial{}).empty() {
		t.Fatal("zero material should be empty")
	}
	partial := caMaterial{certPEM: []byte("c")}
	if partial.empty() {
		t.Fatal("material holding a certificate is not empty")
	}
	// The distinction that matters: a CA with no pepper is neither empty nor
	// complete, so it must be completed rather than adopted or overwritten.
	if partial.complete() {
		t.Fatal("material missing a key and a pepper is not complete")
	}
	full := caMaterial{certPEM: []byte("c"), keyPEM: []byte("k"), pepper: []byte("p")}
	if !full.complete() {
		t.Fatal("fully populated material should be complete")
	}
}

func TestReloadAfterAdoptionUsesTheConfiguredTrustDomain(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := ca.Create(cfg.CACertFile, cfg.CAKeyFile, ca.Options{TrustDomain: cfg.TrustDomain}); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	reloaded, err := reloadAfterAdoption(cfg)
	if err != nil {
		t.Fatalf("reloadAfterAdoption: %v", err)
	}
	if reloaded.TrustDomain() != cfg.TrustDomain {
		t.Fatalf("trust domain = %q, want %q", reloaded.TrustDomain(), cfg.TrustDomain)
	}
}

// contains is strings.Contains, named here so the assertions above read as
// assertions rather than as string plumbing.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func TestPrepareReportsAFailureToWriteAdoptedMaterialToDisk(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	api := newFakeAPI(t)
	fix := newCAFixture(t, cfg.TrustDomain)
	api.put(cfg.CASecretName, fix.secretData())

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	blocker := filepath.Join(cfg.DataDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	cfg.CACertFile = filepath.Join(blocker, "ca.crt")

	b, _ := newBootstrapper(t, cfg, api)
	_, _, err := b.prepare(context.Background(), cfg)
	// The Secret held a CA and it could not be put where the loaders look, so
	// starting anyway would mean generating a second CA over a live fleet.
	if err == nil || !contains(err.Error(), "write CA certificate") {
		t.Fatalf("error = %v, want the failed materialisation", err)
	}
}
