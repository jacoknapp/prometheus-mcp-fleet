// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// keyStub is a store that fails or diverts exactly one operation, so the
// failure and race branches of bootstrapAdminKey can be driven without giving
// up a real store underneath.
type keyStub struct {
	store.Store

	listErr error
	putErr  error
	// beforePut runs after the unusable-record check and before the write,
	// which is precisely the window another replica can win in.
	beforePut func()
}

func (s *keyStub) ListKeys(ctx context.Context, class fleet.KeyClass) ([]*fleet.Key, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.Store.ListKeys(ctx, class)
}

func (s *keyStub) PutKeyIfNoUsable(
	ctx context.Context, k *fleet.Key, at time.Time,
) (bool, error) {
	if s.beforePut != nil {
		s.beforePut()
	}
	if s.putErr != nil {
		return false, s.putErr
	}
	return s.Store.PutKeyIfNoUsable(ctx, k, at)
}

// newKeyHub builds the smallest hub bootstrapAdminKey needs: a configuration,
// a logger, a credential store and a hasher.
func newKeyHub(t *testing.T, st store.Store) (*hub, *logSink) {
	t.Helper()
	logger, sink := newLogSink()
	pepper, err := token.GeneratePepper()
	if err != nil {
		t.Fatalf("generate pepper: %v", err)
	}
	hasher, err := token.NewHasher(pepper)
	if err != nil {
		t.Fatalf("build hasher: %v", err)
	}
	return &hub{cfg: newHubConfig(t), logger: logger, store: st, hasher: hasher}, sink
}

func adminKeys(t *testing.T, st store.Store) []*fleet.Key {
	t.Helper()
	keys, err := st.ListKeys(context.Background(), fleet.ClassAdmin)
	if err != nil {
		t.Fatalf("list admin keys: %v", err)
	}
	return keys
}

func TestBootstrapAdminKeyMintsExactlyOneCredentialAndPrintsItOnce(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	h, sink := newKeyHub(t, st)
	pinned := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	h.now = testutil.NewClock(pinned).Now

	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}
	// A restart must not mint a second credential or reprint the first.
	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey (second start): %v", err)
	}

	keys := adminKeys(t, st)
	if len(keys) != 1 {
		t.Fatalf("admin keys = %d, want exactly 1", len(keys))
	}
	got := keys[0]
	if got.KID != bootstrapKID {
		t.Fatalf("kid = %q, want the well-known %q", got.KID, bootstrapKID)
	}
	if got.Name != bootstrapKeyName {
		t.Fatalf("name = %q, want %q", got.Name, bootstrapKeyName)
	}
	if !got.ExpiresAt.Equal(pinned.Add(h.cfg.AgentKeyTTL)) {
		t.Fatalf("expires at %s, want %s", got.ExpiresAt, pinned.Add(h.cfg.AgentKeyTTL))
	}
	if n := sink.count("BOOTSTRAP ADMIN TOKEN — shown once, store it now"); n != 1 {
		t.Fatalf("the bootstrap token was printed %d times, want exactly 1", n)
	}

	// The printed token must actually authenticate as the stored record, or
	// the operator has been handed something useless.
	rec := sink.mustFind(t, "BOOTSTRAP ADMIN TOKEN — shown once, store it now")
	raw, _ := rec["token"].(string)
	class, kid, secret, err := token.Parse(raw)
	if err != nil {
		t.Fatalf("parse printed token: %v", err)
	}
	if class != fleet.ClassAdmin || kid != bootstrapKID {
		t.Fatalf("printed token is %s/%s, want admin/%s", class, kid, bootstrapKID)
	}
	if !h.hasher.Equal(got.SecretHMAC, secret) {
		t.Fatal("the printed token does not match the stored digest")
	}
}

func TestBootstrapAdminKeySaysNothingWhenAUsableKeyExists(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	h, sink := newKeyHub(t, st)
	now := time.Now()
	existing := &fleet.Key{
		KID: "operator01", Class: fleet.ClassAdmin, Name: "operator",
		SecretHMAC: h.hasher.Sum([]byte("secret")),
		CreatedAt:  now, ExpiresAt: now.Add(time.Hour),
	}
	if err := st.PutKey(context.Background(), existing); err != nil {
		t.Fatalf("seed admin key: %v", err)
	}

	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}

	if keys := adminKeys(t, st); len(keys) != 1 || keys[0].KID != "operator01" {
		t.Fatalf("admin keys = %v, want only the pre-existing one", keys)
	}
	// Not even the key id: a hub that logs on every start is noise, and a hub
	// that logs more than the key id is a leak.
	if sink.String() != "" {
		t.Fatalf("expected silence, got:\n%s", sink.String())
	}
}

func TestBootstrapAdminKeyReplacesAnExpiredButUnrevokedRecord(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	h, sink := newKeyHub(t, st)
	now := time.Now()
	stale := &fleet.Key{
		KID: bootstrapKID, Class: fleet.ClassAdmin, Name: bootstrapKeyName,
		SecretHMAC: h.hasher.Sum([]byte("stale")),
		CreatedAt:  now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	if err := st.PutKey(context.Background(), stale); err != nil {
		t.Fatalf("seed stale key: %v", err)
	}

	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}

	// Expired-but-unrevoked must not suppress recovery forever: a hub with no
	// usable admin credential and no way to mint one is unadministerable.
	keys := adminKeys(t, st)
	if len(keys) != 1 {
		t.Fatalf("admin keys = %d, want exactly 1", len(keys))
	}
	fresh := keys[0]
	if !fresh.Usable(time.Now()) {
		t.Fatal("the replacement key is not usable")
	}
	if string(fresh.SecretHMAC) == string(stale.SecretHMAC) {
		t.Fatal("the stale record was kept rather than replaced")
	}
	sink.mustFind(t, "BOOTSTRAP ADMIN TOKEN — shown once, store it now")
}

func TestBootstrapAdminKeyReportsStoreFailures(t *testing.T) {
	t.Parallel()

	boom := errors.New("the store is down")
	for _, tc := range []struct {
		name string
		stub func(*keyStub)
		want string
	}{
		{"list", func(s *keyStub) { s.listErr = boom }, "list admin keys"},
		{"put", func(s *keyStub) { s.putErr = boom }, "store the bootstrap admin key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := newFileStore(t)
			stub := &keyStub{Store: base}
			tc.stub(stub)
			h, _ := newKeyHub(t, stub)
			err := h.bootstrapAdminKey(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBootstrapAdminKeyStaysSilentWhenAnotherReplicaWinsTheMint(t *testing.T) {
	t.Parallel()

	base := newFileStore(t)
	stub := &keyStub{Store: base}
	h, sink := newKeyHub(t, stub)
	// The other replica writes the well-known identifier in the window between
	// this one deciding to mint and actually writing.
	var once sync.Once
	stub.beforePut = func() {
		once.Do(func() {
			now := time.Now()
			if err := base.PutKey(context.Background(), &fleet.Key{
				KID: bootstrapKID, Class: fleet.ClassAdmin, Name: bootstrapKeyName,
				SecretHMAC: h.hasher.Sum([]byte("winner")),
				CreatedAt:  now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Errorf("seed winner: %v", err)
			}
		})
	}

	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}

	if keys := adminKeys(t, base); len(keys) != 1 {
		t.Fatalf("admin keys = %d, want the winner's alone", len(keys))
	}
	sink.mustFind(t, "another replica minted the bootstrap admin key first")
	// The loser's token was never revealed, so it must never be printed.
	sink.mustNotFind(t, "BOOTSTRAP ADMIN TOKEN — shown once, store it now")
}

func TestTwoReplicasRacingOnAnEmptyStoreMintOneKeyBetweenThem(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	a, sinkA := newKeyHub(t, st)
	b, sinkB := newKeyHub(t, st)
	b.hasher = a.hasher // one fleet, one pepper

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	errs := make([]error, 2)
	for i, replica := range []*hub{a, b} {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			errs[i] = replica.bootstrapAdminKey(context.Background())
		}()
	}
	start.Done()
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	// The fixed key identifier turns the race into a uniqueness conflict, so
	// exactly one credential exists and exactly one token was ever printed.
	if keys := adminKeys(t, st); len(keys) != 1 {
		t.Fatalf("admin keys = %d, want exactly 1", len(keys))
	}
	printed := sinkA.count("BOOTSTRAP ADMIN TOKEN — shown once, store it now") +
		sinkB.count("BOOTSTRAP ADMIN TOKEN — shown once, store it now")
	if printed != 1 {
		t.Fatalf("the bootstrap token was printed %d times, want exactly 1", printed)
	}
}

func TestBootstrapTTLNeverOutlivesTheKeysItMints(t *testing.T) {
	t.Parallel()

	h, _ := newKeyHub(t, newFileStore(t))
	h.cfg.AgentKeyTTL = 48 * time.Hour
	if got := h.bootstrapTTL(); got != 48*time.Hour {
		t.Fatalf("bootstrapTTL = %s, want the configured agent key TTL", got)
	}
	h.cfg.AgentKeyTTL = 0
	if got := h.bootstrapTTL(); got != 720*time.Hour {
		t.Fatalf("bootstrapTTL = %s, want the 720h fallback", got)
	}
}

func TestClockDefaultsToTheWallClock(t *testing.T) {
	t.Parallel()

	h := &hub{}
	before := time.Now()
	got := h.clock()
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("clock() = %s, want a reading from the wall clock", got)
	}

	pinned := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	h.now = testutil.NewClock(pinned).Now
	if got := h.clock(); !got.Equal(pinned) {
		t.Fatalf("clock() = %s, want the injected %s", got, pinned)
	}
}

func TestBootstrapAdminKeyIgnoresARevokedRecordOfAnotherKey(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	h, sink := newKeyHub(t, st)
	now := time.Now()
	if err := st.PutKey(context.Background(), &fleet.Key{
		KID: "retired001", Class: fleet.ClassAdmin, Name: "retired",
		SecretHMAC: h.hasher.Sum([]byte("retired")),
		CreatedAt:  now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeKey(context.Background(), "retired001", "decommissioned", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}

	// A revoked admin key cannot administer anything, so recovery must still
	// happen even though a record of the class exists.
	got, err := st.GetKey(context.Background(), bootstrapKID)
	if err != nil {
		t.Fatalf("get bootstrap key: %v", err)
	}
	if !got.Usable(time.Now()) {
		t.Fatal("the minted replacement is not usable")
	}
	sink.mustFind(t, "BOOTSTRAP ADMIN TOKEN — shown once, store it now")
}

// TestBootstrapAdminKeyTreatsAMissingRecordAsNothingToClear pins that the
// ErrNotFound branch is a normal first boot rather than a failure.
func TestBootstrapAdminKeyTreatsAMissingRecordAsNothingToClear(t *testing.T) {
	t.Parallel()

	st := newFileStore(t)
	h, _ := newKeyHub(t, st)
	if _, err := st.GetKey(context.Background(), bootstrapKID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("precondition: GetKey error = %v, want ErrNotFound", err)
	}
	if err := h.bootstrapAdminKey(context.Background()); err != nil {
		t.Fatalf("bootstrapAdminKey: %v", err)
	}
	if _, err := st.GetKey(context.Background(), bootstrapKID); err != nil {
		t.Fatalf("get bootstrap key: %v", err)
	}
}
