// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/secretstore"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/storetest"
)

// tBase is the fixed reference time used by the tests that need one.
var tBase = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// TestConformance is the whole contract, run against a fake API server with
// real resourceVersion semantics.
func TestConformance(t *testing.T) {
	t.Parallel()
	storetest.RunSuite(t, func(t *testing.T) store.Store {
		t.Helper()
		_, s := newStore(t, secretstore.Options{})
		return s
	})
}

// newStore starts a fake API server and opens a store against it. Defaults
// that would make a test non-deterministic -- the read cache and the backoff
// sleep -- are neutralised unless the test asked for them.
func newStore(t *testing.T, opts secretstore.Options) (*fakeAPI, *secretstore.Store) {
	t.Helper()
	api, client := newFakeAPI(t)
	if opts.Client == nil {
		opts.Client = client
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = -1 // read through on every call
	}
	if opts.Clock == nil {
		opts.Clock = func() time.Time { return tBase }
	}
	if opts.Backoff == 0 {
		opts.Backoff = time.Microsecond
	}
	s, err := secretstore.Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return api, s
}

func TestOpen(t *testing.T) {
	t.Parallel()
	_, client := newFakeAPI(t)
	tests := []struct {
		name    string
		opts    secretstore.Options
		wantErr string
	}{
		{"defaults", secretstore.Options{Client: client}, ""},
		{"no client", secretstore.Options{}, "kubernetes client is required"},
		{"bad secret name", secretstore.Options{Client: client, SecretName: "Not A Name"}, "secret name"},
		{"zero attempts is the default", secretstore.Options{Client: client, MaxAttempts: 0}, ""},
		{"one attempt is the minimum allowed", secretstore.Options{Client: client, MaxAttempts: 1}, ""},
		{"negative attempts", secretstore.Options{Client: client, MaxAttempts: -1}, "max attempts"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := secretstore.Open(tc.opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Open error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if s.SecretName() != secretstore.DefaultSecretName {
				t.Errorf("SecretName() = %q, want %q", s.SecretName(), secretstore.DefaultSecretName)
			}
			if s.Size() != 0 {
				t.Errorf("Size() = %d before the first operation, want 0", s.Size())
			}
		})
	}
}

func TestCreatesTheSecretOnFirstUse(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{Labels: map[string]string{"app.kubernetes.io/name": "prometheus-mcp-fleet"}})

	if _, err := s.Epoch(t.Context()); err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	data, ok := api.get(secretstore.DefaultSecretName)
	if !ok {
		t.Fatal("the state secret was not created on first use")
	}
	if _, ok := data[secretstore.DefaultKey]; !ok {
		t.Errorf("secret keys = %v, want %q", data, secretstore.DefaultKey)
	}
	if s.Size() != len(data[secretstore.DefaultKey]) {
		t.Errorf("Size() = %d, want the document's %d", s.Size(), len(data[secretstore.DefaultKey]))
	}
	_, creates, _, _ := api.counts()
	if creates != 1 {
		t.Errorf("create calls = %d, want 1", creates)
	}
}

func TestAdoptsALostCreateRace(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	// Another replica creates the Secret in the window between this store's
	// 404 and its own create.
	api.beforeWrite = func() {
		api.beforeWrite = nil
		api.seed(secretstore.DefaultSecretName, map[string][]byte{
			secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":7}`),
		})
	}
	got, err := s.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if got != 7 {
		t.Errorf("epoch = %d, want the other replica's 7 -- a lost create race must adopt, not overwrite", got)
	}
}

func TestAdoptsAPreCreatedSecret(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	// The chart may create an empty Secret. It has no state key, which must
	// read as an empty document rather than as corruption.
	api.seed(secretstore.DefaultSecretName, map[string][]byte{"ca.crt": []byte("unrelated")})

	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	data, _ := api.get(secretstore.DefaultSecretName)
	if string(data["ca.crt"]) != "unrelated" {
		t.Errorf("writing state deleted the sibling key: %v", data)
	}
	if _, ok := data[secretstore.DefaultKey]; !ok {
		t.Error("the state key was not written")
	}
}

// TestBurnEnrollmentIsAtomicAcrossReplicas is the reason this backend exists.
// Every "replica" is an independent Store with its own cache, racing to
// redeem one single-use token through one API server.
func TestBurnEnrollmentIsAtomicAcrossReplicas(t *testing.T) {
	t.Parallel()
	api, client := newFakeAPI(t)

	const replicas = 8
	stores := make([]*secretstore.Store, replicas)
	for i := range stores {
		s, err := secretstore.Open(secretstore.Options{
			Client:   client,
			CacheTTL: time.Second, // the real default: a stale read must not break the burn
			Clock:    func() time.Time { return tBase },
			Backoff:  time.Microsecond,
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		stores[i] = s
	}

	token := enrollmentKey("enrol0001", "prod-eu-1")
	if err := stores[0].PutKey(t.Context(), token); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	// Every replica has now cached a document in which the token is unused,
	// which is precisely the state that makes a naive implementation issue
	// two certificates.
	for _, s := range stores {
		if _, err := s.GetKey(t.Context(), token.KID); err != nil {
			t.Fatalf("GetKey: %v", err)
		}
	}

	type outcome struct {
		serial string
		err    error
	}
	results := make([]outcome, replicas)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(replicas)
	for i, s := range stores {
		go func() {
			defer done.Done()
			serial := fmt.Sprintf("serial-%02d", i)
			start.Wait()
			_, err := s.BurnEnrollment(context.Background(), token.KID, serial, tBase)
			results[i] = outcome{serial: serial, err: err}
		}()
	}
	start.Done()
	done.Wait()

	var winners []string
	for _, r := range results {
		switch {
		case r.err == nil:
			winners = append(winners, r.serial)
		case errors.Is(r.err, store.ErrEnrollmentUsed):
		default:
			t.Errorf("%s: error = %v, want nil or ErrEnrollmentUsed", r.serial, r.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("%d of %d replicas redeemed the token, want exactly 1: %v", len(winners), replicas, winners)
	}
	stored, err := stores[0].GetKey(t.Context(), token.KID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if stored.Enrollment.CertSerial != winners[0] {
		t.Errorf("stored CertSerial = %q, want the winner's %q", stored.Enrollment.CertSerial, winners[0])
	}
	if _, _, _, conflicts := api.counts(); conflicts == 0 {
		t.Error("no update was ever rejected: the test did not exercise the compare-and-swap")
	}
}

// TestConcurrentDistinctWritesAllLand proves the retry loop merges rather
// than clobbers: two writers changing different records must both survive.
func TestConcurrentDistinctWritesAllLand(t *testing.T) {
	t.Parallel()
	api, client := newFakeAPI(t)
	const writers = 6
	s, err := secretstore.Open(secretstore.Options{
		Client: client,
		// Raised above the default because this test deliberately creates
		// worst-case contention on one document; the default of 5 is sized
		// for the real workload, where writes are rare.
		MaxAttempts: 40,
		CacheTTL:    -1,
		Backoff:     time.Microsecond,
		Clock:       func() time.Time { return tBase },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.PutKey(context.Background(), agentKey(fmt.Sprintf("agent%04d", i))); err != nil {
				t.Errorf("PutKey: %v", err)
			}
		}()
	}
	wg.Wait()

	keys, err := s.ListKeys(t.Context(), fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != writers {
		t.Errorf("stored %d keys, want %d: a lost update dropped a credential", len(keys), writers)
	}
	epoch, err := s.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if epoch != writers {
		t.Errorf("epoch = %d, want %d", epoch, writers)
	}
	if _, _, _, conflicts := api.counts(); conflicts == 0 {
		t.Error("no update was ever rejected: the test did not exercise the retry loop")
	}
}

func TestRetriesAreBounded(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{MaxAttempts: 3})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
	})
	// A writer that always loses: something else advances the object between
	// every read and write.
	api.beforeWrite = func() {
		api.seed(secretstore.DefaultSecretName, map[string][]byte{
			secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
		})
	}
	err := s.PutKey(t.Context(), agentKey("agent0001"))
	if !errors.Is(err, kube.ErrConflict) {
		t.Fatalf("PutKey error = %v, want a wrapped kube.ErrConflict", err)
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("error %q does not say how many attempts were made", err)
	}
	if _, _, _, conflicts := api.counts(); conflicts != 3 {
		t.Errorf("conflicts = %d, want exactly the 3 permitted attempts", conflicts)
	}
}

// TestMutateFirstAttemptUsesCache proves the first attempt of a mutation
// consults the read cache rather than forcing an API round trip. mutate loads
// with fresh=attempt>0, so attempt 0 must pass fresh=false. A mutant that
// widens or negates that comparison makes even the first attempt force a
// fresh read, which this catches as an extra GET.
func TestMutateFirstAttemptUsesCache(t *testing.T) {
	t.Parallel()
	now := tBase
	api, s := newStore(t, secretstore.Options{
		CacheTTL: 10 * time.Second,
		Clock:    func() time.Time { return now },
	})
	// Populate the cache and let the create/read settle.
	if _, err := s.Epoch(t.Context()); err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	getsBefore, _, _, _ := api.counts()
	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	if getsAfter, _, _, _ := api.counts(); getsAfter != getsBefore {
		t.Errorf("GET calls during an uncontested PutKey = %d, want 0: the first mutate attempt must use the fresh cache",
			getsAfter-getsBefore)
	}
}

// TestConflictLogsOneBasedAttemptNumber proves the retry log's "attempt"
// field is attempt+1 (one-based, matching what an operator reading the log
// expects: "attempt 1" for the first try). An ARITHMETIC_BASE mutant turning
// that into attempt-1 would log -1 on the very first conflict.
func TestConflictLogsOneBasedAttemptNumber(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	api, s := newStore(t, secretstore.Options{MaxAttempts: 3, Logger: logger})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
	})
	// A writer that always loses, so every one of the 3 permitted attempts logs
	// a conflict.
	api.beforeWrite = func() {
		api.seed(secretstore.DefaultSecretName, map[string][]byte{
			secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
		})
	}
	err := s.PutKey(t.Context(), agentKey("agent0001"))
	if !errors.Is(err, kube.ErrConflict) {
		t.Fatalf("PutKey error = %v, want a wrapped kube.ErrConflict", err)
	}

	var attempts []int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Attempt int `json:"attempt"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}
		attempts = append(attempts, rec.Attempt)
	}
	if diff := cmp.Diff([]int{1, 2, 3}, attempts); diff != "" {
		t.Errorf("logged attempt numbers differ (-want +got):\n%s", diff)
	}
}

func TestConflictThenSuccess(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":4}`),
	})
	once := sync.Once{}
	api.beforeWrite = func() {
		once.Do(func() {
			api.seed(secretstore.DefaultSecretName, map[string][]byte{
				secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":5}`),
			})
		})
	}
	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	// The retry must have been applied to the other writer's document, not to
	// the stale one this store first read.
	epoch, err := s.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if epoch != 6 {
		t.Errorf("epoch = %d, want 6 (the concurrent writer's 5, plus this write)", epoch)
	}
}

func TestMutationInitializesANilSecretDataMap(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	api.seed(secretstore.DefaultSecretName, nil)
	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey into Secret with nil data: %v", err)
	}
	if _, err := s.GetKey(t.Context(), "agent0001"); err != nil {
		t.Errorf("GetKey after initializing nil data: %v", err)
	}
}

func TestConflictBackoffHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{MaxAttempts: 3, Backoff: time.Hour})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1}`),
	})
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	api.beforeWrite = func() {
		api.seed(secretstore.DefaultSecretName, map[string][]byte{
			secretstore.DefaultKey: []byte(`{"schemaVersion":1}`),
		})
		once.Do(func() { time.AfterFunc(20*time.Millisecond, cancel) })
	}
	err := s.PutKey(ctx, agentKey("agent0001"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("PutKey = %v, want context.Canceled during conflict backoff", err)
	}
}

func TestCacheServesReads(t *testing.T) {
	t.Parallel()
	now := tBase
	api, s := newStore(t, secretstore.Options{
		CacheTTL: 10 * time.Second,
		Clock:    func() time.Time { return now },
	})
	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	getsAfterWrite, _, _, _ := api.counts()
	for range 5 {
		if _, err := s.GetKey(t.Context(), "agent0001"); err != nil {
			t.Fatalf("GetKey: %v", err)
		}
	}
	gets, _, _, _ := api.counts()
	if gets != getsAfterWrite {
		t.Errorf("%d API reads for 5 cached lookups, want 0", gets-getsAfterWrite)
	}

	// 5s is well past DefaultCacheTTL (1s) but short of the 10s configured
	// above. Serving this one from cache too proves the configured TTL is
	// actually in effect, not silently replaced by the default -- both would
	// pass the "0 refreshes so far" checks above, since nothing has aged past
	// either one yet.
	now = now.Add(5 * time.Second)
	if _, err := s.GetKey(t.Context(), "agent0001"); err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if gets, _, _, _ := api.counts(); gets != getsAfterWrite {
		t.Errorf("API reads at 5s (past the 1s default, inside the configured 10s ttl) = %d, want 0: the configured CacheTTL is not being honoured",
			gets-getsAfterWrite)
	}

	now = now.Add(6 * time.Second) // total 11s since the write
	if _, err := s.GetKey(t.Context(), "agent0001"); err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if gets, _, _, _ := api.counts(); gets != getsAfterWrite+1 {
		t.Errorf("API reads after the ttl = %d, want one refresh", gets-getsAfterWrite)
	}
}

func TestStateTooLarge(t *testing.T) {
	t.Parallel()
	_, s := newStore(t, secretstore.Options{MaxBytes: 500})
	var last error
	for i := range 30 {
		last = s.PutKey(t.Context(), &fleet.Key{
			KID:       fmt.Sprintf("agent%04d", i),
			Class:     fleet.ClassAgent,
			Name:      strings.Repeat("x", 40),
			CreatedAt: tBase,
		})
		if last != nil {
			break
		}
	}
	if !errors.Is(last, store.ErrStateTooLarge) {
		t.Fatalf("error = %v, want ErrStateTooLarge", last)
	}
	for _, want := range []string{"500 byte limit", "keys", "revoked certificates", "notAfter"} {
		if !strings.Contains(last.Error(), want) {
			t.Errorf("error %q does not contain %q -- an operator must be told what to prune", last, want)
		}
	}
	// Size must still report the last good document so the metric does not go
	// blank exactly when it matters.
	if s.Size() == 0 || s.Size() > 500 {
		t.Errorf("Size() = %d, want the last accepted document's size", s.Size())
	}
}

func TestAPIFailuresPropagate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		code    int
		reason  string
		message string
		want    error
		hint    string
	}{
		{
			name: "forbidden", code: http.StatusForbidden, reason: "Forbidden",
			message: `secrets is forbidden: User "system:serviceaccount:monitoring:hub" cannot get resource "secrets"`,
			want:    kube.ErrForbidden,
			hint:    "secrets get/create/update in namespace monitoring",
		},
		{
			name: "server error", code: http.StatusInternalServerError, reason: "InternalError",
			message: "etcd is unavailable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			api, s := newStore(t, secretstore.Options{})
			api.failEvery = func(string) (int, string, string, bool) {
				return tc.code, tc.reason, tc.message, true
			}
			readErr := errFrom(func() error { _, err := s.Epoch(t.Context()); return err })
			writeErr := s.PutKey(t.Context(), agentKey("agent0001"))
			for _, err := range []error{readErr, writeErr} {
				if err == nil {
					t.Fatal("the API failure did not surface")
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Errorf("error = %v, want %v", err, tc.want)
				}
				if tc.hint != "" && !strings.Contains(err.Error(), tc.hint) {
					t.Errorf("error %q does not name the missing RBAC rule", err)
				}
			}
		})
	}
}

func TestCreateFailurePropagates(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	api.failEvery = func(method string) (int, string, string, bool) {
		if method == http.MethodPost {
			return http.StatusForbidden, "Forbidden", "cannot create resource secrets", true
		}
		return 0, "", "", false
	}
	err := s.PutKey(t.Context(), agentKey("agent0001"))
	if !errors.Is(err, kube.ErrForbidden) {
		t.Fatalf("error = %v, want kube.ErrForbidden", err)
	}
	if !strings.Contains(err.Error(), "create state") {
		t.Errorf("error %q does not say which step failed", err)
	}
}

func TestLostCreateRaceReReadFailurePropagates(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	var gets int
	api.failEvery = func(method string) (int, string, string, bool) {
		if method == http.MethodGet {
			gets++
			if gets > 1 {
				return http.StatusInternalServerError, "InternalError", "etcd is unavailable", true
			}
		}
		return 0, "", "", false
	}
	api.beforeWrite = func() {
		api.beforeWrite = nil
		api.seed(secretstore.DefaultSecretName, map[string][]byte{secretstore.DefaultKey: []byte("{}")})
	}
	_, err := s.Epoch(t.Context())
	if err == nil || !strings.Contains(err.Error(), "lost create race") {
		t.Errorf("error = %v, want the re-read failure to name its cause", err)
	}
}

func TestCorruptDocumentIsReported(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{secretstore.DefaultKey: []byte("{not json")})

	if _, err := s.Epoch(t.Context()); !errors.Is(err, store.ErrCorrupt) {
		t.Errorf("Epoch error = %v, want ErrCorrupt", err)
	}
	if err := s.PutKey(t.Context(), agentKey("agent0001")); !errors.Is(err, store.ErrCorrupt) {
		t.Errorf("PutKey error = %v, want ErrCorrupt", err)
	}
}

func TestCancelledContextDuringBackoff(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{MaxAttempts: 5, Backoff: time.Hour})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
	})
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel from a separate goroutine once a conflict has actually been
	// served, not from inside the write hook.
	//
	// beforeWrite runs while the update request is still in flight, so
	// cancelling there raced the response: sometimes the store saw the 409 and
	// was cancelled in the hour-long backoff, which is the path this test is
	// named for, and sometimes the HTTP round trip itself was cancelled and
	// the store took the non-conflict error return instead. errors.Is matched
	// context.Canceled either way, so the test passed either way -- while
	// which of the two statements got executed flipped between runs, and the
	// package's 100% coverage floor failed CI whenever the loser was the
	// non-conflict return. That one now has TestUpdateFailurePropagates.
	//
	// The backoff is an hour, so once a conflict is counted the store is
	// parked in sleep() and cancelling is unambiguous.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, _, conflicts := api.counts(); conflicts > 0 {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })

	api.beforeWrite = func() {
		api.seed(secretstore.DefaultSecretName, map[string][]byte{
			secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
		})
	}
	err := s.PutKey(ctx, agentKey("agent0001"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("PutKey error = %v, want context.Canceled rather than a full backoff", err)
	}
}

// TestUpdateFailurePropagates covers the update error that is not a conflict.
// It is a distinct statement from the conflict retry beside it, and leaving it
// to be reached incidentally by a racing cancellation is how it went uncovered
// at random.
func TestUpdateFailurePropagates(t *testing.T) {
	t.Parallel()
	api, s := newStore(t, secretstore.Options{})
	api.seed(secretstore.DefaultSecretName, map[string][]byte{
		secretstore.DefaultKey: []byte(`{"schemaVersion":1,"epoch":1}`),
	})
	api.failEvery = func(method string) (int, string, string, bool) {
		if method == http.MethodPut {
			return http.StatusInternalServerError, "InternalError", "etcd is unavailable", true
		}
		return 0, "", "", false
	}
	err := s.PutKey(t.Context(), agentKey("agent0001"))
	if err == nil {
		t.Fatal("PutKey = nil, want the update failure")
	}
	if errors.Is(err, kube.ErrConflict) {
		t.Fatalf("PutKey error = %v, want a non-conflict failure", err)
	}
	if !strings.Contains(err.Error(), "secretstore:") {
		t.Errorf("error %q is not wrapped by the store", err)
	}
}

func TestSizeSurvivesClose(t *testing.T) {
	t.Parallel()
	_, s := newStore(t, secretstore.Options{})
	if err := s.PutKey(t.Context(), agentKey("agent0001")); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	before := s.Size()
	if before == 0 {
		t.Fatal("Size() = 0 after a write")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.Size(); got != before {
		t.Errorf("Size() = %d after Close, want the last known %d", got, before)
	}
}

// errFrom runs f and returns its error, keeping the table above readable.
func errFrom(f func() error) error { return f() }

func agentKey(kid string) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassAgent,
		Name:       "key-" + kid,
		SecretHMAC: []byte("hmac-" + kid),
		CreatedAt:  tBase,
		ExpiresAt:  tBase.Add(720 * time.Hour),
	}
}

func enrollmentKey(kid, clusterID string) *fleet.Key {
	return &fleet.Key{
		KID:        kid,
		Class:      fleet.ClassEnrollment,
		Name:       "enroll-" + clusterID,
		SecretHMAC: []byte("hmac-" + kid),
		Enrollment: &fleet.EnrollmentGrant{ClusterID: clusterID},
		CreatedAt:  tBase,
		ExpiresAt:  tBase.Add(15 * time.Minute),
	}
}

// TestPruneIsSafeWithSeveralReplicas is the HA case: every hub replica runs
// its own pruner against one Secret, and on a rollout they all start within
// seconds of each other, so their first passes collide.
//
// What must hold is that the collision is boring. One replica's write wins;
// the losers retry, re-read, find the work already done and return without
// writing at all. No error reaches the caller, no record is removed twice,
// and the surviving records are exactly the ones a single pruner would have
// left.
func TestPruneIsSafeWithSeveralReplicas(t *testing.T) {
	t.Parallel()

	const replicas = 4
	_, client := newFakeAPI(t)
	_, seeder := newStore(t, secretstore.Options{Client: client})

	// Two credentials long past their expiry, one still live.
	for _, kid := range []string{"agent0001", "agent0002"} {
		k := agentKey(kid)
		k.ExpiresAt = tBase.Add(-90 * 24 * time.Hour)
		if err := seeder.PutKey(t.Context(), k); err != nil {
			t.Fatalf("seed %s: %v", kid, err)
		}
	}
	if err := seeder.PutKey(t.Context(), agentKey("agent0003")); err != nil {
		t.Fatalf("seed live key: %v", err)
	}

	// Every replica shares the one API, as they share the one Secret.
	stores := make([]*secretstore.Store, 0, replicas)
	for range replicas {
		_, s := newStore(t, secretstore.Options{Client: client})
		stores = append(stores, s)
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		removed int
		errs    []error
	)
	start := make(chan struct{})
	for _, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release them together, which is the rollout shape
			res, err := s.Prune(context.Background(), 24*time.Hour)
			mu.Lock()
			defer mu.Unlock()
			removed += res.Keys
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("concurrent prunes reported %d errors, want none: %v", len(errs), errs)
	}
	// Exactly one replica does the removing. Anything else means two writers
	// each believed they had pruned the same record.
	if removed != 2 {
		t.Errorf("replicas removed %d keys in total, want 2 (one winner, the rest no-ops)", removed)
	}

	keys, err := seeder.ListKeys(t.Context(), fleet.ClassAgent)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KID != "agent0003" {
		t.Errorf("surviving keys = %+v, want only the live one", keys)
	}
}
