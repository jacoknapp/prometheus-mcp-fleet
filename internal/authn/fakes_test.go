// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// fakeStore is an in-memory [KeyStore]. It is safe for concurrent use and
// records call counts so a test can prove the cache actually avoided a lookup.
type fakeStore struct {
	mu         sync.Mutex
	keys       map[string]*fleet.Key
	epoch      uint64
	getCalls   int
	epochCalls int
	touches    map[string]time.Time

	// touchGate, when non-nil, blocks TouchKey until it is closed. It is how a
	// test proves the last-used write is off the request path.
	touchGate chan struct{}

	getErr   error
	epochErr error
	touchErr error

	// getNil makes GetKey report a miss the other legal way: no key and no
	// error. A store is free to signal absence either way, so the verifier
	// has to classify both as an unknown key.
	getNil bool
}

func (f *fakeStore) setGetNil(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getNil = v
}

func newFakeStore() *fakeStore {
	return &fakeStore{keys: map[string]*fleet.Key{}, touches: map[string]time.Time{}, epoch: 1}
}

func (f *fakeStore) GetKey(_ context.Context, kid string) (*fleet.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getNil {
		return nil, nil
	}
	k, ok := f.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %s: %w", kid, ErrKeyNotFound)
	}
	cp := *k
	return &cp, nil
}

func (f *fakeStore) TouchKey(_ context.Context, kid string, at time.Time) error {
	f.mu.Lock()
	gate := f.touchGate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.touchErr != nil {
		return f.touchErr
	}
	f.touches[kid] = at
	return nil
}

func (f *fakeStore) Epoch(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epochCalls++
	if f.epochErr != nil {
		return 0, f.epochErr
	}
	return f.epoch, nil
}

// put stores a key.
func (f *fakeStore) put(k *fleet.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[k.KID] = k
}

// mutate applies fn to a stored key and bumps the epoch, which is what every
// real mutating store operation except TouchKey does.
func (f *fakeStore) mutate(kid string, fn func(*fleet.Key)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k, ok := f.keys[kid]; ok {
		fn(k)
	}
	f.epoch++
}

func (f *fakeStore) gets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls
}

// epochs returns how many times the revocation epoch has been read.
func (f *fakeStore) epochs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epochCalls
}

// currentEpoch returns the stored epoch without counting as a read.
func (f *fakeStore) currentEpoch() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.epoch
}

func (f *fakeStore) touchedAt(kid string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.touches[kid]
	return at, ok
}

func (f *fakeStore) setErrs(get, epoch error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErr, f.epochErr = get, epoch
}

// countingMetrics records every metric call.
type countingMetrics struct {
	mu        sync.Mutex
	successes map[fleet.KeyClass]int
	failures  map[string]int
	hits      int
	misses    int
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{successes: map[fleet.KeyClass]int{}, failures: map[string]int{}}
}

func (m *countingMetrics) AuthSuccess(c fleet.KeyClass) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successes[c]++
}

func (m *countingMetrics) AuthFailure(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures[reason]++
}

func (m *countingMetrics) CacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits++
}

func (m *countingMetrics) CacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.misses++
}

func (m *countingMetrics) failure(reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failures[reason]
}

func (m *countingMetrics) hitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits
}

// testPepper is a fixed, non-secret pepper for tests.
var testPepper = []byte("0123456789abcdef0123456789abcdef")

// newTestHasher returns a hasher keyed with [testPepper].
func newTestHasher(t *testing.T) *token.Hasher {
	t.Helper()
	h, err := token.NewHasher(testPepper)
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return h
}

// mintKey mints a credential, stores its record in f, and returns the raw
// token alongside the stored record so a test can mutate it.
func mintKey(t *testing.T, f *fakeStore, h *token.Hasher, class fleet.KeyClass, mutate func(*fleet.Key)) (string, *fleet.Key) {
	t.Helper()
	m, err := token.Mint(class)
	if err != nil {
		t.Fatalf("Mint(%s): %v", class, err)
	}
	k := &fleet.Key{
		KID:        m.KID,
		Class:      class,
		Name:       "test-" + string(class),
		SecretHMAC: h.Sum(m.Secret),
		CreatedAt:  testNow.Add(-time.Hour),
		ExpiresAt:  testNow.Add(time.Hour),
	}
	if class == fleet.ClassAgent {
		k.Scope = &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"*"}},
			Tools:    fleet.ToolScope{Allow: []string{"prom.query"}},
		}
	}
	if mutate != nil {
		mutate(k)
	}
	f.put(k)
	return m.Raw.Reveal(), k
}

// testNow is the fixed instant the fake clock starts at.
var testNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: testNow} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
