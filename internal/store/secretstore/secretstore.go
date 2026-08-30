// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
)

// Defaults for [Options].
const (
	// DefaultSecretName is the Secret the hub keeps its state in. It is also
	// the name the chart's Role restricts by resourceNames.
	DefaultSecretName = "prometheus-mcp-fleet-state"
	// DefaultKey is the key within the Secret holding the JSON document.
	DefaultKey = "state.json"
	// DefaultCacheTTL bounds how stale a read may be. One second is long
	// enough to absorb a burst of authentications and short enough that a
	// revocation made on another replica takes effect within one second,
	// which is well inside the verifier cache's own lifetime.
	DefaultCacheTTL = time.Second
	// DefaultMaxAttempts caps the compare-and-swap retries for one mutation.
	DefaultMaxAttempts = 5
	// DefaultBackoff is the first retry delay; it doubles per attempt and is
	// fully jittered.
	DefaultBackoff = 20 * time.Millisecond
	// maxBackoff caps one retry delay regardless of the attempt number.
	maxBackoff = 500 * time.Millisecond
)

// Options configures [Open].
type Options struct {
	// Client is the Kubernetes API client. Required. Its namespace is where
	// the Secret lives.
	Client *kube.Client
	// SecretName is the Secret's name. Empty means [DefaultSecretName].
	SecretName string
	// Key is the key within the Secret. Empty means [DefaultKey]. Other keys
	// in the same Secret are preserved on write.
	Key string
	// Labels are applied to the Secret when this process creates it. They are
	// not reconciled onto an existing Secret, because the chart owns it there.
	Labels map[string]string
	// CacheTTL bounds read staleness. Zero means [DefaultCacheTTL]; negative
	// disables the cache, which every test that asserts on API call counts
	// should do.
	CacheTTL time.Duration
	// MaxAttempts caps the compare-and-swap retries per mutation. Zero means
	// [DefaultMaxAttempts].
	MaxAttempts int
	// MaxBytes bounds the encoded document. Zero means [store.MaxStateBytes];
	// negative is unbounded, which only a test should ask for, since the API
	// server enforces 1 MiB regardless.
	MaxBytes int
	// Backoff is the first retry delay. Zero means [DefaultBackoff].
	Backoff time.Duration
	// Clock supplies the current time for operations given a zero timestamp
	// and for cache expiry. Nil means time.Now.
	Clock func() time.Time
	// Logger records conflicts and retries. Nil discards.
	Logger *slog.Logger
}

// Store is a store.Store backed by one key of one Kubernetes Secret.
type Store struct {
	kc          *kube.Client
	name        string
	key         string
	labels      map[string]string
	ttl         time.Duration
	maxAttempts int
	maxBytes    int
	backoff     time.Duration
	now         func() time.Time
	log         *slog.Logger

	// jitter returns a value in [0,1). It is a field so a test can make the
	// backoff deterministic.
	jitter func() float64
	// sleep waits for d or until ctx ends. It is a field for the same reason.
	sleep func(ctx context.Context, d time.Duration) error

	mu       sync.Mutex
	cached   *kube.Secret
	cachedAt time.Time
	size     int
	closed   bool
}

// Ensure the backend satisfies the interface it claims.
var _ store.Store = (*Store)(nil)

// Open returns a Store. It performs no I/O: the Secret is read, and created
// if absent, on the first operation, so a hub can construct its store before
// the API server is reachable and fail on a request rather than at wiring
// time.
func Open(opts Options) (*Store, error) {
	if opts.Client == nil {
		return nil, errors.New("secretstore: kubernetes client is required")
	}
	name := opts.SecretName
	if name == "" {
		name = DefaultSecretName
	}
	if err := kube.ValidateName(name); err != nil {
		return nil, fmt.Errorf("secretstore: secret name: %w", err)
	}
	key := opts.Key
	if key == "" {
		key = DefaultKey
	}
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}
	attempts := opts.MaxAttempts
	if attempts == 0 {
		attempts = DefaultMaxAttempts
	}
	if attempts < 1 {
		return nil, fmt.Errorf("secretstore: max attempts is %d, want at least 1", attempts)
	}
	maxBytes := opts.MaxBytes
	if maxBytes == 0 {
		maxBytes = store.MaxStateBytes
	}
	backoff := opts.Backoff
	if backoff == 0 {
		backoff = DefaultBackoff
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Store{
		kc:          opts.Client,
		name:        name,
		key:         key,
		labels:      maps.Clone(opts.Labels),
		ttl:         ttl,
		maxAttempts: attempts,
		maxBytes:    maxBytes,
		backoff:     backoff,
		now:         store.Clock(opts.Clock),
		log:         log,
		jitter:      rand.Float64,
		sleep:       sleepCtx,
	}, nil
}

// SecretName returns the Secret the state lives in.
func (s *Store) SecretName() string { return s.name }

// Size returns the encoded size of the document as of the last read or write,
// or 0 before the first operation. It is the value the hub publishes as
// promfleet_hub_state_bytes.
func (s *Store) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// Close releases the store. It is idempotent. There is no connection to tear
// down; the flag exists so that a use-after-close is reported rather than
// quietly served.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cached = nil
	return nil
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// cache stores sec as the current known Secret.
func (s *Store) cache(sec *kube.Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = sec
	s.cachedAt = s.now()
	s.size = len(sec.Data[s.key])
}

// invalidate drops the cache after a conflict, so the next read goes to the
// API server rather than re-proposing a write against a version that is
// already known to be stale.
func (s *Store) invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = nil
}

// cachedSecret returns the cached Secret if it is still fresh.
func (s *Store) cachedSecret() *kube.Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil || s.ttl <= 0 || s.now().Sub(s.cachedAt) >= s.ttl {
		return nil
	}
	return s.cached
}

// load returns the current Secret, creating it if this is the first use.
// fresh forces an API server round trip.
func (s *Store) load(ctx context.Context, fresh bool) (*kube.Secret, error) {
	if !fresh {
		if sec := s.cachedSecret(); sec != nil {
			return sec, nil
		}
	}
	sec, err := s.kc.GetSecret(ctx, s.name)
	switch {
	case err == nil:
		s.cache(sec)
		return sec, nil
	case !errors.Is(err, kube.ErrNotFound):
		return nil, fmt.Errorf("secretstore: %w", err)
	}

	// First use. Create the Secret with an empty document.
	empty, err := store.NewState().Encode()
	if err != nil {
		return nil, fmt.Errorf("secretstore: %w", err)
	}
	created, err := s.kc.CreateSecret(ctx, &kube.Secret{
		Name:   s.name,
		Data:   map[string][]byte{s.key: empty},
		Labels: s.labels,
	})
	switch {
	case err == nil:
		s.cache(created)
		return created, nil
	case errors.Is(err, kube.ErrAlreadyExists):
		// Another replica created it between the read and the create. Its
		// document is as good as ours, so adopt it.
		sec, err = s.kc.GetSecret(ctx, s.name)
		if err != nil {
			return nil, fmt.Errorf("secretstore: re-read after a lost create race: %w", err)
		}
		s.cache(sec)
		return sec, nil
	default:
		return nil, fmt.Errorf("secretstore: create state: %w", err)
	}
}

// decode extracts the document from a Secret. A Secret that exists without
// our key -- pre-created by an operator or by the chart -- reads as an empty
// document rather than as an error, so that a hub can adopt it.
func (s *Store) decode(sec *kube.Secret) (*store.State, error) {
	st, err := store.Decode(sec.Data[s.key])
	if err != nil {
		return nil, fmt.Errorf("secretstore: secret %s key %s: %w", s.name, s.key, err)
	}
	return st, nil
}

// read loads and decodes the document for a read-only operation.
func (s *Store) read(ctx context.Context) (*store.State, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if err := store.CheckContext(ctx, closed); err != nil {
		return nil, err
	}
	sec, err := s.load(ctx, false)
	if err != nil {
		return nil, err
	}
	return s.decode(sec)
}

// mutate applies fn to the document and writes the result back, conditional
// on the resourceVersion it read.
//
// This is the compare-and-swap the design depends on. An error from fn is a
// decision about the state, not a transport failure, so it is returned
// immediately: retrying "this enrollment token is already used" against a
// fresher read would only produce the same answer.
func (s *Store) mutate(ctx context.Context, fn func(*store.State) (bool, error)) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if err := store.CheckContext(ctx, closed); err != nil {
		return err
	}
	for attempt := range s.maxAttempts {
		sec, err := s.load(ctx, attempt > 0)
		if err != nil {
			return err
		}
		st, err := s.decode(sec)
		if err != nil {
			return err
		}
		changed, err := fn(st)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		encoded, err := st.EncodeWithin(s.maxBytes)
		if err != nil {
			return fmt.Errorf("secretstore: secret %s: %w", s.name, err)
		}
		// Copy the Secret's other keys forward: the CA material may share
		// this object, and a blind replace would delete it.
		data := maps.Clone(sec.Data)
		if data == nil {
			data = map[string][]byte{}
		}
		data[s.key] = encoded

		updated, err := s.kc.UpdateSecret(ctx, &kube.Secret{
			Name:            sec.Name,
			ResourceVersion: sec.ResourceVersion,
			Data:            data,
			Labels:          sec.Labels,
			Annotations:     sec.Annotations,
		})
		if err == nil {
			s.cache(updated)
			return nil
		}
		if !errors.Is(err, kube.ErrConflict) {
			return fmt.Errorf("secretstore: %w", err)
		}
		s.invalidate()
		s.log.Debug("secretstore: state secret changed under us, retrying",
			"secret", s.name, "attempt", attempt+1, "resourceVersion", sec.ResourceVersion)
		if err := s.sleep(ctx, s.backoffFor(attempt)); err != nil {
			return err
		}
	}
	return fmt.Errorf("secretstore: secret %s: another writer won every one of %d attempts, "+
		"which means sustained write contention rather than a transient race: %w",
		s.name, s.maxAttempts, kube.ErrConflict)
}

// backoffFor returns a fully jittered exponential delay for the given
// zero-based attempt. Full jitter rather than a fixed delay is what keeps two
// replicas that collided once from colliding again on the same schedule.
func (s *Store) backoffFor(attempt int) time.Duration {
	d := s.backoff << attempt
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	return time.Duration(s.jitter() * float64(d))
}

// PutKey implements store.Store.
func (s *Store) PutKey(ctx context.Context, k *fleet.Key) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.PutKey(k) })
}

// GetKey implements store.Store.
func (s *Store) GetKey(ctx context.Context, kid string) (*fleet.Key, error) {
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.GetKey(kid)
}

// ListKeys implements store.Store.
func (s *Store) ListKeys(ctx context.Context, class fleet.KeyClass) ([]*fleet.Key, error) {
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.ListKeys(class), nil
}

// RevokeKey implements store.Store.
func (s *Store) RevokeKey(ctx context.Context, kid, reason string, at time.Time) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) {
		return st.RevokeKey(kid, reason, at, s.now)
	})
}

// DeleteKey implements store.Store.
func (s *Store) DeleteKey(ctx context.Context, kid string) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.DeleteKey(kid) })
}

// TouchKey implements store.Store.
func (s *Store) TouchKey(ctx context.Context, kid string, at time.Time) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.TouchKey(kid, at, s.now) })
}

// BurnEnrollment implements store.Store.
func (s *Store) BurnEnrollment(ctx context.Context, kid, certSerial string, at time.Time) (*fleet.Key, error) {
	var burned *fleet.Key
	err := s.mutate(ctx, func(st *store.State) (bool, error) {
		k, changed, err := st.BurnEnrollment(kid, certSerial, at, s.now)
		burned = k
		return changed, err
	})
	if err != nil {
		return nil, err
	}
	return burned, nil
}

// RevokeCert implements store.Store.
func (s *Store) RevokeCert(ctx context.Context, rc store.RevokedCert) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.RevokeCert(rc, s.now) })
}

// ListRevokedCerts implements store.Store.
func (s *Store) ListRevokedCerts(ctx context.Context) ([]store.RevokedCert, error) {
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.ListRevokedCerts(), nil
}

// Epoch implements store.Store.
func (s *Store) Epoch(ctx context.Context) (uint64, error) {
	st, err := s.read(ctx)
	if err != nil {
		return 0, err
	}
	return st.Epoch, nil
}
