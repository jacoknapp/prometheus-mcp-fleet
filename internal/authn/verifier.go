// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// Defaults applied by [New] when the corresponding [Options] field is zero.
const (
	// DefaultCacheSize is the number of verified credentials held in the
	// positive cache.
	DefaultCacheSize = 10000
	// DefaultCacheTTL bounds how long a verified credential is served from
	// cache without re-reading the revocation epoch's neighbours. It is also
	// the worst-case revocation latency if the epoch itself cannot be read.
	DefaultCacheTTL = 60 * time.Second
	// DefaultNegativeTTL bounds how long a rejection is remembered. It is
	// short because a legitimate client that has just been issued a
	// replacement credential must not be locked out.
	DefaultNegativeTTL = 5 * time.Second
	// DefaultRealm is the WWW-Authenticate realm when none is configured.
	DefaultRealm = "prometheus-mcp-fleet"
	// touchConcurrency bounds the goroutines spent recording last-used
	// timestamps. Beyond it the update is dropped: it is best-effort telemetry
	// and must never become backpressure on a request.
	touchConcurrency = 32
	// touchTimeout bounds one best-effort last-used write.
	touchTimeout = 5 * time.Second
)

// KeyStore is the subset of persistence the verifier requires.
//
// It is declared here, not imported from internal/store, so that the
// authentication hot path depends on four methods rather than on a persistence
// implementation. The real store satisfies it structurally; tests supply a map.
//
// Implementations must be safe for concurrent use.
type KeyStore interface {
	// GetKey returns the stored record for kid, including its SecretHMAC. It
	// returns an error satisfying errors.Is(err, [ErrKeyNotFound]) -- or an
	// error accepted by [Options.IsNotFound] -- when no record exists.
	GetKey(ctx context.Context, kid string) (*fleet.Key, error)
	// TouchKey records that the key was used at the given time. It must not
	// bump the revocation epoch.
	TouchKey(ctx context.Context, kid string, at time.Time) error
	// Epoch returns the monotonic revocation epoch. Every mutation that can
	// invalidate a cached verification increments it.
	Epoch(ctx context.Context) (uint64, error)
}

// Options configures a [Verifier]. Only Store and Hasher are required; every
// other field has a documented default.
type Options struct {
	// Store is the credential lookup. Required.
	Store KeyStore
	// Hasher reduces a presented secret to the stored digest and supplies the
	// decoy hash used on a key-identifier miss. Required.
	Hasher *token.Hasher
	// Logger receives authentication events. Nil discards them. The verifier
	// never logs a token, a secret, a digest or an Authorization header.
	Logger *slog.Logger
	// Metrics counts successes, failures and cache behaviour. Nil means
	// [NopMetrics].
	Metrics Metrics
	// CacheSize bounds the verified-credential cache. Zero means
	// [DefaultCacheSize].
	CacheSize int
	// CacheTTL bounds how long a verified credential is reused. Zero means
	// [DefaultCacheTTL].
	CacheTTL time.Duration
	// NegativeTTL bounds how long a rejection is remembered. Zero means
	// [DefaultNegativeTTL].
	NegativeTTL time.Duration
	// Clock supplies the current time. Nil means time.Now.
	Clock func() time.Time
	// Realm is the WWW-Authenticate realm emitted on 401. Empty means
	// [DefaultRealm].
	Realm string
	// ResourceMetadataURL, when set, is advertised as resource_metadata in the
	// WWW-Authenticate challenge so an MCP client can discover the protected
	// resource document. See internal/hubapi for what that document says.
	ResourceMetadataURL string
	// IsNotFound reports whether a [KeyStore] error means "no such key", as
	// opposed to "the store could not be read". It only affects the failure
	// reason recorded in metrics and logs -- both outcomes deny the request --
	// but telling them apart is the difference between "someone is guessing
	// key ids" and "persistence is broken". Nil means errors.Is against
	// [ErrKeyNotFound].
	IsNotFound func(error) bool
}

// cacheEntry is one verified credential held in the positive cache. It holds
// no secret material: the principal carries only public identifiers, and the
// cache key is a hash of the token rather than the token.
type cacheEntry struct {
	principal *fleet.Principal
	keyExpiry time.Time
	cachedAt  time.Time
	epoch     uint64
}

// negEntry is one remembered rejection.
type negEntry struct {
	err      error
	reason   string
	cachedAt time.Time
}

// Verifier authenticates `pmf_` bearer credentials against a [KeyStore].
//
// It is safe for concurrent use by any number of goroutines. Construct it once
// per process with [New] and share it between the MCP listener, the admin
// listener and the enrollment endpoint; the cache and the failure limiter are
// process-wide on purpose, so a token verified for one listener is not
// re-verified for another.
type Verifier struct {
	store   KeyStore
	hasher  *token.Hasher
	log     *slog.Logger
	metrics Metrics
	clock   func() time.Time

	cacheTTL    time.Duration
	negativeTTL time.Duration
	realm       string
	resourceMD  string
	isNotFound  func(error) bool

	pos *lruCache[[sha256.Size]byte, cacheEntry]
	neg *lruCache[[sha256.Size]byte, negEntry]

	limiter *failureLimiter

	// epoch is the last revocation epoch the verifier observed. A change
	// purges both caches.
	epochMu sync.Mutex
	epoch   uint64
	epochOK bool

	// decoy performs the constant-work HMAC on a key-identifier miss. It is a
	// field rather than a direct call so tests can prove it actually runs.
	decoy func(secret []byte)

	// touchSem bounds background last-used writes; touchWG lets Close wait for
	// them so a test or a shutdown does not race an in-flight store write.
	touchSem chan struct{}
	touchWG  sync.WaitGroup
}

// New returns a Verifier configured by opts. It returns an error when Store or
// Hasher is missing; every other field is defaulted.
func New(opts Options) (*Verifier, error) {
	if opts.Store == nil {
		return nil, errors.New("authn: Options.Store is required")
	}
	if opts.Hasher == nil {
		return nil, errors.New("authn: Options.Hasher is required")
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = DefaultCacheSize
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = DefaultNegativeTTL
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Metrics == nil {
		opts.Metrics = NopMetrics{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Realm == "" {
		opts.Realm = DefaultRealm
	}
	if opts.IsNotFound == nil {
		opts.IsNotFound = func(err error) bool { return errors.Is(err, ErrKeyNotFound) }
	}
	v := &Verifier{
		store:       opts.Store,
		hasher:      opts.Hasher,
		log:         opts.Logger,
		metrics:     opts.Metrics,
		clock:       opts.Clock,
		cacheTTL:    opts.CacheTTL,
		negativeTTL: opts.NegativeTTL,
		realm:       opts.Realm,
		resourceMD:  opts.ResourceMetadataURL,
		isNotFound:  opts.IsNotFound,
		pos:         newLRU[[sha256.Size]byte, cacheEntry](opts.CacheSize),
		neg:         newLRU[[sha256.Size]byte, negEntry](opts.CacheSize),
		limiter:     newFailureLimiter(),
		touchSem:    make(chan struct{}, touchConcurrency),
	}
	v.decoy = opts.Hasher.Decoy
	return v, nil
}

// Close waits for outstanding best-effort last-used writes to finish. It is
// idempotent, always returns nil, and does not stop the verifier from being
// used afterwards; it exists so a composition root can shut the store down
// without racing a background write.
func (v *Verifier) Close() error {
	v.touchWG.Wait()
	return nil
}

// Verify authenticates a raw bearer token and returns the principal it
// identifies.
//
// want is the credential class the calling listener requires. A token of any
// other class is refused with [ErrWrongClass] even if it is otherwise
// perfectly valid, which is what keeps an agent key off the admin API and an
// admin key out of the enrollment endpoint.
//
// The returned errors are [ErrUnauthenticated], [ErrWrongClass], [ErrExpired],
// [ErrRevoked] and [ErrRateLimited]. None of them contains any part of raw.
// A returned principal is a fresh value the caller may retain; it carries no
// secret material.
func (v *Verifier) Verify(ctx context.Context, raw string, want fleet.KeyClass) (*fleet.Principal, error) {
	p, _, err := v.verify(ctx, raw, want)
	return p, err
}

// verify is Verify plus the credential's expiry, which [Verifier.TokenVerifier]
// needs for auth.TokenInfo and which callers have no other reason to see.
func (v *Verifier) verify(ctx context.Context, raw string, want fleet.KeyClass) (*fleet.Principal, time.Time, error) {
	now := v.clock()

	// 1. Shape, length and checksum, before any lookup or keyed hash.
	class, kid, secret, err := token.Parse(raw)
	if err != nil {
		v.metrics.AuthFailure(ReasonMalformed)
		return nil, time.Time{}, fmt.Errorf("parse credential: %w", ErrUnauthenticated)
	}

	// 2. The class segment is public plaintext, so refusing here leaks
	//    nothing and saves the store a lookup it could never authorize.
	if class != want {
		v.metrics.AuthFailure(ReasonWrongClass)
		return nil, time.Time{}, fmt.Errorf("credential is class %q, listener requires %q: %w", class, want, ErrWrongClass)
	}

	sum := sha256.Sum256([]byte(raw))

	// 3. Epoch first: a bump purges both caches, so a revocation lands on the
	//    very next request rather than at the end of the TTL.
	epoch, epochErr := v.syncEpoch(ctx)

	if epochErr == nil {
		if p, exp, decided, err := v.fromCache(sum, want, epoch, now); decided {
			return p, exp, err
		}
	}
	v.metrics.CacheMiss()

	// 4. Only failures are rate limited, and only after the caches have been
	//    consulted, so a valid client is never throttled.
	ip := SourceIPFrom(ctx)
	if !v.limiter.Allow(ip, now) {
		v.metrics.AuthFailure(ReasonRateLimited)
		return nil, time.Time{}, fmt.Errorf("source in authentication backoff: %w", ErrRateLimited)
	}

	if epochErr != nil {
		// Not negative-cached: the epoch read gates the cache lookup itself,
		// so an entry recorded here could never be consulted.
		v.metrics.AuthFailure(ReasonStoreError)
		v.limiter.Fail(ip, now)
		v.log.LogAttrs(ctx, slog.LevelError, "authentication denied: revocation epoch unreadable",
			slog.String("error", epochErr.Error()))
		return nil, time.Time{}, fmt.Errorf("read revocation epoch: %w", ErrUnauthenticated)
	}

	p, exp, reason, err := v.verifyAgainstStore(ctx, kid, secret, want, now)
	if err != nil {
		v.fail(ctx, ip, now, sum, reason, err)
		return nil, time.Time{}, err
	}

	p.Epoch = epoch
	v.pos.Put(sum, cacheEntry{principal: p, keyExpiry: exp, cachedAt: now, epoch: epoch})
	v.neg.Remove(sum)
	v.limiter.Succeed(ip, now)
	v.metrics.AuthSuccess(want)
	v.touch(ctx, kid, now)
	return p, exp, nil
}

// verifyAgainstStore performs the full, uncached verification. It returns the
// closed-enum failure reason alongside the error so the caller can record one
// metric and cache one rejection.
func (v *Verifier) verifyAgainstStore(
	ctx context.Context, kid string, secret []byte, want fleet.KeyClass, now time.Time,
) (*fleet.Principal, time.Time, string, error) {
	key, err := v.store.GetKey(ctx, kid)
	if err != nil || key == nil {
		// Constant work on the miss branch: without this, a lookup miss
		// returns after a map probe while a hit returns after an HMAC, and
		// latency becomes an oracle for which key identifiers exist.
		v.decoy(secret)
		reason := ReasonStoreError
		if key == nil && err == nil || v.isNotFound(err) {
			reason = ReasonUnknownKey
		}
		return nil, time.Time{}, reason, fmt.Errorf("lookup credential: %w", ErrUnauthenticated)
	}

	// 5. Constant-time comparison, and nothing else, decides authenticity.
	if !v.hasher.Equal(key.SecretHMAC, secret) {
		return nil, time.Time{}, ReasonBadSecret, fmt.Errorf("verify credential: %w", ErrUnauthenticated)
	}

	// 6. The stored class is authoritative. The class segment inside the token
	//    is covered only by an unkeyed CRC, so an attacker can rewrite it; the
	//    record cannot be rewritten without the store.
	if key.Class != want {
		return nil, time.Time{}, ReasonWrongClass,
			fmt.Errorf("stored credential is class %q, listener requires %q: %w", key.Class, want, ErrWrongClass)
	}
	if key.Revoked() {
		return nil, time.Time{}, ReasonRevoked, fmt.Errorf("credential %s: %w", key.KID, ErrRevoked)
	}
	if key.Expired(now) {
		return nil, time.Time{}, ReasonExpired, fmt.Errorf("credential %s: %w", key.KID, ErrExpired)
	}

	return principalFor(key), key.ExpiresAt, "", nil
}

// fromCache answers from the positive or negative cache. decided reports
// whether the caches settled the request at all; when it is false the caller
// must fall through to the store.
func (v *Verifier) fromCache(
	sum [sha256.Size]byte, want fleet.KeyClass, epoch uint64, now time.Time,
) (p *fleet.Principal, expiry time.Time, decided bool, err error) {
	if e, ok := v.pos.Get(sum); ok {
		switch {
		case e.epoch != epoch || now.Sub(e.cachedAt) >= v.cacheTTL:
			v.pos.Remove(sum)
		case !e.keyExpiry.IsZero() && now.After(e.keyExpiry):
			v.pos.Remove(sum)
			v.metrics.AuthFailure(ReasonExpired)
			return nil, time.Time{}, true, fmt.Errorf("credential %s: %w", e.principal.KID, ErrExpired)
		default:
			v.metrics.CacheHit()
			v.metrics.AuthSuccess(want)
			cp := *e.principal
			return &cp, e.keyExpiry, true, nil
		}
	}
	if e, ok := v.neg.Get(sum); ok {
		if now.Sub(e.cachedAt) < v.negativeTTL {
			v.metrics.CacheHit()
			v.metrics.AuthFailure(e.reason)
			return nil, time.Time{}, true, e.err
		}
		v.neg.Remove(sum)
	}
	return nil, time.Time{}, false, nil
}

// fail records a rejection: one metric, one negative-cache entry, one debit
// against the source address, and one log line that names no secret.
func (v *Verifier) fail(ctx context.Context, ip string, now time.Time, sum [sha256.Size]byte, reason string, err error) {
	v.metrics.AuthFailure(reason)
	v.neg.Put(sum, negEntry{err: err, reason: reason, cachedAt: now})
	v.limiter.Fail(ip, now)
	v.log.LogAttrs(ctx, slog.LevelDebug, "authentication failed", slog.String("reason", reason))
}

// syncEpoch reads the store's revocation epoch and purges both caches when it
// has moved. A read failure is reported to the caller, which denies the
// request: serving a cached verification against an unknown epoch would mean
// serving a possibly revoked credential.
func (v *Verifier) syncEpoch(ctx context.Context) (uint64, error) {
	epoch, err := v.store.Epoch(ctx)
	if err != nil {
		return 0, fmt.Errorf("epoch: %w", err)
	}
	v.epochMu.Lock()
	changed := !v.epochOK || v.epoch != epoch
	v.epoch, v.epochOK = epoch, true
	v.epochMu.Unlock()
	if changed {
		v.pos.Purge()
		v.neg.Purge()
	}
	return epoch, nil
}

// touch records the key's last use in the background.
//
// It is deliberately fire-and-forget and deliberately detached from the
// request context: the write must never delay a response, must never fail a
// request, and must still complete if the client disconnects mid-flight. When
// the bounded worker budget is exhausted the update is simply dropped, because
// an approximate last-used timestamp is worth less than a bounded goroutine
// count.
func (v *Verifier) touch(ctx context.Context, kid string, now time.Time) {
	select {
	case v.touchSem <- struct{}{}:
	default:
		return
	}
	base := context.WithoutCancel(ctx)
	v.touchWG.Add(1)
	go func() {
		defer v.touchWG.Done()
		defer func() { <-v.touchSem }()
		tctx, cancel := context.WithTimeout(base, touchTimeout)
		defer cancel()
		if err := v.store.TouchKey(tctx, kid, now); err != nil {
			v.log.LogAttrs(tctx, slog.LevelDebug, "record credential last use",
				slog.String("kid", kid), slog.String("error", err.Error()))
		}
	}()
}

// principalFor derives the request principal from a stored key. The role comes
// from the key's scope when it has one; an admin key is always RoleAdmin, and
// an enrollment token carries no role because it authorizes exactly one
// action, which is not scope-evaluated.
func principalFor(k *fleet.Key) *fleet.Principal {
	p := &fleet.Principal{KID: k.KID, Name: k.Name, Class: k.Class, Scope: k.Scope}
	switch {
	case k.Class == fleet.ClassAdmin:
		p.Role = fleet.RoleAdmin
	case k.Scope != nil:
		p.Role = k.Scope.Role
	}
	return p
}
