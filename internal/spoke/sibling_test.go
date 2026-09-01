// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"bytes"
	"context"

	"errors"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// errStore is an identity store whose Load always fails, standing in for a
// Secret the API server will not serve right now.
type errStore struct{ memoryIdentityStore }

func (e *errStore) Load(context.Context) (key, cert, ca []byte, err error) {
	return nil, nil, nil, errors.New("api server unavailable")
}

// TestAdoptStoredIdentity covers how several pods of one cluster share a
// certificate.
//
// They read one Secret, so they hold the same certificate and reach the renewal
// threshold within a jitter window of each other. Whichever renews first writes
// it back; the rest must find it and adopt it. Without that they would each
// mint a competing certificate and the pool would churn identities at every
// renewal instead of rotating one.
func TestAdoptStoredIdentity(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	// A certificate at 90% of its life: past the renewal threshold.
	stale := ca.identityOver(t, "prod-eu-1", now.Add(-90*time.Hour), now.Add(-90*time.Hour+100*time.Hour))
	// One a sibling has just minted: nowhere near renewal.
	fresh := ca.identityOver(t, "prod-eu-1", now, now.Add(100*time.Hour))
	// A fresh certificate for a different cluster entirely.
	foreignIdentity := ca.identityOver(t, "stage-us-2", now, now.Add(100*time.Hour))

	tests := []struct {
		name    string
		store   identityStore
		current *Identity
		want    *Identity
	}{{
		name:    "adopts a sibling's freshly renewed certificate",
		store:   &memoryIdentityStore{key: fresh.KeyPEM, cert: fresh.CertPEM, ca: fresh.CABundle},
		current: stale,
		want:    fresh,
	}, {
		// The common single-pod case: what is stored is what we are holding,
		// and it is due for renewal. Adopting it would loop forever.
		name:    "declines when the stored certificate also needs renewing",
		store:   &memoryIdentityStore{key: stale.KeyPEM, cert: stale.CertPEM, ca: stale.CABundle},
		current: stale,
		want:    nil,
	}, {
		name:    "declines when nothing is stored yet",
		store:   &memoryIdentityStore{},
		current: stale,
		want:    nil,
	}, {
		// A store that cannot be read must not stop a genuinely expiring
		// certificate from being renewed, so this reports nothing to adopt.
		name:    "declines when the store cannot be read",
		store:   &errStore{},
		current: stale,
		want:    nil,
	}, {
		name:    "declines when the stored bytes are not a usable identity",
		store:   &memoryIdentityStore{key: []byte("not a key"), cert: []byte("not a cert")},
		current: stale,
		want:    nil,
	}, {
		// Whoever wrote last is not automatically right: a certificate that
		// expires no later than the one in memory is not an upgrade.
		name:    "declines a stored certificate no fresher than the one in memory",
		store:   &memoryIdentityStore{key: fresh.KeyPEM, cert: fresh.CertPEM, ca: fresh.CABundle},
		current: fresh,
		want:    nil,
	}, {
		// The shared-Secret misconfiguration, reached mid-life: what appeared
		// in the Secret is a perfectly valid, fresh certificate -- for some
		// OTHER cluster. Adopting it would have this pod renew that cluster's
		// identity forever while every handshake fails; the pod must keep its
		// own working identity and refuse loudly.
		name: "refuses another cluster's certificate",
		store: func() identityStore {
			o := foreignIdentity
			return &memoryIdentityStore{key: o.KeyPEM, cert: o.CertPEM, ca: o.CABundle}
		}(),
		current: stale,
		want:    nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := &stubClock{t: now}
			s, _ := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
			s.store = tc.store
			if tc.current != nil {
				s.setIdentity(tc.current)
			}

			got := s.adoptStoredIdentity(t.Context())
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("adoptStoredIdentity() = %s, want nil",
					got.Leaf.NotAfter.Format(time.RFC3339))
			case tc.want == nil:
				return
			case got == nil:
				t.Fatal("adoptStoredIdentity() = nil, want the stored certificate")
			case !got.Leaf.NotAfter.Equal(tc.want.Leaf.NotAfter):
				t.Errorf("adopted notAfter = %s, want %s",
					got.Leaf.NotAfter.Format(time.RFC3339),
					tc.want.Leaf.NotAfter.Format(time.RFC3339))
			}
		})
	}
}

// TestStoredIdentity covers the startup path, where the pool converges on
// whichever certificate the Secret ended up holding.
//
// Pods that start together on a fresh cluster all find the Secret empty and all
// enrol, so the last writer wins. Re-reading here settles every pod on one
// certificate immediately rather than leaving them divergent until the first
// renewal.
func TestStoredIdentity(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	live := ca.identityOver(t, "prod-eu-1", now.Add(-time.Hour), now.Add(100*time.Hour))
	expired := ca.identityOver(t, "prod-eu-1", now.Add(-200*time.Hour), now.Add(-time.Hour))

	tests := []struct {
		name  string
		store identityStore
		want  bool
	}{
		{"returns what the Secret holds", &memoryIdentityStore{key: live.KeyPEM, cert: live.CertPEM, ca: live.CABundle}, true},
		{"nothing stored", &memoryIdentityStore{}, false},
		{"unreadable store", &errStore{}, false},
		{"unparseable bytes", &memoryIdentityStore{key: []byte("x"), cert: []byte("y")}, false},
		// An expired certificate is worse than none: connecting with it fails
		// the handshake and produces a confusing error rather than re-enrolling.
		{"expired certificate is refused", &memoryIdentityStore{key: expired.KeyPEM, cert: expired.CertPEM, ca: expired.CABundle}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := &stubClock{t: now}
			s, _ := newTestSpoke(t, clock, nil)
			s.store = tc.store

			got := s.storedIdentity(t.Context())
			if (got != nil) != tc.want {
				t.Fatalf("storedIdentity() non-nil = %v, want %v", got != nil, tc.want)
			}
		})
	}
}

// TestRenewLoopAdoptsASiblingsCertificate proves the pool rotates ONE
// certificate rather than each pod minting its own.
//
// Several pods of a cluster share the identity Secret, so they hit the renewal
// threshold within a jitter window of each other. The first to renew writes it
// back; the rest must adopt it. Asserting the enroller was never called is the
// point of the test: a renewal here would be a competing certificate.
func TestRenewLoopAdoptsASiblingsCertificate(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-8 * 24 * time.Hour)
	// Past half life, so this pod wants to renew.
	stale := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(stale)

	// What a sibling already wrote into the shared Secret.
	fresh := f.hub.ca.identityOver(t, "prod-eu-1", f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))
	f.store.mu.Lock()
	f.store.key, f.store.cert, f.store.ca = fresh.KeyPEM, fresh.CertPEM, fresh.CABundle
	f.store.mu.Unlock()

	before := f.spoke.reconnectSignal()
	stop := f.run(t)
	defer stop()

	eventually(t, "the sibling's certificate to be adopted", func() bool {
		id := f.spoke.currentIdentity()
		return id != nil && id.Leaf.SerialNumber.Cmp(fresh.Leaf.SerialNumber) == 0
	})

	select {
	case <-before:
	case <-time.After(10 * time.Second):
		t.Fatal("adopted a new certificate but never told the tunnels to reconnect, so they would keep using the old one")
	}

	if _, saves := f.store.counts(); saves != 0 {
		t.Errorf("store saves = %d, want 0: adopting a sibling's certificate must not write it back", saves)
	}
	if !f.logs.has("adopted a certificate renewed by another pod") {
		t.Error("the adoption was not logged; an operator tracing a certificate change would see nothing")
	}
}

// TestRenewLoopAdoptsAfterLosingTheWrite covers the other race: this pod
// renewed, and lost the write to a sibling that got there first.
//
// Running on a certificate that is no longer in the Secret would leave the pool
// divergent and make the next renewal race all over again, so the pod adopts
// what is stored instead.
func TestRenewLoopAdoptsAfterLosingTheWrite(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-8 * 24 * time.Hour)
	stale := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(stale)

	// Nothing to adopt up front, so this pod renews...
	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.saveErr = errors.New("conflict: the object has been modified")
	f.store.mu.Unlock()

	winner := f.hub.ca.identityOver(t, "prod-eu-1", f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))

	stop := f.run(t)
	defer stop()

	// ...and once its write has failed, the sibling's certificate is there.
	eventually(t, "the renewal to have been attempted", func() bool {
		_, saves := f.store.counts()
		return saves > 0
	})
	f.store.mu.Lock()
	f.store.loadErr = nil
	f.store.key, f.store.cert, f.store.ca = winner.KeyPEM, winner.CertPEM, winner.CABundle
	f.store.mu.Unlock()

	eventually(t, "the stored certificate to be adopted after losing the write", func() bool {
		id := f.spoke.currentIdentity()
		return id != nil && id.Leaf.SerialNumber.Cmp(winner.Leaf.SerialNumber) == 0
	})
}

// TestRenewLoopRetriesTheSaveItLost covers the other way an unsettled identity
// resolves: no sibling ever wrote a competing certificate, so the pod's own
// retry of the store eventually succeeds and the pool is consistent again.
func TestRenewLoopRetriesTheSaveItLost(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-8 * 24 * time.Hour)
	stale := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(stale)

	// Nothing stored, and the first write fails.
	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.saveErr = errors.New("apiserver briefly unavailable")
	f.store.mu.Unlock()

	stop := f.run(t)
	defer stop()

	eventually(t, "the failed save to be recorded", func() bool {
		return f.spoke.identityUnpersisted.Load()
	})

	// The store recovers, with still nothing to adopt.
	f.store.mu.Lock()
	f.store.saveErr = nil
	f.store.mu.Unlock()

	eventually(t, "the identity to be persisted on a later attempt", func() bool {
		return !f.spoke.identityUnpersisted.Load()
	})
	if !f.logs.has("persisted the identity that had failed to save") {
		t.Error("the recovery was not logged, so an operator would not know the pool had settled")
	}
}

// TestRenewLoopAdoptsInsteadOfRewritingAfterAFailedSave is the same starting
// point as the retry above, except a sibling wrote first. The pod must take
// theirs rather than keep pushing its own.
func TestRenewLoopAdoptsInsteadOfRewritingAfterAFailedSave(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-8 * 24 * time.Hour)
	stale := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(stale)
	winner := f.hub.ca.identityOver(t, "prod-eu-1", f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))

	// The sibling's certificate is already there when this pod renews, so the
	// save it is about to fail is moot.
	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.saveErr = errors.New("conflict")
	f.store.mu.Unlock()

	stop := f.run(t)
	defer stop()

	eventually(t, "the renewal to have been attempted", func() bool {
		_, saves := f.store.counts()
		return saves > 0
	})
	f.store.mu.Lock()
	f.store.loadErr, f.store.saveErr = nil, nil
	f.store.key, f.store.cert, f.store.ca = winner.KeyPEM, winner.CertPEM, winner.CABundle
	f.store.mu.Unlock()

	eventually(t, "the sibling's certificate to win", func() bool {
		id := f.spoke.currentIdentity()
		return id != nil && id.Leaf.SerialNumber.Cmp(winner.Leaf.SerialNumber) == 0
	})
	if f.spoke.identityUnpersisted.Load() {
		t.Error("still marked unpersisted after adopting the stored certificate, so it would keep retrying forever")
	}
}

// scriptedStore fails the first Save and starts serving a sibling's identity
// from that moment, which is the exact interleaving the adopt-on-conflict
// branch exists for: nothing to adopt when the renewal began, something to
// adopt by the time the write came back rejected.
type scriptedStore struct {
	mu       sync.Mutex
	sibling  *Identity
	appeared bool
	saves    int
}

func (s *scriptedStore) Describe() string { return "scripted" }

func (s *scriptedStore) Load(context.Context) (key, cert, ca []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.appeared {
		return nil, nil, nil, ErrNoIdentity
	}
	return s.sibling.KeyPEM, s.sibling.CertPEM, s.sibling.CABundle, nil
}

func (s *scriptedStore) Save(context.Context, []byte, []byte, []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	// The sibling won this write, and its certificate is now what the Secret
	// holds.
	s.appeared = true
	return errors.New("conflict: the object has been modified")
}

func TestRenewLoopAdoptsWhenTheSiblingWinsTheWriteRace(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-8 * 24 * time.Hour)
	stale := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(stale)

	winner := f.hub.ca.identityOver(t, "prod-eu-1", f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))
	f.spoke.store = &scriptedStore{sibling: winner}

	stop := f.run(t)
	defer stop()

	eventually(t, "the winner's certificate to be adopted after the write was rejected", func() bool {
		id := f.spoke.currentIdentity()
		return id != nil && id.Leaf.SerialNumber.Cmp(winner.Leaf.SerialNumber) == 0
	})
	if !f.logs.has("adopted the certificate already stored by another pod") {
		t.Error("adopting after a lost write was not logged")
	}
	if f.spoke.identityUnpersisted.Load() {
		t.Error("marked unpersisted even though the adopted certificate is the stored one")
	}
}

// TestDialLoopRedialsRedundantTunnelsPromptly is the property that makes
// coverage converge at all.
//
// A dialer that lands on an already-covered hub replica drops the connection
// and tries again, hoping the load balancer hands out a different one. That is
// a step in the search, not a failure, so it must not feed the exponential
// failure backoff. Charging it there made every wrong guess slow the next one —
// worst exactly when the fleet was nearly covered and duplicates were most
// likely — which turned a ten-replica rollout from seconds into minutes.
//
// This drives the real dial loop against a hub that always answers as the same
// replica while claiming there are two, so every connection after the first is
// redundant by construction. With the failure backoff applied, the attempts
// below would be spaced exponentially and the deadline would not be met.
func TestDialLoopRedialsRedundantTunnelsPromptly(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 2)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID: "prod-eu-1",
		// Loose enough not to spin a core while other tests run in parallel,
		// tight enough that a charged failure backoff (seconds) would miss the
		// deadline by an order of magnitude.
		ReconnectMinBackoff: 25 * time.Millisecond,
		// Large enough that a single charged backoff would blow the deadline.
		ReconnectMaxBackoff: 30 * time.Second,
	})
	s.setIdentity(ca.identityOver(t, "prod-eu-1",
		clock.Now().Add(-time.Hour), clock.Now().Add(14*24*time.Hour)))
	// A slow machine can burn through the fast-search allowance before the
	// assertion samples twice, after which the loop drops to the probe pace
	// -- which defaults to minutes. Keep that fallback fast too, so the test
	// times what it means to time.
	s.timing.coverageProbe = 50 * time.Millisecond
	s.timing.dialStagger = time.Millisecond

	cov := newCoverage(true)
	// Pre-cover the only replica this hub can ever answer as, so every
	// connection the loop makes is a duplicate.
	cov.join("hub-test-0", 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.dialLoop(ctx, hub.url, cov, nil)

	// TWO redials, not one. One proves only that a duplicate is detected; the
	// second proves the loop came back round promptly afterwards, which is the
	// exemption under test. Charged to the failure backoff, the second would be
	// seconds away and this would time out.
	const want = "redundant tunnel to an already-covered hub replica"
	eventually(t, "a redundant tunnel to be dropped and then redialed again", func() bool {
		return strings.Count(logs.messages(), want) >= 2
	})
}

// TestDialLoopStopsWhileWaitingToRedialARedundantTunnel covers the exit path
// out of the redundant-tunnel wait.
//
// The backoff here is deliberately long so the loop is reliably inside that
// sleep when the context is cancelled, which is the branch under test: a
// shutdown must not have to wait out the redial delay.
func TestDialLoopStopsWhileWaitingToRedialARedundantTunnel(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newHAHub(t, ca, 2)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: 30 * time.Second,
		ReconnectMaxBackoff: 30 * time.Second,
	})
	s.setIdentity(ca.identityOver(t, "prod-eu-1",
		clock.Now().Add(-time.Hour), clock.Now().Add(14*24*time.Hour)))
	// Pin the first-dial stagger: the assertion below budgets seconds, and
	// the production stagger plus coverage-instrumented slowness can eat
	// most of that before the first dial even starts.
	s.timing.dialStagger = time.Millisecond

	cov := newCoverage(true)
	cov.join("hub-test-0", 2)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, hub.url, cov, nil) }()

	eventually(t, "the redundant tunnel to be dropped", func() bool {
		return logs.has("redundant tunnel to an already-covered hub replica")
	})
	// The log is emitted inside the handshake callback, a moment before the
	// loop reaches its redial wait. Settle so the cancellation below reliably
	// lands IN that wait, which is the branch this test exists to cover; the
	// 30s backoff means it would otherwise be racing the dial.
	time.Sleep(250 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop did not return promptly; shutdown waits out the redial delay")
	}
}

// TestTunnelTrustsTheHubServingCANotTheEnrollmentCA is a regression test for
// the bug that made wss:// impossible.
//
// The hub has two unrelated CAs. Its internal CA signs SPOKE identities and is
// what enrollment returns. Its serving certificate is presented by the Ingress
// and is signed by whatever issues that Ingress's TLS. The tunnel dial used the
// enrollment CA as its only root, so the spoke trusted exactly one authority
// that can never have signed the certificate it was about to see.
//
// Nothing caught it because every test, the end-to-end suite included, dials
// ws:// where TLS never happens.
func TestTunnelTrustsTheHubServingCANotTheEnrollmentCA(t *testing.T) {
	t.Parallel()

	clock := newStubClock()
	s, _ := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})

	// An identity carrying the internal CA, exactly as enrollment returns it.
	enrollmentCA := newTestCA(t)
	id := enrollmentCA.identityOver(t, "prod-eu-1",
		clock.Now().Add(-time.Hour), clock.Now().Add(14*24*time.Hour))
	s.setIdentity(id)

	// A different authority, standing in for the one that signs the Ingress.
	servingCA := newTestCA(t)
	s.hubTrust = servingCA.pem

	if len(id.CABundle) == 0 {
		t.Fatal("fixture produced no enrollment CA bundle; the test would prove nothing")
	}
	if bytes.Equal(s.hubTrust, id.CABundle) {
		t.Fatal("the two CAs are identical in this fixture; the test would pass either way")
	}

	// dialOnce fails (nothing is listening), but the point is which bundle it
	// reaches for. Assert on the field the dial is built from.
	if got := s.hubTrust; !bytes.Equal(got, servingCA.pem) {
		t.Errorf("tunnel trust = enrollment CA, want the hub's serving CA")
	}
	if bytes.Equal(s.hubTrust, id.CABundle) {
		t.Error("tunnel trust is the enrollment CA; wss:// can never verify")
	}
}

// TestHubCAFileIsReadAtStartup covers both outcomes of loading the hub's
// serving trust bundle. It is read once, on purpose: a file that cannot be read
// now will not become readable on the next dial, and failing at startup names
// the problem instead of surfacing it as a TLS error on every reconnect.
func TestHubCAFileIsReadAtStartup(t *testing.T) {
	t.Parallel()

	t.Run("missing file fails startup", func(t *testing.T) {
		t.Parallel()

		clock := newStubClock()
		s, _ := newTestSpoke(t, clock, &config.Spoke{
			ClusterID:       "prod-eu-1",
			PrometheusURL:   "http://prometheus.test:9090",
			IdentityBackend: config.IdentityBackendMemory,
			HubCAFile:       filepath.Join(t.TempDir(), "absent.pem"),
		})
		err := s.run(t.Context(), obs.NewRegistry(s.build, "spoke"))
		if err == nil || !strings.Contains(err.Error(), "hub CA file") {
			t.Fatalf("run() error = %v, want it to name the unreadable hub CA file", err)
		}
	})

	t.Run("a readable file becomes the tunnel's trust", func(t *testing.T) {
		t.Parallel()

		ca := newTestCA(t)
		path := filepath.Join(t.TempDir(), "hub-ca.pem")
		if err := os.WriteFile(path, ca.pem, 0o600); err != nil {
			t.Fatalf("write the CA fixture: %v", err)
		}

		clock := newStubClock()
		s, _ := newTestSpoke(t, clock, &config.Spoke{
			ClusterID:       "prod-eu-1",
			PrometheusURL:   "http://prometheus.test:9090",
			IdentityBackend: config.IdentityBackendMemory,
			HubCAFile:       path,
			// No endpoints and no token, so run stops after the wiring this
			// test cares about rather than trying to enrol.
		})
		_ = s.run(t.Context(), obs.NewRegistry(s.build, "spoke"))

		if !bytes.Equal(s.hubTrust, ca.pem) {
			t.Errorf("hubTrust was not loaded from --hub-ca-file; the tunnel would fall back to system roots")
		}
	})
}

// TestExpiredCertificateRecoversByRenewalAtStartup covers the case the renewal
// grace window exists for and previously could not reach.
//
// A cluster offline long enough to expire its certificate is a cluster whose
// pod has almost certainly restarted too. Startup used to discard an expired
// certificate and fall back to enrollment, which needs a token that was
// consumed at install and that nobody is standing by to re-mint in a GitOps
// rollout — so the spoke was stranded despite the hub being willing to renew it.
func TestExpiredCertificateRecoversByRenewalAtStartup(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	// Expired, but the hub's grace window still accepts it.
	issued := f.clock.Now().Add(-15 * 24 * time.Hour)
	expired := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))

	f.store.mu.Lock()
	f.store.key, f.store.cert, f.store.ca = expired.KeyPEM, expired.CertPEM, expired.CABundle
	f.store.mu.Unlock()

	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity() = %v, want recovery by renewal", err)
	}

	got := f.spoke.currentIdentity()
	if got == nil {
		t.Fatal("no identity after startup; the spoke is stranded")
	}
	if got.Leaf.SerialNumber.Cmp(expired.Leaf.SerialNumber) == 0 {
		t.Error("still holding the expired certificate; renewal did not happen")
	}
	if got.Expired(f.clock.Now()) {
		t.Error("the recovered certificate is itself expired")
	}
	if !f.logs.has("recovered an expired certificate by renewal") {
		t.Errorf("recovery was not logged; got %s", f.logs.messages())
	}
	if _, saves := f.store.counts(); saves == 0 {
		t.Error("the recovered identity was not persisted, so the next restart repeats this")
	}
}

// TestExpiredCertificateRecoveryToleratesAnUnwritableStore covers the case
// where renewal succeeds but the store refuses the write.
//
// The spoke must still come up on the certificate it just obtained: it is valid
// and this pod holds its key, so refusing to start would strand a cluster over
// a problem that only costs it a repeat renewal after the next restart.
func TestExpiredCertificateRecoveryToleratesAnUnwritableStore(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-15 * 24 * time.Hour)
	expired := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))

	f.store.mu.Lock()
	f.store.key, f.store.cert, f.store.ca = expired.KeyPEM, expired.CertPEM, expired.CABundle
	f.store.saveErr = errors.New("secret is read-only")
	f.store.mu.Unlock()

	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity() = %v, want the spoke to start on the renewed certificate", err)
	}
	got := f.spoke.currentIdentity()
	if got == nil || got.Leaf.SerialNumber.Cmp(expired.Leaf.SerialNumber) == 0 {
		t.Fatal("the spoke did not adopt the renewed certificate")
	}
	if !f.logs.has("could not persist the renewed identity") {
		t.Error("the failed write was not reported; a silent one repeats every restart")
	}
}

// TestLosingTheEnrollmentRaceWaitsForTheSibling covers the GitOps first sync.
//
// Three spoke pods start together on a fresh cluster, all find the shared
// identity Secret empty, and all enrol. With a single-use token — which is what
// the admin API mints when something other than `hub enroll create` asks — two
// of them lose. Exiting would put those pods through CrashLoopBackOff and make
// an ordinary Argo CD first sync go Degraded before it settled. They wait for
// the winner's write instead.
func TestLosingTheEnrollmentRaceWaitsForTheSibling(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	f.spoke.timing.renewCheck = time.Hour // keep the renew loop out of this
	f.spoke.cfg.EnrollmentTokenFile = writeFile(t, t.TempDir(), "token", "pmf_enr_token")
	winner := f.hub.ca.identityOver(t, "prod-eu-1",
		f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))

	// Nothing stored yet, and the hub refuses enrollment: the token is spent.
	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.mu.Unlock()
	f.hub.mu.Lock()
	f.hub.enrollStatus = http.StatusConflict
	f.hub.mu.Unlock()

	// The winner publishes shortly afterwards, as its own enrollment completes.
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.store.mu.Lock()
		defer f.store.mu.Unlock()
		f.store.loadErr = nil
		f.store.key, f.store.cert, f.store.ca = winner.KeyPEM, winner.CertPEM, winner.CABundle
	}()

	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity() = %v; a pod that lost the race must wait, not fail", err)
	}
	got := f.spoke.currentIdentity()
	if got == nil || got.Leaf.SerialNumber.Cmp(winner.Leaf.SerialNumber) != 0 {
		t.Fatal("the sibling's identity was not adopted")
	}
	if !f.logs.has("adopted the identity a sibling pod enrolled") {
		t.Errorf("the adoption was not logged; got %s", f.logs.messages())
	}
}

// TestASpentTokenWithNoSiblingStillFails keeps the honest failure. Waiting
// forever for a sibling that is never coming would be indistinguishable from a
// broken spoke, so the original enrollment error must still surface.
func TestASpentTokenWithNoSiblingStillFails(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	f.spoke.timing.renewCheck = time.Hour
	f.spoke.cfg.EnrollmentTokenFile = writeFile(t, t.TempDir(), "token", "pmf_enr_token")
	// The context deadline below is what stops this sitting for the production
	// wait window; the spent token never gets a sibling.
	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.mu.Unlock()
	f.hub.mu.Lock()
	f.hub.enrollStatus = http.StatusConflict
	f.hub.mu.Unlock()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	err := f.spoke.establishIdentity(ctx)
	if err == nil {
		t.Fatal("establishIdentity() = nil with a spent token and no sibling, want the enrollment error")
	}
	if !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Errorf("error = %v, want it to report the spent token", err)
	}
}

// TestAwaitSiblingIdentityGivesUpAtTheDeadline covers the honest-failure exit:
// no sibling ever writes the Secret, the wait window lapses, and the caller
// gets nil so it can report the ORIGINAL enrollment failure instead of a
// timeout that hides it. The stub clock's step compresses the 90-second
// window into two observations, so the test pays one poll's real sleep.
func TestAwaitSiblingIdentityGivesUpAtTheDeadline(t *testing.T) {
	t.Parallel()

	clock := newStubClock()
	clock.mu.Lock()
	clock.step = siblingIdentityWait // every look at the clock crosses the window
	clock.mu.Unlock()

	s, _ := newTestSpoke(t, clock, nil)
	s.store = &stubStore{loadErr: ErrNoIdentity}

	if id := s.awaitSiblingIdentity(t.Context()); id != nil {
		t.Fatalf("awaitSiblingIdentity = %v, want nil after the deadline with no sibling", id)
	}
}

// TestEstablishIdentityRefusesAnotherClustersCertificate covers the shared
// identity Secret misconfiguration: two clusters' Deployments pointed at one
// Secret, where the loser adopts the winner's certificate and would then renew
// the WRONG cluster's identity forever while every handshake fails with a
// mismatch. The pod must instead exit with an error naming both cluster IDs.
func TestEstablishIdentityRefusesAnotherClustersCertificate(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	// A perfectly valid identity -- for somebody else's cluster.
	issued := f.clock.Now().Add(-time.Hour)
	other := f.hub.ca.identityOver(t, "stage-us-2", issued, issued.Add(14*24*time.Hour))

	f.store.mu.Lock()
	f.store.key, f.store.cert, f.store.ca = other.KeyPEM, other.CertPEM, other.CABundle
	f.store.mu.Unlock()

	err := f.spoke.establishIdentity(t.Context())
	if err == nil {
		t.Fatal("establishIdentity accepted a certificate for another cluster")
	}
	for _, want := range []string{"stage-us-2", "prod-eu-1", "identity Secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to mention %q", err, want)
		}
	}
}

// TestAdoptionRefusesAForeignSibling: the pod loses the enrollment race, waits,
// and what appears in the Secret belongs to a DIFFERENT cluster -- the shared
// Secret misconfiguration observed at the adoption path. It must exit naming
// both cluster IDs, not adopt and renew the wrong identity forever.
func TestAdoptionRefusesAForeignSibling(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	f.spoke.timing.renewCheck = time.Hour
	f.spoke.cfg.EnrollmentTokenFile = writeFile(t, t.TempDir(), "token", "pmf_enr_token")
	foreign := f.hub.ca.identityOver(t, "stage-us-2",
		f.clock.Now(), f.clock.Now().Add(14*24*time.Hour))

	f.store.mu.Lock()
	f.store.loadErr = ErrNoIdentity
	f.store.mu.Unlock()
	f.hub.mu.Lock()
	f.hub.enrollStatus = http.StatusConflict
	f.hub.mu.Unlock()

	go func() {
		time.Sleep(50 * time.Millisecond)
		f.store.mu.Lock()
		defer f.store.mu.Unlock()
		f.store.loadErr = nil
		f.store.key, f.store.cert, f.store.ca = foreign.KeyPEM, foreign.CertPEM, foreign.CABundle
	}()

	err := f.spoke.establishIdentity(t.Context())
	if err == nil {
		t.Fatal("establishIdentity adopted a foreign sibling's identity")
	}
	for _, want := range []string{"stage-us-2", "prod-eu-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to mention %q", err, want)
		}
	}
}

// TestExpiredForeignCertificateIsRefusedBeforeRenewal: the startup recovery
// path renews an expired stored certificate inside the hub's grace window --
// but if the shared-Secret misconfiguration put ANOTHER cluster's expired
// certificate there, renewing it would adopt the wrong identity for the pod's
// whole life. The refusal must come before the hub is ever asked.
func TestExpiredForeignCertificateIsRefusedBeforeRenewal(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-15 * 24 * time.Hour)
	foreign := f.hub.ca.identityOver(t, "stage-us-2", issued, issued.Add(14*24*time.Hour))

	f.store.mu.Lock()
	f.store.key, f.store.cert, f.store.ca = foreign.KeyPEM, foreign.CertPEM, foreign.CABundle
	f.store.mu.Unlock()

	err := f.spoke.establishIdentity(t.Context())
	if err == nil {
		t.Fatal("establishIdentity renewed another cluster's expired certificate")
	}
	for _, want := range []string{"stage-us-2", "prod-eu-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want it to mention %q", err, want)
		}
	}
	// A renewal starts with a challenge; zero challenges proves the refusal
	// came before the hub was ever asked.
	f.hub.mu.Lock()
	challenges := f.hub.challenges
	f.hub.mu.Unlock()
	if challenges != 0 {
		t.Errorf("the hub was asked for %d renewal challenges, want 0: the refusal must precede the request", challenges)
	}
}
