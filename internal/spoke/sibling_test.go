// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"errors"
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
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := &stubClock{t: now}
			s, _ := newTestSpoke(t, clock, nil)
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
