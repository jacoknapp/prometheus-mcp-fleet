// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/clusterfacts"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/httpx"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	pmftestutil "github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// ---------------------------------------------------------------------------
// timings
// ---------------------------------------------------------------------------

// TestNewTimingsDerivesTheLoopPeriods pins the two decisions in the
// derivation: an unconfigured facts interval has a default, and the readiness
// probe has a floor so that a fast facts interval cannot turn a readiness
// check into a scrape storm against the local Prometheus.
func TestNewTimingsDerivesTheLoopPeriods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		configured         time.Duration
		wantFacts          time.Duration
		wantProbe          time.Duration
		wantProbeIsFloored bool
	}{
		{
			name: "unconfigured", configured: 0,
			wantFacts: 10 * time.Minute, wantProbe: 2 * time.Minute,
		},
		{
			name: "negative", configured: -time.Minute,
			wantFacts: 10 * time.Minute, wantProbe: 2 * time.Minute,
		},
		{
			name: "a slow facts interval gives a fifth of it to the probe", configured: 20 * time.Minute,
			wantFacts: 20 * time.Minute, wantProbe: 4 * time.Minute,
		},
		{
			name: "a fast facts interval still floors the probe", configured: 10 * time.Second,
			wantFacts: 10 * time.Second, wantProbe: minProbeInterval, wantProbeIsFloored: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := newTimings(&config.Spoke{FactsRefreshInterval: tc.configured})
			if got.facts != tc.wantFacts {
				t.Errorf("facts = %s, want %s", got.facts, tc.wantFacts)
			}
			if got.probe != tc.wantProbe {
				t.Errorf("probe = %s, want %s", got.probe, tc.wantProbe)
			}
			if tc.wantProbeIsFloored && got.probe < got.facts/5 {
				t.Error("the floor made the probe faster than a fifth of the facts interval")
			}
			// The renewal check follows the certificate's life, not the facts
			// interval; wiring it to configuration would make renewal timing an
			// accident of how often somebody wanted cluster facts refreshed.
			if got.renewCheck != renewCheckInterval {
				t.Errorf("renewCheck = %s, want %s", got.renewCheck, renewCheckInterval)
			}
			if got.dialStagger != maxFirstDialDelay {
				t.Errorf("dialStagger = %s, want %s", got.dialStagger, maxFirstDialDelay)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// identity publication and the reconnect signal
// ---------------------------------------------------------------------------

// TestSetIdentityPublishesTheExpiryGauge. The gauge is what
// promfleet_spoke_client_cert_expiry_seconds alerts on, and it is only ever
// written here, so a renewal that forgot to publish would leave the alert
// counting down on a certificate that had already been replaced.
func TestSetIdentityPublishesTheExpiryGauge(t *testing.T) {
	t.Parallel()

	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, nil)
	ca := newTestCA(t)

	if s.currentIdentity() != nil {
		t.Fatal("a fresh spoke already has an identity")
	}
	id := ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(4*time.Hour))
	s.setIdentity(id)

	if s.currentIdentity() != id {
		t.Error("currentIdentity did not return what was published")
	}
	// x509 stores second precision, so the expected value comes from the
	// certificate rather than from the duration it was asked for.
	want := id.Leaf.NotAfter.Sub(clock.Now()).Seconds()
	if got := logs.metric(t, "promfleet_spoke_client_cert_expiry_seconds"); got != want {
		t.Errorf("client_cert_expiry_seconds = %v, want %v", got, want)
	}
}

// TestSignalReconnectWakesEveryWaiterOnce. Closing the channel is what makes a
// renewal reach every dialer at the same instant; replacing it is what makes
// the next renewal able to do it again.
func TestSignalReconnectWakesEveryWaiterOnce(t *testing.T) {
	t.Parallel()

	s, _ := newTestSpoke(t, newStubClock(), nil)

	first := s.reconnectSignal()
	if first != s.reconnectSignal() {
		t.Fatal("two reads of the reconnect signal returned different channels")
	}
	select {
	case <-first:
		t.Fatal("the reconnect signal was already closed")
	default:
	}

	// Several dialers wait at once, which is the real shape: one tunnel per
	// hub endpoint.
	var woke sync.WaitGroup
	woke.Add(3)
	for range 3 {
		go func() {
			defer woke.Done()
			<-first
		}()
	}
	s.signalReconnect()
	woke.Wait()

	second := s.reconnectSignal()
	if second == first {
		t.Fatal("the signal channel was not replaced, so the next renewal cannot signal")
	}
	select {
	case <-second:
		t.Fatal("the replacement channel was already closed")
	default:
	}
}

// ---------------------------------------------------------------------------
// establishIdentity
// ---------------------------------------------------------------------------

// stubStore is an identityStore whose reads and writes a test controls.
// identityStore is a production interface, so this substitutes for a backend
// rather than opening one up.
type stubStore struct {
	mu                  sync.Mutex
	key, cert, ca       []byte
	loadErr, saveErr    error
	loads, saves        int
	savedKey, savedCert []byte
}

func (s *stubStore) Load(context.Context) (key, cert, ca []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.loadErr != nil {
		return nil, nil, nil, s.loadErr
	}
	return s.key, s.cert, s.ca, nil
}

func (s *stubStore) Save(_ context.Context, key, cert, ca []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.key, s.cert, s.ca = key, cert, ca
	s.savedKey, s.savedCert = key, cert
	return nil
}

func (s *stubStore) Describe() string { return "stub" }

func (s *stubStore) counts() (loads, saves int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads, s.saves
}

// establishFixture wires a spoke, a stubbed store and a real enroller pointed
// at the fake hub.
type establishFixture struct {
	spoke *spoke
	logs  *spokeProbe
	store *stubStore
	hub   *fakeHub
	clock *stubClock
}

func newEstablishFixture(t *testing.T, tokenFileContent string) *establishFixture {
	t.Helper()

	e, hub := newEnroller(t)
	clock := newStubClock()
	cfg := &config.Spoke{ClusterID: "prod-eu-1"}
	if tokenFileContent != "" {
		cfg.EnrollmentTokenFile = writeFile(t, t.TempDir(), "token", tokenFileContent)
	}
	s, logs := newTestSpoke(t, clock, cfg)
	store := &stubStore{}
	s.store = store
	s.enroller = e
	return &establishFixture{spoke: s, logs: logs, store: store, hub: hub, clock: clock}
}

// TestEstablishIdentityUsesAStoredIdentity is the ordinary restart: the spoke
// comes back with the certificate it already had and never touches its
// enrollment token, which is what makes a single-use token workable.
func TestEstablishIdentityUsesAStoredIdentity(t *testing.T) {
	t.Parallel()

	f := newEstablishFixture(t, "pmf_enr_should_not_be_used")
	stored := f.hub.ca.identityOver(t, "prod-eu-1",
		f.clock.Now().Add(-time.Hour), f.clock.Now().Add(10*time.Hour))
	f.store.key, f.store.cert, f.store.ca = stored.KeyPEM, stored.CertPEM, stored.CABundle

	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity: %v", err)
	}
	got := f.spoke.currentIdentity()
	if got == nil || got.Leaf.SerialNumber.Cmp(stored.Leaf.SerialNumber) != 0 {
		t.Fatal("the stored certificate was not the one adopted")
	}
	if _, saves := f.store.counts(); saves != 0 {
		t.Errorf("the store was written %d times for a load that needed nothing", saves)
	}
	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	if f.hub.lastEnrollBody != "" {
		t.Error("a spoke with a usable stored identity still redeemed its enrollment token")
	}
	if !f.logs.has("loaded stored identity") {
		t.Errorf("no line said the identity came from the store; got %s", f.logs.messages())
	}
}

// TestEstablishIdentityDiscardsAnUnusableStoredIdentity covers the two
// conditions docs/spoke-enrollment.md calls out. Neither is fatal: connecting
// with an expired certificate would fail the handshake with a confusing error,
// and refusing to start over an unreadable Secret would strand the spoke.
func TestEstablishIdentityDiscardsAnUnusableStoredIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// spoil replaces what the store hands back.
		spoil   func(t *testing.T, f *establishFixture)
		wantLog string
	}{
		{
			name: "an expired certificate",
			spoil: func(t *testing.T, f *establishFixture) {
				t.Helper()
				expired := f.hub.ca.identityOver(t, "prod-eu-1",
					f.clock.Now().Add(-48*time.Hour), f.clock.Now().Add(-time.Second))
				f.store.key, f.store.cert, f.store.ca = expired.KeyPEM, expired.CertPEM, expired.CABundle
			},
			wantLog: "stored certificate has expired",
		},
		{
			name: "material that does not parse",
			spoil: func(t *testing.T, f *establishFixture) {
				t.Helper()
				f.store.key, f.store.cert = []byte("not a key"), []byte("not a certificate")
			},
			wantLog: "stored identity is unusable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newEstablishFixture(t, "pmf_enr_token")
			tc.spoil(t, f)

			if err := f.spoke.establishIdentity(t.Context()); err != nil {
				t.Fatalf("establishIdentity: %v; an unusable stored identity must "+
					"re-enroll, not stop the process", err)
			}
			if !f.logs.has(tc.wantLog) {
				t.Errorf("no warning mentioning %q; got %s", tc.wantLog, f.logs.messages())
			}
			if f.spoke.currentIdentity() == nil {
				t.Fatal("no identity was established")
			}
			f.hub.mu.Lock()
			defer f.hub.mu.Unlock()
			if f.hub.lastEnrollAuth != "Bearer pmf_enr_token" {
				t.Errorf("enrollment Authorization = %q, want the token to have been redeemed",
					f.hub.lastEnrollAuth)
			}
		})
	}
}

// TestEstablishIdentityDoesNotEnrollOverAStoreFailure. A read that failed for
// a reason other than "nothing stored" — RBAC, a wedged API server — is not an
// invitation to burn the single-use token; an operator has to fix it.
func TestEstablishIdentityDoesNotEnrollOverAStoreFailure(t *testing.T) {
	t.Parallel()

	f := newEstablishFixture(t, "pmf_enr_token")
	f.store.loadErr = errors.New("secrets is forbidden")

	err := f.spoke.establishIdentity(t.Context())
	errContains(t, err, "load identity")
	errContains(t, err, "forbidden")

	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	if f.hub.lastEnrollBody != "" {
		t.Error("the spoke enrolled over a store failure, spending its token on a cluster problem")
	}
}

// TestEstablishIdentityEnrollsAndPersists is the first boot.
func TestEstablishIdentityEnrollsAndPersists(t *testing.T) {
	t.Parallel()

	f := newEstablishFixture(t, "  pmf_enr_token\n")
	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity: %v", err)
	}

	id := f.spoke.currentIdentity()
	if id == nil {
		t.Fatal("no identity was established")
	}
	if _, saves := f.store.counts(); saves != 1 {
		t.Errorf("the identity was persisted %d times, want once", saves)
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if string(f.store.savedCert) != string(id.CertPEM) || string(f.store.savedKey) != string(id.KeyPEM) {
		t.Error("what was persisted is not the identity now in force, so a restart would " +
			"load something else")
	}
	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	if f.hub.lastEnrollAuth != "Bearer pmf_enr_token" {
		t.Errorf("Authorization = %q, want the trimmed token", f.hub.lastEnrollAuth)
	}
}

// TestEstablishIdentitySurvivesAPersistFailure is the property that keeps a
// misconfigured RBAC rule from costing an operator a token: the enrollment has
// already happened and the token is already burned, so failing here would
// spend the credential and produce nothing.
func TestEstablishIdentitySurvivesAPersistFailure(t *testing.T) {
	t.Parallel()

	f := newEstablishFixture(t, "pmf_enr_token")
	f.store.saveErr = errors.New("secrets update is forbidden")

	if err := f.spoke.establishIdentity(t.Context()); err != nil {
		t.Fatalf("establishIdentity: %v; a persist failure must not be fatal, or the "+
			"token is burned for nothing", err)
	}
	if f.spoke.currentIdentity() == nil {
		t.Fatal("the identity that was just issued was thrown away")
	}
	r, ok := f.logs.find("could not persist the identity")
	if !ok {
		t.Fatalf("nothing warned that the identity was not persisted; got %s", f.logs.messages())
	}
	if r.Level != slog.LevelError {
		t.Errorf("logged at %s, want error: a restart now needs a fresh enrollment token", r.Level)
	}
}

// TestEstablishIdentityWithoutACredential covers the two shapes of "there is
// nothing to enroll with", both of which must name the missing token rather
// than failing somewhere further down.
func TestEstablishIdentityWithoutACredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		token   string
		wantErr error
		wantMsg string
	}{
		{name: "no token file configured", wantErr: ErrEnrollmentRequired, wantMsg: "no enrollment token file"},
		{name: "an empty token file", token: "\n  \t\n", wantErr: ErrEnrollmentRequired, wantMsg: "is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newEstablishFixture(t, tc.token)
			err := f.spoke.establishIdentity(t.Context())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("establishIdentity = %v, want %v", err, tc.wantErr)
			}
			errContains(t, err, tc.wantMsg)
		})
	}
}

// TestEstablishIdentityReportsARejectedEnrollment. There is nothing the spoke
// can do about a refused token, so it stops rather than looping on a
// credential the hub has already burned.
func TestEstablishIdentityReportsARejectedEnrollment(t *testing.T) {
	t.Parallel()

	f := newEstablishFixture(t, "pmf_enr_token")
	f.spoke.enroller.apiURL = "http://" + deadAddr(t)

	err := f.spoke.establishIdentity(t.Context())
	errContains(t, err, "post /enroll")
	if f.spoke.currentIdentity() != nil {
		t.Error("a failed enrollment still published an identity")
	}
}

// TestReadTokenFailsOnAnUnreadableFile keeps a mount problem from being
// reported as "enrollment required", which sends an operator to mint a token
// that was never the problem.
func TestReadTokenFailsOnAnUnreadableFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := readToken(mkdir(t, dir, "token"))
	errContains(t, err, "read enrollment token")
	if errors.Is(err, ErrEnrollmentRequired) {
		t.Error("an unreadable token file was reported as a missing one")
	}
}

// ---------------------------------------------------------------------------
// renewLoop
// ---------------------------------------------------------------------------

// renewFixture is a spoke whose renewal loop runs on a millisecond timer
// against the fake hub.
type renewFixture struct {
	spoke *spoke
	logs  *spokeProbe
	store *stubStore
	hub   *fakeHub
	clock *stubClock
}

func newRenewFixture(t *testing.T) *renewFixture {
	t.Helper()

	e, hub := newEnroller(t)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	store := &stubStore{}
	s.store = store
	s.enroller = e
	// The interval is what the loop sleeps on, not what it decides with, so
	// shortening it changes nothing about the renewal decision itself.
	s.timing.renewCheck = 2 * time.Millisecond
	return &renewFixture{spoke: s, logs: logs, store: store, hub: hub, clock: clock}
}

// run starts renewLoop and returns a stop function that waits for it to exit.
func (f *renewFixture) run(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.spoke.renewLoop(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("renewLoop returned %v, want the cancellation it stopped for", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("renewLoop did not stop when its context was cancelled")
		}
	}
}

// TestRenewLoopRenewsAtHalfLifeAndReconnects is the property the whole design
// rests on: a renewed certificate has to reach the tunnels, and the only way
// it does is by dropping them. A spoke that renewed and kept its old
// connection would present the old certificate until it expired.
func TestRenewLoopRenewsAtHalfLifeAndReconnects(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	issued := f.clock.Now().Add(-time.Hour)
	original := f.hub.ca.identityOver(t, "prod-eu-1", issued, issued.Add(14*24*time.Hour))
	f.spoke.setIdentity(original)
	before := f.spoke.reconnectSignal()

	stop := f.run(t)
	defer stop()

	// Nothing is due yet, and nothing must happen while that is true.
	time.Sleep(20 * time.Millisecond)
	if f.spoke.currentIdentity() != original {
		t.Fatal("the certificate was renewed before it was half spent")
	}
	select {
	case <-before:
		t.Fatal("the tunnels were told to reconnect for a renewal that had not happened")
	default:
	}

	// Past half life.
	f.clock.Advance(8 * 24 * time.Hour)

	eventually(t, "the certificate to be renewed", func() bool {
		return f.spoke.currentIdentity() != original
	})
	select {
	case <-before:
	case <-time.After(10 * time.Second):
		t.Fatal("the certificate was renewed but the tunnels were never told to reconnect")
	}

	renewed := f.spoke.currentIdentity()
	if renewed.Leaf.SerialNumber.Cmp(original.Leaf.SerialNumber) == 0 {
		t.Error("the renewal published the same certificate")
	}
	if _, saves := f.store.counts(); saves == 0 {
		t.Error("the renewed identity was never persisted, so a restart would load the old one")
	}
	if got, want := f.logs.metric(t, "promfleet_spoke_client_cert_expiry_seconds"),
		renewed.Leaf.NotAfter.Sub(f.clock.Now()).Seconds(); got != want {
		t.Errorf("client_cert_expiry_seconds = %v after a renewal, want the renewed "+
			"certificate's %v: the alert would still be counting down the old one", got, want)
	}
	if !f.logs.has("certificate renewed") {
		t.Errorf("the renewal was not logged; got %s", f.logs.messages())
	}
}

// TestRenewLoopDoesNotEscalateAtExactlyOneDayLeft pins the boundary of
// "remaining < 24h" against its off-by-one "remaining <= 24h": at exactly one
// day remaining, escalation must not yet have kicked in.
//
// This cannot be a case in TestRenewLoopEscalatesInsideTheLastDay's table: an
// x509 certificate's NotAfter truncates to whole seconds, so a NotAfter built
// from a frozen clock reading with a sub-second fraction round-trips to
// slightly less than the requested remaining -- close enough for that table's
// hour-wide margins, but enough to manufacture a false escalation exactly at
// the boundary this test needs. Aligning the clock to a whole second first
// avoids that.
func TestRenewLoopDoesNotEscalateAtExactlyOneDayLeft(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	f.hub.mu.Lock()
	f.hub.renewStatus = http.StatusServiceUnavailable
	f.hub.mu.Unlock()

	aligned := f.clock.Now().Truncate(time.Second)
	f.clock.Advance(aligned.Sub(f.clock.Now()))
	now := f.clock.Now()

	f.spoke.setIdentity(f.hub.ca.identityOver(t, "prod-eu-1",
		now.Add(-14*24*time.Hour), now.Add(24*time.Hour)))

	stop := f.run(t)
	eventually(t, "the renewal to fail", func() bool {
		return f.logs.has("certificate renewal failed")
	})
	stop()

	if got := f.logs.level(t, "certificate renewal failed"); got != slog.LevelWarn {
		t.Errorf("renewal failure with exactly 24h left logged at %s, want %s", got, slog.LevelWarn)
	}
}

// TestRenewLoopWaitsWhenThereIsNoIdentity. renewLoop and establishIdentity run
// in the same process but not in lockstep, so the loop has to tolerate being
// asked before there is anything to renew.
func TestRenewLoopWaitsWhenThereIsNoIdentity(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	stop := f.run(t)
	time.Sleep(20 * time.Millisecond)
	stop()

	f.hub.mu.Lock()
	defer f.hub.mu.Unlock()
	if f.hub.challenges != 0 {
		t.Errorf("the loop fetched %d renewal challenges with no certificate to renew", f.hub.challenges)
	}
}

// TestRenewLoopEscalatesInsideTheLastDay. Warn for a failure with time left,
// error once the certificate has less than a day: the difference is what an
// operator's alerting is keyed on, and getting it backwards means either
// paging on a retry that will succeed or not paging on a fleet about to
// disconnect.
func TestRenewLoopEscalatesInsideTheLastDay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		remaining time.Duration
		wantLevel slog.Level
	}{
		{name: "days left", remaining: 6 * 24 * time.Hour, wantLevel: slog.LevelWarn},
		{name: "just over a day left", remaining: 25 * time.Hour, wantLevel: slog.LevelWarn},
		{name: "inside the last day", remaining: 23 * time.Hour, wantLevel: slog.LevelError},
		{name: "an hour left", remaining: time.Hour, wantLevel: slog.LevelError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRenewFixture(t)
			f.hub.mu.Lock()
			f.hub.renewStatus = http.StatusServiceUnavailable
			f.hub.mu.Unlock()

			now := f.clock.Now()
			// Issued long enough ago that it is well past half life, and
			// expiring in exactly the window under test.
			f.spoke.setIdentity(f.hub.ca.identityOver(t, "prod-eu-1",
				now.Add(-14*24*time.Hour), now.Add(tc.remaining)))

			stop := f.run(t)
			eventually(t, "the renewal to fail", func() bool {
				return f.logs.has("certificate renewal failed")
			})
			stop()

			if got := f.logs.level(t, "certificate renewal failed"); got != tc.wantLevel {
				t.Errorf("renewal failure with %s left logged at %s, want %s",
					tc.remaining, got, tc.wantLevel)
			}
			if f.spoke.currentIdentity() == nil {
				t.Error("a failed renewal discarded the certificate the spoke still has")
			}
		})
	}
}

// TestRenewLoopSurvivesAPersistFailure. The renewed certificate is already in
// hand; refusing to use it because it could not be written down would drop the
// tunnels for nothing.
func TestRenewLoopSurvivesAPersistFailure(t *testing.T) {
	t.Parallel()

	f := newRenewFixture(t)
	f.store.saveErr = errors.New("secrets update is forbidden")
	now := f.clock.Now()
	original := f.hub.ca.identityOver(t, "prod-eu-1", now.Add(-14*24*time.Hour), now.Add(24*time.Hour))
	f.spoke.setIdentity(original)

	stop := f.run(t)
	eventually(t, "the certificate to be renewed", func() bool {
		return f.spoke.currentIdentity() != original
	})
	stop()

	if !f.logs.has("could not persist the renewed identity") {
		t.Errorf("the failed write was not reported; got %s", f.logs.messages())
	}
	if f.spoke.currentIdentity() == original {
		t.Error("the renewed certificate was discarded because it could not be persisted")
	}
}

// ---------------------------------------------------------------------------
// probeLoop
// ---------------------------------------------------------------------------

// switchableProm is a Prometheus that answers or refuses on command and counts
// what it was asked.
type switchableProm struct {
	mu       sync.Mutex
	up       bool
	requests int
}

func newSwitchableProm(t *testing.T, up bool) (*switchableProm, string) {
	t.Helper()
	p := &switchableProm{up: up}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.requests++
		ok := p.up
		p.mu.Unlock()
		if !ok {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return p, srv.URL
}

func (p *switchableProm) set(up bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.up = up
}

func (p *switchableProm) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

// TestProbeLoopNeedsTwoFailuresBeforeReportingNotReady. One slow scrape must
// not take the pod out of service: the probe feeds readiness, and readiness
// removes the spoke from the fleet's view.
func TestProbeLoopNeedsTwoFailuresBeforeReportingNotReady(t *testing.T) {
	t.Parallel()

	prom, url := newSwitchableProm(t, false)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, nil)
	s.prom = newPromClient(t, url)
	// Long enough that the gap between two probes dwarfs one probe, so
	// "exactly one failure has been seen" is a state the test can observe.
	s.timing.probe = 500 * time.Millisecond
	s.health.Set("prometheus", true, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.probeLoop(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	// Ping tries /-/healthy and then /api/v1/status/buildinfo, so one probe is
	// two requests.
	eventually(t, "the first probe to fail", func() bool { return prom.count() >= 2 })
	if reason, blocked := notReady(s.health, "prometheus"); blocked {
		t.Fatalf("one failed probe already reported not-ready (%q); a single slow "+
			"scrape must not flap readiness", reason)
	}
	if got := logs.metric(t, "promfleet_spoke_prom_up"); got != 0 {
		t.Errorf("prom_up = %v after a failed probe, want 0", got)
	}

	eventually(t, "the second probe to fail", func() bool { return prom.count() >= 4 })
	eventually(t, "readiness to drop", func() bool {
		_, blocked := notReady(s.health, "prometheus")
		return blocked
	})
	reason, _ := notReady(s.health, "prometheus")
	if !strings.Contains(reason, "local Prometheus unreachable") {
		t.Errorf("readiness reason = %q, want it to name the unreachable Prometheus", reason)
	}

	// Recovery resets the count, so the next single failure does not
	// immediately take readiness away again.
	prom.set(true)
	eventually(t, "readiness to come back", func() bool {
		_, blocked := notReady(s.health, "prometheus")
		return !blocked
	})
	if got := logs.metric(t, "promfleet_spoke_prom_up"); got != 1 {
		t.Errorf("prom_up = %v after recovery, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// runFacts
// ---------------------------------------------------------------------------

// TestRunFactsCountsEveryRefresh. The collector owns the schedule but knows
// nothing about metrics, so if this loop stopped counting,
// promfleet_spoke_facts_refresh_total would be a metric the charts alert on
// that nothing ever increments.
func TestRunFactsCountsEveryRefresh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		promURL    func(t *testing.T) string
		wantResult string
		wantWarn   bool
	}{
		{
			name: "a healthy Prometheus",
			promURL: func(t *testing.T) string {
				t.Helper()
				return pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{}).URL
			},
			wantResult: "ok",
		},
		{
			name:       "a Prometheus that is not there",
			promURL:    func(t *testing.T) string { t.Helper(); return "http://" + deadAddr(t) },
			wantResult: "error",
			wantWarn:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clock := newStubClock()
			s, logs := newTestSpoke(t, clock, nil)
			s.prom = newPromClient(t, tc.promURL(t))
			s.facts = newFacts(t, s.prom)
			// The facts interval doubles as the budget for one collection, and
			// promclient refuses a budget under its 250ms hop margin, so this
			// cannot be shortened arbitrarily.
			s.timing.facts = 600 * time.Millisecond

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); s.runFacts(ctx) }()

			eventually(t, "a refresh to be counted", func() bool {
				return logs.metric(t, "promfleet_spoke_facts_refresh_total", "result="+tc.wantResult) >= 1
			})
			cancel()
			<-done

			if tc.wantWarn && !logs.has("cluster facts refresh incomplete") {
				t.Errorf("a failed refresh was counted but not logged; got %s", logs.messages())
			}
			if !tc.wantWarn && logs.has("cluster facts refresh incomplete") {
				t.Errorf("a healthy refresh logged a warning; got %s", logs.messages())
			}
		})
	}
}

// TestProbeLoopExactlyTwoFailuresAreEnough pins the boundary itself.
// TestProbeLoopNeedsTwoFailuresBeforeReportingNotReady proves one failure is
// not enough by polling generously for up to ten seconds, which would pass
// just as happily if the real threshold were three: the loop keeps probing on
// its own schedule and would eventually cross a higher threshold too. This
// gives the loop only a fraction of one probe interval after the second
// failure, a window a three-failure threshold could not meet.
func TestProbeLoopExactlyTwoFailuresAreEnough(t *testing.T) {
	t.Parallel()

	prom, url := newSwitchableProm(t, false)
	s, _ := newTestSpoke(t, newStubClock(), nil)
	s.prom = newPromClient(t, url)
	// Long enough that a deadline well short of one interval cannot be
	// confused with a third probe arriving on schedule.
	s.timing.probe = 2 * time.Second
	s.health.Set("prometheus", true, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.probeLoop(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	// Ping is two requests per probe; four requests is the second probe done.
	eventually(t, "the second probe to fail", func() bool { return prom.count() >= 4 })

	deadline := time.Now().Add(time.Second) // well inside the 2s probe interval
	for time.Now().Before(deadline) {
		if _, blocked := notReady(s.health, "prometheus"); blocked {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("readiness had not dropped within one probe interval of the second " +
		"consecutive failure; the threshold must be exactly two, not three")
}

// ---------------------------------------------------------------------------
// dialOnce and dialLoop
// ---------------------------------------------------------------------------

// TestDialOnceRefusesWithoutAnIdentity. Dialling without a certificate would
// fail the handshake and be counted as a hub problem; naming it is what tells
// an operator the enrollment never completed.
func TestDialOnceRefusesWithoutAnIdentity(t *testing.T) {
	t.Parallel()

	s, logs := newTestSpoke(t, newStubClock(), nil)
	if got := s.dialOnce(t.Context(), "wss://hub.test/tunnel", quiet()); got != "no-identity" {
		t.Errorf("dialOnce with no identity = %q, want no-identity", got)
	}
	if got := logs.metric(t, "promfleet_spoke_tunnel_up", "endpoint=wss://hub.test/tunnel"); got != 0 {
		t.Errorf("tunnel_up = %v for a tunnel that was never dialled, want 0", got)
	}
}

// TestDialOnceServesTheHubOverARealTunnel drives the whole spoke side of
// ADR-0014 against a real wstun server: the upgrade, the in-band proof of
// possession, and then the two calls the hub makes back down the tunnel.
//
// Do and Describe are only interesting over the wire. Called directly they are
// two lines of delegation; called from the hub they are what the product does.
func TestDialOnceServesTheHubOverARealTunnel(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newTunnelHub(t, ca)
	fakeProm := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})

	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	s.prom = newPromClient(t, fakeProm.URL)
	s.facts = newFacts(t, s.prom)
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))
	if err := s.facts.Refresh(t.Context()); err != nil {
		t.Fatalf("prime the facts cache: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	reason := make(chan string, 1)
	go func() { reason <- s.dialOnce(ctx, hub.url, quiet()) }()

	session := hub.awaitSession(t)
	if got := session.Identity().ClusterID; got != "prod-eu-1" {
		t.Errorf("the hub derived cluster %q from the certificate, want prod-eu-1", got)
	}
	if got := logs.metric(t, "promfleet_spoke_tunnel_up", "endpoint="+hub.url); got != 1 {
		t.Errorf("tunnel_up = %v while connected, want 1", got)
	}
	if _, blocked := notReady(s.health, "tunnel"); blocked {
		t.Error("readiness still reports no tunnel while one is established")
	}

	// The hub asks the spoke for cluster facts. This reaches spoke.Describe.
	facts, err := session.Describe(t.Context(), "")
	if err != nil {
		t.Fatalf("Describe over the tunnel: %v", err)
	}
	if facts.Cluster.ID != "prod-eu-1" {
		t.Errorf("facts cluster = %q, want prod-eu-1", facts.Cluster.ID)
	}
	if facts.Fingerprint == "" {
		t.Error("the facts carried no fingerprint, so the hub cannot tell when they change")
	}

	// And then a query. This reaches spoke.Do and the local Prometheus.
	resp, err := session.Do(t.Context(), &tunnel.Request{
		Method: http.MethodPost, Path: "/api/v1/query", Form: []byte("query=up"),
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Do over the tunnel: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close the response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status"`) {
		t.Errorf("query answered %d %q, want a Prometheus document", resp.StatusCode, body)
	}

	cancel()
	select {
	case got := <-reason:
		if got != "context-cancelled" {
			t.Errorf("dialOnce reported %q for a cancelled tunnel, want context-cancelled", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("dialOnce did not return after its context was cancelled")
	}
}

// TestDialOnceDropsTheTunnelOnAReconnectSignal is how a renewed certificate
// reaches the hub. Waiting for the old connection to die on its own would mean
// presenting the superseded certificate for up to another week.
func TestDialOnceDropsTheTunnelOnAReconnectSignal(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newTunnelHub(t, ca)
	clock := newStubClock()
	s, _ := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	s.prom = newPromClient(t, pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{}).URL)
	s.facts = newFacts(t, s.prom)
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reason := make(chan string, 1)
	go func() { reason <- s.dialOnce(ctx, hub.url, quiet()) }()

	session := hub.awaitSession(t)
	s.signalReconnect()

	select {
	case got := <-reason:
		if got != "context-cancelled" {
			t.Errorf("dialOnce reported %q after a reconnect signal, want context-cancelled", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a reconnect signal did not drop the tunnel")
	}
	select {
	case <-session.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("the hub still thinks the session is live after the spoke reconnected")
	}
}

// TestDialOnceClassifiesAFailedDial keeps the reconnect counter's reason label
// inside its closed set even when the hub is not there at all.
func TestDialOnceClassifiesAFailedDial(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	clock := newStubClock()
	s, _ := newTestSpoke(t, clock, &config.Spoke{ClusterID: "prod-eu-1"})
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	got := s.dialOnce(t.Context(), "ws://"+deadAddr(t)+"/tunnel", quiet())
	if got != "dial" {
		t.Errorf("dialOnce against nothing = %q, want dial", got)
	}
}

// TestDialLoopStopsOnAnEndpointItCannotUse. A value that cannot be normalised
// will never work, so retrying it forever would just be noise; the operator
// needs one line naming the setting.
func TestDialLoopStopsOnAnEndpointItCannotUse(t *testing.T) {
	t.Parallel()

	s, logs := newTestSpoke(t, newStubClock(), nil)
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(context.Background(), "ftp://hub.test/tunnel") }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop retried an endpoint that can never be dialled")
	}
	if !logs.has("hub endpoint is unusable") {
		t.Errorf("the bad endpoint was not reported; got %s", logs.messages())
	}
}

// TestDialLoopNormalisesTheEndpoint keeps the pre-ADR-0014 host:port form
// working, and says so once rather than logging a URL an operator never
// configured without explanation.
func TestDialLoopNormalisesTheEndpoint(t *testing.T) {
	t.Parallel()

	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: time.Millisecond,
		ReconnectMaxBackoff: 5 * time.Millisecond,
	})
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(newTestCA(t).identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, deadAddr(t)) }()

	eventually(t, "the normalised endpoint to be logged", func() bool {
		return logs.has("hub endpoint normalised")
	})
	r, _ := logs.find("hub endpoint normalised")
	if got := attrString(r, "url"); !strings.HasPrefix(got, "wss://") || !strings.HasSuffix(got, "/tunnel") {
		t.Errorf("normalised url = %q, want a wss:// URL ending in /tunnel", got)
	}
	cancel()
	<-done
}

// TestDialLoopStopsDuringTheOpeningStagger. The stagger exists so that a
// hundred spokes installed in one afternoon do not arrive together; a spoke
// asked to shut down inside it must not sit out the delay first.
func TestDialLoopStopsDuringTheOpeningStagger(t *testing.T) {
	t.Parallel()

	s, _ := newTestSpoke(t, newStubClock(), nil)
	s.timing.dialStagger = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, "ws://hub.test/tunnel") }()
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop waited out its opening stagger after being cancelled")
	}
}

// TestDialLoopStopsDuringTheBackoff. The wait between attempts is the longest
// thing this loop ever does, so it is where a SIGTERM most often lands. Sitting
// out a ten-second backoff before noticing would put the pod past its
// termination grace period and turn a clean drain into a kill.
func TestDialLoopStopsDuringTheBackoff(t *testing.T) {
	t.Parallel()

	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID: "prod-eu-1",
		// Long enough that the loop is certainly still asleep when the context
		// is cancelled, rather than back at the top dialling again.
		ReconnectMinBackoff: 30 * time.Second,
		ReconnectMaxBackoff: time.Minute,
	})
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(newTestCA(t).identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, "ws://"+deadAddr(t)+"/tunnel") }()

	// The line is logged immediately before the sleep starts.
	eventually(t, "the loop to reach its backoff", func() bool {
		return logs.has("tunnel closed, reconnecting")
	})
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dialLoop sat out a 30 second backoff after being cancelled")
	}
}

// TestDialLoopReconnectsAndCounts drives the loop against a real hub that
// hangs up, and pins that a reconnect is counted under a reason from the
// closed set rather than under the raw error.
func TestDialLoopReconnectsAndCounts(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	hub := newTunnelHub(t, ca)
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: time.Millisecond,
		ReconnectMaxBackoff: 5 * time.Millisecond,
	})
	s.prom = newPromClient(t, pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{}).URL)
	s.facts = newFacts(t, s.prom)
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(ca.identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(24*time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, hub.url) }()

	// Hang up on the spoke twice: the loop has to come back both times.
	for i := range 2 {
		session := hub.awaitSession(t)
		if err := session.Close("hub restart"); err != nil {
			t.Fatalf("close session %d: %v", i, err)
		}
	}
	eventually(t, "the reconnect to be counted", func() bool {
		return logs.metric(t, "promfleet_spoke_tunnel_reconnects_total", "reason=conn-closed") >= 1
	})
	if !logs.has("tunnel closed, reconnecting") {
		t.Errorf("the reconnect was not logged; got %s", logs.messages())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("dialLoop did not stop when cancelled")
	}
	if got := logs.metric(t, "promfleet_spoke_tunnel_up", "endpoint="+hub.url); got != 0 {
		t.Errorf("tunnel_up = %v after shutdown, want 0", got)
	}
}

// TestDialLoopResetsBackoffOnlyAfterAConnectionThatLasted is the anti-hammer
// property. A hub that accepts a connection and dies half a second later must
// see the backoff keep growing; a hub that held a tunnel up for a minute has
// earned a fresh start.
//
// The two phases are told apart by the delay the loop logs: a window that has
// grown for eight attempts practically never yields five consecutive delays
// short enough to have come from the opening window.
func TestDialLoopResetsBackoffOnlyAfterAConnectionThatLasted(t *testing.T) {
	t.Parallel()

	const base = time.Millisecond
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: base,
		ReconnectMaxBackoff: 10 * time.Second,
	})
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(newTestCA(t).identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(time.Hour)))

	// Nothing is listening, so every attempt fails at once and the loop is
	// bounded only by its own backoff.
	endpoint := "ws://" + deadAddr(t) + "/tunnel"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, endpoint) }()

	// Phase one: the clock does not move, so no connection ever "lasts" and
	// the window keeps doubling.
	eventually(t, "the backoff window to grow", func() bool {
		return maxLoggedDelay(logs) > 8*base
	})

	// Phase two: every read of the clock moves it past a minute, so each
	// connection counts as one that lasted.
	clock.setStep(minConnectionLifetime + time.Second)
	grown := countLoggedDelays(logs)
	eventually(t, "five more reconnects", func() bool { return countLoggedDelays(logs) >= grown+5 })
	cancel()
	<-done

	for _, d := range loggedDelays(logs)[grown:] {
		if d > 4*base+base/4 {
			t.Fatalf("a delay of %s after a connection that lasted; the backoff was not "+
				"reset, so a hub that recovers is still being backed off", d)
		}
	}
}

// TestDialLoopDoesNotResetBackoffAtExactlyTheThreshold pins the boundary of
// "lasted": minConnectionLifetime is a floor a connection must exceed, not
// merely meet. TestDialLoopResetsBackoffOnlyAfterAConnectionThatLasted only
// proves a connection a full second past the floor resets the backoff, which
// an off-by-one ">=" threshold would do identically. Stepping the clock by
// exactly the floor on every read makes each connection appear to have lasted
// precisely minConnectionLifetime, which must not reset anything.
func TestDialLoopDoesNotResetBackoffAtExactlyTheThreshold(t *testing.T) {
	t.Parallel()

	const base = time.Millisecond
	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, &config.Spoke{
		ClusterID:           "prod-eu-1",
		ReconnectMinBackoff: base,
		ReconnectMaxBackoff: 10 * time.Second,
	})
	s.timing.dialStagger = time.Millisecond
	s.setIdentity(newTestCA(t).identityOver(t, "prod-eu-1", clock.Now().Add(-time.Hour), clock.Now().Add(time.Hour)))
	// Every read of the clock advances it by exactly the floor, so
	// s.now().Sub(connected) is exactly minConnectionLifetime on every
	// attempt: "longer than" (>) must refuse to reset here, and the
	// off-by-one ">=" would wrongly accept.
	clock.setStep(minConnectionLifetime)

	endpoint := "ws://" + deadAddr(t) + "/tunnel"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.dialLoop(ctx, endpoint) }()
	defer func() {
		cancel()
		<-done
	}()

	eventually(t, "the backoff window to grow past its floor", func() bool {
		return maxLoggedDelay(logs) > 8*base
	})
}

// loggedDelays returns the reconnect delay from every "tunnel closed" line.
func loggedDelays(logs *spokeProbe) []time.Duration {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var out []time.Duration
	for _, r := range logs.records {
		if !strings.Contains(r.Message, "tunnel closed") {
			continue
		}
		d, err := time.ParseDuration(attrString(r, "in"))
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

func countLoggedDelays(logs *spokeProbe) int { return len(loggedDelays(logs)) }

func maxLoggedDelay(logs *spokeProbe) time.Duration {
	var worst time.Duration
	for _, d := range loggedDelays(logs) {
		if d > worst {
			worst = d
		}
	}
	return worst
}

// ---------------------------------------------------------------------------
// Do
// ---------------------------------------------------------------------------

// TestDoTracksInflightRequests. The gauge is what an operator looks at to see
// whether a spoke is saturated, and it is only touched here — so it is only
// observable while a request is actually in flight.
func TestDoTracksInflightRequests(t *testing.T) {
	t.Parallel()

	entered, release, promURL := newBlockingProm(t)
	s, logs := newTestSpoke(t, newStubClock(), nil)
	s.prom = newPromClient(t, promURL)

	if got := logs.metric(t, "promfleet_spoke_inflight_requests"); got != 0 {
		t.Fatalf("inflight_requests = %v before any request", got)
	}
	type result struct {
		resp *tunnel.Response
		err  error
	}
	out := make(chan result, 1)
	go func() {
		resp, err := s.Do(t.Context(), &tunnel.Request{
			Method: http.MethodPost, Path: "/api/v1/query", Form: []byte("query=up"),
		})
		out <- result{resp, err}
	}()

	<-entered
	if got := logs.metric(t, "promfleet_spoke_inflight_requests"); got != 1 {
		t.Errorf("inflight_requests = %v while a request is upstream, want 1", got)
	}
	release()

	got := <-out
	if got.err != nil {
		t.Fatalf("Do: %v", got.err)
	}
	if err := got.resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if v := logs.metric(t, "promfleet_spoke_inflight_requests"); v != 0 {
		t.Errorf("inflight_requests = %v after the request finished, want 0", v)
	}
}

// newBlockingProm is a Prometheus that answers only when told to, so that a
// gauge which is non-zero purely for the duration of a request has a duration
// the test controls.
func newBlockingProm(t *testing.T) (entered <-chan struct{}, release func(), url string) {
	t.Helper()

	arrived := make(chan struct{}, 1)
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived <- struct{}{}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(srv.Close)

	var once sync.Once
	return arrived, func() { once.Do(func() { close(gate) }) }, srv.URL
}

// ---------------------------------------------------------------------------
// the admin listener
// ---------------------------------------------------------------------------

// TestStartAdminServesTheOperatorEndpoints. These are what a Deployment, a
// scrape config and an operator all depend on, so they are asserted by
// fetching them rather than by inspecting the mux.
func TestStartAdminServesTheOperatorEndpoints(t *testing.T) {
	t.Parallel()

	build := version.Build{Version: "test"}
	registry := obs.NewRegistry(build, "spoke")
	s, logs := newTestSpoke(t, newStubClock(), &config.Spoke{
		AdminAddr: "127.0.0.1:0", ShutdownGrace: 5 * time.Second, PprofEnabled: true,
	})

	srv, err := s.startAdmin(t.Context(), registry)
	if err != nil {
		t.Fatalf("startAdmin: %v", err)
	}
	defer s.stopAdmin(srv)

	for _, tc := range []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/healthz", wantStatus: http.StatusOK, wantBody: `"status"`},
		{path: "/readyz", wantStatus: http.StatusOK, wantBody: `"status"`},
		{path: "/metrics", wantStatus: http.StatusOK, wantBody: "promfleet_spoke_build_info"},
		{path: "/debug/pprof/cmdline", wantStatus: http.StatusOK},
		// Nothing else is mounted: the admin listener is not a general
		// surface, and a catch-all here would hide a routing mistake.
		{path: "/anything-else", wantStatus: http.StatusNotFound},
	} {
		body, status, header := getAdmin(t, srv, tc.path)
		if status != tc.wantStatus {
			t.Errorf("GET %s = %d, want %d", tc.path, status, tc.wantStatus)
		}
		if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
			t.Errorf("GET %s body does not contain %q", tc.path, tc.wantBody)
		}
		// Every response goes through the same chain, so the security headers
		// and the request id are the evidence the chain is wired at all.
		if header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s served without the security headers", tc.path)
		}
		if header.Get("X-Request-Id") == "" {
			t.Errorf("GET %s served without a request id", tc.path)
		}
	}
	if !logs.has("pprof is enabled") {
		t.Errorf("pprof was mounted without a warning; got %s", logs.messages())
	}
	if !logs.has("admin listener ready") {
		t.Errorf("the bound address was never logged; got %s", logs.messages())
	}
}

// getAdmin fetches one path from the admin listener.
func getAdmin(t *testing.T, srv *httpx.Server, path string) (string, int, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+srv.Addr()+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body), resp.StatusCode, resp.Header
}

// TestStartAdminReportsABindFailure. Binding happens synchronously so that a
// port conflict comes back here rather than into a channel nobody reads while
// the process comes up looking healthy and serving nothing.
func TestStartAdminReportsABindFailure(t *testing.T) {
	t.Parallel()

	s, _ := newTestSpoke(t, newStubClock(), &config.Spoke{AdminAddr: "not-an-address"})
	srv, err := s.startAdmin(t.Context(), obs.NewRegistry(version.Build{Version: "test"}, "spoke"))
	if srv != nil {
		t.Error("a failed bind still returned a server")
	}
	errContains(t, err, "start the admin listener")
}

// TestStopAdminReportsAnUnfinishedDrain. The grace is a bound, not a promise:
// when it expires with work still in flight the operator has to be told, or a
// pod killed mid-request looks like a clean shutdown.
func TestStopAdminReportsAnUnfinishedDrain(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httpx.NewServer(httpx.ServerConfig{
		Name: "admin", Addr: "127.0.0.1:0", Logger: quiet(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			entered <- struct{}{}
			<-release
			w.WriteHeader(http.StatusOK)
		}),
	})
	if err := srv.Start(t.Context()); err != nil {
		t.Fatalf("start: %v", err)
	}

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"http://"+srv.Addr()+"/wedged", nil)
		if err != nil {
			return
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-entered

	s, logs := newTestSpoke(t, newStubClock(), &config.Spoke{ShutdownGrace: 20 * time.Millisecond})
	s.stopAdmin(srv)

	if !logs.has("admin listener did not shut down cleanly") {
		t.Errorf("a drain that ran out of time was not reported; got %s", logs.messages())
	}
	close(release)
	<-requestDone
}

// TestStopAdminIsSilentWhenTheDrainCompletes is the other half: an ordinary
// shutdown must not produce a warning an operator learns to ignore.
func TestStopAdminIsSilentWhenTheDrainCompletes(t *testing.T) {
	t.Parallel()

	s, logs := newTestSpoke(t, newStubClock(), &config.Spoke{
		AdminAddr: "127.0.0.1:0", ShutdownGrace: 5 * time.Second,
	})
	srv, err := s.startAdmin(t.Context(), obs.NewRegistry(s.build, "spoke"))
	if err != nil {
		t.Fatalf("startAdmin: %v", err)
	}
	s.stopAdmin(srv)

	if logs.has("did not shut down cleanly") {
		t.Errorf("a clean shutdown warned anyway; got %s", logs.messages())
	}
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

// spokeConfig is a configuration that starts.
func spokeConfig(t *testing.T, hubAPI, tunnelURL, promURL string) *config.Spoke {
	t.Helper()
	return &config.Spoke{
		HubEndpoints:         []string{tunnelURL},
		HubAPIURL:            hubAPI,
		EnrollmentTokenFile:  writeFile(t, t.TempDir(), "token", "pmf_enr_token"),
		ClusterID:            "prod-eu-1",
		ClusterLabels:        map[string]string{"env": "prod"},
		IdentityBackend:      config.IdentityBackendMemory,
		PrometheusURL:        promURL,
		FactsRefreshInterval: time.Minute,
		ReconnectMinBackoff:  time.Millisecond,
		ReconnectMaxBackoff:  10 * time.Millisecond,
		AdminAddr:            "127.0.0.1:0",
		LogLevel:             "debug",
		LogFormat:            "json",
		ShutdownGrace:        5 * time.Second,
	}
}

// TestRunWiresTheSpokeAndDrainsOnShutdown is the composition root doing its
// one job: everything below it exists and is connected, and a cancelled
// context is a clean exit rather than a failure.
func TestRunWiresTheSpokeAndDrainsOnShutdown(t *testing.T) {
	t.Parallel()

	e, _ := newEnroller(t)
	prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})
	cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", prom.URL)

	clock := newStubClock()
	s, logs := newTestSpoke(t, clock, cfg)
	registry := obs.NewRegistry(s.build, "spoke")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, registry) }()

	eventually(t, "the spoke to obtain a certificate", func() bool {
		return s.currentIdentity() != nil
	})
	eventually(t, "the admin listener to be ready", func() bool {
		return logs.has("admin listener ready")
	})
	if s.health.Draining() {
		t.Error("the spoke reported draining before it was asked to stop")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() = %v, want nil for a cancelled context: a clean SIGTERM must "+
				"not exit non-zero", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}
	if !s.health.Draining() {
		t.Error("readiness did not start draining on shutdown, so a load balancer keeps sending work")
	}
	if !logs.has("identity store selected") {
		t.Errorf("the chosen identity backend was never logged; got %s", logs.messages())
	}
}

// TestRunReportsAFailureToWireAnything walks every dependency run() builds.
// Each one is fatal on purpose: a spoke that came up without its Prometheus
// client, its facts collector or its identity would be a cluster that shows as
// connected and answers nothing.
func TestRunReportsAFailureToWireAnything(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spoil   func(cfg *config.Spoke)
		wantMsg string
	}{
		{
			name:    "the admin listener cannot bind",
			spoil:   func(cfg *config.Spoke) { cfg.AdminAddr = "not-an-address" },
			wantMsg: "start the admin listener",
		},
		{
			name:    "the Prometheus URL is unusable",
			spoil:   func(cfg *config.Spoke) { cfg.PrometheusURL = "" },
			wantMsg: "configure the Prometheus client",
		},
		{
			name:    "the cluster ID is not a legal identity",
			spoil:   func(cfg *config.Spoke) { cfg.ClusterID = "Not A Cluster" },
			wantMsg: "configure the facts collector",
		},
		{
			name:    "the identity backend does not exist",
			spoil:   func(cfg *config.Spoke) { cfg.IdentityBackend = "vault" },
			wantMsg: "configure the identity store",
		},
		{
			name:    "there is no enrollment token",
			spoil:   func(cfg *config.Spoke) { cfg.EnrollmentTokenFile = "" },
			wantMsg: "no enrollment token file",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, _ := newEnroller(t)
			prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})
			cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", prom.URL)
			tc.spoil(cfg)

			s, _ := newTestSpoke(t, newStubClock(), cfg)
			err := s.run(t.Context(), obs.NewRegistry(s.build, "spoke"))
			errContains(t, err, tc.wantMsg)
		})
	}
}

// TestRunWarnsWhenTheFirstFactsRefreshFails. "Cluster reachable, Prometheus
// down" is far more useful to an agent than silence, so a spoke whose
// Prometheus is unreachable must still connect and say so.
func TestRunWarnsWhenTheFirstFactsRefreshFails(t *testing.T) {
	t.Parallel()

	e, _ := newEnroller(t)
	cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", "http://"+deadAddr(t))

	s, logs := newTestSpoke(t, newStubClock(), cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, obs.NewRegistry(s.build, "spoke")) }()

	eventually(t, "the incomplete first refresh to be reported", func() bool {
		return logs.has("initial facts refresh incomplete")
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run() = %v, want nil: a Prometheus that is down must not stop the spoke", err)
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// TestRunRejectsAnUnusableObservabilityConfiguration. Logging and tracing come
// first because everything below them is only visible through them, so a
// failure here has to stop the process rather than start a spoke nobody can
// see.
func TestRunRejectsAnUnusableObservabilityConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spoil   func(cfg *config.Spoke)
		wantMsg string
	}{
		{
			name:    "an unknown log level",
			spoil:   func(cfg *config.Spoke) { cfg.LogLevel = "chatty" },
			wantMsg: "configure logging",
		},
		{
			name:    "an unknown log format",
			spoil:   func(cfg *config.Spoke) { cfg.LogFormat = "xml" },
			wantMsg: "configure logging",
		},
		{
			name:    "a collector address that is not an address",
			spoil:   func(cfg *config.Spoke) { cfg.OTLPEndpoint = "\x00" },
			wantMsg: "initialise tracing",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := spokeConfig(t, "http://hub.test", "ws://hub.test/tunnel", "http://prom.test")
			tc.spoil(cfg)
			errContains(t, Run(t.Context(), cfg), tc.wantMsg)
		})
	}
}

// TestRunStartsAndStopsTheWholeProcess is Run's own path: it builds the
// logger, the registry, the health set and tracing, hands over to run, and
// comes back nil on a cancelled context.
//
// It is not parallel because it captures os.Stdout, which is where the
// composition root's logger writes by construction.
func TestRunStartsAndStopsTheWholeProcess(t *testing.T) {
	e, _ := newEnroller(t)
	prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})
	cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", prom.URL)

	stdout := captureStdout(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	eventually(t, "the spoke to obtain a certificate", func() bool {
		return strings.Contains(stdout(), "obtained client certificate")
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil on a clean shutdown", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	logged := stdout()
	for _, want := range []string{`"component":"spoke"`, `"cluster_id":"prod-eu-1"`, `"msg":"starting"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("the process log does not contain %s\n%s", want, logged)
		}
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(logged, "\n", 2)[0]), &first); err != nil {
		t.Fatalf("the first log line is not JSON: %v", err)
	}
	if first["version"] != version.Get().Version {
		t.Errorf("startup line reported version %v, want %v", first["version"], version.Get().Version)
	}
}

// TestRunDoesNotFailBecauseTracesCouldNotBeFlushed. The collector being
// unreachable at shutdown is an observability problem, not a process one: a
// spoke that exited non-zero because a trace could not be delivered would look
// like a crash to every restart policy watching it.
//
// It is not parallel: it captures os.Stdout and installs a global tracer
// provider.
func TestRunDoesNotFailBecauseTracesCouldNotBeFlushed(t *testing.T) {
	e, _ := newEnroller(t)
	prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})
	cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", prom.URL)
	// A collector that is not there. The exporter connects lazily, so this
	// fails at the flush rather than at startup.
	cfg.OTLPEndpoint = "http://" + deadAddr(t)
	cfg.TraceSampleRatio = 1

	stdout := captureStdout(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	eventually(t, "the spoke to obtain a certificate", func() bool {
		return strings.Contains(stdout(), "obtained client certificate")
	})
	// Put a span in the batch so the shutdown flush has something to fail to
	// deliver. Run installed the global provider.
	_, span := otel.Tracer("spoke-test").Start(context.Background(), "operation")
	span.End()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil: an undeliverable trace is not a process failure", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Run did not return")
	}
	eventually(t, "the failed flush to be reported", func() bool {
		return strings.Contains(stdout(), "flushing traces failed")
	})
}

// TestRunTraceFlushRespectsItsOwnDeadline pins the 5-second budget Run gives
// the trace flush at shutdown.
//
// TestRunDoesNotFailBecauseTracesCouldNotBeFlushed points the exporter at a
// dead address, which fails fast (connection refused) regardless of the
// budget and so cannot tell a 5-second deadline from one collapsed by a
// mutated arithmetic expression to near zero. This test instead points it at
// a listener that accepts a connection and then never completes the gRPC
// handshake, so the flush can only be resolved by its deadline expiring, and
// the elapsed time between cancellation and shutdown pins how long that
// deadline actually was.
//
// It is not parallel: it captures os.Stdout and installs a global tracer
// provider, same as its sibling.
func TestRunTraceFlushRespectsItsOwnDeadline(t *testing.T) {
	e, _ := newEnroller(t)
	prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})

	cfg := spokeConfig(t, e.apiURL, "ws://"+deadAddr(t)+"/tunnel", prom.URL)
	cfg.OTLPEndpoint = "http://" + ln.Addr().String()
	cfg.TraceSampleRatio = 1

	stdout := captureStdout(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	eventually(t, "the spoke to obtain a certificate", func() bool {
		return strings.Contains(stdout(), "obtained client certificate")
	})
	// Put a span in the batch so the shutdown flush has something to try to
	// deliver. Run installed the global provider.
	_, span := otel.Tracer("spoke-test").Start(context.Background(), "operation")
	span.End()

	cancel()
	start := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() = %v, want nil: an undeliverable trace is not a process failure", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
	}
	elapsed := time.Since(start)
	// Comfortably below the real 5s budget, but far above what a budget
	// collapsed by a mutated "5*time.Second" (to ~0, via division, or to a
	// negative duration, via subtraction) would produce: either gives up
	// almost immediately instead of waiting out a collector that never
	// answers.
	if elapsed < 3*time.Second {
		t.Errorf("Run returned after %s; the flush must wait close to its 5s budget "+
			"against a collector that never completes the handshake, not give up almost "+
			"immediately", elapsed)
	}
}

// captureStdout replaces os.Stdout for the duration of the test and returns a
// function reading everything written to it. Run's logger writes to os.Stdout
// by construction, which is the only way to see what a composition root said.
func captureStdout(t *testing.T) func() string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w

	var (
		mu  sync.Mutex
		buf strings.Builder
	)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		chunk := make([]byte, 4096)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				mu.Lock()
				buf.Write(chunk[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		os.Stdout = original
		_ = w.Close()
		<-drained
		_ = r.Close()
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// ---------------------------------------------------------------------------
// small wiring helpers
// ---------------------------------------------------------------------------

// newPromClient builds the client the spoke would build for a local
// Prometheus.
func newPromClient(t *testing.T, baseURL string) *promclient.Client {
	t.Helper()
	c, err := promclient.New(promclient.Config{
		BaseURL: baseURL, Timeout: 5 * time.Second, Logger: quiet(),
	})
	if err != nil {
		t.Fatalf("promclient.New: %v", err)
	}
	return c
}

// newFacts builds the collector the spoke would build.
func newFacts(t *testing.T, client *promclient.Client) *clusterfacts.Collector {
	t.Helper()
	c, err := clusterfacts.New(clusterfacts.Config{
		ClusterID:       "prod-eu-1",
		AgentVersion:    "test",
		ProtocolVersion: protocolVersion,
		Client:          client,
		Logger:          quiet(),
	})
	if err != nil {
		t.Fatalf("clusterfacts.New: %v", err)
	}
	return c
}
