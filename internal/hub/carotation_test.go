// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/obs"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// rotationBase is the instant every rotation fixture starts at. Whole seconds,
// because the phase timestamp is RFC 3339 and a fractional base would make
// "the moment it was written" and "the moment it was read back" differ.
var rotationBase = time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)

// rotationClock is a manually advanced clock safe for concurrent use.
type rotationClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *rotationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *rotationClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeHoldouts is a stand-in for the issuer tracker. The state machine's own
// tests use it so that "a spoke still depends on the outgoing root" is a fact
// the test states rather than a session it has to build; one test below uses
// the real tracker instead.
type fakeHoldouts struct {
	mu sync.Mutex
	n  map[string]int
	// asked records every fingerprint queried, so a test can prove the gate
	// consulted the outgoing root and not something else.
	asked []string
}

func newFakeHoldouts() *fakeHoldouts { return &fakeHoldouts{n: map[string]int{}} }

func (f *fakeHoldouts) holdoutsOn(fingerprint string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, fingerprint)
	return f.n[fingerprint]
}

func (f *fakeHoldouts) set(fingerprint string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n[fingerprint] = n
}

func (f *fakeHoldouts) queried() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// recordingMetrics captures what the rotator publishes.
type recordingMetrics struct {
	mu          sync.Mutex
	phase       string
	since       time.Time
	roots       int
	outgoing    int
	expiry      time.Time
	transitions []string
}

func (m *recordingMetrics) CACertExpiry(notAfter time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expiry = notAfter
}

func (m *recordingMetrics) CATrustRoots(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.roots = n
}

func (m *recordingMetrics) CARotationPhase(phase string, since time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase, m.since = phase, since
}

func (m *recordingMetrics) CAOutgoingRootSessions(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outgoing = n
}

func (m *recordingMetrics) CARotationTransition(to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transitions = append(m.transitions, to)
}

func (m *recordingMetrics) snapshot() (phase string, roots, outgoing int, transitions []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase, m.roots, m.outgoing, append([]string(nil), m.transitions...)
}

// rotationFixture is one hub replica's rotation controller over a fake API
// server holding a real CA Secret.
type rotationFixture struct {
	t        *testing.T
	api      *fakeAPI
	cfg      *config.Hub
	clock    *rotationClock
	holdouts *fakeHoldouts
	metrics  *recordingMetrics
	sink     *logSink
	rotator  *caRotator

	certPEM, keyPEM []byte
}

// caLifetime is how long the fixture's root lives. With the fixture's 4h
// certificate TTL and 2h renewal grace the rotation runway is 10h, so 100h
// leaves the fraction trigger (20h) in charge and 20h leaves the runway floor
// in charge -- both are exercised below.
const caLifetime = 100 * time.Hour

// newRotationFixture builds a rotator whose Secret holds a fresh root minted
// at rotationBase.
func newRotationFixture(t *testing.T, caTTL time.Duration, extra ...string) *rotationFixture {
	t.Helper()

	clock := &rotationClock{t: rotationBase}
	args := append([]string{
		"--spoke-cert-ttl", "4h",
		"--renew-grace", "2h",
		"--ca-rotation-poll-interval", "1m",
	}, extra...)
	cfg := newHubConfig(t, args...)

	certPEM, keyPEM, err := ca.NewRootPEM(ca.Options{
		TrustDomain: cfg.TrustDomain,
		CATTL:       caTTL,
		Clock:       func() time.Time { return rotationBase },
	})
	if err != nil {
		t.Fatalf("mint the fixture root: %v", err)
	}
	authority, err := ca.Parse(certPEM, keyPEM, ca.Options{
		TrustDomain:  cfg.TrustDomain,
		SpokeCertTTL: cfg.SpokeCertTTL,
		Clock:        clock.Now,
	})
	if err != nil {
		t.Fatalf("parse the fixture root: %v", err)
	}

	pepper, err := token.GeneratePepper()
	if err != nil {
		t.Fatalf("generate pepper: %v", err)
	}
	api := newFakeAPI(t)
	api.put(cfg.CASecretName, map[string][]byte{
		secretKeyCACert: certPEM,
		secretKeyCAKey:  keyPEM,
		secretKeyPepper: pepper,
	})

	logger, sink := newLogSink()
	f := &rotationFixture{
		t: t, api: api, cfg: cfg, clock: clock,
		holdouts: newFakeHoldouts(), metrics: &recordingMetrics{}, sink: sink,
		certPEM: certPEM, keyPEM: keyPEM,
	}
	f.rotator = &caRotator{
		client:    api.client(t),
		secret:    cfg.CASecretName,
		cfg:       cfg,
		logger:    logger,
		metrics:   f.metrics,
		holdouts:  f.holdouts,
		authority: authority,
		now:       clock.Now,
		// Started well before the clock, so the settle guard is satisfied
		// unless a test deliberately pushes it.
		startedAt: rotationBase.Add(-24 * time.Hour),
	}
	return f
}

// step runs one poll and fails on error.
func (f *rotationFixture) step() {
	f.t.Helper()
	if err := f.rotator.step(context.Background()); err != nil {
		f.t.Fatalf("step: %v", err)
	}
}

// data reads the CA Secret as the API server holds it.
func (f *rotationFixture) data() map[string][]byte { return f.api.get(f.cfg.CASecretName) }

// phase reads the persisted phase.
func (f *rotationFixture) phase() string { return string(f.data()[secretKeyRotationPhase]) }

// seed rewrites the Secret's rotation keys, standing in for whatever state a
// previous replica, or a previous process lifetime, left behind.
func (f *rotationFixture) seed(mutate func(data map[string][]byte), annotations map[string]string) {
	f.t.Helper()
	data := f.data()
	mutate(data)
	f.api.putAnnotated(f.cfg.CASecretName, data, annotations)
}

// mintRoot returns a second root, standing in for a successor or a
// predecessor.
func (f *rotationFixture) mintRoot() (certPEM, keyPEM []byte) {
	f.t.Helper()
	certPEM, keyPEM, err := ca.NewRootPEM(ca.Options{TrustDomain: f.cfg.TrustDomain})
	if err != nil {
		f.t.Fatalf("mint a root: %v", err)
	}
	return certPEM, keyPEM
}

// fingerprintOf names the root in a PEM certificate.
func fingerprintOf(t *testing.T, pemBytes []byte) string {
	t.Helper()
	cert, err := parseOneCertificate(pemBytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return ca.Fingerprint(cert)
}

// --- steady state ------------------------------------------------------

func TestCARotationSteadyWritesNothing(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	_, _, updatesBefore := f.api.counts()

	f.step()
	f.step()

	if _, _, updates := f.api.counts(); updates != updatesBefore {
		t.Errorf("a steady hub performed %d Secret writes, want none", updates-updatesBefore)
	}
	phase, roots, outgoing, transitions := f.metrics.snapshot()
	if phase != string(caPhaseSteady) || roots != 1 || outgoing != 0 || len(transitions) != 0 {
		t.Errorf("steady metrics = (%q, roots %d, outgoing %d, transitions %v), want (steady, 1, 0, none)",
			phase, roots, outgoing, transitions)
	}
}

func TestCARotationTriggers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		caTTL    time.Duration
		advance  time.Duration
		annotate string
		want     caPhase
	}{
		{
			name:  "a young root is left alone",
			caTTL: caLifetime, advance: time.Hour, want: caPhaseSteady,
		},
		{
			name:  "the configured fraction starts a rotation",
			caTTL: caLifetime, advance: 85 * time.Hour, want: caPhasePublishing,
		},
		{
			name: "the runway floor starts a rotation the fraction alone would not",
			// 20h of life: a fifth of it is 4h, but a rotation needs 10h, so
			// the floor is what fires at 9h remaining.
			caTTL: 20 * time.Hour, advance: 11 * time.Hour, want: caPhasePublishing,
		},
		{
			name:  "an operator annotation starts one immediately",
			caTTL: caLifetime, advance: 0, annotate: "suspected key compromise",
			want: caPhasePublishing,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRotationFixture(t, tc.caTTL)
			if tc.annotate != "" {
				f.seed(func(map[string][]byte) {}, map[string]string{annotationRotateNow: tc.annotate})
			}
			f.clock.Advance(tc.advance)

			f.step()

			if tc.want == caPhaseSteady {
				// A steady hub writes nothing at all, so the phase key is
				// simply absent rather than spelled out.
				if got := f.phase(); got != "" {
					t.Fatalf("phase = %q, want a hub that wrote nothing", got)
				}
				return
			}
			if got := f.phase(); got != string(tc.want) {
				t.Fatalf("phase = %q, want %q", got, tc.want)
			}
			data := f.data()
			if len(data[secretKeyCANextCert]) == 0 || len(data[secretKeyCANextKey]) == 0 {
				t.Fatal("publishing without a successor root in the Secret")
			}
			if diff := cmp.Diff(f.certPEM, data[secretKeyCACert]); diff != "" {
				t.Errorf("publishing moved the signer (-want +got):\n%s", diff)
			}
			if got := len(f.rotator.authority.TrustBundle()); got != 2 {
				t.Errorf("the local authority trusts %d roots, want 2", got)
			}
			_, roots, _, transitions := f.metrics.snapshot()
			if roots != 2 {
				t.Errorf("trust-roots gauge = %d, want 2", roots)
			}
			if diff := cmp.Diff([]string{string(caPhasePublishing)}, transitions); diff != "" {
				t.Errorf("transitions (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCARotationDueBoundaryIsInclusive pins the exact instant rotationDue
// flips from "not yet" to "due": AT the threshold (remaining == threshold)
// a rotation must already fire, and one tick earlier it must not. This is
// the "remaining > threshold" comparison itself: a CONDITIONALS_BOUNDARY
// mutant turning it into ">=" would wait one tick past the threshold before
// firing, which none of the coarser-grained trigger tests above -- which
// advance the clock by whole hours -- land on closely enough to catch.
func TestCARotationDueBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	cert := f.rotator.authority.Certificate()
	total := cert.NotAfter.Sub(cert.NotBefore)
	threshold := time.Duration(float64(total) * f.cfg.CARotateAtRemainingFraction)
	if runway := f.cfg.CARotationRunway(); threshold < runway {
		threshold = runway
	}
	wantNow := cert.NotAfter.Add(-threshold)

	// One tick before the boundary: remaining is one nanosecond MORE than
	// threshold, so "remaining > threshold" is true and nothing must fire.
	f.clock.Advance(wantNow.Add(-time.Nanosecond).Sub(rotationBase))
	f.step()
	if got := f.phase(); got != "" {
		t.Fatalf("phase = %q one tick before the threshold, want a hub that wrote nothing", got)
	}

	// Exactly at the boundary: remaining == threshold, so "remaining >
	// threshold" is false and the rotation must be due now, not one poll
	// later.
	f.clock.Advance(time.Nanosecond)
	f.step()
	if got := f.phase(); got != string(caPhasePublishing) {
		t.Fatalf("phase = %q exactly at the threshold, want %q", got, caPhasePublishing)
	}
}

func TestCARotationForcedAnnotationIsConsumedOnce(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	f.seed(func(map[string][]byte) {}, map[string]string{annotationRotateNow: "compromise"})

	f.step()

	ann := f.api.annotationsOf(f.cfg.CASecretName)
	if _, still := ann[annotationRotateNow]; still {
		t.Error("the rotate-now annotation survived the rotation it started; it would fire again")
	}
	if ann[annotationRotateAccepted] == "" {
		t.Error("no rotate-accepted annotation records that the trigger was picked up")
	}
	f.sink.mustFind(t, "CA rotation advanced")
}

func TestCARotationForcedDuringARotationDoesNotStartASecond(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	nextCert, nextKey := f.mintRoot()
	f.seed(func(data map[string][]byte) {
		data[secretKeyRotationPhase] = []byte(caPhasePublishing)
		data[secretKeyRotationSince] = []byte(rotationBase.Format(time.RFC3339))
		data[secretKeyCANextCert] = nextCert
		data[secretKeyCANextKey] = nextKey
	}, map[string]string{annotationRotateNow: "again"})

	f.step()

	if got := f.phase(); got != string(caPhasePublishing) {
		t.Fatalf("phase = %q, want it unchanged at publishing", got)
	}
	if diff := cmp.Diff(nextCert, f.data()[secretKeyCANextCert]); diff != "" {
		t.Errorf("the successor root was replaced (-want +got):\n%s", diff)
	}
	if _, still := f.api.annotationsOf(f.cfg.CASecretName)[annotationRotateNow]; still {
		t.Error("the annotation was not consumed, so it would fire once this rotation finished")
	}
	// The phase start must not have been reset by consuming the annotation.
	if got := string(f.data()[secretKeyRotationSince]); got != rotationBase.Format(time.RFC3339) {
		t.Errorf("phase start = %q, want it untouched at %q", got, rotationBase.Format(time.RFC3339))
	}
	f.sink.mustFind(t, "CA rotation state recorded")
}

func TestCARotationSteadyTidiesStrayMaterial(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	strayCert, strayKey := f.mintRoot()
	f.seed(func(data map[string][]byte) {
		data[secretKeyCANextCert] = strayCert
		data[secretKeyCANextKey] = strayKey
		data[secretKeyCAPrevCert] = strayCert
		data[secretKeyRotationHoldout] = []byte("not a timestamp")
	}, nil)

	f.step()

	data := f.data()
	for _, key := range []string{
		secretKeyCANextCert, secretKeyCANextKey, secretKeyCAPrevCert, secretKeyRotationHoldout,
	} {
		if _, present := data[key]; present {
			t.Errorf("%s survived the steady-state tidy-up", key)
		}
	}
	if got := len(f.rotator.authority.TrustBundle()); got != 1 {
		t.Errorf("stray material was trusted: %d roots, want 1", got)
	}
}

func TestCARotationFreezesWideOnAnUnknownPhase(t *testing.T) {
	t.Parallel()

	// An unrecognised phase most plausibly means a rollback to an older
	// binary mid-rotation: the Secret carries material this build cannot
	// interpret. The old behaviour "reset to steady" then narrowed trust to
	// the signer alone and tidied away the very roots an in-flight rotation
	// depends on. The contract now: trust EVERYTHING present, write nothing,
	// report the phase as unknown so the stalled alert pages a human.
	f := newRotationFixture(t, caLifetime)
	prevCert, _ := f.mintRoot()
	f.seed(func(data map[string][]byte) {
		data[secretKeyRotationPhase] = []byte("half-way")
		data[secretKeyCAPrevCert] = prevCert
	}, nil)

	f.step()

	if got := f.phase(); got != "half-way" {
		t.Fatalf("phase = %q, want the unknown phase left exactly as found", got)
	}
	if _, ok := f.data()[secretKeyCAPrevCert]; !ok {
		t.Fatal("the outgoing root was tidied away while the phase was ambiguous")
	}
	if got := len(f.rotator.authority.TrustBundle()); got != 2 {
		t.Fatalf("the local authority trusts %d roots, want 2: ambiguity must widen trust, not narrow it", got)
	}
	if f.sink.find("the CA Secret records a rotation phase this build does not know; holding trust wide and touching nothing") == nil {
		t.Error("the freeze was not logged; nothing would tell an operator why rotation is stuck")
	}
}
func TestCARotationPublishing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		elapsed  time.Duration
		omitNext bool
		want     caPhase
	}{
		{name: "before a full certificate lifetime, nothing moves", elapsed: 3 * time.Hour, want: caPhasePublishing},
		{name: "after a full certificate lifetime, the successor signs", elapsed: 4 * time.Hour, want: caPhaseSigning},
		{name: "a missing successor falls back to steady", elapsed: 8 * time.Hour, omitNext: true, want: caPhaseSteady},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRotationFixture(t, caLifetime)
			nextCert, nextKey := f.mintRoot()
			f.seed(func(data map[string][]byte) {
				data[secretKeyRotationPhase] = []byte(caPhasePublishing)
				data[secretKeyRotationSince] = []byte(rotationBase.Format(time.RFC3339))
				if !tc.omitNext {
					data[secretKeyCANextCert] = nextCert
					data[secretKeyCANextKey] = nextKey
				}
			}, nil)
			f.clock.Advance(tc.elapsed)

			f.step()

			if got := f.phase(); got != string(tc.want) {
				t.Fatalf("phase = %q, want %q", got, tc.want)
			}
			data := f.data()
			if tc.want != caPhaseSigning {
				return
			}
			if diff := cmp.Diff(nextCert, data[secretKeyCACert]); diff != "" {
				t.Errorf("the successor did not become the signer (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(nextKey, data[secretKeyCAKey]); diff != "" {
				t.Errorf("the successor's key did not become the signing key (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(f.certPEM, data[secretKeyCAPrevCert]); diff != "" {
				t.Errorf("the outgoing root was not retained for verification (-want +got):\n%s", diff)
			}
			for _, key := range []string{secretKeyCANextCert, secretKeyCANextKey} {
				if _, present := data[key]; present {
					t.Errorf("%s survived promotion", key)
				}
			}
			if _, present := data[secretKeyCAKey]; !present {
				t.Error("the signing key is missing after promotion")
			}
			// The trust bundle is the same SET across the promotion, which is
			// why no spoke can be disconnected by it.
			if got := len(f.rotator.authority.TrustBundle()); got != 2 {
				t.Errorf("the local authority trusts %d roots after promotion, want 2", got)
			}
			if got := ca.Fingerprint(f.rotator.authority.Certificate()); got != fingerprintOf(t, nextCert) {
				t.Error("the local authority did not adopt the successor as its signer")
			}
			// Two adoptions happened inside this one step: sync() first
			// widens trust to the successor (signer unchanged, root count
			// 1->2), then advance()'s promotion moves the signer itself
			// (fingerprint changes, root count 2->2). The second is the only
			// one of the two whose log line depends on the fingerprint
			// comparison rather than the root-count comparison, so counting
			// it pins "after != before": a mutant reading "after == before"
			// would silently drop it, since the root count alone does not
			// change across the promotion.
			if n := f.sink.count("adopted rotated CA material"); n != 2 {
				t.Errorf("logged %d material adoptions, want 2: widening to the successor, then promoting it to signer", n)
			}
		})
	}
}

// --- signing -----------------------------------------------------------

// signingFixture puts a fixture into the signing phase with the original root
// as the one being retired.
func signingFixture(t *testing.T, elapsed time.Duration) (*rotationFixture, []byte) {
	t.Helper()
	f := newRotationFixture(t, caLifetime)
	nextCert, nextKey := f.mintRoot()
	outgoing := f.certPEM
	f.seed(func(data map[string][]byte) {
		data[secretKeyCACert] = nextCert
		data[secretKeyCAKey] = nextKey
		data[secretKeyCAPrevCert] = outgoing
		data[secretKeyRotationPhase] = []byte(caPhaseSigning)
		data[secretKeyRotationSince] = []byte(rotationBase.Format(time.RFC3339))
	}, nil)
	f.clock.Advance(elapsed)
	return f, outgoing
}

func TestCARotationSigningToSteady(t *testing.T) {
	t.Parallel()

	f, outgoing := signingFixture(t, 7*time.Hour) // hold is 4h + 2h

	f.step()

	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q, want steady", got)
	}
	if _, present := f.data()[secretKeyCAPrevCert]; present {
		t.Error("the outgoing root was not dropped")
	}
	if got := len(f.rotator.authority.TrustBundle()); got != 1 {
		t.Errorf("the local authority trusts %d roots, want 1", got)
	}
	if want := fingerprintOf(t, outgoing); !contains(strings.Join(f.holdouts.queried(), " "), want) {
		t.Error("the retirement gate never asked about the outgoing root")
	}
}

// TestCARotationRetirementPadIsInclusive pins the exact instant the padded
// retirement gate flips from refuse to proceed: one tick before the padded
// hold has elapsed, the outgoing root must stay trusted no matter how safe
// retiring it would otherwise be; AT the hold it must be evaluated for
// retirement. This is "now.Sub(st.since) < hold" together with the
// arithmetic that computes hold: a CONDITIONALS_BOUNDARY mutant turning "<"
// into "<=" would refuse one tick too late by itself, and an ARITHMETIC_BASE
// mutant shrinking hold (its "+" turned to "-", or its "2*" turned to "2/")
// would make the "one tick before" case wrongly proceed, since a shorter
// hold has already elapsed by then. TestCARotationSigningToSteady's 7h
// advance is nowhere near this boundary and cannot catch either.
func TestCARotationRetirementPadIsInclusive(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 0)
	hold := f.cfg.SpokeCertTTL + f.cfg.RenewGrace + 2*f.cfg.CARotationPollInterval

	f.clock.Advance(hold - time.Nanosecond)
	f.step()
	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q one tick before the padded hold, want it still signing", got)
	}

	f.clock.Advance(time.Nanosecond)
	f.step()
	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q exactly at the padded hold, want %q", got, caPhaseSteady)
	}
}

func TestCARotationSigningWaitsOutTheClock(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 5*time.Hour) // hold is 6h
	_, _, updatesBefore := f.api.counts()

	f.step()

	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q, want it still signing", got)
	}
	if _, _, updates := f.api.counts(); updates != updatesBefore {
		t.Error("a rotation waiting out its clock wrote to the Secret")
	}
}

// TestCARotationRefusesToDropARootASpokeStillDependsOn is the failure the
// manual procedure warned about, and the one automation must not reproduce.
func TestCARotationRefusesToDropARootASpokeStillDependsOn(t *testing.T) {
	t.Parallel()

	f, outgoing := signingFixture(t, 7*time.Hour)
	f.holdouts.set(fingerprintOf(t, outgoing), 1)

	f.step()

	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q, want it held at signing", got)
	}
	if _, present := f.data()[secretKeyCAPrevCert]; !present {
		t.Fatal("the outgoing root was dropped while a spoke still held a certificate from it")
	}
	if len(f.data()[secretKeyRotationHoldout]) == 0 {
		t.Fatal("the sighting was not published, so other replicas would not see it")
	}
	if _, _, outgoingGauge, _ := f.metrics.snapshot(); outgoingGauge != 1 {
		t.Errorf("outgoing-root session gauge = %d, want 1", outgoingGauge)
	}

	// The same poll again must not write a second time: one sighting per
	// interval is enough, and a Secret write per replica per poll is not.
	_, _, updatesBefore := f.api.counts()
	f.step()
	if _, _, updates := f.api.counts(); updates != updatesBefore {
		t.Error("a second poll in the same interval wrote the sighting again")
	}

	// Once the spoke is gone, the fleet still has to go quiet for two poll
	// intervals before the root may be dropped.
	f.holdouts.set(fingerprintOf(t, outgoing), 0)
	f.clock.Advance(90 * time.Second) // one and a half poll intervals
	f.step()
	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q, want it still held during the quiet period", got)
	}

	f.clock.Advance(2 * time.Minute)
	f.step()
	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q, want steady once the fleet went quiet", got)
	}
}

// TestCARotationSettleGuardBoundaryIsInclusive pins the exact instant the
// "this replica just started" guard flips: one tick before this replica has
// been up for the holdout-quiet window, an empty session table must not be
// trusted as evidence; AT the window it must be. The test above settles for
// margins of 90s and 2m either side of the guard, both far enough from it
// that a CONDITIONALS_BOUNDARY mutant turning "<" into "<=" would not
// change either outcome.
func TestCARotationSettleGuardBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 7*time.Hour) // well past the retirement pad
	quiet := f.rotator.holdoutQuiet()

	// One tick before this replica has settled.
	f.rotator.startedAt = f.clock.Now().Add(-(quiet - time.Second))
	f.step()
	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q one tick before the settle guard, want it still signing", got)
	}

	// Exactly at the guard: this replica has settled, and nothing depends on
	// the outgoing root, so retirement must proceed now.
	f.rotator.startedAt = f.clock.Now().Add(-quiet)
	f.step()
	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q exactly at the settle guard, want %q", got, caPhaseSteady)
	}
}

// TestCARotationHoldoutRepublishBoundaryIsInclusive pins the exact instant a
// live holdout sighting becomes stale enough to republish: one tick before a
// full poll interval has passed since it was last recorded, the Secret must
// not be written again; AT the interval it must be. The "second poll in the
// same interval" check above runs in the very same interval, nowhere near
// this boundary, so it cannot catch a CONDITIONALS_BOUNDARY mutant here.
func TestCARotationHoldoutRepublishBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	f, outgoing := signingFixture(t, 7*time.Hour) // well past the retirement pad
	f.holdouts.set(fingerprintOf(t, outgoing), 1)

	f.step() // records the first sighting
	firstHoldout := f.data()[secretKeyRotationHoldout]

	// One tick before a full poll interval has elapsed since the sighting.
	f.clock.Advance(f.cfg.CARotationPollInterval - time.Second)
	f.step()
	if got := f.data()[secretKeyRotationHoldout]; string(got) != string(firstHoldout) {
		t.Fatalf("holdout timestamp changed one tick before the poll interval elapsed")
	}

	// Exactly at the poll interval: the sighting is stale enough to publish
	// again.
	f.clock.Advance(time.Second)
	f.step()
	if got := f.data()[secretKeyRotationHoldout]; string(got) == string(firstHoldout) {
		t.Fatalf("holdout timestamp did not change exactly at the poll interval; want a fresh sighting")
	}
}

// TestCARotationHoldoutQuietBoundaryIsInclusive pins the exact instant a
// stale holdout sighting stops blocking retirement: one tick before the
// quiet window has elapsed since the last sighting, the outgoing root must
// stay trusted; AT the window it must be evaluated for retirement -- and
// here retired, since no replica currently sees a live session on it. The
// test above overshoots this boundary by 90s, wide enough that a
// CONDITIONALS_BOUNDARY mutant turning "<" into "<=" would not be caught.
func TestCARotationHoldoutQuietBoundaryIsInclusive(t *testing.T) {
	t.Parallel()

	f, outgoing := signingFixture(t, 7*time.Hour) // well past the retirement pad
	f.holdouts.set(fingerprintOf(t, outgoing), 1)
	f.step() // records a sighting

	f.holdouts.set(fingerprintOf(t, outgoing), 0) // the spoke is gone
	quiet := f.rotator.holdoutQuiet()

	// One tick before the quiet window has elapsed since that sighting.
	f.clock.Advance(quiet - time.Second)
	f.step()
	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q one tick before the holdout quiet window, want it still signing", got)
	}

	// Exactly at the window: the sighting is stale enough to retire on.
	f.clock.Advance(time.Second)
	f.step()
	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q exactly at the holdout quiet window, want %q", got, caPhaseSteady)
	}
}

// TestCARotationRefusesToDropARootWithARealTracker wires the actual issuer
// tracker to the actual authority, so the gate is driven by a certificate a
// handshake verified rather than by a number a test typed in.
func TestCARotationRefusesToDropARootWithARealTracker(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 7*time.Hour)

	// An authority that still holds the outgoing root, so a certificate that
	// root issued can be verified and recorded the way a handshake would.
	verifier, err := ca.Parse(f.certPEM, f.keyPEM, ca.Options{
		TrustDomain:  f.cfg.TrustDomain,
		SpokeCertTTL: f.cfg.SpokeCertTTL,
		Clock:        f.clock.Now,
	})
	if err != nil {
		t.Fatalf("parse the outgoing authority: %v", err)
	}
	_, leaf, err := verifier.IssueSpokeFromCSR(newSpokeCSR(t), "alpha")
	if err != nil {
		t.Fatalf("issue a spoke certificate from the outgoing root: %v", err)
	}
	// Liveness is per certificate serial, not per cluster: that is what keeps
	// a renewed sibling's handshake from hiding this session. See caissuers.go.
	live := map[string]bool{leaf.SerialNumber.Text(16): true}
	tracker := newCAIssuerTracker(verifier, func() map[string]bool { return live })
	f.rotator.holdouts = tracker

	if _, err := tracker.Verify([]*x509.Certificate{leaf}); err != nil {
		t.Fatalf("verify the spoke certificate: %v", err)
	}

	f.step()
	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q, want it held while a real session chains to the outgoing root", got)
	}

	// Disconnect the spoke and let the fleet go quiet.
	delete(live, leaf.SerialNumber.Text(16))
	f.clock.Advance(3 * time.Minute)
	f.step()
	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q, want steady once nothing chains to the outgoing root", got)
	}
}

// newSpokeCSR builds a minimal valid P-256 certificate signing request.
func newSpokeCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return der
}

func TestCARotationSigningWithoutAnOutgoingRootFinishes(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 7*time.Hour)
	f.seed(func(data map[string][]byte) { delete(data, secretKeyCAPrevCert) }, nil)

	f.step()

	if got := f.phase(); got != string(caPhaseSteady) {
		t.Fatalf("phase = %q, want steady", got)
	}
}

func TestCARotationSigningWaitsForThisReplicaToSettle(t *testing.T) {
	t.Parallel()

	f, _ := signingFixture(t, 7*time.Hour)
	// A replica that started a moment ago has an empty session table, which is
	// not evidence that nothing depends on the outgoing root.
	f.rotator.startedAt = f.clock.Now()

	f.step()

	if got := f.phase(); got != string(caPhaseSigning) {
		t.Fatalf("phase = %q, want it held until this replica has settled", got)
	}
}

// --- repair ------------------------------------------------------------

func TestCARotationRepairsAnUnreadablePhaseStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		phase caPhase
		since []byte
	}{
		{"missing while publishing", caPhasePublishing, nil},
		{"unparseable while publishing", caPhasePublishing, []byte("last tuesday")},
		{"missing while signing", caPhaseSigning, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRotationFixture(t, caLifetime)
			otherCert, otherKey := f.mintRoot()
			f.seed(func(data map[string][]byte) {
				data[secretKeyRotationPhase] = []byte(tc.phase)
				delete(data, secretKeyRotationSince)
				if tc.phase == caPhasePublishing {
					data[secretKeyCANextCert] = otherCert
					data[secretKeyCANextKey] = otherKey
				} else {
					data[secretKeyCACert] = otherCert
					data[secretKeyCAKey] = otherKey
					data[secretKeyCAPrevCert] = f.certPEM
				}
				if tc.since != nil {
					data[secretKeyRotationSince] = tc.since
				}
			}, nil)
			f.clock.Advance(10 * time.Hour)

			f.step()

			if got := f.phase(); got != string(tc.phase) {
				t.Fatalf("phase = %q, want it unchanged while the clock is repaired", got)
			}
			want := f.clock.Now().UTC().Format(time.RFC3339)
			if got := string(f.data()[secretKeyRotationSince]); got != want {
				t.Fatalf("repaired phase start = %q, want %q", got, want)
			}
			// The repaired clock must not immediately satisfy the gate: a
			// repair may only ever delay a transition.
			f.step()
			if got := f.phase(); got != string(tc.phase) {
				t.Fatalf("phase = %q, want the repaired clock to be honoured", got)
			}
		})
	}
}

// --- races and adoption ------------------------------------------------

// TestCARotationLoserOfTheRaceAdoptsRatherThanRetrying drives both sides of
// the compare-and-swap: two replicas read the same Secret, one writes, and the
// other must not write on top of it.
func TestCARotationLoserOfTheRaceAdoptsRatherThanRetrying(t *testing.T) {
	t.Parallel()

	winner := newRotationFixture(t, caLifetime)
	loser := winner.secondReplica(t)
	winner.clock.Advance(85 * time.Hour)
	loser.clock.Advance(85 * time.Hour)

	ctx := context.Background()
	secA, err := winner.rotator.client.GetSecret(ctx, winner.cfg.CASecretName)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	secB, err := loser.rotator.client.GetSecret(ctx, loser.cfg.CASecretName)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}

	advancedA, err := winner.rotator.advance(ctx, secA, readCARotation(secA))
	if err != nil {
		t.Fatalf("winner advance: %v", err)
	}
	if advancedA == nil {
		t.Fatal("the winner did not advance")
	}

	advancedB, err := loser.rotator.advance(ctx, secB, readCARotation(secB))
	if err != nil {
		t.Fatalf("the loser of the race returned an error instead of standing down: %v", err)
	}
	if advancedB != nil {
		t.Fatal("the loser believed it had advanced")
	}
	loser.sink.mustFind(t, "another replica advanced the CA rotation first; adopting its result")

	// One successor root, not two.
	if diff := cmp.Diff(winner.data(), loser.data()); diff != "" {
		t.Errorf("the two replicas see different Secrets (-winner +loser):\n%s", diff)
	}

	// And both adopt on their next poll: the winner because advance alone only
	// writes, the loser because re-reading is the whole of how a replica
	// notices somebody else's rotation.
	winner.step()
	loser.step()
	if got := len(loser.rotator.authority.TrustBundle()); got != 2 {
		t.Fatalf("the loser trusts %d roots, want the winner's 2", got)
	}
	if diff := cmp.Diff(winner.rotator.authority.BundlePEM(), loser.rotator.authority.BundlePEM()); diff != "" {
		t.Errorf("the replicas disagree about what to trust (-winner +loser):\n%s", diff)
	}
	loser.sink.mustFind(t, "adopted rotated CA material")
}

// TestCARotationConcurrentReplicasProduceOneRotation is the same race run for
// real, under -race, with every replica polling at once.
func TestCARotationConcurrentReplicasProduceOneRotation(t *testing.T) {
	t.Parallel()

	first := newRotationFixture(t, caLifetime)
	replicas := []*rotationFixture{first, first.secondReplica(t), first.secondReplica(t)}
	for _, f := range replicas {
		f.clock.Advance(85 * time.Hour)
	}

	var wg sync.WaitGroup
	errs := make([]error, len(replicas))
	for i, f := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = f.rotator.step(context.Background())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}

	if got := first.phase(); got != string(caPhasePublishing) {
		t.Fatalf("phase = %q, want publishing", got)
	}
	successor := first.data()[secretKeyCANextCert]
	if len(successor) == 0 {
		t.Fatal("no successor root was stored")
	}
	// Every replica converges on the same successor after one more poll,
	// whichever of them won.
	for i, f := range replicas {
		f.step()
		if diff := cmp.Diff(successor, f.data()[secretKeyCANextCert]); diff != "" {
			t.Errorf("replica %d sees a different successor (-want +got):\n%s", i, diff)
		}
		if got := len(f.rotator.authority.TrustBundle()); got != 2 {
			t.Errorf("replica %d trusts %d roots, want 2", i, got)
		}
	}
}

// secondReplica builds another rotator over the same fake API and the same
// starting material, as a second hub pod would be.
func (f *rotationFixture) secondReplica(t *testing.T) *rotationFixture {
	t.Helper()
	authority, err := ca.Parse(f.certPEM, f.keyPEM, ca.Options{
		TrustDomain:  f.cfg.TrustDomain,
		SpokeCertTTL: f.cfg.SpokeCertTTL,
		Clock:        f.clock.Now,
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	clock := &rotationClock{t: f.clock.Now()}
	logger, sink := newLogSink()
	other := &rotationFixture{
		t: t, api: f.api, cfg: f.cfg, clock: clock,
		holdouts: newFakeHoldouts(), metrics: &recordingMetrics{}, sink: sink,
		certPEM: f.certPEM, keyPEM: f.keyPEM,
	}
	other.rotator = &caRotator{
		client:    f.api.client(t),
		secret:    f.cfg.CASecretName,
		cfg:       f.cfg,
		logger:    logger,
		metrics:   other.metrics,
		holdouts:  other.holdouts,
		authority: authority,
		now:       clock.Now,
		startedAt: rotationBase.Add(-24 * time.Hour),
	}
	return other
}

// --- failure paths -----------------------------------------------------

func TestCARotationStepFailures(t *testing.T) {
	t.Parallel()

	t.Run("the Secret cannot be read", func(t *testing.T) {
		t.Parallel()
		f := newRotationFixture(t, caLifetime)
		f.api.onGet = func(string, int) *fault {
			return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
		}
		err := f.rotator.step(context.Background())
		if err == nil || !contains(err.Error(), "read the CA secret") {
			t.Fatalf("step() = %v, want a read failure", err)
		}
	})

	t.Run("the stored material does not parse", func(t *testing.T) {
		t.Parallel()
		f := newRotationFixture(t, caLifetime)
		f.seed(func(data map[string][]byte) { data[secretKeyCACert] = []byte("not a certificate") }, nil)
		err := f.rotator.step(context.Background())
		if err == nil || !contains(err.Error(), "adopt the CA material") {
			t.Fatalf("step() = %v, want an adoption failure", err)
		}
		if !errors.Is(err, ca.ErrInvalidCA) {
			t.Errorf("step() = %v, want it to wrap ErrInvalidCA", err)
		}
	})

	t.Run("the successor cannot be minted", func(t *testing.T) {
		t.Parallel()
		f := newRotationFixture(t, caLifetime)
		f.clock.Advance(85 * time.Hour)
		broken := *f.cfg
		broken.TrustDomain = "NOT A TRUST DOMAIN"
		f.rotator.cfg = &broken
		err := f.rotator.step(context.Background())
		if err == nil || !contains(err.Error(), "mint the successor root") {
			t.Fatalf("step() = %v, want a minting failure", err)
		}
	})

	t.Run("the write is rejected for a reason that is not a conflict", func(t *testing.T) {
		t.Parallel()
		f := newRotationFixture(t, caLifetime)
		f.clock.Advance(85 * time.Hour)
		f.api.onUpdate = func(string, int) *fault {
			return &fault{code: http.StatusForbidden, reason: "Forbidden", message: "no"}
		}
		err := f.rotator.step(context.Background())
		if err == nil || !contains(err.Error(), "record CA rotation phase") {
			t.Fatalf("step() = %v, want a write failure", err)
		}
	})
}

// TestCARotationRunPollsAndStops proves the loop actually polls, and that a
// failing poll is survived rather than fatal.
func TestCARotationRunPollsAndStops(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime, "--ca-rotation-poll-interval", "5ms")
	f.api.onGet = func(_ string, n int) *fault {
		if n == 1 {
			return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.rotator.Run(ctx)
	}()

	eventually(t, 2*time.Second, "the rotator to poll past its first failure", func() bool {
		gets, _, _ := f.api.counts()
		return gets >= 2
	})
	f.sink.mustFind(t, "CA rotation poll failed; every root already trusted stays trusted")
	cancel()
	<-done
}

// TestCARotationRunOnlyLogsOnFailingPolls pins the direction of Run's guard,
// "err != nil && ctx.Err() == nil". TestCARotationRunPollsAndStops's mustFind
// alone cannot tell this from a mutant that flips it to "err == nil": that
// mutant logs the very same message on every SUCCESSFUL poll instead, and
// mustFind would still find it. Letting several successful polls run around
// the one failure and counting the message pins the direction: it must fire
// exactly once, on the poll that actually failed.
func TestCARotationRunOnlyLogsOnFailingPolls(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime, "--ca-rotation-poll-interval", "5ms")
	f.api.onGet = func(_ string, n int) *fault {
		if n == 1 {
			return &fault{code: http.StatusInternalServerError, reason: "InternalError", message: "boom"}
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.rotator.Run(ctx)
	}()

	eventually(t, 2*time.Second, "several successful polls past the one failure", func() bool {
		gets, _, _ := f.api.counts()
		return gets >= 6
	})
	cancel()
	<-done

	const msg = "CA rotation poll failed; every root already trusted stays trusted"
	if n := f.sink.count(msg); n != 1 {
		t.Fatalf("logged %d times, want exactly 1 (once, for the single failing poll)", n)
	}
}

// --- wiring ------------------------------------------------------------

func TestNewCARotatorDeclinesWhereItCannotBeSafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(t *testing.T, h *hub)
		want    string
	}{
		{
			name:    "the file backend has no compare-and-swap",
			prepare: func(*testing.T, *hub) {},
			want:    "file state backend",
		},
		{
			name: "rotation switched off",
			prepare: func(_ *testing.T, h *hub) {
				h.cfg.CARotationEnabled = false
			},
			want: "--ca-rotation-enabled=false",
		},
		{
			name: "the CA was supplied by the operator",
			prepare: func(t *testing.T, h *hub) {
				t.Helper()
				h.kube = newFakeAPI(t).client(t)
				h.cfg.CACertFile = filepath.Join(t.TempDir(), "mounted.crt")
			},
			want: "belongs to whatever supplies it",
		},
		{
			// Unreachable from run(), which wires the tunnel server first;
			// checked so a future reordering panics a test instead of the
			// process (a nil concrete pointer in the interface field would be
			// a non-nil interface that panics inside holdoutsOn).
			name: "the issuer tracker is not wired",
			prepare: func(t *testing.T, h *hub) {
				t.Helper()
				h.kube = newFakeAPI(t).client(t)
				h.caIssuers = nil
			},
			want: "issuer tracker is not wired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _ := newBareHub(t, newHubConfig(t))
			tc.prepare(t, h)
			rotator, why := h.newCARotator()
			if rotator != nil {
				t.Fatalf("newCARotator returned a rotator, want nil with a reason")
			}
			if !contains(why, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", why, tc.want)
			}
		})
	}
}

func TestNewCARotatorRunsWithTheSecretBackend(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	cfg := newHubConfig(t)
	h, _ := newBareHub(t, cfg)
	h.kube = api.client(t)
	h.authority = mustFixtureAuthority(t, cfg)
	h.caIssuers = newCAIssuerTracker(h.authority, func() map[string]bool { return nil })

	rotator, why := h.newCARotator()
	if rotator == nil {
		t.Fatalf("newCARotator declined with %q, want a rotator", why)
	}
	if rotator.secret != cfg.CASecretName || rotator.authority != h.authority {
		t.Error("the rotator was not wired to the hub's Secret and authority")
	}
	if rotator.now().IsZero() {
		t.Error("the rotator has no clock")
	}
}

// mustFixtureAuthority builds a throwaway authority for wiring tests.
func mustFixtureAuthority(t *testing.T, cfg *config.Hub) *ca.CA {
	t.Helper()
	certPEM, keyPEM, err := ca.NewRootPEM(ca.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	authority, err := ca.Parse(certPEM, keyPEM, ca.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return authority
}

// TestBootstrapRestoresARotationInFlight is the restart story: a hub that
// comes back in the middle of a rotation must trust exactly what it trusted
// before it went down.
func TestBootstrapRestoresARotationInFlight(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		phase caPhase
		key   string
	}{
		{"restarted while publishing", caPhasePublishing, secretKeyCANextCert},
		{"restarted while signing", caPhaseSigning, secretKeyCAPrevCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := newHubConfig(t)
			fixture := newCAFixture(t, cfg.TrustDomain)
			otherPEM, _, err := ca.NewRootPEM(ca.Options{TrustDomain: cfg.TrustDomain})
			if err != nil {
				t.Fatalf("mint the other root: %v", err)
			}
			data := fixture.secretData()
			data[secretKeyRotationPhase] = []byte(tc.phase)
			data[secretKeyRotationSince] = []byte(rotationBase.Format(time.RFC3339))
			data[tc.key] = otherPEM

			api := newFakeAPI(t)
			api.put(cfg.CASecretName, data)
			b, _ := newBootstrapper(t, cfg, api)

			authority, _, err := b.prepare(context.Background(), cfg)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if got := len(authority.TrustBundle()); got != 2 {
				t.Fatalf("a hub restarted mid-rotation trusts %d roots, want 2", got)
			}
			if got := ca.Fingerprint(authority.Certificate()); got != fingerprintOf(t, fixture.certPEM) {
				t.Error("the restarted hub signs with the wrong root")
			}
		})
	}
}

// TestBootstrapIgnoresRotationMaterialWhenSteady pins the other half: material
// left over in the steady state is not silently trusted at startup either.
func TestBootstrapIgnoresRotationMaterialWhenSteady(t *testing.T) {
	t.Parallel()

	cfg := newHubConfig(t)
	fixture := newCAFixture(t, cfg.TrustDomain)
	otherPEM, _, err := ca.NewRootPEM(ca.Options{TrustDomain: cfg.TrustDomain})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	data := fixture.secretData()
	data[secretKeyCAPrevCert] = otherPEM

	api := newFakeAPI(t)
	api.put(cfg.CASecretName, data)
	b, _ := newBootstrapper(t, cfg, api)

	authority, _, err := b.prepare(context.Background(), cfg)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if got := len(authority.TrustBundle()); got != 1 {
		t.Fatalf("stray rotation material was trusted at startup: %d roots, want 1", got)
	}
}

func TestJoinRootsPEM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, a, b, want string
	}{
		{"both empty", "", "", ""},
		{"only the first", "-A-\n", "", "-A-\n"},
		{"only the second", "", "-B-\n", "-B-\n"},
		{"whitespace counts as empty", "  \n", "-B-\n", "-B-\n"},
		{"both, separated by exactly one newline", "-A-\n", "-B-\n", "-A-\n-B-\n"},
		{"a first bundle with no trailing newline", "-A-", "-B-\n", "-A-\n-B-\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := string(joinRootsPEM([]byte(tc.a), []byte(tc.b)))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("joinRootsPEM (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOutgoingFingerprintOfUnusableMaterial(t *testing.T) {
	t.Parallel()

	f := newRotationFixture(t, caLifetime)
	st := caRotationState{phase: caPhaseSigning, prevCertPEM: []byte("not a certificate")}
	if got := f.rotator.outgoingFingerprint(st); got != "" {
		t.Errorf("outgoingFingerprint = %q, want \"\" for unparseable material", got)
	}
}

// TestCARotationTrustBundleFileSurvivesEveryPhase proves the operator's own
// roots are never dropped by a rotation.
func TestCARotationTrustBundleFileSurvivesEveryPhase(t *testing.T) {
	t.Parallel()

	extraPEM, _, err := ca.NewRootPEM(ca.Options{TrustDomain: "fleet.local"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	bundle := filepath.Join(t.TempDir(), "extra.crt")
	if err := os.WriteFile(bundle, extraPEM, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	f := newRotationFixture(t, caLifetime, "--ca-trust-bundle-file", bundle)
	f.rotator.base = extraPEM
	if err := f.rotator.authority.AdoptPEM(f.certPEM, f.keyPEM, extraPEM); err != nil {
		t.Fatalf("seed the operator root: %v", err)
	}
	f.clock.Advance(85 * time.Hour)

	f.step()
	if got := len(f.rotator.authority.TrustBundle()); got != 3 {
		t.Fatalf("publishing trusts %d roots, want signer + operator root + successor", got)
	}
	f.clock.Advance(5 * time.Hour)
	f.step()
	if got := len(f.rotator.authority.TrustBundle()); got != 3 {
		t.Fatalf("signing trusts %d roots, want signer + operator root + outgoing", got)
	}
	f.clock.Advance(7 * time.Hour)
	f.step()
	if got := len(f.rotator.authority.TrustBundle()); got != 2 {
		t.Fatalf("steady trusts %d roots, want signer + operator root", got)
	}
}

// TestReadTrustBundle covers the operator-supplied roots at the point they are
// loaded: startup, where a malformed bundle must name itself rather than
// surface later as every spoke failing to verify.
func TestReadTrustBundle(t *testing.T) {
	t.Parallel()

	goodPEM, _, err := ca.NewRootPEM(ca.Options{TrustDomain: "fleet.local"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	tests := []struct {
		name     string
		contents []byte
		absent   bool
		unset    bool
		wantErr  string
	}{
		{name: "unset is the steady state", unset: true},
		{name: "a usable bundle loads", contents: goodPEM},
		{name: "a missing file is named", absent: true, wantErr: "read the CA trust bundle"},
		{name: "an unusable bundle is named", contents: []byte("not a certificate"), wantErr: "is unusable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "bundle.crt")
			switch {
			case tc.unset:
				path = ""
			case !tc.absent:
				if err := os.WriteFile(path, tc.contents, 0o600); err != nil {
					t.Fatalf("write bundle: %v", err)
				}
			}

			got, err := readTrustBundle(path)
			if tc.wantErr != "" {
				if err == nil || !contains(err.Error(), tc.wantErr) {
					t.Fatalf("readTrustBundle() = %v, want an error mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readTrustBundle: %v", err)
			}
			if diff := cmp.Diff(tc.contents, got); diff != "" {
				t.Errorf("readTrustBundle (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAnUnusableTrustBundleStopsStartup pins where that error surfaces: before
// anything is served, from every path that loads the CA.
func TestAnUnusableTrustBundleStopsStartup(t *testing.T) {
	t.Parallel()

	bundle := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(bundle, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	t.Run("openState", func(t *testing.T) {
		t.Parallel()
		h, _ := newBareHub(t, newHubConfig(t, "--ca-trust-bundle-file", bundle))
		if err := h.openState(context.Background()); err == nil || !contains(err.Error(), "is unusable") {
			t.Fatalf("openState = %v, want the bundle to be named", err)
		}
	})

	t.Run("prepare", func(t *testing.T) {
		t.Parallel()
		cfg := newHubConfig(t, "--ca-trust-bundle-file", bundle)
		b, _ := newBootstrapper(t, cfg, nil)
		if _, _, err := b.prepare(context.Background(), cfg); err == nil ||
			!contains(err.Error(), "is unusable") {
			t.Fatalf("prepare = %v, want the bundle to be named", err)
		}
	})

	t.Run("reload after a lost create race", func(t *testing.T) {
		t.Parallel()
		cfg := newHubConfig(t, "--ca-trust-bundle-file", bundle)
		if _, err := reloadAfterAdoption(cfg); err == nil || !contains(err.Error(), "is unusable") {
			t.Fatalf("reloadAfterAdoption = %v, want the bundle to be named", err)
		}
	})
}

// TestRunStartsTheCARotationController checks the wiring itself: the
// controller is started when it can be, and the reason is said out loud when
// it cannot.
func TestRunStartsTheCARotationController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secretMode bool
		want       string
	}{
		{name: "with the secret backend", secretMode: true, want: "CA rotation controller started"},
		{name: "with the file backend", want: "the CA will not rotate itself; its expiry is yours to manage"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := newHubConfig(t)
			h, sink := newBareHub(t, cfg)
			if tc.secretMode {
				api := newFakeAPI(t)
				cfg.StateBackend = config.StateBackendSecret
				h.inCluster = func() (*kube.Client, error) { return api.client(t), nil }
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- h.run(ctx) }()

			eventually(t, 30*time.Second, tc.want, func() bool { return sink.find(tc.want) != nil })
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("run: %v", err)
			}
		})
	}
}

func TestMetricsAdapterCARotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		phase     string
		since     time.Time
		wantStart float64
		wantPhase map[string]float64
	}{
		{
			name: "a phase in force", phase: string(caPhasePublishing),
			since:     time.Unix(1_800_000_000, 0),
			wantStart: 1_800_000_000,
			wantPhase: map[string]float64{"steady": 0, "publishing": 1, "signing": 0},
		},
		{
			name: "no rotation has ever run", phase: string(caPhaseSteady),
			wantStart: 0,
			wantPhase: map[string]float64{"steady": 1, "publishing": 0, "signing": 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := prometheus.NewRegistry()
			a := newMetricsAdapter(obs.NewHubMetrics(reg))

			a.CARotationPhase(tc.phase, tc.since)
			a.CAOutgoingRootSessions(3)
			a.CARotationTransition("signing")

			got := map[string]float64{}
			for phase := range tc.wantPhase {
				got[phase] = gaugeValue(t, a.m.CARotationPhase.WithLabelValues(phase))
			}
			if diff := cmp.Diff(tc.wantPhase, got); diff != "" {
				t.Errorf("phase gauges (-want +got):\n%s", diff)
			}
			if start := gaugeValue(t, a.m.CARotationPhaseStart); start != tc.wantStart {
				t.Errorf("phase start = %v, want %v", start, tc.wantStart)
			}
			if n := gaugeValue(t, a.m.CAOutgoingRootSessions); n != 3 {
				t.Errorf("outgoing root sessions = %v, want 3", n)
			}
			if n := counterValue(t, a.m.CARotationTransitionsTotal.WithLabelValues("signing")); n != 1 {
				t.Errorf("transitions = %v, want 1", n)
			}
		})
	}
}

// gaugeValue reads one gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

// counterValue reads one counter.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestRevocationPredicateIsBuiltOnce pins the memo: the handshake and the
// eviction sweep must consult ONE predicate, so the second caller gets the
// first caller's function rather than a second poller of the state Secret.
func TestRevocationPredicateIsBuiltOnce(t *testing.T) {
	t.Parallel()

	h, _ := newWiredHub(t, newHubConfig(t))
	ctx := context.Background()

	first, err := h.revocationPredicate(ctx)
	if err != nil {
		t.Fatalf("revocationPredicate: %v", err)
	}
	second, err := h.revocationPredicate(ctx)
	if err != nil {
		t.Fatalf("revocationPredicate: %v", err)
	}
	if reflect.ValueOf(first).Pointer() != reflect.ValueOf(second).Pointer() {
		t.Error("a second call built a second predicate; the handshake and the sweep could disagree")
	}

	// Building the predicate also hands the enforcer its refresh hook, so an
	// idle replica's revocation list stays current without a single
	// handshake. It must be callable and must not error the process.
	if h.revocationRefresh == nil {
		t.Fatal("revocationRefresh was not wired alongside the predicate")
	}
	h.revocationRefresh(ctx)
}
