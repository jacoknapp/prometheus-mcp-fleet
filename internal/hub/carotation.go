// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
)

// Keys inside the CA Secret that describe a rotation.
//
// They live beside ca.crt and ca.key because the Secret is the only durable
// state this system has (ADR-0005) and because the phase and the material it
// describes must move together: promoting the successor and recording that it
// was promoted are one compare-and-swap, not two, so no replica can ever read
// a phase that disagrees with the keys next to it.
const (
	// secretKeyCANextCert and secretKeyCANextKey hold the successor root while
	// it is trusted but not yet signing. They exist only in the publishing
	// phase; promotion moves them onto ca.crt and ca.key and deletes them.
	secretKeyCANextCert = "ca-next.crt"
	secretKeyCANextKey  = "ca-next.key"
	// secretKeyCAPrevCert holds the outgoing root's certificate while it is
	// trusted but no longer signing. Its private key is deliberately not kept:
	// a root that has stopped signing must not be able to start again, which
	// also means a rotation run because a key was compromised really does
	// dispose of that key.
	secretKeyCAPrevCert = "ca-previous.crt"
	// secretKeyRotationPhase is the phase name; secretKeyRotationSince is when
	// it was entered, RFC 3339 in UTC.
	secretKeyRotationPhase = "ca-rotation.phase"
	// #nosec G101 -- a key NAME inside the Secret, not a credential. The
	// secretKey* prefix names the map key these constants index; the values
	// they point at are what is sensitive, and none of those is in source.
	secretKeyRotationSince = "ca-rotation.since"
	// secretKeyRotationHoldout is the last time ANY replica saw a live session
	// still admitted by the outgoing root. It is how a per-replica observation
	// becomes a fleet-wide veto on retiring that root.
	secretKeyRotationHoldout = "ca-rotation.last-holdout"
	// secretKeyRotationRetireAfter is the earliest instant the outgoing root
	// may be retired, fixed by the replica that promoted the successor from
	// the certificate lifetime and renewal grace IN FORCE AT THAT MOMENT. The
	// clock gate in planSigning is otherwise recomputed from live config on
	// every poll, and shortening --spoke-cert-ttl or --renew-grace
	// mid-rotation would open it early -- while certificates issued under
	// the longer old values are still renewable. Persisting the horizon
	// turns that from a documented hazard into a non-event. RFC 3339 in UTC.
	// #nosec G101 -- a key NAME inside the Secret, as above.
	secretKeyRotationRetireAfter = "ca-rotation.retire-after"
)

// Annotations on the CA Secret.
const (
	// annotationRotateNow starts a rotation immediately, whatever the signing
	// root's remaining life. It is the operator's hand on the wheel for a
	// suspected key compromise, and it needs no file, no restart and no
	// endpoint: `kubectl annotate secret <ca-secret>
	// promfleet.io/rotate-now=<reason>`.
	//
	// It is edge triggered. The hub clears it in the same compare-and-swap
	// that records the new phase, so an annotation left in place cannot make
	// the hub rotate again and again.
	annotationRotateNow = "promfleet.io/rotate-now"
	// annotationRotateAccepted records when a forced rotation was picked up,
	// so that clearing annotationRotateNow does not look like nothing
	// happened.
	annotationRotateAccepted = "promfleet.io/rotate-accepted"
)

// caPhase is the persisted state of a CA rotation.
//
// The phases are the manual procedure of ADR-0015 with the human removed, and
// they are ordered by what the fleet can survive. Widening the set of trusted
// roots is always safe; narrowing it is the only step that can disconnect a
// spoke, so it is last and it is the one gated on evidence rather than on a
// clock.
type caPhase string

const (
	// caPhaseSteady is one root, which signs. This is where a hub spends
	// almost all of its life, and in it the rotator writes nothing at all.
	caPhaseSteady caPhase = "steady"
	// caPhasePublishing is two roots trusted, the OLD one signing. The
	// successor has been minted and is served in the trust bundle; spokes pick
	// it up as they renew, and -- the part that matters for a multi-replica
	// hub -- every replica learns to trust it before any replica signs with
	// it.
	caPhasePublishing caPhase = "publishing"
	// caPhaseSigning is two roots trusted, the NEW one signing. Certificates
	// already in the field still verify, because the root that issued them is
	// still in the bundle.
	caPhaseSigning caPhase = "signing"
)

// caPhases is the closed set, in the order a rotation walks them. It is also
// the label set of the phase gauge.
var caPhases = []caPhase{caPhaseSteady, caPhasePublishing, caPhaseSigning}

// caRotationMetrics is what the rotator reports. It is declared here rather
// than imported so this file can be tested without a Prometheus registry;
// *metricsAdapter satisfies it.
type caRotationMetrics interface {
	CACertExpiry(notAfter time.Time)
	CATrustRoots(n int)
	CARotationPhase(phase string, since time.Time)
	CAOutgoingRootSessions(n int)
	CARotationTransition(to string)
}

// caHoldoutCounter reports how many live sessions on this replica were
// admitted by one root. *caIssuerTracker satisfies it.
type caHoldoutCounter interface {
	holdoutsOn(fingerprint string) int
}

// caRotationState is the CA Secret read as a rotation.
type caRotationState struct {
	// rawPhase is the phase exactly as stored, including a value this build
	// does not recognise; phase is the interpretation, which falls back to
	// steady.
	rawPhase   string
	phase      caPhase
	phaseKnown bool

	since   time.Time
	sinceOK bool

	certPEM, keyPEM         []byte
	nextCertPEM, nextKeyPEM []byte
	prevCertPEM             []byte

	lastHoldout time.Time
	// hasHoldout is whether the key is present at all, which is not the same
	// as lastHoldout being non-zero: a hand-edited value that does not parse
	// still has to be tidied away.
	hasHoldout bool
	// retireAfter is the persisted retirement horizon, zero when absent or
	// unreadable -- a rotation promoted by an older build has none, and the
	// live-config gate alone applies to it, as it always did.
	retireAfter    time.Time
	hasRetireAfter bool
	force          string
}

// readCARotation interprets a CA Secret.
//
// An unreadable or absent phase reads as steady, and an unreadable timestamp
// reads as "not known". Neither is treated as fatal: the rotator repairs both,
// because a hub that refuses to run because somebody hand-edited an annotation
// is a hub that has to be rescued by hand -- which is the thing this exists to
// remove.
func readCARotation(sec *kube.Secret) caRotationState {
	st := caRotationState{
		rawPhase:    string(sec.Data[secretKeyRotationPhase]),
		phase:       caPhaseSteady,
		certPEM:     sec.Data[secretKeyCACert],
		keyPEM:      sec.Data[secretKeyCAKey],
		nextCertPEM: sec.Data[secretKeyCANextCert],
		nextKeyPEM:  sec.Data[secretKeyCANextKey],
		prevCertPEM: sec.Data[secretKeyCAPrevCert],
		force:       sec.Annotations[annotationRotateNow],
	}
	if slices.Contains(caPhases, caPhase(st.rawPhase)) {
		st.phase, st.phaseKnown = caPhase(st.rawPhase), true
	}
	if t, err := time.Parse(time.RFC3339, string(sec.Data[secretKeyRotationSince])); err == nil {
		st.since, st.sinceOK = t, true
	}
	holdout := sec.Data[secretKeyRotationHoldout]
	st.hasHoldout = len(holdout) > 0
	if t, err := time.Parse(time.RFC3339, string(holdout)); err == nil {
		st.lastHoldout = t
	}
	retireAfter := sec.Data[secretKeyRotationRetireAfter]
	st.hasRetireAfter = len(retireAfter) > 0
	if t, err := time.Parse(time.RFC3339, string(retireAfter)); err == nil {
		st.retireAfter = t
	}
	return st
}

// additionalRoots returns the roots to trust alongside the active signer:
// whatever the operator configured, plus the other root of a rotation in
// flight.
//
// The two phases in flight name different certificates and produce the SAME
// set of trusted roots -- {old, new} either way -- which is why promotion
// cannot disconnect anybody. Only the signer moves.
func (s caRotationState) additionalRoots(base []byte) []byte {
	if s.rawPhase != "" && !s.phaseKnown {
		// A phase this build does not recognise -- most plausibly a rollback
		// to an older binary mid-rotation, or a hand edit. Ambiguity must
		// not narrow trust: reading it as steady would drop every root but
		// the signer while the Secret still carries a rotation's material,
		// disconnecting whichever half of the fleet is on the other root.
		// Trust everything present and let advance() freeze until a human or
		// a newer binary resolves it; too-wide is recoverable, too-narrow is
		// an outage.
		return joinRootsPEM(joinRootsPEM(base, s.nextCertPEM), s.prevCertPEM)
	}
	var extra []byte
	switch s.phase {
	case caPhasePublishing:
		extra = s.nextCertPEM
	case caPhaseSigning:
		extra = s.prevCertPEM
	case caPhaseSteady:
		// Nothing: steady state trusts the signer and whatever the operator
		// configured, and any leftover material is tidied away rather than
		// trusted.
	}
	return joinRootsPEM(base, extra)
}

// joinRootsPEM concatenates two PEM trust bundles, either of which may be
// empty. The separator is a newline because a bundle whose last block is not
// newline-terminated would otherwise swallow the first line of the next.
func joinRootsPEM(a, b []byte) []byte {
	switch {
	case len(bytes.TrimSpace(a)) == 0:
		return b
	case len(bytes.TrimSpace(b)) == 0:
		return a
	default:
		return slices.Concat(bytes.TrimRight(a, "\n"), []byte("\n"), b)
	}
}

// caRotator is the controller. One runs per replica; several will reach the
// same conclusion at the same moment, and the Secret's resourceVersion decides
// which of them acts.
type caRotator struct {
	client   *kube.Client
	secret   string
	cfg      *config.Hub
	base     []byte // operator-configured additional roots, always trusted
	logger   *slog.Logger
	metrics  caRotationMetrics
	holdouts caHoldoutCounter

	// authority is the live CA. It is a stable handle whose material is
	// swapped atomically, so adopting another replica's rotation reaches the
	// tunnel verifier, the enrollment handler and /pki/bundle without any of
	// them being rebuilt.
	authority *ca.CA

	now       func() time.Time
	startedAt time.Time

	// appliedCert and appliedRoots are the bytes behind the material this
	// replica last adopted, so the overwhelmingly common poll -- nothing
	// changed -- costs a byte comparison.
	appliedCert  []byte
	appliedRoots []byte
}

// Run polls the CA Secret until ctx is cancelled.
//
// Every poll does the same two things in the same order: adopt whatever the
// Secret says is in force, then consider advancing it. Adoption comes first
// because a replica that is behind must stop being behind before it decides
// anything -- otherwise it would judge a rotation against material it has
// already been superseded on.
//
// A failed poll is logged and the loop continues. There is no state to unwind:
// nothing was written unless the compare-and-swap succeeded, and the fleet
// keeps trusting every root it already trusted.
func (r *caRotator) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.CARotationPollInterval)
	defer ticker.Stop()
	for {
		if err := r.step(ctx); err != nil && ctx.Err() == nil {
			r.logger.WarnContext(ctx, "CA rotation poll failed; every root already trusted stays trusted",
				"secret", r.secret, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// step is one poll.
func (r *caRotator) step(ctx context.Context) error {
	sec, err := r.client.GetSecret(ctx, r.secret)
	if err != nil {
		return fmt.Errorf("read the CA secret %s: %w", r.secret, err)
	}
	st := readCARotation(sec)
	if err := r.sync(ctx, st); err != nil {
		return err
	}
	advanced, err := r.advance(ctx, sec, st)
	if err != nil {
		return err
	}
	if advanced != nil {
		return r.sync(ctx, *advanced)
	}
	return nil
}

// sync makes this replica's authority match what the Secret says, and
// republishes the gauges either way.
//
// This is the whole of "notice a rotation another replica performed". There is
// no PersistentVolumeClaim and no channel between replicas, so the Secret is
// the only thing they share, and re-reading it is the only way to find out.
func (r *caRotator) sync(ctx context.Context, st caRotationState) error {
	certPEM := st.certPEM
	rootsPEM := st.additionalRoots(r.base)
	if !bytes.Equal(certPEM, r.appliedCert) || !bytes.Equal(rootsPEM, r.appliedRoots) {
		before := ca.Fingerprint(r.authority.Certificate())
		beforeRoots := len(r.authority.TrustBundle())
		if err := r.authority.AdoptPEM(certPEM, st.keyPEM, rootsPEM); err != nil {
			return fmt.Errorf("adopt the CA material in secret %s: %w", r.secret, err)
		}
		r.appliedCert, r.appliedRoots = certPEM, rootsPEM
		after := ca.Fingerprint(r.authority.Certificate())
		if afterRoots := len(r.authority.TrustBundle()); after != before || afterRoots != beforeRoots {
			r.logger.InfoContext(ctx, "adopted rotated CA material",
				"phase", string(st.phase), "signer", after, "trust_roots", afterRoots)
		}
	}
	r.report(st)
	return nil
}

// report publishes the phase, its age and the outgoing root's remaining
// dependants. It runs on every poll, including the ones that change nothing,
// because a gauge that is only written when something happens goes stale
// exactly when an operator starts looking at it.
func (r *caRotator) report(st caRotationState) {
	r.metrics.CACertExpiry(r.authority.NotAfter())
	r.metrics.CATrustRoots(len(r.authority.TrustBundle()))
	phase := string(st.phase)
	if st.rawPhase != "" && !st.phaseKnown {
		phase = "unknown"
	}
	r.metrics.CARotationPhase(phase, st.since)
	r.metrics.CAOutgoingRootSessions(r.holdouts.holdoutsOn(r.outgoingFingerprint(st)))
}

// outgoingFingerprint names the root a rotation is retiring, or "" when none
// is. "" matches no recorded issuer, so the holdout count is zero outside the
// signing phase without a second code path saying so.
func (r *caRotator) outgoingFingerprint(st caRotationState) string {
	if st.phase != caPhaseSigning {
		return ""
	}
	cert, err := parseOneCertificate(st.prevCertPEM)
	if err != nil {
		return ""
	}
	return ca.Fingerprint(cert)
}

// parseOneCertificate decodes a single PEM certificate. The trust-bundle
// parser is reused so that what counts as a usable root is decided in exactly
// one place.
func parseOneCertificate(pemBytes []byte) (*x509.Certificate, error) {
	roots, err := ca.ParseTrustBundlePEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return roots[0], nil
}

// caRotationPlan is one compare-and-swap: the phase to record and the keys to
// set and delete alongside it.
type caRotationPlan struct {
	to     caPhase
	reason string
	// keepSince leaves the phase's start time alone. It is set by the writes
	// that record an observation rather than a transition, which must not
	// restart the clock they are being measured against.
	keepSince bool
	set       map[string][]byte
	del       []string
	// consumeForce clears the rotate-now annotation in this same write. Only
	// the plan that ACTS on the annotation -- starting the rotation it asks
	// for, or declining because one is already running -- may set it. A
	// steady-state write made for another reason, such as discarding stray
	// material, leaves the annotation for the next poll to honour; consuming
	// it there would silently swallow an operator's order to rotate a key
	// they no longer trust.
	consumeForce bool
}

// advance evaluates the gates and, if one has opened, performs the transition.
// It returns the state now in force, or nil if nothing was written.
func (r *caRotator) advance(ctx context.Context, sec *kube.Secret, st caRotationState) (*caRotationState, error) {
	plan, err := r.plan(st)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, nil
	}

	now := r.now()
	sec.Data[secretKeyRotationPhase] = []byte(plan.to)
	if !plan.keepSince {
		sec.Data[secretKeyRotationSince] = []byte(now.UTC().Format(time.RFC3339))
	}
	maps.Copy(sec.Data, plan.set)
	for _, key := range plan.del {
		delete(sec.Data, key)
	}
	if plan.consumeForce {
		// Edge triggered: the annotation is consumed in the same write that
		// records what it caused, so it cannot fire twice. The map is
		// necessarily non-nil here -- a plan only consumes a force that
		// readCARotation found in it.
		delete(sec.Annotations, annotationRotateNow)
		sec.Annotations[annotationRotateAccepted] = now.UTC().Format(time.RFC3339)
	}

	updated, err := r.client.UpdateSecret(ctx, sec)
	if err != nil {
		if errors.Is(err, kube.ErrConflict) {
			// Another replica got there first. Its write is authoritative and
			// the next poll adopts it; retrying here would either repeat work
			// that is already done or race the same way again.
			r.logger.InfoContext(ctx, "another replica advanced the CA rotation first; adopting its result",
				"intended", string(plan.to))
			return nil, nil
		}
		return nil, fmt.Errorf("record CA rotation phase %s in secret %s: %w", plan.to, r.secret, err)
	}

	if plan.to != st.phase {
		r.metrics.CARotationTransition(string(plan.to))
		r.logger.InfoContext(ctx, "CA rotation advanced",
			"from", string(st.phase), "to", string(plan.to), "reason", plan.reason)
	} else {
		r.logger.InfoContext(ctx, "CA rotation state recorded",
			"phase", string(plan.to), "reason", plan.reason)
	}
	next := readCARotation(updated)
	return &next, nil
}

// plan decides what, if anything, this poll should write.
//
// Nil means stay put, which is the answer to every ambiguity: the safe state
// of a half-finished rotation is the one it is already in, because both roots
// are trusted there and nothing in the fleet can fail to verify.
func (r *caRotator) plan(st caRotationState) (*caRotationPlan, error) {
	if st.rawPhase != "" && !st.phaseKnown {
		// Checked before ANY other planning: the branches below all reason
		// from st.phase, which defaulted to steady precisely because the
		// recorded phase could not be read -- and steady's first act is to
		// tidy away material an in-flight rotation may depend on. Freeze,
		// loudly. sync() has already widened trust to everything present, so
		// nothing disconnects while frozen, and the phase gauge reports
		// "unknown" so the stalled alert eventually pages a human.
		r.logger.Error("the CA Secret records a rotation phase this build does not know; holding trust wide and touching nothing",
			"phase", st.rawPhase)
		return nil, nil
	}
	if st.force != "" && st.phase != caPhaseSteady {
		// A forced rotation only ever starts one. Consuming the annotation
		// here rather than leaving it is the point: an annotation that
		// survived the phase it was set in would fire again the moment the
		// current rotation finished, months later, for a reason nobody
		// remembers.
		return &caRotationPlan{
			to: st.phase, keepSince: true, consumeForce: true,
			reason: "a CA rotation is already in progress, so " + annotationRotateNow +
				" is consumed without starting a second one",
		}, nil
	}
	switch st.phase {
	case caPhaseSteady:
		return r.planSteady(st)
	case caPhasePublishing:
		return r.planPublishing(st), nil
	default:
		return r.planSigning(st), nil
	}
}

// planSteady tidies up after an interrupted rotation and decides whether to
// start a new one.
func (r *caRotator) planSteady(st caRotationState) (*caRotationPlan, error) {
	if stray := strayRotationKeys(st); len(stray) > 0 {
		// Material belonging to no phase. It is not trusted -- steady state
		// trusts the signer alone -- so leaving it would be harmless except
		// for one thing: ca-next.key is a private key for a root nothing will
		// ever use, and dead key material is a liability, not a spare.
		return &caRotationPlan{
			to: caPhaseSteady, reason: "discarding rotation material that belongs to no phase",
			keepSince: true, del: stray,
		}, nil
	}
	reason, due := r.rotationDue(st)
	if !due {
		return nil, nil
	}
	certPEM, keyPEM, err := ca.NewRootPEM(ca.Options{TrustDomain: r.cfg.TrustDomain})
	if err != nil {
		return nil, fmt.Errorf("mint the successor root: %w", err)
	}
	return &caRotationPlan{
		to: caPhasePublishing, reason: reason, consumeForce: st.force != "",
		set: map[string][]byte{secretKeyCANextCert: certPEM, secretKeyCANextKey: keyPEM},
	}, nil
}

// strayRotationKeys names rotation material present in the steady state.
func strayRotationKeys(st caRotationState) []string {
	var stray []string
	for key, present := range map[string]bool{
		secretKeyCANextCert:          len(st.nextCertPEM) > 0,
		secretKeyCANextKey:           len(st.nextKeyPEM) > 0,
		secretKeyCAPrevCert:          len(st.prevCertPEM) > 0,
		secretKeyRotationHoldout:     st.hasHoldout,
		secretKeyRotationRetireAfter: st.hasRetireAfter,
	} {
		if present {
			stray = append(stray, key)
		}
	}
	slices.Sort(stray)
	return stray
}

// rotationDue reports whether a rotation should begin, and why.
//
// Two independent triggers. An operator's annotation is honoured immediately,
// because the reason to use it is a key you no longer trust and there is no
// argument for waiting. Otherwise the signing root is rotated once it is deep
// enough into its life -- the configured fraction, or the rotation's own
// runway if that is longer, because starting a rotation that cannot finish
// before the signer expires is worse than starting one early.
func (r *caRotator) rotationDue(st caRotationState) (string, bool) {
	if st.force != "" {
		return "an operator set " + annotationRotateNow + ": " + st.force, true
	}
	cert := r.authority.Certificate()
	remaining := cert.NotAfter.Sub(r.now())
	total := cert.NotAfter.Sub(cert.NotBefore)

	threshold := time.Duration(float64(total) * r.cfg.CARotateAtRemainingFraction)
	if runway := r.cfg.CARotationRunway(); threshold < runway {
		threshold = runway
	}
	if remaining > threshold {
		return "", false
	}
	return fmt.Sprintf("the signing root has %s of its %s life left, at or below the %s rotation threshold",
		remaining.Round(time.Hour), total.Round(time.Hour), threshold.Round(time.Hour)), true
}

// planPublishing decides whether the successor may start signing.
//
// The gate is one full spoke-certificate lifetime. Spokes renew at half their
// certificate's life, so a lifetime is twice what convergence needs and every
// healthy spoke has renewed onto the two-root bundle at least once by then.
// The tighter requirement it also satisfies is the one that would otherwise
// break a multi-replica hub: every replica polls this Secret, so a lifetime is
// many thousand poll intervals, and no replica can still be ignorant of the
// successor when another starts signing with it.
//
// The one thing that opens the gate early is the signer itself expiring.
// Waiting is for spokes to renew onto the two-root bundle, and past the
// signer's notAfter no spoke can renew at all -- every certificate it would
// issue chains to an expired root -- so the rest of the wait protects nothing
// and costs every cluster whose renewal falls due inside it. This is the
// runway-floor case in rotationDue having lost anyway: a rotation forced or
// begun too late to finish. Promoting is the only move that gets issuance
// back.
func (r *caRotator) planPublishing(st caRotationState) *caRotationPlan {
	if len(st.nextCertPEM) == 0 || len(st.nextKeyPEM) == 0 {
		return &caRotationPlan{
			to:     caPhaseSteady,
			reason: "no successor root is stored, so there is nothing to publish",
			del:    rotationScratchKeys,
		}
	}
	if plan := r.repairSince(st); plan != nil {
		return plan
	}
	now := r.now()
	reason := fmt.Sprintf("the successor root has been published for %s, a full spoke certificate lifetime",
		r.cfg.SpokeCertTTL)
	if now.Sub(st.since) < r.cfg.SpokeCertTTL {
		if now.Before(r.authority.NotAfter()) {
			return nil
		}
		reason = "the signing root has expired, so nothing can renew onto the outgoing bundle; " +
			"promoting the successor restores issuance"
	}
	// The retirement horizon is fixed here, from the lifetime and grace this
	// promotion was made under, and read back by planSigning. See
	// secretKeyRotationRetireAfter for why it is stored rather than
	// recomputed.
	retireAfter := now.Add(r.retirementHold())
	return &caRotationPlan{
		to:     caPhaseSigning,
		reason: reason,
		set: map[string][]byte{
			secretKeyCACert:              st.nextCertPEM,
			secretKeyCAKey:               st.nextKeyPEM,
			secretKeyCAPrevCert:          st.certPEM,
			secretKeyRotationRetireAfter: []byte(retireAfter.UTC().Format(time.RFC3339)),
		},
		del: []string{secretKeyCANextCert, secretKeyCANextKey, secretKeyRotationHoldout},
	}
}

// rotationScratchKeys is every rotation key a return to steady state clears.
// One list rather than one per transition, because the transitions that
// merely tidy up -- a missing successor, a missing outgoing root -- must
// clear exactly the same set, and a key left behind by one of them would be
// mistaken for stray material on the very next poll.
var rotationScratchKeys = []string{
	secretKeyCANextCert, secretKeyCANextKey, secretKeyRotationHoldout, secretKeyRotationRetireAfter,
}

// retirementHold is how long after promotion the outgoing root must stay
// trusted, from the config in force now: a full certificate lifetime plus
// the renewal grace, padded by two poll intervals.
//
// By the time it has elapsed, every certificate the outgoing root ever issued
// is past its own expiry AND the window in which a spoke that was switched
// off could still have renewed it. The padding is for the replicas that LOST
// the promotion: each keeps signing with the old root until its next poll
// adopts the new signer, and a certificate issued in that lag is legitimately
// renewable until lag + TTL + grace after the promotion. Two intervals rather
// than one because the poll is jittered and a read can straddle a boundary.
func (r *caRotator) retirementHold() time.Duration {
	return r.cfg.SpokeCertTTL + r.cfg.RenewGrace + 2*r.cfg.CARotationPollInterval
}

// planSigning decides whether the outgoing root may be dropped.
//
// This is the only step that takes trust away, so it is the only one with two
// gates. The clock must have run a full certificate lifetime plus the renewal
// grace -- after which every certificate the outgoing root issued has expired
// AND passed the window in which a spoke that was switched off could still
// have renewed it -- and no replica may have seen a live session admitted by
// that root in the recent past. Either alone is defensible; both is what
// stops this reproducing the failure the manual procedure warned about.
func (r *caRotator) planSigning(st caRotationState) *caRotationPlan {
	if len(st.prevCertPEM) == 0 {
		return &caRotationPlan{
			to:     caPhaseSteady,
			reason: "the outgoing root is no longer stored, so the rotation is already complete",
			del:    rotationScratchKeys,
		}
	}
	if plan := r.repairSince(st); plan != nil {
		return plan
	}

	now := r.now()
	// THIS clock gate is the load-bearing protection, and the holdout count
	// below is the second belt. By the time the gate opens, every certificate
	// the outgoing root ever issued is past its own expiry AND the renewal
	// grace (see retirementHold), so retiring the root strands nothing that
	// could still come back. The holdout veto is advisory on top of that: it
	// is per-replica evidence with a startup quiet window, and a replica
	// restart racing the retirement can leave a short gap where a live
	// holdout goes unreported. That gap is only dangerous if this arithmetic
	// is broken.
	//
	// The gate is the LATER of two horizons: the one the promoting replica
	// persisted from the config it promoted under, and the one the live
	// config gives from the phase start. The persisted one is what makes
	// shortening --spoke-cert-ttl or --renew-grace mid-rotation safe -- the
	// certificates in the field were issued under the old values and the old
	// values are what bound their renewal. The live one still counts because
	// LENGTHENING mid-rotation can only ever be conservative, and because a
	// rotation promoted by an older build persisted nothing.
	gate := st.since.Add(r.retirementHold())
	if st.retireAfter.After(gate) {
		gate = st.retireAfter
	}
	if now.Before(gate) {
		// Nothing is decided here yet, and nothing is written either. Every
		// spoke is on the outgoing root at the start of this phase, so
		// recording sightings before the clock is anywhere near open would be
		// one Secret write per replica per poll for a month, to reach a
		// conclusion nobody can act on until the clock runs out anyway.
		return nil
	}
	// A replica that has only just started sees an empty session table, which
	// is not evidence of anything. Give the fleet time to reconnect before
	// believing a zero.
	if now.Sub(r.startedAt) < r.holdoutQuiet() {
		return nil
	}
	// Publish what this replica can see, so that a replica which is not the
	// one advancing still contributes its evidence. This is what makes a
	// per-replica session table into a fleet-wide veto.
	if n := r.holdouts.holdoutsOn(r.outgoingFingerprint(st)); n > 0 {
		if now.Sub(st.lastHoldout) < r.cfg.CARotationPollInterval {
			return nil // already recorded this interval; do not write twice
		}
		return &caRotationPlan{
			to: caPhaseSigning, keepSince: true,
			reason: fmt.Sprintf("%d live session(s) here still hold a certificate from the outgoing root", n),
			set:    map[string][]byte{secretKeyRotationHoldout: []byte(now.UTC().Format(time.RFC3339))},
		}
	}
	if !st.lastHoldout.IsZero() && now.Sub(st.lastHoldout) < r.holdoutQuiet() {
		return nil
	}
	return &caRotationPlan{
		to:     caPhaseSteady,
		reason: "no replica has seen a session on the outgoing root, and every certificate it issued has passed expiry and the renewal grace",
		del:    []string{secretKeyCAPrevCert, secretKeyRotationHoldout, secretKeyRotationRetireAfter},
	}
}

// holdoutQuiet is how long the fleet must go without any replica sighting a
// session on the outgoing root. Two poll intervals: one is a single missed
// observation, two means every replica has looked and found nothing.
func (r *caRotator) holdoutQuiet() time.Duration { return 2 * r.cfg.CARotationPollInterval }

// repairSince restarts the phase clock when the recorded start time is missing
// or unreadable.
//
// Restarting it is the conservative direction: it can only delay the next
// transition, never bring one forward. Refusing to run instead would leave a
// rotation wedged in a state only a human could clear, which is the failure
// mode this whole controller exists to remove.
func (r *caRotator) repairSince(st caRotationState) *caRotationPlan {
	if st.sinceOK {
		return nil
	}
	return &caRotationPlan{
		to:     st.phase,
		reason: "the recorded phase start time is missing or unreadable; restarting the phase clock",
	}
}

// newCARotator builds the rotation controller, or returns nil with the reason
// it cannot run. A nil rotator is not an error: it is a supported deployment
// whose CA is somebody else's to rotate.
func (h *hub) newCARotator() (*caRotator, string) {
	switch {
	case !h.cfg.CARotationEnabled:
		return nil, "disabled by --ca-rotation-enabled=false"
	case h.kube == nil:
		return nil, "the file state backend has no compare-and-swap to coordinate replicas with, " +
			"and is a single-process development mode; see ADR-0005"
	case !selfManagedCAPaths(h.cfg):
		return nil, fmt.Sprintf("the CA is supplied at %s rather than generated into --data-dir, "+
			"so its lifecycle belongs to whatever supplies it", h.cfg.CACertFile)
	case h.caIssuers == nil:
		// run() wires the tunnel server -- and with it the issuer tracker --
		// before this is called, so this is unreachable there. Checked
		// because a nil concrete pointer assigned to the interface below
		// would be a non-nil interface that panics inside holdoutsOn, and
		// that ordering is a fact of run(), not of this function.
		return nil, "the issuer tracker is not wired; rotation cannot gather holdout evidence"
	}
	return &caRotator{
		client:    h.kube,
		secret:    h.cfg.CASecretName,
		cfg:       h.cfg,
		base:      h.caBaseRoots,
		logger:    h.logger,
		metrics:   h.metrics,
		holdouts:  h.caIssuers,
		authority: h.authority,
		now:       func() time.Time { return h.clock() },
		startedAt: h.clock(),
	}, ""
}

// selfManagedCAPaths reports whether the CA files are the ones the hub
// generates for itself inside its scratch directory.
//
// When they are not, the operator mounted their own -- typically a projected
// Secret, which is read-only. Rotating in that deployment would write a new
// root into the CA Secret that the next restart could not materialise back
// onto the mounted path, so the hub declines to rotate what it was handed.
func selfManagedCAPaths(cfg *config.Hub) bool {
	return cfg.CACertFile == filepath.Join(cfg.DataDir, config.CACertFileName) &&
		cfg.CAKeyFile == filepath.Join(cfg.DataDir, config.CAKeyFileName)
}
