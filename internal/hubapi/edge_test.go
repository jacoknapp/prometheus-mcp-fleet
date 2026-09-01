// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// TestMintedTokenIsReturnedExactlyOnce is the API's central promise: the raw
// credential exists in exactly one response and is unrecoverable afterwards.
func TestMintedTokenIsReturnedExactlyOnce(t *testing.T) {
	t.Parallel()

	mints := []struct {
		name string
		path string
		body any
	}{
		{
			name: "agent key",
			path: "/admin/v1/keys",
			body: CreateKeyRequest{Class: fleet.ClassAgent, Name: "once", Scope: validScope()},
		},
		{
			name: "admin key",
			path: "/admin/v1/keys",
			body: CreateKeyRequest{Class: fleet.ClassAdmin, Name: "once-admin"},
		},
		{
			name: "enrollment token",
			path: "/admin/v1/enrollments",
			body: CreateEnrollmentRequest{ClusterID: "prod-eu-1"},
		},
	}

	for _, tc := range mints {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)

			var minted MintedKeyResponse
			resp := h.adminDo(http.MethodPost, tc.path, tc.body)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, decode(t, resp, nil))
			}
			decode(t, resp, &minted)
			if minted.Token == "" {
				t.Fatal("no token returned")
			}
			if !minted.TokenShownOnce {
				t.Error("TokenShownOnce is false")
			}
			if minted.Warning != TokenOnceNotice {
				t.Errorf("Warning = %q, want the once-only notice", minted.Warning)
			}
			// The stored record is a digest, not the token.
			stored, ok := h.store.get(minted.Key.KID)
			if !ok {
				t.Fatal("the minted key was not stored")
			}
			if strings.Contains(string(stored.SecretHMAC), minted.Token) {
				t.Fatal("the raw token was stored")
			}

			reads := []string{
				"/admin/v1/keys/" + minted.Key.KID,
				"/admin/v1/keys",
				"/admin/v1/enrollments",
				"/admin/v1/certs/revoked",
				"/admin/v1/ca",
			}
			for _, path := range reads {
				body := decode(t, h.adminDo(http.MethodGet, path, nil), nil)
				if strings.Contains(body, minted.Token) {
					t.Errorf("GET %s returned the raw token again", path)
				}
				if tokenShapeRE.MatchString(body) {
					t.Errorf("GET %s returned a token-shaped string", path)
				}
			}
			// Rotation issues a new token and still does not resurrect the old.
			var rotated MintedKeyResponse
			rot := h.adminDo(http.MethodPost, "/admin/v1/keys/"+minted.Key.KID+"/rotate", nil)
			if rot.StatusCode == http.StatusCreated {
				body := decode(t, rot, &rotated)
				if strings.Contains(body, minted.Token) {
					t.Error("rotation echoed the original token")
				}
			} else {
				rot.Body.Close()
			}
			if strings.Contains(h.logs.String(), minted.Token) {
				t.Error("the minted token reached the log")
			}
			assertNoSecretMaterial(t, h, "")
		})
	}
}

// TestNewServerAppliesDefaults pins the documented zero-value behaviour, since
// the composition root relies on it.
func TestNewServerAppliesDefaults(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	s, err := newServer(Options{Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if s.agentKeyTTL != DefaultAgentKeyTTL || s.adminKeyTTL != DefaultAdminKeyTTL ||
		s.enrollmentTTL != DefaultEnrollmentTTL || s.spokeCertTTL != DefaultSpokeCertTTL ||
		s.crlValidity != DefaultCRLValidity {
		t.Errorf("lifetimes were not defaulted: %+v", s)
	}
	if s.clock == nil || s.log == nil || s.metrics == nil {
		t.Error("clock, logger or metrics was left nil")
	}
	if s.draining() {
		t.Error("a nil Draining must mean never draining")
	}
	// The defaults must recognise the production store's sentinels as well as
	// this package's, so a composition root that wires the shipped backend and
	// nothing else still answers 404 and 409 rather than 500.
	for _, err := range []error{ErrNotFound, store.ErrNotFound, fmt.Errorf("kid x: %w", store.ErrNotFound)} {
		if !s.isNotFound(err) {
			t.Errorf("the default IsNotFound does not match %v", err)
		}
	}
	if s.isNotFound(errors.New("other")) {
		t.Error("the default IsNotFound matches an unrelated error")
	}
	for _, err := range []error{
		ErrEnrollmentUsed, ErrAlreadyExists,
		store.ErrEnrollmentUsed, store.ErrAlreadyExists,
		fmt.Errorf("kid x: %w", store.ErrEnrollmentUsed),
	} {
		if !s.isConflict(err) {
			t.Errorf("the default IsConflict does not match %v", err)
		}
	}
	if s.isConflict(errors.New("other")) {
		t.Error("the default IsConflict matches an unrelated error")
	}
	if s.enrollmentEnabled {
		t.Error("enrollment must be off unless enabled explicitly")
	}
}

// TestMintKeyRejectsUnknownClass covers mintKey's own error path from
// token.Mint, distinct from the CSPRNG failure token.Mint can also return:
// since Go 1.24, crypto/rand.Read calls runtime.fatal on a reader error
// instead of returning one, so that half of token.Mint's error surface is
// unreachable by any test. token.ErrUnknownClass is not: every *handler* in
// this package validates class before calling mintKey, but mintKey is an
// unexported method in the same package, so nothing stops a test from
// driving it directly with a class that fails fleet.KeyClass.Valid() — the
// same technique already used above to reach handleEnroll with a nil
// principal.
func TestMintKeyRejectsUnknownClass(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	s, err := newServer(Options{Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}

	bogus := fleet.KeyClass("bogus")
	if bogus.Valid() {
		t.Fatal("test setup: this class must be invalid")
	}
	key, raw, err := s.mintKey(t.Context(), bogus, "name", "owner", time.Now().Add(time.Hour), nil, nil)
	if err == nil {
		t.Fatal("mintKey accepted an unknown key class")
	}
	if !errors.Is(err, token.ErrUnknownClass) {
		t.Errorf("err = %v, want it to wrap token.ErrUnknownClass", err)
	}
	if key != nil || raw != "" {
		t.Errorf("mintKey returned a credential despite the error: key=%+v raw=%q", key, raw)
	}
}

// TestNopMetricsDoesNothing exercises the default metrics sink.
func TestNopMetricsDoesNothing(t *testing.T) {
	t.Parallel()
	var m Metrics = NopMetrics{}
	m.Enrollment(ResultIssued)
	m.SecurityEvent(EventKeyMinted)
}

// TestValidateHelpers covers the field validators at their boundaries.
func TestValidateHelpers(t *testing.T) {
	t.Parallel()

	t.Run("reason", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			reason string
			wantOK bool
		}{
			{name: "ordinary", reason: "spoke decommissioned", wantOK: true},
			{name: "blank", reason: "  ", wantOK: false},
			{name: "at the limit", reason: strings.Repeat("r", MaxReasonBytes), wantOK: true},
			{name: "over the limit", reason: strings.Repeat("r", MaxReasonBytes+1), wantOK: false},
			{name: "forged audit line", reason: "ok\nevent=key.minted", wantOK: false},
		}
		for _, tc := range tests {
			if err := validateReason(tc.reason); (err == nil) != tc.wantOK {
				t.Errorf("validateReason(%s) error = %v, want ok=%v", tc.name, err, tc.wantOK)
			}
		}
	})

	t.Run("serial", func(t *testing.T) {
		t.Parallel()
		tests := map[string]bool{
			"a": true, "0a1b": true, "ff": true,
			strings.Repeat("a", 64): true,
			"":                      false,
			"0":                     false,
			"00":                    false,
			"0A":                    false,
			"0x1f":                  false,
			strings.Repeat("a", 65): false,
		}
		for in, want := range tests {
			if got := validSerial(in); got != want {
				t.Errorf("validSerial(%q) = %v, want %v", in, got, want)
			}
		}
	})

	t.Run("ttl", func(t *testing.T) {
		t.Parallel()
		if got, err := resolveTTL(0, time.Hour); err != nil || got != time.Hour {
			t.Errorf("resolveTTL(0) = %s, %v, want the default", got, err)
		}
		if _, err := resolveTTL(fleet.Duration(-time.Second), time.Hour); err == nil {
			t.Error("a negative ttl was accepted")
		}
		if _, err := resolveTTL(fleet.Duration(2*time.Hour), time.Hour); err == nil {
			t.Error("a ttl above the maximum was accepted")
		}
		if got, err := resolveTTL(fleet.Duration(time.Minute), time.Hour); err != nil || got != time.Minute {
			t.Errorf("resolveTTL(1m) = %s, %v", got, err)
		}
	})
}

// TestDecodeCSRAcceptsPaddedAndUnpadded proves both base64 spellings work,
// because installers produce both.
func TestDecodeCSRAcceptsPaddedAndUnpadded(t *testing.T) {
	t.Parallel()
	der := []byte{1, 2, 3, 4, 5}

	for _, in := range []string{
		base64.StdEncoding.EncodeToString(der),
		base64.RawStdEncoding.EncodeToString(der),
		"  " + base64.StdEncoding.EncodeToString(der) + "\n",
	} {
		got, err := decodeCSR(in)
		if err != nil {
			t.Fatalf("decodeCSR(%q): %v", in, err)
		}
		if string(got) != string(der) {
			t.Errorf("decodeCSR(%q) = %v, want %v", in, got, der)
		}
	}
	if _, err := decodeCSR("not base64 !!"); err == nil {
		t.Error("decodeCSR accepted a non-base64 string")
	}
}

// TestViewKeysSkipsNilRecords proves a hole in a store's slice cannot panic a
// list route.
func TestViewKeysSkipsNilRecords(t *testing.T) {
	t.Parallel()
	got := viewKeys([]*fleet.Key{nil, {KID: "a", Class: fleet.ClassAgent}, nil}, testNow)
	if len(got) != 1 || got[0].KID != "a" {
		t.Fatalf("viewKeys = %+v, want exactly the non-nil record", got)
	}
}

// TestRequestIDIsEchoed proves the correlation id reaches the error envelope
// from either side.
func TestRequestIDIsEchoed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	req := mustRequest(t, http.MethodGet, h.admin.URL+"/admin/v1/keys/not-a-kid", h.adminToken, "")
	req.Header.Set(authnRequestIDHeader, "corr-42")
	resp, err := h.admin.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if env := envelopeOf(t, resp); env.Error.RequestID != "corr-42" {
		t.Errorf("RequestID = %q, want %q", env.Error.RequestID, "corr-42")
	}
}

// TestLoadKeyFailureModes covers the two store shapes that are not "found".
func TestLoadKeyFailureModes(t *testing.T) {
	t.Parallel()

	t.Run("unreadable store is a 500", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAgent, Name: "x", Scope: validScope()}), &created)
		h.store.inject(t, func(f *fakeStore) {
			f.errGet = errors.New("state secret unreadable")
			f.errGetKID = created.Key.KID
		})

		resp := h.adminDo(http.MethodGet, "/admin/v1/keys/"+created.Key.KID, nil)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
		}
		resp.Body.Close()
	})

	t.Run("a nil record with no error is a 404", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAgent, Name: "x", Scope: validScope()}), &created)
		h.store.inject(t, func(f *fakeStore) { f.getNil, f.errGetKID = true, created.Key.KID })

		resp := h.adminDo(http.MethodGet, "/admin/v1/keys/"+created.Key.KID, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
		resp.Body.Close()
	})
}

// TestMintRetriesAreBounded proves a store that reports a collision forever
// fails the request rather than looping.
func TestMintRetriesAreBounded(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.store.inject(t, func(f *fakeStore) { f.putAlwaysConflict = true })

	resp := h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "doomed", Scope: validScope()})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	env := envelopeOf(t, resp)
	if env.Error.Code != CodeInternal {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeInternal)
	}
	assertNoSecretMaterial(t, h, "")

	// The retry warning is the only signal an operator gets that key
	// identifiers are colliding, so the count it reports has to be the
	// attempt number and not the loop index. Both ends are pinned: a
	// zero-based or otherwise shifted counter would misreport how close the
	// hub came to exhausting its retries.
	logs := h.logs.String()
	for _, want := range []string{`"attempt":1`, fmt.Sprintf(`"attempt":%d`, mintRetries)} {
		if !strings.Contains(logs, want) {
			t.Errorf("collision log does not contain %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, `"attempt":0`) || strings.Contains(logs, `"attempt":-1`) {
		t.Errorf("collision log counts attempts from below one: %s", logs)
	}
}

// TestMutationStoreFailures covers the write paths that only fail after the
// record has been read.
// TestMintKeyRefusesImmortalNonAgent pins the structural guard inside the
// mint path itself: resolveExpiry already refuses no-expiry for admin and
// enrollment classes at every route, but a future caller passing the zero
// time directly must hit a wall here rather than persist an immortal admin
// credential.
func TestMintKeyRefusesImmortalNonAgent(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	s, err := newServer(Options{Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	for _, class := range []fleet.KeyClass{fleet.ClassAdmin, fleet.ClassEnrollment} {
		if _, _, err := s.mintKey(t.Context(), class, "name", "owner", time.Time{}, nil, nil); err == nil {
			t.Errorf("mintKey minted an immortal %s credential", class)
		}
	}
}

// TestRotateRevokedKeyRefused pins the replay refusal: rotating an
// already-revoked key must not mint it back into life, because the retry of a
// rotation whose response was lost would otherwise strand a second live
// replacement whose raw token nobody ever saw.
func TestRotateRevokedKeyRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	var created MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "rotate-once", Scope: validScope()}), &created)

	var first MintedKeyResponse
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate", nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first rotation status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	decode(t, resp, &first)

	// The replay. The refusal must name the replacement, which the operator
	// needs precisely because its raw token was in the response they lost.
	replay := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate", nil)
	if replay.StatusCode != http.StatusConflict {
		t.Fatalf("replayed rotation status = %d, want %d (%s)", replay.StatusCode, http.StatusConflict, decode(t, replay, nil))
	}
	env := envelopeOf(t, replay)
	if env.Error.Code != CodeConflict {
		t.Errorf("code = %q, want %q", env.Error.Code, CodeConflict)
	}
	if !strings.Contains(env.Error.Message, first.Key.KID) {
		t.Errorf("refusal %q does not name the replacement key %s", env.Error.Message, first.Key.KID)
	}

	var after KeyListResponse
	decode(t, h.adminDo(http.MethodGet, "/admin/v1/keys?class=agt", nil), &after)
	var replacements int
	for _, k := range after.Keys {
		if k.Name == "rotate-once" && !k.Revoked {
			replacements++
		}
	}
	if replacements != 1 {
		t.Errorf("live keys named rotate-once = %d, want exactly 1: the replay minted a ghost", replacements)
	}
}

// TestRotateFailureChangesNothing pins the atomicity that replaced the old
// two-phase rotate: when the single ReplaceKey mutation fails, the original
// key is still live and no replacement exists. Before this, a revoke failing
// after the mint succeeded stranded a live credential whose raw token was
// already unrecoverable.
func TestRotateFailureChangesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	var created MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "victim", Scope: validScope()}), &created)
	h.store.inject(t, func(f *fakeStore) { f.errPut = errors.New("the secret is unwritable") })

	resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusInternalServerError, decode(t, resp, nil))
	}

	h.store.inject(t, func(f *fakeStore) { f.errPut = nil })
	var after KeyListResponse
	decode(t, h.adminDo(http.MethodGet, "/admin/v1/keys?class=agt", nil), &after)
	// The harness mints its own agent key, so assert on the victim by name:
	// exactly one key carries it, it is the original, and it is still live.
	var victims []KeyView
	for _, k := range after.Keys {
		if k.Name == "victim" {
			victims = append(victims, k)
		}
	}
	if len(victims) != 1 {
		t.Fatalf("keys named victim after failed rotation = %d, want 1: a failed rotation minted or destroyed something", len(victims))
	}
	if got := victims[0]; got.KID != created.Key.KID || got.Revoked {
		t.Errorf("original key after failed rotation = %+v, want %s live and unrevoked", got, created.Key.KID)
	}
}

func TestMutationStoreFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("state secret unwritable")

	tests := []struct {
		name   string
		inject func(*fakeStore)
		method string
		path   func(kid string) string
		body   any
		class  fleet.KeyClass
	}{
		{
			name:   "revoke key",
			inject: func(f *fakeStore) { f.errRevokeKey = boom },
			method: http.MethodDelete,
			path:   func(kid string) string { return "/admin/v1/keys/" + kid + "?reason=x" },
			class:  fleet.ClassAgent,
		},
		{
			name:   "purge key",
			inject: func(f *fakeStore) { f.errDelete = boom },
			method: http.MethodDelete,
			path:   func(kid string) string { return "/admin/v1/keys/" + kid + "?reason=x&purge=true" },
			class:  fleet.ClassAgent,
		},
		{
			name:   "rotate: mint fails",
			inject: func(f *fakeStore) { f.errPut = boom },
			method: http.MethodPost,
			path:   func(kid string) string { return "/admin/v1/keys/" + kid + "/rotate" },
			class:  fleet.ClassAgent,
		},
		{
			name:   "revoke enrollment",
			inject: func(f *fakeStore) { f.errRevokeKey = boom },
			method: http.MethodDelete,
			path:   func(kid string) string { return "/admin/v1/enrollments/" + kid },
			class:  fleet.ClassEnrollment,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			var kid string
			if tc.class == fleet.ClassEnrollment {
				kid = h.mintEnrollment("prod-eu-1")
			} else {
				var created MintedKeyResponse
				decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
					CreateKeyRequest{Class: tc.class, Name: "victim", Scope: validScope()}), &created)
				kid = created.Key.KID
			}
			h.store.inject(t, tc.inject)

			resp := h.adminDo(tc.method, tc.path(kid), tc.body)
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusInternalServerError,
					decode(t, resp, nil))
			}
			env := envelopeOf(t, resp)
			if env.Error.Code != CodeInternal {
				t.Errorf("code = %q, want %q", env.Error.Code, CodeInternal)
			}
			if strings.Contains(env.Error.Message, "unwritable") {
				t.Errorf("the store error leaked into the response: %q", env.Error.Message)
			}
		})
	}
}

// TestCreateEnrollmentStoreFailure covers the mint path on the enrollment
// route.
func TestCreateEnrollmentStoreFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.store.inject(t, func(f *fakeStore) { f.errPut = errors.New("state secret unwritable") })

	resp := h.adminDo(http.MethodPost, "/admin/v1/enrollments", CreateEnrollmentRequest{ClusterID: "prod-eu-1"})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	resp.Body.Close()
}

// TestRevokedCertListIsAlwaysAnArray proves an empty revocation list is `[]`
// and not `null`, so a client does not have to special-case it.
func TestRevokedCertListIsAlwaysAnArray(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	body := decode(t, h.adminDo(http.MethodGet, "/admin/v1/certs/revoked", nil), nil)
	if !strings.Contains(body, `"revoked":[]`) {
		t.Errorf("empty revocation list = %s, want an explicit empty array", body)
	}
}

// TestOversizeBodyOnEveryMutatingRoute proves the limit is on the route, not
// on one handler that happened to remember it.
func TestOversizeBodyOnEveryMutatingRoute(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	kid := h.mintEnrollment("prod-eu-1")

	routes := []struct{ name, path, field string }{
		{name: "create key", path: "/admin/v1/keys", field: "name"},
		{name: "rotate key", path: "/admin/v1/keys/" + kid + "/rotate", field: "reason"},
		{name: "create enrollment", path: "/admin/v1/enrollments", field: "clusterId"},
		{name: "revoke cert", path: "/admin/v1/certs/0a1b/revoke", field: "reason"},
	}
	for _, tc := range routes {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.doRaw(h.admin, http.MethodPost, tc.path, h.adminToken, oversizeJSON(tc.field))
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusRequestEntityTooLarge,
					decode(t, resp, nil))
			}
			if env := envelopeOf(t, resp); env.Error.Code != CodePayloadTooLarge {
				t.Errorf("code = %q, want %q", env.Error.Code, CodePayloadTooLarge)
			}
		})
	}
}

// TestTokenClassSegments proves each route mints the class it advertises.
func TestTokenClassSegments(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	tests := []struct {
		name string
		path string
		body any
		want fleet.KeyClass
	}{
		{
			name: "agent",
			path: "/admin/v1/keys",
			body: CreateKeyRequest{Class: fleet.ClassAgent, Name: "a", Scope: validScope()},
			want: fleet.ClassAgent,
		},
		{
			name: "admin",
			path: "/admin/v1/keys",
			body: CreateKeyRequest{Class: fleet.ClassAdmin, Name: "b"},
			want: fleet.ClassAdmin,
		},
		{
			name: "enrollment",
			path: "/admin/v1/enrollments",
			body: CreateEnrollmentRequest{ClusterID: "prod-eu-1"},
			want: fleet.ClassEnrollment,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got MintedKeyResponse
			decode(t, h.adminDo(http.MethodPost, tc.path, tc.body), &got)
			class, kid, _, err := token.Parse(got.Token)
			if err != nil {
				t.Fatalf("token.Parse: %v", err)
			}
			if class != tc.want {
				t.Errorf("class = %q, want %q", class, tc.want)
			}
			if kid != got.Key.KID {
				t.Errorf("token kid = %q, record kid = %q", kid, got.Key.KID)
			}
		})
	}
}

// TestPathKIDValidationOnMutatingRoutes proves every route that reads a
// {kid} path segment refuses a malformed one before it ever reaches the
// store, not just the one route ([TestListAndGetKeys]'s "malformed kid" case)
// that already covered GET.
func TestPathKIDValidationOnMutatingRoutes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	routes := []struct {
		name   string
		method string
		path   string
	}{
		{name: "revoke key", method: http.MethodDelete, path: "/admin/v1/keys/not-a-kid?reason=x"},
		{name: "rotate key", method: http.MethodPost, path: "/admin/v1/keys/not-a-kid/rotate"},
		{name: "revoke enrollment", method: http.MethodDelete, path: "/admin/v1/enrollments/not-a-kid"},
	}
	for _, tc := range routes {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := h.adminDo(tc.method, tc.path, nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusBadRequest, decode(t, resp, nil))
			}
			if env := envelopeOf(t, resp); env.Error.Code != CodeInvalidRequest {
				t.Errorf("code = %q, want %q", env.Error.Code, CodeInvalidRequest)
			}
		})
	}
}

// TestListRevokedCertsNormalizesNilSlice proves a store that returns a nil
// slice with no error -- a shape a store bug, or a store backed by a format
// with no empty/absent distinction, could produce even when [errors.New] was
// never called -- still answers with an explicit `"revoked":[]`, exactly as
// TestRevokedCertListIsAlwaysAnArray already proves for the ordinary "nothing
// revoked yet" case where the fake naturally builds an empty (not nil) slice.
func TestListRevokedCertsNormalizesNilSlice(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.store.inject(t, func(f *fakeStore) { f.revokedCertsNil = true })

	body := decode(t, h.adminDo(http.MethodGet, "/admin/v1/certs/revoked", nil), nil)
	if !strings.Contains(body, `"revoked":[]`) {
		t.Errorf("revoked list for a nil store slice = %s, want an explicit empty array", body)
	}
}

// TestRequestIDPrefersResponseHeader proves the correlation id in an error
// envelope is read from the response header the request-id middleware
// stamps, when present, rather than always falling back to the header the
// client sent. TestRequestIDIsEchoed already pins the fallback (this
// package's own test harness never stamps a response header, so that test
// exercises exactly the second return); this test pins the branch that
// prefers it, by stamping the response header itself, the way that
// middleware -- which lives in internal/hub, outside this package -- does in
// production.
func TestRequestIDPrefersResponseHeader(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	w.Header().Set(authnRequestIDHeader, "from-response")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(authnRequestIDHeader, "from-request")

	if got := requestID(w, r); got != "from-response" {
		t.Errorf("requestID = %q, want the response header's value", got)
	}
}

// TestWriteJSONLogsWriteFailure proves a write failure after the status and
// headers are already on the wire -- the shape a client that hung up
// mid-response takes -- is logged rather than silently dropped, and that it
// cannot be reported to the caller: the status is already sent.
func TestWriteJSONLogsWriteFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	logs := &syncBuffer{}
	srv, err := newServer(Options{
		Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Clock: h.clock.Now,
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}

	w := newFailingResponseWriter()
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/keys/aaaaaaaaaa", nil)
	srv.writeJSON(w, r, http.StatusOK, KeyListResponse{Keys: []KeyView{}, Count: 0})

	if w.status != http.StatusOK {
		t.Errorf("status recorded = %d, want %d", w.status, http.StatusOK)
	}
	if !strings.Contains(logs.String(), "write response") || !strings.Contains(logs.String(), "connection reset") {
		t.Errorf("write failure was not logged: %s", logs.String())
	}
}

// mintKey's own token.Mint entropy-failure branch (admin.go, inside mintKey)
// is deliberately not exercised here. [token.Mint] routes its CSPRNG read
// through crypto/rand.Read, and since Go 1.24 (see
// https://go.dev/issue/66821) that function crashes the process
// irrecoverably ("fatal error: crypto/rand: failed to read random data")
// instead of returning an error when the underlying reader fails -- verified
// empirically: swapping crypto/rand.Reader for a failing one and minting a
// key takes the whole test binary down rather than reaching mintKey's error
// branch. Combined with every call site in admin.go always passing one of
// the three valid KeyClass values (so token.Mint's other error,
// ErrUnknownClass, is equally unreachable from here), mintKey's
// `if err != nil` after `token.Mint` cannot be driven from this package
// without either modifying internal/token (out of scope for this pass) or
// adding a test-only seam to inject a fake mint function into hubapi -- which
// would exist purely to dodge coverage and make the production code worse.
// See the coverage report for the fuller writeup.

// TestLimitsAcceptExactlyTheDocumentedValue pins the accepting side of every
// size bound the enrollment and renewal paths advertise.
//
// Each of these already had a test proving that one over the limit is refused,
// which does not distinguish `>` from `>=`. A bound written one too tight
// rejects the largest legitimate request -- an operator stamping the full 32
// labels the API documents, or a spoke presenting a chain of exactly
// MaxChainCerts -- and every existing test would still have passed.
func TestLimitsAcceptExactlyTheDocumentedValue(t *testing.T) {
	t.Parallel()

	t.Run("labels", func(t *testing.T) {
		t.Parallel()

		if err := validateLabels(manyLabels(MaxLabels)); err != nil {
			t.Errorf("exactly MaxLabels (%d) labels were rejected: %v", MaxLabels, err)
		}
		if err := validateLabels(manyLabels(MaxLabels + 1)); err == nil {
			t.Errorf("MaxLabels+1 (%d) labels were accepted", MaxLabels+1)
		}

		atKeyLimit := map[string]string{strings.Repeat("k", MaxLabelKeyBytes): "v"}
		if err := validateLabels(atKeyLimit); err != nil {
			t.Errorf("a key of exactly MaxLabelKeyBytes (%d) was rejected: %v", MaxLabelKeyBytes, err)
		}
		overKeyLimit := map[string]string{strings.Repeat("k", MaxLabelKeyBytes+1): "v"}
		if err := validateLabels(overKeyLimit); err == nil {
			t.Errorf("a key of MaxLabelKeyBytes+1 (%d) was accepted", MaxLabelKeyBytes+1)
		}

		atValueLimit := map[string]string{"env": strings.Repeat("v", MaxLabelValueBytes)}
		if err := validateLabels(atValueLimit); err != nil {
			t.Errorf("a value of exactly MaxLabelValueBytes (%d) was rejected: %v", MaxLabelValueBytes, err)
		}
		overValueLimit := map[string]string{"env": strings.Repeat("v", MaxLabelValueBytes+1)}
		if err := validateLabels(overValueLimit); err == nil {
			t.Errorf("a value of MaxLabelValueBytes+1 (%d) was accepted", MaxLabelValueBytes+1)
		}
	})

	t.Run("chain and csr", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t, nil)
		srv, err := newServer(Options{
			Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier, Clock: h.clock.Now,
		})
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		id := h.issueSpoke("prod")

		// readChain and decodeCSRField answer the caller directly, so they are
		// driven here rather than through a route: the size gate is what is
		// under test, not the handler that follows it.
		call := func(fn func(http.ResponseWriter, *http.Request) bool) (bool, string) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			ok := fn(w, r)
			return ok, w.Body.String()
		}

		atChainLimit := slices.Repeat(id.chain(), MaxChainCerts)
		ok, body := call(func(w http.ResponseWriter, r *http.Request) bool {
			chain, ok := srv.readChain(w, r, atChainLimit)
			if ok && len(chain) != MaxChainCerts {
				t.Errorf("readChain returned %d certificates, want %d", len(chain), MaxChainCerts)
			}
			return ok
		})
		if !ok {
			t.Errorf("a chain of exactly MaxChainCerts (%d) was rejected: %s", MaxChainCerts, body)
		}
		overChainLimit := slices.Repeat(id.chain(), MaxChainCerts+1)
		if ok, _ := call(func(w http.ResponseWriter, r *http.Request) bool {
			_, ok := srv.readChain(w, r, overChainLimit)
			return ok
		}); ok {
			t.Errorf("a chain of MaxChainCerts+1 (%d) was accepted", MaxChainCerts+1)
		}

		// "A" repeated is valid base64 of the right width, and decodeCSRField
		// deliberately does not parse the request, so the size gate is the
		// only thing that can refuse it.
		atCSRLimit := strings.Repeat("A", MaxCSRBytes)
		ok, body = call(func(w http.ResponseWriter, r *http.Request) bool {
			_, ok := srv.decodeCSRField(w, r, atCSRLimit)
			return ok
		})
		if !ok {
			t.Errorf("a CSR field of exactly MaxCSRBytes (%d) was rejected: %s", MaxCSRBytes, body)
		}
		overCSRLimit := strings.Repeat("A", MaxCSRBytes+4)
		if ok, _ := call(func(w http.ResponseWriter, r *http.Request) bool {
			_, ok := srv.decodeCSRField(w, r, overCSRLimit)
			return ok
		}); ok {
			t.Errorf("a CSR field of MaxCSRBytes+4 (%d) was accepted", MaxCSRBytes+4)
		}
	})
}

// TestRotateRaceErrorsKeepTheirMeaning covers the window the pre-flight check
// cannot see: the source key revoked or deleted between loading it and the
// atomic ReplaceKey. Those are conflicts and disappearances, not server
// faults, and a 500 would send an operator hunting hub logs for a race that
// resolved exactly as designed.
func TestRotateRaceErrorsKeepTheirMeaning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		inject     error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "revoked in the window is a conflict",
			inject:     fmt.Errorf("kid X is already revoked (leaked): %w", store.ErrRevoked),
			wantStatus: http.StatusConflict,
			wantCode:   CodeConflict,
		},
		{
			name:       "deleted in the window is not found",
			inject:     fmt.Errorf("kid X: %w", ErrNotFound),
			wantStatus: http.StatusNotFound,
			wantCode:   CodeNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			var created MintedKeyResponse
			decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
				CreateKeyRequest{Class: fleet.ClassAgent, Name: "raced", Scope: validScope()}), &created)
			h.store.inject(t, func(f *fakeStore) { f.errReplace = tc.inject })

			resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate", nil)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, decode(t, resp, nil))
			}
			if env := envelopeOf(t, resp); env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", env.Error.Code, tc.wantCode)
			}
		})
	}
}
