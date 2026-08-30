// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
}

// TestMutationStoreFailures covers the write paths that only fail after the
// record has been read.
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
			name:   "rotate: revoking the original fails",
			inject: func(f *fakeStore) { f.errRevokeKey = boom },
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
