// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// validScope is a scope document that passes fleet.Scope.Validate.
func validScope() *fleet.Scope {
	return &fleet.Scope{
		Role:     fleet.RoleViewer,
		Clusters: fleet.ClusterScope{Allow: []string{"prod-eu"}},
		Tools:    fleet.ToolScope{Allow: []string{"prom.query"}},
	}
}

func TestNewMuxRejectsIncompleteOptions(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	full := Options{Store: h.store, Hasher: h.hasher, CA: h.ca, Verifier: h.verifier}

	tests := []struct {
		name string
		mut  func(*Options)
		want string
	}{
		{name: "no store", mut: func(o *Options) { o.Store = nil }, want: "Store is required"},
		{name: "no hasher", mut: func(o *Options) { o.Hasher = nil }, want: "Hasher is required"},
		{name: "no ca", mut: func(o *Options) { o.CA = nil }, want: "CA is required"},
		{name: "no verifier", mut: func(o *Options) { o.Verifier = nil }, want: "Verifier is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := full
			tc.mut(&opts)
			if _, err := NewAdminMux(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewAdminMux() error = %v, want one containing %q", err, tc.want)
			}
			if _, err := NewPublicMux(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewPublicMux() error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// TestAdminRoutesRequireAnAdminCredential walks every admin route with no
// credential, with an agent credential and with an enrollment credential. None
// of them may reach a handler.
func TestAdminRoutesRequireAnAdminCredential(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	enrollToken := h.mint(fleet.ClassEnrollment, func(k *fleet.Key) {
		k.Enrollment = &fleet.EnrollmentGrant{ClusterID: "prod-eu"}
	})

	routes := []struct{ method, path string }{
		{http.MethodPost, "/admin/v1/keys"},
		{http.MethodGet, "/admin/v1/keys"},
		{http.MethodGet, "/admin/v1/keys/aaaaaaaaaa"},
		{http.MethodDelete, "/admin/v1/keys/aaaaaaaaaa?reason=x"},
		{http.MethodPost, "/admin/v1/keys/aaaaaaaaaa/rotate"},
		{http.MethodPost, "/admin/v1/enrollments"},
		{http.MethodGet, "/admin/v1/enrollments"},
		{http.MethodDelete, "/admin/v1/enrollments/aaaaaaaaaa"},
		{http.MethodPost, "/admin/v1/certs/0a1b/revoke"},
		{http.MethodGet, "/admin/v1/certs/revoked"},
		{http.MethodGet, "/admin/v1/ca"},
	}
	creds := []struct{ name, token string }{
		{name: "no credential", token: ""},
		{name: "agent credential", token: h.agentToken},
		{name: "enrollment credential", token: enrollToken},
		{name: "garbage", token: "pmf_adm_notarealtokenatallnotarealtokenatallnotar_zzzzzz"},
	}

	for _, route := range routes {
		for _, cred := range creds {
			t.Run(route.method+" "+route.path+" with "+cred.name, func(t *testing.T) {
				t.Parallel()
				resp := h.do(h.admin, route.method, route.path, cred.token, nil)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
				}
				if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `scope="admin"`) {
					t.Errorf("WWW-Authenticate = %q, want the admin scope", got)
				}
			})
		}
	}
}

func TestCreateKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantCode   string
		check      func(t *testing.T, h *harness, got MintedKeyResponse)
	}{
		{
			name:       "agent key",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "sre-bot", Owner: "sre@example", Scope: validScope()},
			wantStatus: http.StatusCreated,
			check: func(t *testing.T, h *harness, got MintedKeyResponse) {
				if !got.TokenShownOnce || got.Warning != TokenOnceNotice {
					t.Error("the response does not make the one-time nature of the token unmissable")
				}
				class, kid, _, err := token.Parse(got.Token)
				if err != nil {
					t.Fatalf("the returned token does not parse: %v", err)
				}
				if class != fleet.ClassAgent {
					t.Errorf("token class = %q, want %q", class, fleet.ClassAgent)
				}
				if kid != got.Key.KID {
					t.Errorf("token kid %q disagrees with the record %q", kid, got.Key.KID)
				}
				stored, ok := h.store.get(kid)
				if !ok {
					t.Fatal("the key was not stored")
				}
				if len(stored.SecretHMAC) == 0 {
					t.Error("the stored record has no digest")
				}
				// The presented token must actually authenticate.
				resp := h.do(h.admin, http.MethodGet, "/admin/v1/keys", got.Token, nil)
				resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("a fresh agent key reached the admin API: status %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "admin key",
			body:       CreateKeyRequest{Class: fleet.ClassAdmin, Name: "break-glass"},
			wantStatus: http.StatusCreated,
			check: func(t *testing.T, h *harness, got MintedKeyResponse) {
				resp := h.do(h.admin, http.MethodGet, "/admin/v1/keys", got.Token, nil)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("a freshly minted admin key was refused: status %d", resp.StatusCode)
				}
			},
		},
		{
			name:       "explicit ttl inside the maximum",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "short", Scope: validScope(), TTL: fleet.Duration(time.Hour)},
			wantStatus: http.StatusCreated,
			check: func(t *testing.T, h *harness, got MintedKeyResponse) {
				if want := testNow.Add(time.Hour); !got.Key.ExpiresAt.Equal(want) {
					t.Errorf("ExpiresAt = %s, want %s", got.Key.ExpiresAt, want)
				}
			},
		},
		{
			name:       "ttl above the configured maximum is refused not clamped",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "long", Scope: validScope(), TTL: fleet.Duration(10000 * time.Hour)},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "negative ttl",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "neg", Scope: validScope(), TTL: fleet.Duration(-time.Hour)},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "unknown class",
			body:       CreateKeyRequest{Class: "root", Name: "nope"},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "enrollment class is routed elsewhere",
			body:       CreateKeyRequest{Class: fleet.ClassEnrollment, Name: "nope"},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "missing name",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "  ", Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "name with a control character",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "line\nbreak", Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "over-long name",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: strings.Repeat("n", MaxNameBytes+1), Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "over-long owner",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "ok", Owner: strings.Repeat("o", MaxOwnerBytes+1), Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "owner with a control character",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "ok", Owner: "a\x00b", Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "agent key without a scope",
			body:       CreateKeyRequest{Class: fleet.ClassAgent, Name: "unscoped"},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name: "agent key asking for the admin role",
			body: CreateKeyRequest{Class: fleet.ClassAgent, Name: "escalate", Scope: &fleet.Scope{
				Role:     fleet.RoleAdmin,
				Clusters: fleet.ClusterScope{Allow: []string{"*"}},
				Tools:    fleet.ToolScope{Allow: []string{"*"}},
			}},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
		{
			name:       "admin key carrying a scope",
			body:       CreateKeyRequest{Class: fleet.ClassAdmin, Name: "scoped-admin", Scope: validScope()},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeInvalidRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			resp := h.adminDo(http.MethodPost, "/admin/v1/keys", tc.body)
			if resp.StatusCode != tc.wantStatus {
				body := decode(t, resp, nil)
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus != http.StatusCreated {
				env := envelopeOf(t, resp)
				if env.Error.Code != tc.wantCode {
					t.Errorf("error code = %q, want %q", env.Error.Code, tc.wantCode)
				}
				return
			}
			var got MintedKeyResponse
			raw := decode(t, resp, &got)
			if got.Token == "" {
				t.Fatal("no token returned")
			}
			assertNoSecretMaterial(t, h, raw)
			if tc.check != nil {
				tc.check(t, h, got)
			}
		})
	}
}

func TestCreateKeyRejectsBadBodies(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	tests := []struct {
		name       string
		raw        string
		wantStatus int
		wantCode   string
	}{
		{name: "not json", raw: "{", wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{name: "unknown field", raw: `{"class":"agt","name":"x","surprise":1}`, wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{name: "two documents", raw: `{"class":"agt","name":"x"}{"class":"adm"}`, wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{name: "bad ttl", raw: `{"class":"agt","name":"x","ttl":"forever"}`, wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{
			name:       "oversize body",
			raw:        `{"class":"agt","name":"` + strings.Repeat("x", MaxBodyBytes+16) + `"}`,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantCode:   CodePayloadTooLarge,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := h.doRaw(h.admin, http.MethodPost, "/admin/v1/keys", h.adminToken, tc.raw)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if env := envelopeOf(t, resp); env.Error.Code != tc.wantCode {
				t.Errorf("error code = %q, want %q", env.Error.Code, tc.wantCode)
			}
		})
	}
}

func TestListAndGetKeys(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	var created MintedKeyResponse
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "listed", Scope: validScope()})
	decode(t, resp, &created)

	t.Run("list all", func(t *testing.T) {
		var list KeyListResponse
		raw := decode(t, h.adminDo(http.MethodGet, "/admin/v1/keys", nil), &list)
		if list.Count != len(list.Keys) || list.Count < 3 {
			t.Fatalf("count = %d, keys = %d, want at least 3 and equal", list.Count, len(list.Keys))
		}
		assertNoSecretMaterial(t, h, raw)
	})

	t.Run("filter by class", func(t *testing.T) {
		var list KeyListResponse
		decode(t, h.adminDo(http.MethodGet, "/admin/v1/keys?class=adm", nil), &list)
		for _, k := range list.Keys {
			if k.Class != fleet.ClassAdmin {
				t.Errorf("class filter returned a %q key", k.Class)
			}
		}
	})

	t.Run("invalid class filter", func(t *testing.T) {
		resp := h.adminDo(http.MethodGet, "/admin/v1/keys?class=root", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		if env := envelopeOf(t, resp); env.Error.Code != CodeInvalidRequest {
			t.Errorf("code = %q, want %q", env.Error.Code, CodeInvalidRequest)
		}
	})

	t.Run("get one", func(t *testing.T) {
		var view KeyView
		raw := decode(t, h.adminDo(http.MethodGet, "/admin/v1/keys/"+created.Key.KID, nil), &view)
		if diff := cmp.Diff(created.Key, view); diff != "" {
			t.Errorf("record changed between mint and read (-mint +read):\n%s", diff)
		}
		assertNoSecretMaterial(t, h, raw)
	})

	t.Run("get missing", func(t *testing.T) {
		resp := h.adminDo(http.MethodGet, "/admin/v1/keys/aaaaaaaaaa", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
		if env := envelopeOf(t, resp); env.Error.Code != CodeNotFound {
			t.Errorf("code = %q, want %q", env.Error.Code, CodeNotFound)
		}
	})

	t.Run("malformed kid", func(t *testing.T) {
		resp := h.adminDo(http.MethodGet, "/admin/v1/keys/not-a-kid", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("unrouted admin path", func(t *testing.T) {
		resp := h.adminDo(http.MethodGet, "/admin/v1/nonsense", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
		if env := envelopeOf(t, resp); env.Error.Code != CodeNotFound {
			t.Errorf("code = %q, want %q", env.Error.Code, CodeNotFound)
		}
	})
}

func TestRevokeKey(t *testing.T) {
	t.Parallel()

	t.Run("revocation takes effect immediately", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAdmin, Name: "doomed"}), &created)

		// Prove it works before revocation, so the epoch cache is warm.
		if resp := h.do(h.admin, http.MethodGet, "/admin/v1/keys", created.Token, nil); resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("fresh key status = %d, want 200", resp.StatusCode)
		} else {
			resp.Body.Close()
		}

		resp := h.adminDo(http.MethodDelete, "/admin/v1/keys/"+created.Key.KID+"?reason=compromised", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
		stored, _ := h.store.get(created.Key.KID)
		if stored.RevokedAt == nil || stored.RevokedReason != "compromised" {
			t.Fatalf("record not revoked with a reason: %+v", stored)
		}
		// The revocation bumped the epoch, so the verifier's cached decision
		// is invalidated at once rather than at the end of its TTL.
		after := h.do(h.admin, http.MethodGet, "/admin/v1/keys", created.Token, nil)
		after.Body.Close()
		if after.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked key still authenticated: status %d", after.StatusCode)
		}
		if h.metrics.securityEvents(EventKeyRevoked) != 1 {
			t.Error("no key.revoked security event")
		}
	})

	t.Run("reason is required", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAgent, Name: "x", Scope: validScope()}), &created)
		resp := h.adminDo(http.MethodDelete, "/admin/v1/keys/"+created.Key.KID, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("purge deletes the record", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAgent, Name: "x", Scope: validScope()}), &created)
		resp := h.adminDo(http.MethodDelete, "/admin/v1/keys/"+created.Key.KID+"?reason=gdpr&purge=true", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
		if _, ok := h.store.get(created.Key.KID); ok {
			t.Error("purge left the record behind")
		}
		if h.metrics.securityEvents(EventKeyDeleted) != 1 {
			t.Error("no key.deleted security event")
		}
	})

	t.Run("invalid purge value", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		resp := h.adminDo(http.MethodDelete, "/admin/v1/keys/aaaaaaaaaa?reason=x&purge=maybe", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, nil)
		resp := h.adminDo(http.MethodDelete, "/admin/v1/keys/aaaaaaaaaa?reason=x", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})
}

func TestRotateKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	var original MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "rotating", Owner: "team", Scope: validScope()}), &original)

	var rotated MintedKeyResponse
	raw := decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys/"+original.Key.KID+"/rotate",
		rotateRequest{Reason: "quarterly rotation"}), &rotated)
	assertNoSecretMaterial(t, h, raw)

	if rotated.Key.KID == original.Key.KID {
		t.Fatal("rotation reused the key identifier")
	}
	if rotated.Token == original.Token {
		t.Fatal("rotation reused the token")
	}
	if diff := cmp.Diff(original.Key.Scope, rotated.Key.Scope); diff != "" {
		t.Errorf("rotation changed the scope (-old +new):\n%s", diff)
	}
	if rotated.Key.Name != original.Key.Name || rotated.Key.Owner != original.Key.Owner {
		t.Error("rotation changed the identity metadata")
	}
	old, _ := h.store.get(original.Key.KID)
	if old.RevokedAt == nil {
		t.Fatal("the original key was not revoked")
	}
	if !strings.Contains(old.RevokedReason, rotated.Key.KID) {
		t.Errorf("revocation reason %q does not name the replacement", old.RevokedReason)
	}
	if h.metrics.securityEvents(EventKeyRotated) != 1 {
		t.Error("no key.rotated security event")
	}
}

func TestRotateKeyEdgeCases(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	t.Run("enrollment token cannot be rotated", func(t *testing.T) {
		kid := h.mintEnrollment("prod-eu")
		resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+kid+"/rotate", nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		resp := h.adminDo(http.MethodPost, "/admin/v1/keys/aaaaaaaaaa/rotate", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})

	t.Run("ttl above the maximum", func(t *testing.T) {
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAdmin, Name: "adm"}), &created)
		resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate",
			rotateRequest{TTL: fleet.Duration(100000 * time.Hour)})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("blank reason", func(t *testing.T) {
		var created MintedKeyResponse
		decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
			CreateKeyRequest{Class: fleet.ClassAdmin, Name: "adm2"}), &created)
		resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+created.Key.KID+"/rotate",
			rotateRequest{Reason: "   "})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})
}

// TestRotateKeyUsesTheCeilingForItsOwnClass proves rotation reads the maximum
// lifetime from the class of the credential being rotated.
//
// The existing ceiling test asks for a TTL far above both maxima, which passes
// whichever ceiling is consulted. A TTL between the two is what separates
// them: swapping the classes would either cap an admin rotation at the agent
// maximum, quietly shortening the highest-value credential in the system, or
// let an agent rotation mint itself the ninety-day admin lifetime.
func TestRotateKeyUsesTheCeilingForItsOwnClass(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)

	// Between DefaultAgentKeyTTL (30 days) and DefaultAdminKeyTTL (90 days).
	between := fleet.Duration(60 * 24 * time.Hour)
	if time.Duration(between) <= DefaultAgentKeyTTL || time.Duration(between) >= DefaultAdminKeyTTL {
		t.Fatalf("the chosen TTL %s no longer sits between the two ceilings", time.Duration(between))
	}

	var admin MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAdmin, Name: "admin-rotate"}), &admin)
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys/"+admin.Key.KID+"/rotate",
		rotateRequest{TTL: between})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("rotating an admin key to %s = %d, want %d: the admin ceiling allows it",
			time.Duration(between), resp.StatusCode, http.StatusCreated)
	}

	var agent MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "agent-rotate", Scope: validScope()}), &agent)
	resp = h.adminDo(http.MethodPost, "/admin/v1/keys/"+agent.Key.KID+"/rotate",
		rotateRequest{TTL: between})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("rotating an agent key to %s = %d, want %d: the agent ceiling refuses it",
			time.Duration(between), resp.StatusCode, http.StatusBadRequest)
	}
}

func TestEnrollmentAdminRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       any
		wantStatus int
	}{
		{
			name:       "valid",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu-1", Labels: map[string]string{"env": "prod"}},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "uppercase cluster id",
			body:       CreateEnrollmentRequest{ClusterID: "Prod-EU"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "cluster id with a path separator",
			body:       CreateEnrollmentRequest{ClusterID: "prod/../admin"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty cluster id",
			body:       CreateEnrollmentRequest{ClusterID: ""},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "over-long cluster id",
			body:       CreateEnrollmentRequest{ClusterID: strings.Repeat("a", 64)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "too many labels",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Labels: manyLabels(MaxLabels + 1)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid label key",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Labels: map[string]string{"bad key": "v"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "over-long label value",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Labels: map[string]string{"env": strings.Repeat("v", MaxLabelValueBytes+1)}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "label value with a control character",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Labels: map[string]string{"env": "a\nb"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "name with a control character",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Name: "a\tb"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "over-long owner",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", Owner: strings.Repeat("o", MaxOwnerBytes+1)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ttl above the maximum",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", TTL: fleet.Duration(time.Hour)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "negative maxRedemptions",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", MaxRedemptions: -1},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "maxRedemptions without reusable",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu", MaxRedemptions: 5},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "reusable with zero maxRedemptions is fine: zero means no cap",
			body:       CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			resp := h.adminDo(http.MethodPost, "/admin/v1/enrollments", tc.body)
			if resp.StatusCode != tc.wantStatus {
				body := decode(t, resp, nil)
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus != http.StatusCreated {
				return
			}
			var got MintedKeyResponse
			raw := decode(t, resp, &got)
			assertNoSecretMaterial(t, h, raw)
			if got.Key.Enrollment == nil || got.Key.Enrollment.ClusterID != "prod-eu-1" {
				t.Fatalf("enrollment grant = %+v, want a binding to prod-eu-1", got.Key.Enrollment)
			}
			if class, _, _, err := token.Parse(got.Token); err != nil || class != fleet.ClassEnrollment {
				t.Errorf("minted token class = %q (err %v), want %q", class, err, fleet.ClassEnrollment)
			}
			if h.metrics.securityEvents(EventEnrollmentMinted) != 1 {
				t.Error("no enrollment.minted security event")
			}
		})
	}
}

func TestListAndRevokeEnrollments(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	kid := h.mintEnrollment("prod-eu")

	var list KeyListResponse
	raw := decode(t, h.adminDo(http.MethodGet, "/admin/v1/enrollments", nil), &list)
	assertNoSecretMaterial(t, h, raw)
	if list.Count != 1 || list.Keys[0].KID != kid {
		t.Fatalf("enrollment list = %+v, want exactly the one token", list)
	}

	resp := h.adminDo(http.MethodDelete, "/admin/v1/enrollments/"+kid, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	stored, _ := h.store.get(kid)
	if stored.RevokedAt == nil {
		t.Error("the enrollment token was not revoked")
	}
	// The security event has to name the cluster the token was bound to. It is
	// the only field that ties the revocation to what was actually closed off,
	// and the audit trail is the reason the event exists.
	if !strings.Contains(h.logs.String(), `"cluster":"prod-eu"`) {
		t.Errorf("the %s event did not name the cluster: %s", EventKeyRevoked, h.logs.String())
	}

	// An agent key id must not be reachable through the enrollment route: it
	// would let one route confirm the existence of a key in another class.
	var agent MintedKeyResponse
	decode(t, h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "a", Scope: validScope()}), &agent)
	wrong := h.adminDo(http.MethodDelete, "/admin/v1/enrollments/"+agent.Key.KID, nil)
	if wrong.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d for a key of the wrong class", wrong.StatusCode, http.StatusNotFound)
	}
	wrong.Body.Close()

	blank := h.adminDo(http.MethodDelete, "/admin/v1/enrollments/"+kid+"?reason=%20", nil)
	if blank.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for a blank reason", blank.StatusCode, http.StatusBadRequest)
	}
	blank.Body.Close()
}

func TestCertRevocationRoutes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	serial := hex.EncodeToString([]byte{0x0a, 0x1b, 0x2c})

	t.Run("revoke", func(t *testing.T) {
		resp := h.adminDo(http.MethodPost, "/admin/v1/certs/"+serial+"/revoke",
			RevokeCertRequest{Reason: "spoke decommissioned"})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
		if h.metrics.securityEvents(EventCertRevoked) != 1 {
			t.Error("no cert.revoked security event")
		}
	})

	t.Run("list", func(t *testing.T) {
		var list RevokedCertListResponse
		decode(t, h.adminDo(http.MethodGet, "/admin/v1/certs/revoked", nil), &list)
		if list.Count != 1 || list.Revoked[0].Serial != serial {
			t.Fatalf("revoked list = %+v, want one entry for %s", list, serial)
		}
		if list.Revoked[0].NotAfter.IsZero() {
			t.Error("NotAfter was not defaulted")
		}
	})

	t.Run("explicit notAfter is preserved", func(t *testing.T) {
		want := testNow.Add(48 * time.Hour)
		resp := h.adminDo(http.MethodPost, "/admin/v1/certs/ff00/revoke",
			RevokeCertRequest{Reason: "rotated", NotAfter: want})
		resp.Body.Close()
		var list RevokedCertListResponse
		decode(t, h.adminDo(http.MethodGet, "/admin/v1/certs/revoked", nil), &list)
		for _, rc := range list.Revoked {
			if rc.Serial == "ff00" && !rc.NotAfter.Equal(want) {
				t.Errorf("NotAfter = %s, want %s", rc.NotAfter, want)
			}
		}
	})

	t.Run("bad serial", func(t *testing.T) {
		resp := h.adminDo(http.MethodPost, "/admin/v1/certs/NOTHEX/revoke", RevokeCertRequest{Reason: "x"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		resp.Body.Close()
	})

	t.Run("missing reason", func(t *testing.T) {
		resp := h.adminDo(http.MethodPost, "/admin/v1/certs/"+serial+"/revoke", RevokeCertRequest{})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		resp.Body.Close()
	})
}

func TestAdminCABundle(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	var got CABundleResponse
	raw := decode(t, h.adminDo(http.MethodGet, "/admin/v1/ca", nil), &got)
	if !strings.Contains(got.CABundle, "BEGIN CERTIFICATE") {
		t.Fatalf("bundle is not PEM: %q", got.CABundle)
	}
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("the response contains a private key")
	}
	if got.TrustDomain != h.ca.TrustDomain() {
		t.Errorf("TrustDomain = %q, want %q", got.TrustDomain, h.ca.TrustDomain())
	}
	if !got.NotAfter.Equal(h.ca.NotAfter()) {
		t.Errorf("NotAfter = %s, want %s", got.NotAfter, h.ca.NotAfter())
	}
}

func TestDrainingRefusesMutations(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.setDraining(true)

	mutations := []struct{ method, path string }{
		{http.MethodPost, "/admin/v1/keys"},
		{http.MethodDelete, "/admin/v1/keys/aaaaaaaaaa?reason=x"},
		{http.MethodPost, "/admin/v1/keys/aaaaaaaaaa/rotate"},
		{http.MethodPost, "/admin/v1/enrollments"},
		{http.MethodDelete, "/admin/v1/enrollments/aaaaaaaaaa?reason=x"},
		{http.MethodPost, "/admin/v1/certs/0a/revoke"},
	}
	for _, m := range mutations {
		t.Run(m.method+" "+m.path, func(t *testing.T) {
			resp := h.adminDo(m.method, m.path, nil)
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
			}
			if env := envelopeOf(t, resp); env.Error.Code != CodeUnavailable {
				t.Errorf("code = %q, want %q", env.Error.Code, CodeUnavailable)
			}
		})
	}

	t.Run("reads still work", func(t *testing.T) {
		resp := h.adminDo(http.MethodGet, "/admin/v1/keys", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestStoreFailuresBecomeGenericInternalErrors(t *testing.T) {
	t.Parallel()
	boom := errors.New("secret 4f2a is unreadable by service account hub")

	tests := []struct {
		name   string
		inject func(*fakeStore)
		method string
		path   string
		body   any
	}{
		{
			name:   "put",
			inject: func(f *fakeStore) { f.errPut = boom },
			method: http.MethodPost, path: "/admin/v1/keys",
			body: CreateKeyRequest{Class: fleet.ClassAgent, Name: "x", Scope: validScope()},
		},
		{
			name:   "list",
			inject: func(f *fakeStore) { f.errList = boom },
			method: http.MethodGet, path: "/admin/v1/keys",
		},
		{
			name:   "list enrollments",
			inject: func(f *fakeStore) { f.errList = boom },
			method: http.MethodGet, path: "/admin/v1/enrollments",
		},
		{
			name:   "list revoked",
			inject: func(f *fakeStore) { f.errListRevoked = boom },
			method: http.MethodGet, path: "/admin/v1/certs/revoked",
		},
		{
			name:   "revoke cert",
			inject: func(f *fakeStore) { f.errRevokeCert = boom },
			method: http.MethodPost, path: "/admin/v1/certs/0a/revoke",
			body: RevokeCertRequest{Reason: "x"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			h.store.inject(t, tc.inject)
			resp := h.adminDo(tc.method, tc.path, tc.body)
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
			}
			env := envelopeOf(t, resp)
			if env.Error.Code != CodeInternal {
				t.Errorf("code = %q, want %q", env.Error.Code, CodeInternal)
			}
			if strings.Contains(env.Error.Message, "4f2a") || strings.Contains(env.Error.Message, "service account") {
				t.Errorf("the internal error leaked into the response: %q", env.Error.Message)
			}
			if !strings.Contains(h.logs.String(), "4f2a") {
				t.Error("the internal error was not logged")
			}
		})
	}
}

func TestKeyIdentifierCollisionIsRetried(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	h.store.inject(t, func(f *fakeStore) { f.putConflictOnce = true })

	var got MintedKeyResponse
	resp := h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "retried", Scope: validScope()})
	if resp.StatusCode != http.StatusCreated {
		body := decode(t, resp, nil)
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, http.StatusCreated, body)
	}
	decode(t, resp, &got)
	if got.Token == "" {
		t.Error("the retry did not produce a token")
	}
}

func TestSecurityEventsNameTheActingPrincipal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	adminKID := kidOf(t, h.adminToken)

	resp := h.adminDo(http.MethodPost, "/admin/v1/keys",
		CreateKeyRequest{Class: fleet.ClassAgent, Name: "audited", Scope: validScope()})
	resp.Body.Close()

	logs := h.logs.String()
	if !strings.Contains(logs, `"event":"`+EventKeyMinted+`"`) {
		t.Fatalf("no key.minted security event in the log: %s", logs)
	}
	if !strings.Contains(logs, adminKID) {
		t.Errorf("the security event does not name the acting principal %q", adminKID)
	}
	if strings.Contains(logs, h.adminToken) {
		t.Error("the acting principal's token reached the log")
	}
}

// manyLabels builds a label map with n entries.
func manyLabels(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m["k"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	return m
}

// kidOf extracts the public key identifier from a raw token.
func kidOf(t *testing.T, raw string) string {
	t.Helper()
	_, kid, _, err := token.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return kid
}
