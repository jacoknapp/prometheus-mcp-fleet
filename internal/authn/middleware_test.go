// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// echoPrincipal is the protected handler: it reports the principal the
// middleware installed, so a test can prove the context was populated.
func echoPrincipal(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"kid": p.KID, "class": string(p.Class)})
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func(t *testing.T, f *fakeStore, h *token.Hasher, c *fakeClock) string
		authHeader func(raw string) string
		want       fleet.KeyClass
		wantStatus int
		wantCode   string
	}{
		{
			name: "valid agent key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) string {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw
			},
			want:       fleet.ClassAgent,
			wantStatus: http.StatusOK,
		},
		{
			name:       "no authorization header",
			setup:      func(*testing.T, *fakeStore, *token.Hasher, *fakeClock) string { return "" },
			authHeader: func(string) string { return "" },
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name:       "not a bearer scheme",
			setup:      func(*testing.T, *fakeStore, *token.Hasher, *fakeClock) string { return "" },
			authHeader: func(string) string { return "Basic dXNlcjpwYXNz" },
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name:       "bearer with no credential",
			setup:      func(*testing.T, *fakeStore, *token.Hasher, *fakeClock) string { return "" },
			authHeader: func(string) string { return "Bearer" },
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name:       "garbage credential",
			setup:      func(*testing.T, *fakeStore, *token.Hasher, *fakeClock) string { return "not-a-token" },
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name: "agent key on the admin listener",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) string {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, nil)
				return raw
			},
			want:       fleet.ClassAdmin,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name: "revoked key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, _ *fakeClock) string {
				raw, key := mintKey(t, f, h, fleet.ClassAgent, nil)
				at := testNow
				f.mutate(key.KID, func(k *fleet.Key) { k.RevokedAt = &at })
				return raw
			},
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
		{
			name: "expired key",
			setup: func(t *testing.T, f *fakeStore, h *token.Hasher, c *fakeClock) string {
				raw, _ := mintKey(t, f, h, fleet.ClassAgent, func(k *fleet.Key) {
					k.ExpiresAt = testNow.Add(time.Second)
				})
				c.advance(time.Minute)
				return raw
			},
			want:       fleet.ClassAgent,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthenticated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, store, _, clock := newTestVerifier(t, func(o *Options) {
				o.ResourceMetadataURL = "https://hub.example/.well-known/oauth-protected-resource/mcp"
			})
			raw := tc.setup(t, store, v.hasher, clock)

			srv := httptest.NewServer(v.Middleware(tc.want)(http.HandlerFunc(echoPrincipal)))
			t.Cleanup(srv.Close)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			header := "Bearer " + raw
			if tc.authHeader != nil {
				header = tc.authHeader(raw)
			}
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			body := readAll(t, resp.Body)
			if raw != "" && strings.Contains(body, raw) {
				t.Error("the response body echoes the presented credential")
			}
			if tc.wantStatus == http.StatusOK {
				if !strings.Contains(body, `"class":"`+string(tc.want)+`"`) {
					t.Errorf("handler did not see the principal: %s", body)
				}
				return
			}

			challenge := resp.Header.Get("WWW-Authenticate")
			for _, want := range []string{`realm="prometheus-mcp-fleet"`, `scope="` + ScopeName(tc.want) + `"`,
				`resource_metadata="https://hub.example/.well-known/oauth-protected-resource/mcp"`,
				`error="invalid_token"`} {
				if !strings.Contains(challenge, want) {
					t.Errorf("WWW-Authenticate = %q, want it to contain %q", challenge, want)
				}
			}
			if raw != "" && strings.Contains(challenge, raw) {
				t.Error("the challenge echoes the presented credential")
			}
			var env struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(body), &env); err != nil {
				t.Fatalf("decode error envelope %q: %v", body, err)
			}
			if env.Error.Code != tc.wantCode {
				t.Errorf("error code = %q, want %q", env.Error.Code, tc.wantCode)
			}
		})
	}
}

func TestMiddlewareRateLimitAnswers429(t *testing.T) {
	t.Parallel()
	v, _, _, _ := newTestVerifier(t, nil)
	handler := v.Middleware(fleet.ClassAgent)(http.HandlerFunc(echoPrincipal))

	var last *httptest.ResponseRecorder
	for range failureBurst + 3 {
		m, err := token.Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.RemoteAddr = "192.0.2.55:41000"
		req.Header.Set("Authorization", "Bearer "+m.Raw.Reveal())
		last = httptest.NewRecorder()
		handler.ServeHTTP(last, req)
		if last.Code == http.StatusTooManyRequests {
			break
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d after exceeding the failure burst", last.Code, http.StatusTooManyRequests)
	}
	if got := last.Header().Get("WWW-Authenticate"); strings.Contains(got, "error=") {
		t.Errorf("a 429 must not claim an invalid token: %q", got)
	}
}

func TestMiddlewareUsesTheRequestID(t *testing.T) {
	t.Parallel()
	v, _, _, _ := newTestVerifier(t, nil)
	inner := v.Middleware(fleet.ClassAgent)(http.HandlerFunc(echoPrincipal))
	// The request-id middleware stamps the response before authentication runs.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(RequestIDHeader, "req-from-response")
		inner.ServeHTTP(w, r)
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if !strings.Contains(rec.Body.String(), "req-from-response") {
		t.Errorf("error envelope did not carry the response request id: %s", rec.Body.String())
	}

	// Falling back to the client-supplied header keeps the correlation working
	// when no middleware stamped one.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(RequestIDHeader, "req-from-request")
	inner.ServeHTTP(rec2, req)
	if !strings.Contains(rec2.Body.String(), "req-from-request") {
		t.Errorf("error envelope did not fall back to the request header: %s", rec2.Body.String())
	}
}

func TestTokenVerifier(t *testing.T) {
	t.Parallel()
	v, store, _, clock := newTestVerifier(t, nil)
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	tv := v.TokenVerifier(fleet.ClassAgent)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.RemoteAddr = "198.51.100.7:5555"
	info, err := tv(context.Background(), raw, req)
	if err != nil {
		t.Fatalf("TokenVerifier: %v", err)
	}
	if info.UserID != key.KID {
		t.Errorf("UserID = %q, want %q", info.UserID, key.KID)
	}
	if !info.Expiration.Equal(key.ExpiresAt) {
		t.Errorf("Expiration = %s, want %s", info.Expiration, key.ExpiresAt)
	}
	if got := info.Extra["class"]; got != string(fleet.ClassAgent) {
		t.Errorf("Extra[class] = %v, want %q", got, fleet.ClassAgent)
	}
	if len(info.Scopes) == 0 {
		t.Error("TokenInfo carries no scopes")
	}

	// Failures must unwrap to the SDK's sentinel so its middleware answers 401
	// rather than 500, and must still expose this package's own sentinel.
	if _, err := tv(context.Background(), "garbage", req); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("error = %v, want it to wrap auth.ErrInvalidToken", err)
	} else if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("error = %v, want it to also wrap %v", err, ErrUnauthenticated)
	}

	// A nil request is legal: the SDK does not always have one.
	if _, err := tv(context.Background(), raw, nil); err != nil {
		t.Fatalf("TokenVerifier with a nil request: %v", err)
	}

	// A credential with no stored expiry still gets a usable horizon, because
	// the SDK middleware rejects a TokenInfo without one.
	rawNoExp, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, func(k *fleet.Key) { k.ExpiresAt = time.Time{} })
	info, err = tv(context.Background(), rawNoExp, req)
	if err != nil {
		t.Fatalf("TokenVerifier: %v", err)
	}
	if want := clock.Now().Add(v.cacheTTL); !info.Expiration.Equal(want) {
		t.Errorf("Expiration = %s, want %s", info.Expiration, want)
	}
}

func TestTokenVerifierWorksWithSDKMiddleware(t *testing.T) {
	t.Parallel()
	// The SDK middleware compares the advertised expiry against the wall
	// clock, so this test runs on the real one.
	v, store, _, _ := newTestVerifier(t, func(o *Options) { o.Clock = time.Now })
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, func(k *fleet.Key) {
		k.ExpiresAt = time.Now().Add(time.Hour)
	})

	handler := auth.RequireBearerToken(v.TokenVerifier(fleet.ClassAgent), &auth.RequireBearerTokenOptions{})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.TokenInfoFromContext(r.Context()) == nil {
				t.Error("the SDK did not install TokenInfo")
			}
			w.WriteHeader(http.StatusNoContent)
		}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	rec = httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	bad.Header.Set("Authorization", "Bearer nonsense")
	handler.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{name: "absent", header: "", wantOK: false},
		{name: "lowercase scheme", header: "bearer abc", want: "abc", wantOK: true},
		{name: "mixed case scheme", header: "BeArEr abc", want: "abc", wantOK: true},
		{name: "extra fields", header: "Bearer abc def", wantOK: false},
		{name: "wrong scheme", header: "Token abc", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got, ok := BearerToken(r)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("BearerToken() = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestSourceAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, remote, want string
	}{
		{name: "host and port", remote: "192.0.2.10:1234", want: "192.0.2.10"},
		{name: "ipv6", remote: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "no port", remote: "unix", want: "unix"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if got := SourceAddr(r); got != tc.want {
				t.Errorf("SourceAddr(%q) = %q, want %q", tc.remote, got, tc.want)
			}
		})
	}
}

func TestMiddlewareForwardedHeadersAreIgnored(t *testing.T) {
	t.Parallel()
	v, _, _, _ := newTestVerifier(t, nil)
	handler := v.Middleware(fleet.ClassAgent)(http.HandlerFunc(echoPrincipal))

	// Every request comes from the same peer but claims a different
	// forwarded-for address. Honouring the header would give each a fresh
	// budget and defeat the limiter entirely.
	var limited bool
	for i := range failureBurst * 2 {
		m, err := token.Mint(fleet.ClassAgent)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.RemoteAddr = "192.0.2.77:9000"
		req.Header.Set("X-Forwarded-For", "10.0.0."+string(rune('0'+i%10)))
		req.Header.Set("Authorization", "Bearer "+m.Raw.Reveal())
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("spoofed forwarded-for headers evaded the per-source limiter")
	}
}

func TestMiddlewareLogsNoCredential(t *testing.T) {
	t.Parallel()
	var buf syncBuffer
	v, store, _, _ := newTestVerifier(t, func(o *Options) {
		o.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	raw, key := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	at := testNow
	store.mutate(key.KID, func(k *fleet.Key) { k.RevokedAt = &at })

	handler := v.Middleware(fleet.ClassAgent)(http.HandlerFunc(echoPrincipal))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	handler.ServeHTTP(rec, req)

	if got := buf.String(); strings.Contains(got, raw) || strings.Contains(got, "Authorization") {
		t.Errorf("the log captured credential material: %s", got)
	}
}

// readAll drains a response body into a string.
func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
