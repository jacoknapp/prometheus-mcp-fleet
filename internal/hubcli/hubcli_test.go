// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
)

// --- test doubles ----------------------------------------------------------

// fakeDoer implements Doer with a plain function, so a test drives the
// request/response exchange without opening a socket. It is the hand-written
// substitute for a mock library.
type fakeDoer struct {
	do func(*http.Request) (*http.Response, error)
}

func (f fakeDoer) Do(r *http.Request) (*http.Response, error) { return f.do(r) }

// jsonResponse builds a 2xx (or any status) response carrying body as JSON.
func jsonResponse(status int, body any) *http.Response {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(bytes.NewReader(raw)),
		Header:     make(http.Header),
	}
}

// rawResponse builds a response carrying an arbitrary, non-JSON body.
func rawResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// capture records the single request a fakeDoer received, decoded body
// included, so a test can assert on what was actually sent.
type capture struct {
	req  *http.Request
	body []byte
}

// capturingDoer returns a Doer that records the request it receives and then
// answers with resp.
func capturingDoer(resp *http.Response) (Doer, *capture) {
	c := &capture{}
	return fakeDoer{do: func(r *http.Request) (*http.Response, error) {
		c.req = r
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			c.body = b
		}
		return resp, nil
	}}, c
}

// env builds a getenv function over a map, so a test never touches the
// process environment.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// decodeEnrollmentBody decodes a captured request body as the enrollment
// request it must be.
func decodeEnrollmentBody(t *testing.T, c *capture) hubapi.CreateEnrollmentRequest {
	t.Helper()
	var got hubapi.CreateEnrollmentRequest
	if err := json.Unmarshal(c.body, &got); err != nil {
		t.Fatalf("decode request body: %v (body: %s)", err, c.body)
	}
	return got
}

// decodeKeyBody decodes a captured request body as the key request it must
// be.
func decodeKeyBody(t *testing.T, c *capture) hubapi.CreateKeyRequest {
	t.Helper()
	var got hubapi.CreateKeyRequest
	if err := json.Unmarshal(c.body, &got); err != nil {
		t.Fatalf("decode request body: %v (body: %s)", err, c.body)
	}
	return got
}

// wantMinted is a fixture minted-key response with an enrollment grant, used
// by every test that just needs a plausible 201 body.
func wantMinted() hubapi.MintedKeyResponse {
	return hubapi.MintedKeyResponse{
		Token: "pmf_enr_abcdef0123456789",
		Key: hubapi.KeyView{
			KID:       "enrol0001",
			Class:     fleet.ClassEnrollment,
			Name:      "enroll:prod-eu-1",
			ExpiresAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
			Enrollment: &hubapi.EnrollmentView{
				ClusterID: "prod-eu-1",
				Labels:    map[string]string{"zone": "eu-west-1", "env": "prod"},
			},
		},
		TokenShownOnce: true,
		Warning:        hubapi.TokenOnceNotice,
	}
}

// --- Run: usage and dispatch ------------------------------------------------

func TestRunUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"one arg", []string{"enroll"}},
		{"unknown first word", []string{"nope", "create"}},
		{"unknown second word", []string{"enroll", "update"}},
		{"unknown pair entirely", []string{"foo", "bar"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			err := Run(context.Background(), tc.args, env(nil), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("an unroutable command reached the HTTP client")
					return nil, nil
				},
			})
			if !errors.Is(err, ErrUsage) {
				t.Fatalf("Run(%v) error = %v, want ErrUsage", tc.args, err)
			}
		})
	}
}

// TestRunDispatchesToSubcommands proves "enroll create" and "keys create"
// reach their own flag sets and not each other's, by checking each fails on
// the other subcommand's required flag rather than its own.
func TestRunDispatchesToSubcommands(t *testing.T) {
	t.Parallel()

	t.Run("enroll create reaches enrollCreate", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create"}, env(nil), &stdout, fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				t.Fatal("validation failure still reached the network")
				return nil, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "--cluster is required") {
			t.Fatalf("Run(enroll create) error = %v, want a --cluster complaint", err)
		}
	})

	t.Run("keys create reaches keysCreate", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"keys", "create"}, env(nil), &stdout, fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				t.Fatal("validation failure still reached the network")
				return nil, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "--name is required") {
			t.Fatalf("Run(keys create) error = %v, want a --name complaint", err)
		}
	})
}

// TestRunDefaultsClientWhenNil proves passing a nil Doer does not panic: Run
// must construct its own *http.Client. The case never reaches the network
// because the flags given are invalid, so this cannot flake against a real
// listener.
func TestRunDefaultsClientWhenNil(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	err := Run(context.Background(), []string{"enroll", "create"}, env(nil), &stdout, nil)
	if err == nil || !strings.Contains(err.Error(), "--cluster is required") {
		t.Fatalf("Run() with a nil client, error = %v, want a --cluster complaint", err)
	}
}

// TestFlagParseErrorsAreReturned proves an unrecognized flag surfaces as an
// error from Run rather than being swallowed, for both subcommands. flag's
// own ContinueOnError already guarantees this; the point of the test is
// pinning that this package's "if err := fs.Parse(args); err != nil { return
// err }" line actually runs, since nothing else in this file supplies a flag
// flag.Parse itself rejects.
func TestFlagParseErrorsAreReturned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"enroll create", []string{"enroll", "create", "--this-flag-does-not-exist"}},
		{"keys create", []string{"keys", "create", "--this-flag-does-not-exist"}},
		{"keys list", []string{"keys", "list", "--this-flag-does-not-exist"}},
		{"keys revoke", []string{"keys", "revoke", "--this-flag-does-not-exist"}},
		{"keys rotate", []string{"keys", "rotate", "--this-flag-does-not-exist"}},
		{"enroll list", []string{"enroll", "list", "--this-flag-does-not-exist"}},
		{"enroll revoke", []string{"enroll", "revoke", "--this-flag-does-not-exist"}},
		{"certs revoke", []string{"certs", "revoke", "--this-flag-does-not-exist"}},
		{"certs list", []string{"certs", "list", "--this-flag-does-not-exist"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			err := Run(context.Background(), tc.args, env(nil), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("an unparseable flag set still reached the network")
					return nil, nil
				},
			})
			if err == nil {
				t.Fatal("Run() error = nil, want the flag parse error")
			}
		})
	}
}

// --- enroll create: validation ---------------------------------------------

func TestEnrollCreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		kv      map[string]string
		wantErr string
	}{
		{
			name:    "missing cluster",
			args:    nil,
			wantErr: "--cluster is required",
		},
		{
			name:    "labels missing equals",
			args:    []string{"--cluster=prod-eu-1", "--labels=env"},
			wantErr: `label "env" is not k=v`,
		},
		{
			name:    "labels with an empty key",
			args:    []string{"--cluster=prod-eu-1", "--labels==prod"},
			wantErr: `label "=prod" is not k=v`,
		},
		{
			name:    "no admin token anywhere",
			args:    []string{"--cluster=prod-eu-1"},
			kv:      map[string]string{},
			wantErr: "no admin credential",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			err := Run(context.Background(), append([]string{"enroll", "create"}, tc.args...), env(tc.kv), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("a validation failure still reached the network")
					return nil, nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// --- enroll create: request body --------------------------------------------

func TestEnrollCreateRequestBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want hubapi.CreateEnrollmentRequest
	}{
		{
			name: "minimal",
			args: []string{"--cluster=prod-eu-1"},
			want: hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true},
		},
		{
			name: "labels parsed into a map",
			args: []string{"--cluster=prod-eu-1", "--labels=env=prod,zone=eu-west-1"},
			want: hubapi.CreateEnrollmentRequest{
				ClusterID: "prod-eu-1", Reusable: true,
				Labels: map[string]string{"env": "prod", "zone": "eu-west-1"},
			},
		},
		{
			name: "a stray empty entry between commas is skipped",
			args: []string{"--cluster=prod-eu-1", "--labels=env=prod,,zone=eu-west-1,"},
			want: hubapi.CreateEnrollmentRequest{
				ClusterID: "prod-eu-1", Reusable: true,
				Labels: map[string]string{"env": "prod", "zone": "eu-west-1"},
			},
		},
		{
			name: "name and owner",
			args: []string{"--cluster=prod-eu-1", "--name=bootstrap", "--owner=sre@example.com"},
			want: hubapi.CreateEnrollmentRequest{
				ClusterID: "prod-eu-1", Reusable: true, Name: "bootstrap", Owner: "sre@example.com",
			},
		},
		{
			name: "ttl above zero is sent",
			args: []string{"--cluster=prod-eu-1", "--ttl=1h"},
			want: hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true, TTL: fleet.Duration(time.Hour)},
		},
		{
			name: "zero ttl is omitted, meaning the hub default",
			args: []string{"--cluster=prod-eu-1", "--ttl=0s"},
			want: hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true},
		},
		{
			name: "reusable with no cap",
			args: []string{"--cluster=prod-eu-1"},
			want: hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true},
		},
		{
			name: "reusable with a cap",
			args: []string{"--cluster=prod-eu-1", "--max-redemptions=5"},
			want: hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true, MaxRedemptions: 5},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
			var stdout bytes.Buffer
			err := Run(context.Background(), append([]string{"enroll", "create"}, tc.args...),
				env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := decodeEnrollmentBody(t, rec)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("request body (-want +got):\n%s", diff)
			}
		})
	}
}

// TestEnrollCreateRequestTarget pins the method, path and headers of the
// admin call, including that the bearer token never leaks into the URL.
func TestEnrollCreateRequestTarget(t *testing.T) {
	t.Parallel()
	doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
	var stdout bytes.Buffer
	err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "s3cr3t"}), &stdout, doer)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if rec.req.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", rec.req.Method)
	}
	if got, want := rec.req.URL.String(), DefaultAdminURL+"/admin/v1/enrollments"; got != want {
		t.Errorf("URL = %s, want %s", got, want)
	}
	if got, want := rec.req.Header.Get("Authorization"), "Bearer s3cr3t"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if got, want := rec.req.Header.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
}

// --- keys create: validation -------------------------------------------------

func TestKeysCreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing name",
			args:    []string{"--class=agent"},
			wantErr: "--name is required",
		},
		{
			name:    "missing class",
			args:    []string{"--name=bot"},
			wantErr: "--class is required",
		},
		{
			name:    "unknown class",
			args:    []string{"--name=bot", "--class=superuser"},
			wantErr: `unknown class "superuser"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			err := Run(context.Background(), append([]string{"keys", "create"}, tc.args...),
				env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, fakeDoer{
					do: func(*http.Request) (*http.Response, error) {
						t.Fatal("a validation failure still reached the network")
						return nil, nil
					},
				})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestKeyClassAcceptsWireSpellings pins that keyClass accepts both the
// friendly command-line spelling and the wire value directly, for both
// classes, since a caller might reasonably script either.
// TestKeysCreateRejectsTTLWithNoExpiry pins the contradiction at the CLI, so
// the operator is told in the flag spellings they typed rather than by a round
// trip that reports the wire field names.
func TestKeysCreateRejectsTTLWithNoExpiry(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	err := Run(context.Background(),
		[]string{"keys", "create", "--class=agent", "--name=sre-bot", "--ttl=2h", "--no-expiry"},
		env(nil), &stdout, fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a contradictory request still reached the network")
				return nil, nil
			},
		})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want a mutual-exclusion complaint", err)
	}
}

func TestKeyClassAcceptsWireSpellings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want fleet.KeyClass
	}{
		{"agent", fleet.ClassAgent},
		{string(fleet.ClassAgent), fleet.ClassAgent},
		{"admin", fleet.ClassAdmin},
		{string(fleet.ClassAdmin), fleet.ClassAdmin},
	}
	for _, tc := range tests {
		got, err := keyClass(tc.in)
		if err != nil {
			t.Errorf("keyClass(%q) error = %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("keyClass(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- keys create: request body -----------------------------------------------

func TestKeysCreateRequestBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want hubapi.CreateKeyRequest
	}{
		{
			name: "admin key carries no scope",
			args: []string{"--class=admin", "--name=root-op"},
			want: hubapi.CreateKeyRequest{Class: fleet.ClassAdmin, Name: "root-op"},
		},
		{
			name: "admin key ignores clusters and tools",
			args: []string{"--class=admin", "--name=root-op", "--clusters=*", "--tools=*"},
			want: hubapi.CreateKeyRequest{Class: fleet.ClassAdmin, Name: "root-op"},
		},
		{
			name: "agent key defaults to viewer with empty scope lists",
			args: []string{"--class=agent", "--name=sre-bot"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{Role: fleet.RoleViewer},
			},
		},
		{
			name: "agent key with no expiry",
			args: []string{"--class=agent", "--name=sre-bot", "--no-expiry"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot", NoExpiry: true,
				Scope: &fleet.Scope{Role: fleet.RoleViewer},
			},
		},
		{
			name: "agent key with owner and ttl",
			args: []string{"--class=agent", "--name=sre-bot", "--owner=sre@example.com", "--ttl=2h"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot", Owner: "sre@example.com",
				TTL:   fleet.Duration(2 * time.Hour),
				Scope: &fleet.Scope{Role: fleet.RoleViewer},
			},
		},
		{
			name: "clusters: ids only",
			args: []string{"--class=agent", "--name=sre-bot", "--clusters=prod-eu-1,prod-us-9"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{
					Role:     fleet.RoleViewer,
					Clusters: fleet.ClusterScope{Allow: []string{"prod-eu-1", "prod-us-9"}},
				},
			},
		},
		{
			name: "clusters: labels only",
			args: []string{"--class=agent", "--name=sre-bot", "--clusters=env=prod,zone=eu-west-1"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{
					Role: fleet.RoleViewer,
					Clusters: fleet.ClusterScope{
						MatchLabels: map[string]string{"env": "prod", "zone": "eu-west-1"},
					},
				},
			},
		},
		{
			name: "clusters: a mix of ids and labels in one flag",
			args: []string{"--class=agent", "--name=sre-bot", "--clusters=prod-eu-1,env=prod"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{
					Role: fleet.RoleViewer,
					Clusters: fleet.ClusterScope{
						Allow:       []string{"prod-eu-1"},
						MatchLabels: map[string]string{"env": "prod"},
					},
				},
			},
		},
		{
			name: "clusters: wildcard is an allow entry, not a label",
			args: []string{"--class=agent", "--name=sre-bot", "--clusters=*"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{
					Role:     fleet.RoleViewer,
					Clusters: fleet.ClusterScope{Allow: []string{"*"}},
				},
			},
		},
		{
			name: "clusters: empty flag produces an empty scope",
			args: []string{"--class=agent", "--name=sre-bot", "--clusters="},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{Role: fleet.RoleViewer},
			},
		},
		{
			name: "tools flag",
			args: []string{"--class=agent", "--name=sre-bot", "--tools=prom.query,prom.range_query"},
			want: hubapi.CreateKeyRequest{
				Class: fleet.ClassAgent, Name: "sre-bot",
				Scope: &fleet.Scope{
					Role:  fleet.RoleViewer,
					Tools: fleet.ToolScope{Allow: []string{"prom.query", "prom.range_query"}},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
			var stdout bytes.Buffer
			err := Run(context.Background(), append([]string{"keys", "create"}, tc.args...),
				env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := decodeKeyBody(t, rec)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("request body (-want +got):\n%s", diff)
			}
		})
	}
}

// clusterScope is covered end to end above via the CLI; this pins the
// "=v" edge case directly against the unexported function, since it is a
// deliberate and easy-to-invert decision (treated as an ID, not a label,
// because the key half is empty) that an end-to-end body diff would not call
// out by name if it flipped.
func TestClusterScopeEmptyKeyIsAnID(t *testing.T) {
	t.Parallel()
	got := clusterScope("=v")
	want := fleet.ClusterScope{Allow: []string{"=v"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("clusterScope(%q) (-want +got):\n%s", "=v", diff)
	}
}

// --- admin URL resolution ----------------------------------------------------

func TestAdminURLPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		kv   map[string]string
		want string
	}{
		{
			name: "default when neither is set",
			want: DefaultAdminURL,
		},
		{
			name: "env beats default",
			kv:   map[string]string{"PMF_ADMIN_URL": "http://admin.example:9091"},
			want: "http://admin.example:9091",
		},
		{
			name: "flag beats env",
			args: []string{"--admin-url=http://flag.example:9091"},
			kv:   map[string]string{"PMF_ADMIN_URL": "http://admin.example:9091"},
			want: "http://flag.example:9091",
		},
		{
			name: "trailing slash is trimmed on the flag",
			args: []string{"--admin-url=http://flag.example:9091/"},
			want: "http://flag.example:9091",
		},
		{
			name: "trailing slash is trimmed on the env value",
			kv:   map[string]string{"PMF_ADMIN_URL": "http://admin.example:9091/"},
			want: "http://admin.example:9091",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kv := map[string]string{"PMF_ADMIN_TOKEN": "tok"}
			for k, v := range tc.kv {
				kv[k] = v
			}
			doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
			var stdout bytes.Buffer
			err := Run(context.Background(), append([]string{"enroll", "create", "--cluster=prod-eu-1"}, tc.args...),
				env(kv), &stdout, doer)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got, want := rec.req.URL.String(), tc.want+"/admin/v1/enrollments"; got != want {
				t.Errorf("URL = %s, want %s", got, want)
			}
		})
	}
}

// --- admin token resolution ---------------------------------------------------

func TestAdminTokenResolution(t *testing.T) {
	t.Parallel()

	writeToken := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		return p
	}

	t.Run("env only still works", func(t *testing.T) {
		t.Parallel()
		doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "env-token"}), &stdout, doer)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if got := rec.req.Header.Get("Authorization"); got != "Bearer env-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer env-token")
		}
	})

	t.Run("file wins over env", func(t *testing.T) {
		t.Parallel()
		file := writeToken(t, "file-token\n")
		doer, rec := capturingDoer(jsonResponse(http.StatusCreated, wantMinted()))
		var stdout bytes.Buffer
		err := Run(context.Background(),
			[]string{"enroll", "create", "--cluster=prod-eu-1", "--admin-token-file=" + file},
			env(map[string]string{"PMF_ADMIN_TOKEN": "env-token"}), &stdout, doer)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if got := rec.req.Header.Get("Authorization"); got != "Bearer file-token" {
			t.Errorf("Authorization = %q, want the file's token, trimmed", got)
		}
	})

	t.Run("missing file is a read error", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(),
			[]string{"enroll", "create", "--cluster=prod-eu-1",
				"--admin-token-file=" + filepath.Join(t.TempDir(), "does-not-exist")},
			env(map[string]string{"PMF_ADMIN_TOKEN": "env-token"}), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("a missing token file still reached the network")
					return nil, nil
				},
			})
		if err == nil || !strings.Contains(err.Error(), "read admin token file") {
			t.Fatalf("error = %v, want a read-admin-token-file complaint", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		file := writeToken(t, "")
		var stdout bytes.Buffer
		err := Run(context.Background(),
			[]string{"enroll", "create", "--cluster=prod-eu-1", "--admin-token-file=" + file},
			env(nil), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("an empty token file still reached the network")
					return nil, nil
				},
			})
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("error = %v, want an empty-file complaint", err)
		}
	})

	t.Run("whitespace-only file is treated as empty", func(t *testing.T) {
		t.Parallel()
		file := writeToken(t, "   \n\t\n")
		var stdout bytes.Buffer
		err := Run(context.Background(),
			[]string{"enroll", "create", "--cluster=prod-eu-1", "--admin-token-file=" + file},
			env(nil), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("a whitespace-only token file still reached the network")
					return nil, nil
				},
			})
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("error = %v, want an empty-file complaint", err)
		}
	})

	t.Run("neither set", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(nil), &stdout, fakeDoer{
				do: func(*http.Request) (*http.Response, error) {
					t.Fatal("no credential still reached the network")
					return nil, nil
				},
			})
		wantMsg := "no admin credential: set PMF_ADMIN_TOKEN or pass --admin-token-file"
		if err == nil || err.Error() != wantMsg {
			t.Fatalf("error = %v, want %q", err, wantMsg)
		}
	})
}

// --- post: response handling --------------------------------------------------

func TestPostResponseHandling(t *testing.T) {
	t.Parallel()

	t.Run("non-2xx with a decodable error envelope", func(t *testing.T) {
		t.Parallel()
		resp := jsonResponse(http.StatusConflict, hubapi.ErrorEnvelope{
			Error: hubapi.ErrorBody{Code: hubapi.CodeConflict, Message: "enrollment already redeemed"},
		})
		resp.Status = "409 Conflict"
		doer, _ := capturingDoer(resp)
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if err == nil || !strings.Contains(err.Error(), "enrollment already redeemed") {
			t.Fatalf("error = %v, want it to carry the envelope message", err)
		}
		// Exact: the raw-body fallback would also contain the message (it is
		// in the JSON), so only the bare "status: message" shape proves the
		// envelope was decoded rather than dumped.
		if got, want := err.Error(), "409 Conflict: enrollment already redeemed"; got != want {
			t.Errorf("error = %q, want %q", got, want)
		}
	})

	t.Run("non-2xx without a decodable envelope", func(t *testing.T) {
		t.Parallel()
		resp := rawResponse(http.StatusBadGateway, "upstream timeout\n")
		resp.Status = "502 Bad Gateway"
		doer, _ := capturingDoer(resp)
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if err == nil || !strings.Contains(err.Error(), "upstream timeout") {
			t.Fatalf("error = %v, want it to carry the raw body", err)
		}
	})

	t.Run("non-2xx with a JSON body that is not the envelope shape", func(t *testing.T) {
		t.Parallel()
		// Valid JSON, but it has no error.message: json.Unmarshal succeeds and
		// leaves Message empty, so the raw-body fallback must still fire.
		resp := rawResponse(http.StatusForbidden, `{"unexpected":"shape"}`)
		resp.Status = "403 Forbidden"
		doer, _ := capturingDoer(resp)
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if err == nil || !strings.Contains(err.Error(), `{"unexpected":"shape"}`) {
			t.Fatalf("error = %v, want the raw body since there was no envelope message", err)
		}
	})

	t.Run("malformed JSON on a 201 is a decode error", func(t *testing.T) {
		t.Parallel()
		resp := rawResponse(http.StatusCreated, `{not json`)
		doer, _ := capturingDoer(resp)
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if err == nil || !strings.Contains(err.Error(), "decode response") {
			t.Fatalf("error = %v, want a decode-response complaint", err)
		}
	})

	t.Run("200 is accepted as well as 201", func(t *testing.T) {
		t.Parallel()
		doer, _ := capturingDoer(jsonResponse(http.StatusOK, wantMinted()))
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1", "--quiet"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if err != nil {
			t.Fatalf("Run() error = %v, want a 200 to be accepted", err)
		}
	})

	t.Run("a request body that cannot be JSON-encoded", func(t *testing.T) {
		t.Parallel()
		// post is exercised directly here: every real caller in this package
		// only ever hands it a struct that always marshals, so this is the
		// only way to reach its encode failure branch.
		err := post(context.Background(), fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				t.Fatal("an unencodable body still reached the network")
				return nil, nil
			},
		}, "http://admin.example/x", func() (string, error) { return "tok", nil },
			make(chan int), &struct{}{})
		if err == nil || !strings.Contains(err.Error(), "encode request") {
			t.Fatalf("post() error = %v, want an encode-request complaint", err)
		}
	})

	t.Run("a URL that cannot become a request", func(t *testing.T) {
		t.Parallel()
		err := post(context.Background(), fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				t.Fatal("an unbuildable request still reached the network")
				return nil, nil
			},
		}, "://bad-url", func() (string, error) { return "tok", nil },
			struct{}{}, &struct{}{})
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("post() error = %v, want a build-request complaint", err)
		}
	})

	t.Run("a response body that fails to read", func(t *testing.T) {
		t.Parallel()
		err := post(context.Background(), fakeDoer{
			do: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusCreated,
					Status:     "201 Created",
					Body:       io.NopCloser(failingReader{}),
					Header:     make(http.Header),
				}, nil
			},
		}, "http://admin.example/x", func() (string, error) { return "tok", nil },
			struct{}{}, &struct{}{})
		if err == nil || !strings.Contains(err.Error(), "read response") {
			t.Fatalf("post() error = %v, want a read-response complaint", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("connection refused")
		doer := fakeDoer{do: func(*http.Request) (*http.Response, error) { return nil, wantErr }}
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want it to wrap %v", err, wantErr)
		}
		if !strings.Contains(err.Error(), "/admin/v1/enrollments") {
			t.Errorf("error = %v, want it to name the URL that failed", err)
		}
	})

	t.Run("request context is honoured", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		doer := fakeDoer{do: func(r *http.Request) (*http.Response, error) {
			return nil, r.Context().Err()
		}}
		var stdout bytes.Buffer
		err := Run(ctx, []string{"enroll", "create", "--cluster=prod-eu-1"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "tok"}), &stdout, doer)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want it to wrap context.Canceled", err)
		}
	})
}

// --- report: human and quiet output -------------------------------------------

func TestReportOutput(t *testing.T) {
	t.Parallel()

	t.Run("quiet prints only the token", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		if err := report(&stdout, wantMinted(), true); err != nil {
			t.Fatalf("report: %v", err)
		}
		if got, want := stdout.String(), "pmf_enr_abcdef0123456789\n"; got != want {
			t.Errorf("stdout = %q, want %q", got, want)
		}
	})

	t.Run("human report names every field", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		if err := report(&stdout, wantMinted(), false); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := stdout.String()
		for _, want := range []string{
			"token:   pmf_enr_abcdef0123456789",
			"kid:     enrol0001",
			"class:   enr",
			"expires: 2026-09-15T00:00:00Z",
			"cluster: prod-eu-1",
			// Labels must be sorted, since the source map has no order:
			// asserting the exact joined string is what pins that, not just
			// that both keys appear somewhere.
			"labels:  env=prod,zone=eu-west-1",
			"This token is shown once and cannot be retrieved again.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("report output missing %q; got:\n%s", want, out)
			}
		}
	})

	t.Run("reusable with no cap reports unlimited", func(t *testing.T) {
		t.Parallel()
		m := wantMinted()
		m.Key.Enrollment.Reusable = true
		var stdout bytes.Buffer
		if err := report(&stdout, m, false); err != nil {
			t.Fatalf("report: %v", err)
		}
		if !strings.Contains(stdout.String(), "reusable: yes (redemptions: unlimited)") {
			t.Errorf("report output = %q, want an unlimited redemptions line", stdout.String())
		}
	})

	t.Run("reusable with a cap reports the number", func(t *testing.T) {
		t.Parallel()
		m := wantMinted()
		m.Key.Enrollment.Reusable = true
		m.Key.Enrollment.MaxRedemptions = 5
		var stdout bytes.Buffer
		if err := report(&stdout, m, false); err != nil {
			t.Fatalf("report: %v", err)
		}
		if !strings.Contains(stdout.String(), "reusable: yes (redemptions: 5)") {
			t.Errorf("report output = %q, want a capped redemptions line", stdout.String())
		}
	})

	t.Run("a token without labels reports no labels line", func(t *testing.T) {
		t.Parallel()
		m := wantMinted()
		m.Key.Enrollment.Labels = nil
		var stdout bytes.Buffer
		if err := report(&stdout, m, false); err != nil {
			t.Fatalf("report: %v", err)
		}
		if strings.Contains(stdout.String(), "labels:") {
			t.Errorf("report output = %q, an unlabelled token must not print an empty labels line", stdout.String())
		}
	})

	t.Run("single-use token reports no reusable line", func(t *testing.T) {
		t.Parallel()
		m := wantMinted()
		var stdout bytes.Buffer
		if err := report(&stdout, m, false); err != nil {
			t.Fatalf("report: %v", err)
		}
		if strings.Contains(stdout.String(), "reusable:") {
			t.Errorf("report output = %q, a single-use token must not claim reusability", stdout.String())
		}
	})

	t.Run("no expiry and no enrollment grant", func(t *testing.T) {
		t.Parallel()
		m := hubapi.MintedKeyResponse{
			Token: "pmf_adm_xyz",
			Key:   hubapi.KeyView{KID: "admin0001", Class: fleet.ClassAdmin, Name: "root-op"},
		}
		var stdout bytes.Buffer
		if err := report(&stdout, m, false); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := stdout.String()
		// A zero expiry means the credential never expires, which is stated
		// rather than omitted: a missing line would be indistinguishable from
		// a field the hub simply did not return.
		if !strings.Contains(out, "expires: never") {
			t.Errorf("report output = %q, a key with no expiry must say so", out)
		}
		if strings.Contains(out, "cluster:") {
			t.Errorf("report output = %q, a non-enrollment key must not print a cluster line", out)
		}
	})

	t.Run("write failure surfaces", func(t *testing.T) {
		t.Parallel()
		err := report(failingWriter{}, wantMinted(), true)
		if !errors.Is(err, errWriteFailed) {
			t.Fatalf("report() error = %v, want %v", err, errWriteFailed)
		}
	})
}

// errWriteFailed and failingWriter let a test observe that report propagates
// an io.Writer failure instead of swallowing it.
var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

// failingReader lets a test simulate a response body that fails mid-read,
// which io.ReadAll must surface rather than silently truncate.
type failingReader struct{}

var errReadFailed = errors.New("read failed")

func (failingReader) Read([]byte) (int, error) { return 0, errReadFailed }

// --- end-to-end over a real HTTP round trip -----------------------------------

// TestEnrollCreateOverRealServer drives the full path through a real
// net/http round trip instead of the fake Doer, for the one scenario where
// seeing the actual client/server exchange is worth more than a fake: it
// proves the request this package builds is one net/http can actually send
// and a real handler can actually parse, headers included.
func TestEnrollCreateOverRealServer(t *testing.T) {
	t.Parallel()

	var gotAuth, gotMethod, gotPath string
	var gotBody hubapi.CreateEnrollmentRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("server: decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(wantMinted())
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	err := Run(context.Background(),
		[]string{"enroll", "create", "--cluster=prod-eu-1", "--max-redemptions=3", "--quiet"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "real-token", "PMF_ADMIN_URL": srv.URL}),
		&stdout, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/admin/v1/enrollments" {
		t.Errorf("path = %s, want /admin/v1/enrollments", gotPath)
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer real-token")
	}
	want := hubapi.CreateEnrollmentRequest{ClusterID: "prod-eu-1", Reusable: true, MaxRedemptions: 3}
	if diff := cmp.Diff(want, gotBody); diff != "" {
		t.Errorf("request body (-want +got):\n%s", diff)
	}
	if got, want := stdout.String(), wantMinted().Token+"\n"; got != want {
		t.Errorf("--quiet stdout = %q, want %q", got, want)
	}
}

// TestKeysCreateOverRealServerReportsAuthFailure drives a real 401 through
// the whole path, confirming the human-readable error a caller sees for the
// single most common operational mistake: a stale or missing admin token.
func TestKeysCreateOverRealServerReportsAuthFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(hubapi.ErrorEnvelope{
			Error: hubapi.ErrorBody{Code: hubapi.CodeUnauthenticated, Message: "the admin credential is invalid or has expired"},
		})
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	err := Run(context.Background(),
		[]string{"keys", "create", "--class=agent", "--name=sre-bot"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "stale", "PMF_ADMIN_URL": srv.URL}),
		&stdout, nil)
	if err == nil || !strings.Contains(err.Error(), "the admin credential is invalid or has expired") {
		t.Fatalf("error = %v, want the envelope message surfaced", err)
	}
}

// keyViews is a small listing for the read commands to render.
func keyViews() []hubapi.KeyView {
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	revoked := at.Add(time.Hour)
	return []hubapi.KeyView{
		{KID: "agent0001", Class: fleet.ClassAgent, Name: "sre-bot", CreatedAt: at, ExpiresAt: at.Add(2160 * time.Hour)},
		{KID: "agent0002", Class: fleet.ClassAgent, Name: "immortal", CreatedAt: at},
		{KID: "agent0003", Class: fleet.ClassAgent, Name: "old", CreatedAt: at, ExpiresAt: at.Add(-time.Hour), Expired: true},
		{
			KID: "enr00001", Class: fleet.ClassEnrollment, Name: "enroll:prod-eu-1", CreatedAt: at,
			ExpiresAt: at.Add(15 * time.Minute), RevokedAt: &revoked, Revoked: true,
			Enrollment: &hubapi.EnrollmentView{ClusterID: "prod-eu-1"},
		},
	}
}

// TestKeysListRendersStatusAndTarget covers the listing an operator reads
// before acting: the status column has to say the one thing that decides
// whether a credential still works, and a key with no expiry must read
// "never" rather than a zero year.
func TestKeysListRendersStatusAndTarget(t *testing.T) {
	t.Parallel()

	doer, cap := capturingDoer(jsonResponse(http.StatusOK,
		hubapi.KeyListResponse{Keys: keyViews(), Count: 4}))
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"keys", "list"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
		t.Fatalf("keys list: %v", err)
	}
	if got := cap.req.Method; got != http.MethodGet {
		t.Errorf("method = %s, want GET", got)
	}
	out := stdout.String()
	for _, want := range []string{
		"KID", "CLASS", "STATUS", "EXPIRES", "CLUSTER",
		"agent0001", "live",
		"agent0002", "never", // no expiry
		"agent0003", "expired",
		"enr00001", "revoked", "prod-eu-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing is missing %q:\n%s", want, out)
		}
	}
}

// TestKeysListJSONIsTheAPIListing pins --json: a script selecting on
// .revokedAt must see the admin API's own fields, not a re-projection that
// could drift from them.
func TestKeysListJSONIsTheAPIListing(t *testing.T) {
	t.Parallel()

	want := hubapi.KeyListResponse{Keys: keyViews(), Count: 4}
	doer, _ := capturingDoer(jsonResponse(http.StatusOK, want))
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"keys", "list", "--json"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
		t.Fatalf("keys list --json: %v", err)
	}
	var got hubapi.KeyListResponse
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout.String())
	}
	if got.Count != want.Count || len(got.Keys) != len(want.Keys) {
		t.Fatalf("decoded %d keys (count %d), want %d (count %d)", len(got.Keys), got.Count, len(want.Keys), want.Count)
	}
	for i := range want.Keys {
		if got.Keys[i].KID != want.Keys[i].KID || got.Keys[i].Revoked != want.Keys[i].Revoked {
			t.Errorf("key %d = %+v, want %+v", i, got.Keys[i], want.Keys[i])
		}
	}
	if strings.Contains(stdout.String(), "STATUS") {
		t.Error("--json still printed the table header")
	}
	if !strings.HasSuffix(stdout.String(), "\n") {
		t.Error("--json output does not end in a newline")
	}
}

// TestKeysListFiltersByClass pins the query the filter builds, since a typo
// there would silently list everything.
func TestKeysListFiltersByClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, arg, wantQuery string
		wantErr              bool
	}{
		{name: "agent", arg: "agent", wantQuery: "class=agt"},
		{name: "admin", arg: "admin", wantQuery: "class=adm"},
		{name: "enrollment", arg: "enrollment", wantQuery: "class=enr"},
		{name: "wire spelling passes through", arg: "agt", wantQuery: "class=agt"},
		{name: "unknown is refused", arg: "operator", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doer, cap := capturingDoer(jsonResponse(http.StatusOK, hubapi.KeyListResponse{}))
			var stdout bytes.Buffer
			err := Run(context.Background(), []string{"keys", "list", "--class=" + tc.arg},
				env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer)
			if tc.wantErr {
				if err == nil {
					t.Fatal("an unknown class was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("keys list: %v", err)
			}
			if got := cap.req.URL.RawQuery; got != tc.wantQuery {
				t.Errorf("query = %q, want %q", got, tc.wantQuery)
			}
		})
	}
}

// TestKeysListEmpty: an empty fleet says so rather than printing a bare
// header an operator has to interpret.
func TestKeysListEmpty(t *testing.T) {
	t.Parallel()
	doer, _ := capturingDoer(jsonResponse(http.StatusOK, hubapi.KeyListResponse{}))
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"keys", "list"},
		env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
		t.Fatalf("keys list: %v", err)
	}
	if !strings.Contains(stdout.String(), "no credentials") {
		t.Errorf("empty listing = %q", stdout.String())
	}
}

// TestKeysRevoke covers the control the threat model leans on: the right
// method, the reason carried as a query parameter, and a confirmation naming
// what was withdrawn.
func TestKeysRevoke(t *testing.T) {
	t.Parallel()

	t.Run("revokes with a reason", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(&http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody})
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"keys", "revoke", "--kid=agent0001", "--reason=leaked in a build log"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("keys revoke: %v", err)
		}
		if cap.req.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", cap.req.Method)
		}
		if !strings.HasSuffix(cap.req.URL.Path, "/admin/v1/keys/agent0001") {
			t.Errorf("path = %q", cap.req.URL.Path)
		}
		if got := cap.req.URL.Query().Get("reason"); got != "leaked in a build log" {
			t.Errorf("reason = %q", got)
		}
		if !strings.Contains(stdout.String(), "revoked agent0001") {
			t.Errorf("output = %q", stdout.String())
		}
	})

	t.Run("purge is opt-in and says so", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(&http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody})
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"keys", "revoke", "--kid=agent0001", "--purge"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("keys revoke --purge: %v", err)
		}
		if got := cap.req.URL.Query().Get("purge"); got != "true" {
			t.Errorf("purge = %q, want true", got)
		}
		if !strings.Contains(stdout.String(), "purged agent0001") {
			t.Errorf("a purge reported itself as a revocation: %q", stdout.String())
		}
	})

	t.Run("a missing kid never reaches the network", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"keys", "revoke"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
			fakeDoer{do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a revoke with no kid was sent")
				return nil, nil
			}})
		if err == nil || !strings.Contains(err.Error(), "--kid is required") {
			t.Fatalf("err = %v, want a --kid complaint", err)
		}
	})

	t.Run("the hub's refusal is reported, not a status line", func(t *testing.T) {
		t.Parallel()
		doer, _ := capturingDoer(jsonResponse(http.StatusConflict, hubapi.ErrorEnvelope{
			Error: hubapi.ErrorBody{Code: hubapi.CodeConflict, Message: "key agent0001 is revoked"},
		}))
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"keys", "revoke", "--kid=agent0001"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer)
		if err == nil || !strings.Contains(err.Error(), "key agent0001 is revoked") {
			t.Fatalf("err = %v, want the hub's own message", err)
		}
	})
}

// TestKeysRotate pins the replacement path, including the mutual exclusion
// that would otherwise be decided by the hub after a round trip.
func TestKeysRotate(t *testing.T) {
	t.Parallel()

	t.Run("sends the body and prints the replacement", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(jsonResponse(http.StatusCreated, hubapi.MintedKeyResponse{
			Key:   hubapi.KeyView{KID: "agent0009", Class: fleet.ClassAgent},
			Token: "pmf_agt_new", TokenShownOnce: true, Warning: hubapi.TokenOnceNotice,
		}))
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"keys", "rotate", "--kid=agent0001", "--reason=suspected leak", "--ttl=2h"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("keys rotate: %v", err)
		}
		if !strings.HasSuffix(cap.req.URL.Path, "/admin/v1/keys/agent0001/rotate") {
			t.Errorf("path = %q", cap.req.URL.Path)
		}
		var body rotateBody
		if err := json.Unmarshal(cap.body, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Reason != "suspected leak" || time.Duration(body.TTL) != 2*time.Hour {
			t.Errorf("body = %+v", body)
		}
		if !strings.Contains(stdout.String(), "pmf_agt_new") {
			t.Errorf("the replacement token was not printed: %q", stdout.String())
		}
	})

	t.Run("no-expiry alone is sent as such", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(jsonResponse(http.StatusCreated, hubapi.MintedKeyResponse{
			Key: hubapi.KeyView{KID: "agent0009", Class: fleet.ClassAgent}, Token: "pmf_agt_new",
		}))
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"keys", "rotate", "--kid=agent0001", "--no-expiry"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("keys rotate: %v", err)
		}
		var body rotateBody
		if err := json.Unmarshal(cap.body, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if !body.NoExpiry || body.TTL != 0 {
			t.Errorf("body = %+v, want noExpiry with no ttl", body)
		}
	})

	t.Run("ttl and no-expiry are refused together, before the round trip", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(),
			[]string{"keys", "rotate", "--kid=agent0001", "--ttl=2h", "--no-expiry"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
			fakeDoer{do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a contradictory rotate was sent")
				return nil, nil
			}})
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v, want a mutual-exclusion complaint", err)
		}
	})

	t.Run("a missing kid never reaches the network", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"keys", "rotate"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
			fakeDoer{do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a rotate with no kid was sent")
				return nil, nil
			}})
		if err == nil || !strings.Contains(err.Error(), "--kid is required") {
			t.Fatalf("err = %v, want a --kid complaint", err)
		}
	})
}

// TestEnrollListAndRevoke covers the enrollment half, which exists so the
// noun is not half-implemented: you could mint a token and never see or
// withdraw it.
func TestEnrollListAndRevoke(t *testing.T) {
	t.Parallel()

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(jsonResponse(http.StatusOK,
			hubapi.KeyListResponse{Keys: keyViews()[3:], Count: 1}))
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"enroll", "list"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("enroll list: %v", err)
		}
		if !strings.HasSuffix(cap.req.URL.Path, "/admin/v1/enrollments") {
			t.Errorf("path = %q", cap.req.URL.Path)
		}
		if !strings.Contains(stdout.String(), "prod-eu-1") {
			t.Errorf("the cluster binding was not shown: %q", stdout.String())
		}
	})

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(&http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody})
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"enroll", "revoke", "--kid=enr00001", "--reason=cluster cancelled"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("enroll revoke: %v", err)
		}
		if cap.req.Method != http.MethodDelete ||
			!strings.HasSuffix(cap.req.URL.Path, "/admin/v1/enrollments/enr00001") {
			t.Errorf("request = %s %s", cap.req.Method, cap.req.URL.Path)
		}
		if got := cap.req.URL.Query().Get("reason"); got != "cluster cancelled" {
			t.Errorf("reason = %q", got)
		}
	})

	t.Run("revoke requires a kid", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"enroll", "revoke"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
			fakeDoer{do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a revoke with no kid was sent")
				return nil, nil
			}})
		if err == nil || !strings.Contains(err.Error(), "--kid is required") {
			t.Fatalf("err = %v, want a --kid complaint", err)
		}
	})
}

// TestCertsRevokeAndList covers cutting off a compromised cluster, which is
// the one revocation that also terminates a live session.
func TestCertsRevokeAndList(t *testing.T) {
	t.Parallel()

	t.Run("revoke", func(t *testing.T) {
		t.Parallel()
		doer, cap := capturingDoer(jsonResponse(http.StatusOK, map[string]any{"serial": "0a1b"}))
		var stdout bytes.Buffer
		if err := Run(context.Background(),
			[]string{"certs", "revoke", "--serial=0a1b", "--reason=decommissioned"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("certs revoke: %v", err)
		}
		if cap.req.Method != http.MethodPost ||
			!strings.HasSuffix(cap.req.URL.Path, "/admin/v1/certs/0a1b/revoke") {
			t.Errorf("request = %s %s", cap.req.Method, cap.req.URL.Path)
		}
		var body hubapi.RevokeCertRequest
		if err := json.Unmarshal(cap.body, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Reason != "decommissioned" {
			t.Errorf("reason = %q", body.Reason)
		}
		if !strings.Contains(stdout.String(), "revoked certificate 0a1b") {
			t.Errorf("output = %q", stdout.String())
		}
	})

	t.Run("revoke requires a serial", func(t *testing.T) {
		t.Parallel()
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"certs", "revoke"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
			fakeDoer{do: func(*http.Request) (*http.Response, error) {
				t.Fatal("a revoke with no serial was sent")
				return nil, nil
			}})
		if err == nil || !strings.Contains(err.Error(), "--serial is required") {
			t.Fatalf("err = %v, want a --serial complaint", err)
		}
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
		doer, _ := capturingDoer(jsonResponse(http.StatusOK, hubapi.RevokedCertListResponse{
			Revoked: []hubapi.RevokedCert{
				{Serial: "0a1b", RevokedAt: at, NotAfter: at.Add(336 * time.Hour), Reason: "decommissioned"},
				{Serial: "0c2d", RevokedAt: at},
			},
			Count: 2,
		}))
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"certs", "list"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("certs list: %v", err)
		}
		out := stdout.String()
		for _, want := range []string{"SERIAL", "0a1b", "decommissioned", "0c2d"} {
			if !strings.Contains(out, want) {
				t.Errorf("listing is missing %q:\n%s", want, out)
			}
		}
		// An unrecorded expiry prints as a dash, not the zero year.
		if strings.Contains(out, "0001-01-01") {
			t.Errorf("a zero timestamp was printed raw:\n%s", out)
		}
	})

	t.Run("list empty", func(t *testing.T) {
		t.Parallel()
		doer, _ := capturingDoer(jsonResponse(http.StatusOK, hubapi.RevokedCertListResponse{}))
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"certs", "list"},
			env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout, doer); err != nil {
			t.Fatalf("certs list: %v", err)
		}
		if !strings.Contains(stdout.String(), "no revoked certificates") {
			t.Errorf("output = %q", stdout.String())
		}
	})
}

// TestEveryCommandSurfacesATransportFailure: a hub that cannot be reached --
// the usual cause being a forgotten port-forward, or an exec into a pod whose
// admin listener is not up yet -- must produce the transport error, not a nil
// error and an empty listing that reads like an empty fleet.
func TestEveryCommandSurfacesATransportFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("connection refused")
	tests := []struct {
		name string
		args []string
	}{
		{"keys list", []string{"keys", "list"}},
		{"keys revoke", []string{"keys", "revoke", "--kid=agent0001"}},
		{"keys rotate", []string{"keys", "rotate", "--kid=agent0001"}},
		{"enroll list", []string{"enroll", "list"}},
		{"enroll revoke", []string{"enroll", "revoke", "--kid=enr00001"}},
		{"certs revoke", []string{"certs", "revoke", "--serial=0a1b"}},
		{"certs list", []string{"certs", "list"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			err := Run(context.Background(), tc.args,
				env(map[string]string{"PMF_ADMIN_TOKEN": "pmf_adm_x"}), &stdout,
				fakeDoer{do: func(*http.Request) (*http.Response, error) { return nil, boom }})
			if err == nil || !strings.Contains(err.Error(), "connection refused") {
				t.Fatalf("err = %v, want the transport failure", err)
			}
		})
	}
}
