// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetSecret(t *testing.T) {
	t.Parallel()
	// Arbitrary bytes, including NUL and the whole high half of the byte
	// range: the wire form is base64, and a backend that treated it as text
	// would corrupt an HMAC or a DER-encoded private key silently.
	arbitrary := make([]byte, 256)
	for i := range arbitrary {
		arbitrary[i] = byte(i)
	}
	want := &Secret{
		Name:            "prometheus-mcp-fleet-state",
		ResourceVersion: "4242",
		Data:            map[string][]byte{"state.json": arbitrary, "empty": {}},
		Labels:          map[string]string{"app.kubernetes.io/name": "prometheus-mcp-fleet"},
		Annotations:     map[string]string{"note": "managed by the hub"},
	}

	var gotPath, gotMethod string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		writeSecret(t, w, http.StatusOK, want.toWire(testNamespace))
	})

	got, err := c.GetSecret(t.Context(), want.Name)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
	if wantPath := "/api/v1/namespaces/monitoring/secrets/prometheus-mcp-fleet-state"; gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
}

func TestSecretDataIsBase64OnTheWire(t *testing.T) {
	t.Parallel()
	var body []byte
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		writeSecret(t, w, http.StatusOK, &wireSecret{Metadata: wireMeta{Name: "state", ResourceVersion: "1"}})
	})
	if _, err := c.CreateSecret(t.Context(), &Secret{Name: "state", Data: map[string][]byte{"k": {0x00, 0xff, 'a'}}}); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	var raw struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if want := "AP9h"; raw.Data["k"] != want {
		t.Errorf("wire data = %q, want the base64 %q", raw.Data["k"], want)
	}
}

func TestGetSecretErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		code     int
		reason   string
		message  string
		want     error
		contains []string
	}{
		{
			name: "not found", code: http.StatusNotFound, reason: "NotFound",
			message: `secrets "prometheus-mcp-fleet-state" not found`,
			want:    ErrNotFound,
		},
		{
			name: "forbidden", code: http.StatusForbidden, reason: "Forbidden",
			message: `secrets "prometheus-mcp-fleet-state" is forbidden: User "system:serviceaccount:monitoring:hub" cannot get resource "secrets" in API group "" in the namespace "monitoring"`,
			want:    ErrForbidden,
			contains: []string{
				`cannot get resource "secrets"`,
				"secrets get/create/update in namespace monitoring",
				`verbs: ["get","create","update"]`,
			},
		},
		{
			name: "unauthorized", code: http.StatusUnauthorized, reason: "Unauthorized",
			message: "credentials required", want: ErrUnauthorized,
		},
		{
			name: "server error", code: http.StatusInternalServerError, reason: "InternalError",
			message: "etcd is unavailable", contains: []string{"500", "etcd is unavailable"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeStatus(t, w, tc.code, tc.reason, tc.message)
			})
			got, err := c.GetSecret(t.Context(), "prometheus-mcp-fleet-state")
			if got != nil {
				t.Error("GetSecret returned a secret alongside an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if err == nil {
				t.Fatal("GetSecret = nil, want an error")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %v does not unwrap to *APIError", err)
			}
			if apiErr.Status != tc.code {
				t.Errorf("APIError.Status = %d, want %d", apiErr.Status, tc.code)
			}
			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if !strings.Contains(err.Error(), "secret monitoring/prometheus-mcp-fleet-state") {
				t.Errorf("error %q does not name the object", err)
			}
		})
	}
}

func TestForbiddenWithAnUnparseableBody(t *testing.T) {
	t.Parallel()
	// An intermediary can return an HTML error page. The status still carries
	// the meaning, and the RBAC hint must still appear.
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>403 Forbidden</html>"))
	})
	_, err := c.GetSecret(t.Context(), "state")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("error = %v, want ErrForbidden", err)
	}
	for _, want := range []string{"Forbidden", "secrets get/create/update in namespace monitoring"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "<html>") {
		t.Errorf("error %q echoes the response body", err)
	}
}

func TestCreateSecret(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		var got wireSecret
		var path, method string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			path, method = r.URL.Path, r.Method
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode request: %v", err)
			}
			out := got
			out.Metadata.ResourceVersion = "1"
			writeSecret(t, w, http.StatusCreated, &out)
		})
		in := &Secret{
			Name:            "state",
			ResourceVersion: "ignored",
			Data:            map[string][]byte{"state.json": []byte("{}")},
			Labels:          map[string]string{"k": "v"},
		}
		out, err := c.CreateSecret(t.Context(), in)
		if err != nil {
			t.Fatalf("CreateSecret: %v", err)
		}
		if out.ResourceVersion != "1" {
			t.Errorf("ResourceVersion = %q, want %q", out.ResourceVersion, "1")
		}
		if got.Metadata.ResourceVersion != "" {
			t.Errorf("create sent resourceVersion %q, want it omitted", got.Metadata.ResourceVersion)
		}
		if got.Metadata.Namespace != testNamespace || got.Type != "Opaque" || got.Kind != "Secret" {
			t.Errorf("request metadata = %+v type=%q kind=%q", got.Metadata, got.Type, got.Kind)
		}
		if path != "/api/v1/namespaces/monitoring/secrets" || method != http.MethodPost {
			t.Errorf("request = %s %s, want POST on the collection", method, path)
		}
	})

	t.Run("already exists", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			writeStatus(t, w, http.StatusConflict, "AlreadyExists", `secrets "state" already exists`)
		})
		if _, err := c.CreateSecret(t.Context(), &Secret{Name: "state"}); !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("error = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("conflict without a reason falls back to the verb", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
		})
		if _, err := c.CreateSecret(t.Context(), &Secret{Name: "state"}); !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("error = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("rejects a nil secret", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
		if _, err := c.CreateSecret(t.Context(), nil); err == nil {
			t.Error("CreateSecret(nil) = nil, want an error")
		}
	})

	t.Run("rejects an illegal name", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {
			t.Error("an illegal name reached the API server")
		})
		if _, err := c.CreateSecret(t.Context(), &Secret{Name: "../kube-system"}); err == nil {
			t.Error("CreateSecret = nil, want a name validation error")
		}
	})
}

func TestUpdateSecret(t *testing.T) {
	t.Parallel()

	t.Run("sends the resource version", func(t *testing.T) {
		t.Parallel()
		var got wireSecret
		var path, method string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			path, method = r.URL.Path, r.Method
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode request: %v", err)
			}
			out := got
			out.Metadata.ResourceVersion = "43"
			writeSecret(t, w, http.StatusOK, &out)
		})
		out, err := c.UpdateSecret(t.Context(), &Secret{
			Name: "state", ResourceVersion: "42",
			Data: map[string][]byte{"state.json": []byte("{}")},
		})
		if err != nil {
			t.Fatalf("UpdateSecret: %v", err)
		}
		if got.Metadata.ResourceVersion != "42" {
			t.Errorf("sent resourceVersion %q, want %q -- without it the write is not a compare-and-swap",
				got.Metadata.ResourceVersion, "42")
		}
		if out.ResourceVersion != "43" {
			t.Errorf("ResourceVersion = %q, want the new %q", out.ResourceVersion, "43")
		}
		if path != "/api/v1/namespaces/monitoring/secrets/state" || method != http.MethodPut {
			t.Errorf("request = %s %s, want PUT on the object", method, path)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			writeStatus(t, w, http.StatusConflict, "Conflict",
				`Operation cannot be fulfilled on secrets "state": the object has been modified; please apply your changes to the latest version and try again`)
		})
		_, err := c.UpdateSecret(t.Context(), &Secret{Name: "state", ResourceVersion: "42"})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("error = %v, want ErrConflict", err)
		}
		if errors.Is(err, ErrAlreadyExists) {
			t.Error("an update conflict must not be reported as ErrAlreadyExists")
		}
	})

	t.Run("conflict without a reason falls back to the verb", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
		})
		_, err := c.UpdateSecret(t.Context(), &Secret{Name: "state", ResourceVersion: "42"})
		if !errors.Is(err, ErrConflict) {
			t.Errorf("error = %v, want ErrConflict", err)
		}
	})

	t.Run("refuses an empty resource version", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {
			t.Error("an unconditional update reached the API server")
		})
		_, err := c.UpdateSecret(t.Context(), &Secret{Name: "state"})
		if err == nil || !strings.Contains(err.Error(), "no resource version") {
			t.Errorf("error = %v, want a refusal to overwrite unconditionally", err)
		}
	})

	t.Run("rejects a nil secret", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {})
		if _, err := c.UpdateSecret(t.Context(), nil); err == nil {
			t.Error("UpdateSecret(nil) = nil, want an error")
		}
	})

	t.Run("rejects an illegal name", func(t *testing.T) {
		t.Parallel()
		c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {
			t.Error("an illegal name reached the API server")
		})
		if _, err := c.UpdateSecret(t.Context(), &Secret{Name: "Bad Name", ResourceVersion: "1"}); err == nil {
			t.Error("UpdateSecret = nil, want a name validation error")
		}
	})
}

func TestGetSecretRejectsAnIllegalName(t *testing.T) {
	t.Parallel()
	c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an illegal name reached the API server")
	})
	if _, err := c.GetSecret(t.Context(), "../../kube-system/secrets/root"); err == nil {
		t.Error("GetSecret = nil, want a name validation error")
	}
}
