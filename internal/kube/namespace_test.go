// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestWithNamespaceRetargetsWithoutLosingTheConnection pins the property the
// hub depends on: an operator-configured namespace overrides the projected one
// and nothing else. Rebuilding the client instead would discard the API server
// address, the token file and the CA bundle that only InCluster knows.
func TestWithNamespaceRetargetsWithoutLosingTheConnection(t *testing.T) {
	t.Parallel()

	var paths []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		writeSecret(t, w, http.StatusOK, &wireSecret{
			Metadata: wireMeta{Name: "state", Namespace: "other", ResourceVersion: "7"},
			Data:     map[string][]byte{"k": []byte("v")},
		})
	})

	moved, err := c.WithNamespace("other")
	if err != nil {
		t.Fatalf("WithNamespace: %v", err)
	}
	if moved.Namespace() != "other" {
		t.Fatalf("namespace = %q, want %q", moved.Namespace(), "other")
	}
	if c.Namespace() != testNamespace {
		t.Fatalf("the original client moved to %q", c.Namespace())
	}

	// It still talks to the same API server, which is the half a rebuild
	// would have thrown away.
	if _, err := moved.GetSecret(context.Background(), "state"); err != nil {
		t.Fatalf("GetSecret through the retargeted client: %v", err)
	}
	if len(paths) != 1 || !strings.HasPrefix(paths[0], "/api/v1/namespaces/other/secrets/") {
		t.Fatalf("requested %v, want the other namespace", paths)
	}
}

func TestWithNamespaceRefusesANamespaceThatIsNotAName(t *testing.T) {
	t.Parallel()

	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeStatus(t, w, http.StatusNotFound, "NotFound", "unused")
	})

	// The namespace is interpolated into a URL path, so a value carrying a
	// "/" or a ".." would address a different object entirely.
	if _, err := c.WithNamespace("Not A Namespace"); err == nil {
		t.Fatal("an illegal namespace was accepted")
	}
	if _, err := c.WithNamespace(""); err == nil {
		t.Fatal("an empty namespace was accepted")
	}
}
