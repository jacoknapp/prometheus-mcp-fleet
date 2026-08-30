// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testNamespace is the namespace every test client is scoped to.
const testNamespace = "monitoring"

// newTestClient starts an httptest.Server impersonating the API server and
// returns a Client pointed at it. The client uses the server's own
// http.Client, so no TLS trust is involved; the TLS path is exercised
// separately by TestTLSVerification.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		APIServerURL: srv.URL,
		Namespace:    testNamespace,
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

// writeStatus writes a metav1.Status document with the given code.
func writeStatus(t *testing.T, w http.ResponseWriter, code int, reason, message string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(wireStatus{Code: code, Reason: reason, Message: message}); err != nil {
		t.Errorf("encode status: %v", err)
	}
}

// writeSecret writes a Secret document.
func writeSecret(t *testing.T, w http.ResponseWriter, code int, s *wireSecret) {
	t.Helper()
	s.APIVersion, s.Kind = "v1", "Secret"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(s); err != nil {
		t.Errorf("encode secret: %v", err)
	}
}

// writeTokenFile writes a token file with a controlled mtime so that mtime
// granularity cannot make a rotation test flaky.
func writeTokenFile(t *testing.T, path, token string, mtimeNanos int64) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	setMtime(t, path, mtimeNanos)
}

// setMtime pins a file's modification time so that two writes inside one
// filesystem timestamp tick are still distinguishable by the token source.
func setMtime(t *testing.T, path string, nanos int64) {
	t.Helper()
	ts := time.Unix(0, nanos)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// pemCert renders a certificate as PEM.
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// dirMarker asks serviceAccountDir to create the named entry as a directory,
// which is how a test provokes a read or stat failure that is not
// fs.ErrNotExist without depending on file modes (the tests may run as root).
const dirMarker = "\x00directory"

// serviceAccountDir builds a projected service account directory.
func serviceAccountDir(t *testing.T, token, ca, namespace string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{"token": token, "ca.crt": ca, "namespace": namespace} {
		switch content {
		case "":
			continue
		case dirMarker:
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatalf("mkdir %s: %v", name, err)
			}
		default:
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	return dir
}
