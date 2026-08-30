// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient_test

import (
	"encoding/pem"
	"net/http/httptest"
	"testing"
)

// pemEncodeCert renders the certificate an httptest TLS server presents as a
// PEM bundle, so a test can hand it to Config.TLSCAFile and exercise the real
// verification path instead of disabling verification.
func pemEncodeCert(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("httptest server is not TLS, it has no certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
