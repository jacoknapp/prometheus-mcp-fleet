// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package bench holds regression tests for the project's quantitative claims
// that are not about tokens. [internal/render.TestTokenCountRegression] pins
// the 272x context-size reduction; this package pins the other number a
// reader checks first: how much memory an idle spoke uses.
//
// See the long comment on [TestSpokeIdleHeapFootprint] for what is and is not
// actually measured here, and why.
package bench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/spoke"
	pmftestutil "github.com/jacoknapp/prometheus-mcp-fleet/internal/testutil"
)

// -----------------------------------------------------------------------
// a minimal, self-contained stand-in for the hub's enrollment API
// -----------------------------------------------------------------------
//
// internal/spoke cannot be reused directly for this: its own test helpers
// (the fake hub, the test CA) are unexported, package-private types, and
// pulling them out would mean editing internal/spoke, which is out of scope
// for this file. What follows re-implements just enough of the documented
// wire contract (internal/spoke/enroll.go's enrollRequest/enrollResponse) to
// let a real spoke.Run enroll against it. It is deliberately not a copy of
// the richer fakeHub in internal/spoke/enroll_test.go, which also exercises
// renewal — this one only ever needs to answer /enroll once.

// footprintCA is a throwaway certificate authority standing in for the hub's,
// exactly as internal/spoke's own tests do (see testCA in enroll_test.go).
type footprintCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newFootprintCA(t *testing.T) *footprintCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bench test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &footprintCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// sign issues a spoke client certificate for the CSR's public key, carrying
// the URI SAN the spoke's own clusterIDFromCert reads the cluster ID back
// from (see internal/spoke/enroll.go).
func (c *footprintCA) sign(clusterID string, pub any) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "spoke:" + clusterID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "pmf", Host: "fleet.bench", Path: "/spoke/" + clusterID}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// footprintEnrollRequest and footprintEnrollResponse mirror
// internal/spoke/enroll.go's enrollRequest/enrollResponse field-for-field.
// They are redeclared here, rather than imported, because those types are
// unexported.
type footprintEnrollRequest struct {
	CSR string `json:"csr"`
}

type footprintEnrollResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"caBundle"`
	ClusterID   string `json:"clusterId"`
	NotAfter    string `json:"notAfter"`
}

// newFakeHubAPI starts an httptest.Server answering exactly one route,
// POST /enroll, the way the real hub does per docs/spoke-enrollment.md. It
// deliberately does not implement /renew: the test runs for a few seconds
// against a certificate valid for 24 hours, and the spoke's renewal check
// (internal/spoke/spoke.go's renewCheckInterval, a hard-coded hour) never
// fires in that window.
func newFakeHubAPI(t *testing.T, ca *footprintCA, clusterID string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req footprintEnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		der, err := base64.StdEncoding.DecodeString(req.CSR)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		certPEM, err := ca.sign(clusterID, csr.PublicKey)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(footprintEnrollResponse{
			Certificate: string(certPEM),
			CABundle:    string(ca.pem),
			ClusterID:   clusterID,
			NotAfter:    time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// deadTunnelAddr returns a loopback address nobody is listening on, so a dial
// against it fails immediately (connection refused) instead of timing out —
// the same trick internal/spoke's own tests use (see deadAddr in
// internal/spoke/helpers_test.go). The spoke's dial loop then does exactly
// what it would do against a hub that is briefly unreachable: retry with
// backoff, which is part of the idle steady state this test measures.
func deadTunnelAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// captureStdout replaces os.Stdout for the duration of the test and returns a
// function reading everything written to it so far. spoke.Run's logger writes
// to os.Stdout unconditionally (it is the composition root; see
// internal/spoke/spoke.go), so this is the only way to observe its lifecycle
// from outside the package. Not safe to run with another test in this
// package that also touches os.Stdout concurrently — there is only one test
// here, and it is not marked t.Parallel.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w

	var (
		mu  sync.Mutex
		buf strings.Builder
	)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		chunk := make([]byte, 4096)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				mu.Lock()
				buf.Write(chunk[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		os.Stdout = original
		_ = w.Close()
		<-drained
		_ = r.Close()
	})
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// eventually polls cond until it is true or the deadline passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settledHeap forces the allocator to give back what it can and returns a
// stable MemStats snapshot. Two GC cycles, not one: a single runtime.GC() can
// still leave objects that were only reachable through a finalizer or a
// stack that had not yet been rescanned; a second pass after the first is the
// usual way to pin that down (it is what net/http's own tests do for the
// same reason). debug.FreeOSMemory additionally returns freed pages to the
// OS, which matters for the informational RSS reading below but not for the
// HeapInuse figure the assertion is actually made on.
func settledHeap() runtime.MemStats {
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// procRSSKiB reads this process's resident set size from /proc, in KiB. It
// returns 0, false when unavailable (any OS other than Linux, or a sandboxed
// /proc). CI runs on ubuntu-24.04 (see .github/workflows/ci.yml), where this
// always works; the fallback exists only so `go test` does not fail for a
// contributor on a different OS.
func procRSSKiB(t *testing.T) (int64, bool) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0, false
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kib, true
	}
	return 0, false
}

// TestSpokeIdleHeapFootprint is the regression test behind the README's
// memory claim, on the same principle as
// internal/render.TestTokenCountRegression: "the spoke idles at about 20 MiB"
// is a number a reader checks first, so it needs a test behind it like every
// other number in this README, not just an assertion.
//
// What this test actually measures, and why that is not quite the claim:
//
//   - The README claim (and its restatement in docs/architecture.md and
//     ADR-0009) is about a pod's RESIDENT memory — what a kubelet reports and
//     a memory limit is billed against. That is the operating system's view
//     of physical pages mapped into the process, and it includes the Go
//     runtime, the binary's own text and data segments, thread stacks, and
//     whatever the allocator has not returned to the OS yet.
//   - A test living inside `go test` cannot observe that in isolation. It
//     shares one OS process — and one address space, one Go runtime, one set
//     of already-loaded packages — with the test binary itself, with every
//     other package under test, and with the `-race` instrumentation `make
//     test` always runs under (see .github/workflows/ci.yml: "make test is
//     go test -race ..."). Reading /proc/self/status here would report the
//     whole test binary's RSS, not one idle spoke's, so it is logged as
//     context below but never asserted on.
//   - What CAN be measured cleanly is the spoke's own contribution to the Go
//     HEAP: the live objects its goroutines are holding once it has enrolled,
//     started its admin listener, completed one facts refresh and settled
//     its dial loop into backoff against an unreachable hub. That is measured
//     as the delta in runtime.MemStats between immediately before spoke.Run
//     is started and after it has reached that steady state and a forced GC,
//     which cancels out the baseline cost of the test harness itself.
//
// Heap is not RSS. A real pod also pays for the Go runtime's own baseline (a
// large fraction of the reasoned — not measured — "30 MiB Go runtime
// baseline" in docs/architecture.md's capacity section), for stacks, and for
// memory the allocator holds but has not returned to the OS. This test cannot
// see any of that, and does not claim to. What it defends is narrower and
// still worth defending: that the spoke's own live heap, once idle, is small
// and stays small — a regression here (a buffer that stops being released, a
// map that grows without bound) would move the real RSS by the same order of
// magnitude, even though the two numbers are not equal.
//
// One more gap: this spoke never completes a tunnel connection to a hub —
// doing that in-process would need a working WebSocket+gRPC tunnel server
// (internal/tunnel/wstun.NewServer plus a gRPC client over the accepted
// connection), which is materially more machinery than an enrollment stub and
// was judged not worth the added complexity and failure surface for a memory
// benchmark. docs/architecture.md's own capacity section puts one idle tunnel
// on the hub side at "about 86 KiB" (buffers plus three goroutines); the
// spoke side of the same connection is the same order of magnitude, i.e. a
// small fraction of the claimed 20 MiB. Its absence undercounts the true
// figure slightly; it does not invalidate the heap-vs-RSS point above, which
// is the dominant source of error here.
//
// Tolerance: the assertion allows the spoke's own live heap to grow to 48
// MiB above baseline before failing, and its goroutine count to grow by more
// than 40. Both are roughly an order of magnitude above what a healthy idle
// spoke's own state should occupy (low single-digit MiB; a dozen or so
// goroutines for the admin listener, the Prometheus client, the facts
// collector, the renewal and probe loops, and one dialer per hub endpoint).
// That headroom is deliberate, not sloppy: `-race` instruments every memory
// access and adds real, variable per-allocation overhead; this test runs on a
// shared CI runner whose scheduling and GC pacing are outside its control;
// and forcing two GC cycles reduces but does not eliminate that noise. A
// tolerance this wide still catches what actually matters — a leak or a
// regression large enough to move the real pod's RSS materially — while
// never flaking because a loaded runner had the race detector hold on to a
// few extra megabytes.
func TestSpokeIdleHeapFootprint(t *testing.T) {
	ca := newFootprintCA(t)
	const clusterID = "bench-cluster"
	hubAPI := newFakeHubAPI(t, ca, clusterID)
	prom := pmftestutil.NewFakePrometheus(t, pmftestutil.FakeOptions{})

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("pmf_enr_bench_token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := &config.Spoke{
		HubEndpoints:         []string{"ws://" + deadTunnelAddr(t) + "/tunnel"},
		HubAPIURL:            hubAPI.URL,
		EnrollmentTokenFile:  tokenFile,
		ClusterID:            clusterID,
		ClusterSDLC:          "prod",
		ClusterLabels:        map[string]string{"env": "prod"},
		IdentityBackend:      config.IdentityBackendMemory,
		PrometheusURL:        prom.URL,
		FactsRefreshInterval: time.Minute,
		ReconnectMinBackoff:  5 * time.Millisecond,
		ReconnectMaxBackoff:  20 * time.Millisecond,
		AdminAddr:            "127.0.0.1:0",
		LogLevel:             "info",
		LogFormat:            "json",
		ShutdownGrace:        5 * time.Second,
	}

	stdout := captureStdout(t)

	before := settledHeap()
	beforeGoroutines := runtime.NumGoroutine()
	beforeRSS, haveRSS := procRSSKiB(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- spoke.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("spoke.Run did not return after its context was cancelled")
		}
	})

	// Reached the certificate, i.e. enrollment against the fake hub API
	// completed and the identity is in place (see internal/spoke/enroll.go's
	// "obtained client certificate" log line).
	eventually(t, 15*time.Second, "the spoke to obtain a certificate", func() bool {
		return strings.Contains(stdout(), "obtained client certificate")
	})
	// Reached steady state: the dial loop has attempted the (dead) tunnel
	// endpoint at least once and backed off, which only happens after the
	// admin listener, the Prometheus client, the facts collector and every
	// other piece of s.run's wiring already exist (see internal/spoke/
	// spoke.go's dialLoop, which logs "tunnel closed, reconnecting" here).
	eventually(t, 15*time.Second, "the dial loop to settle into backoff", func() bool {
		return strings.Contains(stdout(), "tunnel closed, reconnecting")
	})
	// A short additional pause: the log line above fires the instant dialOnce
	// returns, which is slightly before the backoff sleep — and therefore the
	// idle steady state — actually begins.
	time.Sleep(200 * time.Millisecond)

	after := settledHeap()
	afterGoroutines := runtime.NumGoroutine()
	afterRSS, _ := procRSSKiB(t)

	heapDelta := int64(after.HeapInuse) - int64(before.HeapInuse)
	allocDelta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	goroutineDelta := afterGoroutines - beforeGoroutines

	t.Logf("spoke idle heap: HeapInuse %d -> %d bytes (delta %+d, %.2f MiB)",
		before.HeapInuse, after.HeapInuse, heapDelta, float64(heapDelta)/(1<<20))
	t.Logf("spoke idle heap: HeapAlloc %d -> %d bytes (delta %+d, %.2f MiB)",
		before.HeapAlloc, after.HeapAlloc, allocDelta, float64(allocDelta)/(1<<20))
	t.Logf("goroutines: %d -> %d (delta %+d)", beforeGoroutines, afterGoroutines, goroutineDelta)
	if haveRSS {
		rssDelta := afterRSS - beforeRSS
		t.Logf("process VmRSS (informational only, NOT the pod-RSS claim — see the "+
			"doc comment on this test): %d -> %d KiB (delta %+d KiB, %.2f MiB)",
			beforeRSS, afterRSS, rssDelta, float64(rssDelta)/1024)
	} else {
		t.Log("process VmRSS unavailable on this OS; skipped (informational only)")
	}

	const heapCeiling = 48 << 20 // see the tolerance paragraph in the doc comment above
	if heapDelta > heapCeiling {
		t.Errorf("an idle spoke's own live heap grew by %.2f MiB, above the %.0f MiB "+
			"regression ceiling; see TestSpokeIdleHeapFootprint's doc comment for what "+
			"this measures and why the ceiling is this wide",
			float64(heapDelta)/(1<<20), float64(heapCeiling)/(1<<20))
	}
	const goroutineCeiling = 40
	if goroutineDelta > goroutineCeiling {
		t.Errorf("goroutine count grew by %d starting an idle spoke, above the %d "+
			"regression ceiling — that shape (not the exact count) is what would "+
			"indicate a leak", goroutineDelta, goroutineCeiling)
	}

	// Sanity, not a claim: an idle spoke plus the whole test binary and the
	// race detector should never approach a gigabyte. This would only fire if
	// something ran away completely.
	if haveRSS {
		const rssSanityCeiling = 1 << 20 // 1 GiB, in KiB units (afterRSS is KiB)
		if afterRSS > rssSanityCeiling {
			t.Errorf("process VmRSS reached %.0f MiB; see the doc comment above for why "+
				"this is a sanity check on the whole test binary, not a measurement of "+
				"one spoke", float64(afterRSS)/1024)
		}
	}
}
