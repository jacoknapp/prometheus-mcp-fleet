// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// newTestHealth returns a Health logging into the returned buffer.
func newTestHealth(t *testing.T) (*Health, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewHealth(log), &buf
}

func TestHealthReady(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(*Health)
		wantReady    bool
		wantBlockers map[string]string
	}{
		{
			name:         "no components is ready",
			setup:        func(*Health) {},
			wantReady:    true,
			wantBlockers: map[string]string{},
		},
		{
			name:         "one ready component",
			setup:        func(h *Health) { h.Set("store", true, "") },
			wantReady:    true,
			wantBlockers: map[string]string{},
		},
		{
			name:         "one blocker",
			setup:        func(h *Health) { h.Set("store", false, "not opened") },
			wantReady:    false,
			wantBlockers: map[string]string{"store": "not opened"},
		},
		{
			name: "several blockers",
			setup: func(h *Health) {
				h.Set("store", false, "not opened")
				h.Set("ca", false, "certificate expires in 3h")
				h.Set("tunnel", true, "")
			},
			wantReady:    false,
			wantBlockers: map[string]string{"store": "not opened", "ca": "certificate expires in 3h"},
		},
		{
			name:         "blocker without a reason still explains itself",
			setup:        func(h *Health) { h.Set("pepper", false, "") },
			wantReady:    false,
			wantBlockers: map[string]string{"pepper": "not ready"},
		},
		{
			name: "recovery clears the blocker",
			setup: func(h *Health) {
				h.Set("store", false, "not opened")
				h.Set("store", true, "")
			},
			wantReady:    true,
			wantBlockers: map[string]string{},
		},
		{
			name: "draining blocks readiness on its own",
			setup: func(h *Health) {
				h.Set("store", true, "")
				h.StartDraining()
			},
			wantReady:    false,
			wantBlockers: map[string]string{DrainingComponent: "shutdown in progress"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _ := newTestHealth(t)
			tc.setup(h)
			ready, blockers := h.Ready()
			if ready != tc.wantReady {
				t.Errorf("Ready() = %v, want %v (blockers %v)", ready, tc.wantReady, blockers)
			}
			if diff := cmp.Diff(tc.wantBlockers, blockers); diff != "" {
				t.Errorf("blockers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHealthSetLogsTransitionsOnly(t *testing.T) {
	t.Parallel()

	h, buf := newTestHealth(t)

	h.Set("store", true, "") // transition: unknown -> ready
	h.Set("store", true, "") // no-op
	h.Set("store", true, "") // no-op
	if got := strings.Count(buf.String(), "readiness check passed"); got != 1 {
		t.Errorf("logged %d ready transitions, want 1:\n%s", got, buf)
	}

	h.Set("store", false, "write failed") // transition
	h.Set("store", false, "write failed") // no-op
	if got := strings.Count(buf.String(), "component not ready"); got != 1 {
		t.Errorf("logged %d not-ready transitions, want 1:\n%s", got, buf)
	}

	h.Set("store", false, "disk full") // reason changed: a real transition
	if got := strings.Count(buf.String(), "component not ready"); got != 2 {
		t.Errorf("a changed reason must be logged:\n%s", buf)
	}
	if !strings.Contains(buf.String(), "disk full") {
		t.Errorf("the new reason is missing:\n%s", buf)
	}
}

func TestHealthSetIgnoresReasonWhenReady(t *testing.T) {
	t.Parallel()

	h, buf := newTestHealth(t)
	h.Set("store", true, "ignored")
	h.Set("store", true, "also ignored")
	if got := strings.Count(buf.String(), "readiness check passed"); got != 1 {
		t.Errorf("a reason on a ready component must not create a transition:\n%s", buf)
	}
}

func TestHealthStartDrainingIsIdempotent(t *testing.T) {
	t.Parallel()

	h, buf := newTestHealth(t)
	if h.Draining() {
		t.Error("Draining() = true before StartDraining")
	}
	h.StartDraining()
	h.StartDraining()
	if !h.Draining() {
		t.Error("Draining() = false after StartDraining")
	}
	if got := strings.Count(buf.String(), `"msg":"draining"`); got != 1 {
		t.Errorf("logged %d draining lines, want 1:\n%s", got, buf)
	}
}

func TestHealthNilLoggerUsesDefault(t *testing.T) {
	t.Parallel()

	h := NewHealth(nil)
	h.Set("component", true, "")
	if ready, _ := h.Ready(); !ready {
		t.Error("Ready() = false, want true")
	}
}

func TestHealthLiveHandler(t *testing.T) {
	t.Parallel()

	h, _ := newTestHealth(t)
	h.Set("store", false, "not opened")
	h.StartDraining()

	rec := httptest.NewRecorder()
	h.LiveHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: liveness must never depend on a component", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var body liveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body, err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
}

func TestHealthReadyHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(*Health)
		wantCode     int
		wantStatus   string
		wantDraining bool
		wantBlockers map[string]string
	}{
		{
			name:       "ready",
			setup:      func(h *Health) { h.Set("store", true, "") },
			wantCode:   http.StatusOK,
			wantStatus: "ready",
		},
		{
			name:         "blocked",
			setup:        func(h *Health) { h.Set("ca", false, "key unloadable") },
			wantCode:     http.StatusServiceUnavailable,
			wantStatus:   "unready",
			wantBlockers: map[string]string{"ca": "key unloadable"},
		},
		{
			name:         "draining",
			setup:        func(h *Health) { h.StartDraining() },
			wantCode:     http.StatusServiceUnavailable,
			wantStatus:   "unready",
			wantDraining: true,
			wantBlockers: map[string]string{DrainingComponent: "shutdown in progress"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _ := newTestHealth(t)
			tc.setup(h)

			rec := httptest.NewRecorder()
			h.ReadyHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body)
			}
			var body readyResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not JSON: %v", rec.Body, err)
			}
			if body.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", body.Status, tc.wantStatus)
			}
			if body.Draining != tc.wantDraining {
				t.Errorf("draining = %v, want %v", body.Draining, tc.wantDraining)
			}
			if diff := cmp.Diff(tc.wantBlockers, body.Blockers); diff != "" {
				t.Errorf("blockers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHealthIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	h := NewHealth(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 64 {
				h.Set("component", j%2 == 0, "flapping")
				h.Ready()
				if i == 0 && j == 32 {
					h.StartDraining()
				}
			}
		}(i)
	}
	wg.Wait()
	if ready, _ := h.Ready(); ready {
		t.Error("Ready() = true after draining started")
	}
}

func TestWriteHealthJSONMarshalFailure(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeHealthJSON(rec, http.StatusOK, func() {})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Body.String(); got != "{\"status\":\"error\"}\n" {
		t.Fatalf("body = %q", got)
	}
}
