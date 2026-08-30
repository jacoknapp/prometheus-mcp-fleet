// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
)

// DrainingComponent is the synthetic component name reported as a readiness
// blocker once [Health.StartDraining] has been called.
const DrainingComponent = "draining"

// Health tracks per-component readiness and serves the liveness and readiness
// endpoints.
//
// The split is deliberate and load-bearing: liveness never consults a
// dependency, so an unreachable Prometheus or a disconnected spoke can never
// turn into a restart loop. Only readiness reflects dependencies.
//
// A Health is safe for concurrent use.
type Health struct {
	mu         sync.Mutex
	components map[string]componentState
	draining   bool
	logger     *slog.Logger
}

// componentState is one component's readiness and, when not ready, why.
type componentState struct {
	ready  bool
	reason string
}

// NewHealth returns a Health with no components registered, which is therefore
// ready until something registers itself as not ready. A nil logger uses
// slog.Default.
func NewHealth(logger *slog.Logger) *Health {
	if logger == nil {
		logger = slog.Default()
	}
	return &Health{components: make(map[string]componentState), logger: logger}
}

// Set records the readiness of a component. It is idempotent: repeating the
// same state is a no-op and, in particular, logs nothing. Only transitions are
// logged, at info when a component becomes ready and at warn when it stops
// being ready, so a flapping dependency produces one line per change rather
// than one per probe.
//
// reason is ignored when ready is true.
func (h *Health) Set(component string, ready bool, reason string) {
	if ready {
		reason = ""
	}
	h.mu.Lock()
	prev, existed := h.components[component]
	unchanged := existed && prev.ready == ready && prev.reason == reason
	if !unchanged {
		h.components[component] = componentState{ready: ready, reason: reason}
	}
	h.mu.Unlock()

	if unchanged {
		return
	}
	if ready {
		h.logger.Info("readiness check passed", slog.String("check", component))
		return
	}
	h.logger.Warn("component not ready",
		slog.String("check", component),
		slog.String("reason", reason))
}

// Ready reports whether every registered component is ready and draining has
// not started. The returned map holds one entry per blocker, keyed by
// component name, with the reason as the value; it is empty when ready is
// true. Draining appears as the [DrainingComponent] entry.
func (h *Health) Ready() (bool, map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	blockers := make(map[string]string)
	if h.draining {
		blockers[DrainingComponent] = "shutdown in progress"
	}
	for name, state := range h.components {
		if !state.ready {
			reason := state.reason
			if reason == "" {
				reason = "not ready"
			}
			blockers[name] = reason
		}
	}
	return len(blockers) == 0, blockers
}

// StartDraining marks the process as shutting down. Readiness immediately
// reports false so a load balancer stops sending new work, while liveness
// keeps reporting 200 so nothing kills the process mid-drain. It is
// idempotent.
func (h *Health) StartDraining() {
	h.mu.Lock()
	already := h.draining
	h.draining = true
	names := slices.Sorted(maps.Keys(h.components))
	h.mu.Unlock()

	if already {
		return
	}
	h.logger.Info("draining", slog.Int("components", len(names)))
}

// Draining reports whether shutdown has begun.
func (h *Health) Draining() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.draining
}

// liveResponse is the /healthz body.
type liveResponse struct {
	Status string `json:"status"`
}

// readyResponse is the /readyz body. Blockers is omitted when ready.
type readyResponse struct {
	Status   string            `json:"status"`
	Draining bool              `json:"draining,omitempty"`
	Blockers map[string]string `json:"blockers,omitempty"`
}

// LiveHandler serves /healthz. It returns 200 as soon as the process is
// serving and never consults a dependency.
func (h *Health) LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeHealthJSON(w, http.StatusOK, liveResponse{Status: "ok"})
	})
}

// ReadyHandler serves /readyz. It returns 200 only when every registered
// component is ready and draining has not started; otherwise 503 with a JSON
// body listing each blocker and its reason.
func (h *Health) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready, blockers := h.Ready()
		if ready {
			writeHealthJSON(w, http.StatusOK, readyResponse{Status: "ready"})
			return
		}
		_, draining := blockers[DrainingComponent]
		writeHealthJSON(w, http.StatusServiceUnavailable, readyResponse{
			Status:   "unready",
			Draining: draining,
			Blockers: blockers,
		})
	})
}

// writeHealthJSON writes a health body. Probes must never be cached, and a
// probe body is small enough to marshal before writing the status so a
// marshalling failure cannot produce a truncated 200.
func writeHealthJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
