// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"net/http"
	"net/http/pprof"
)

// PprofHandler returns the runtime profiling endpoints.
//
// Mount it on the admin listener at the "/debug/pprof/" prefix, and only when
// PMF_PPROF_ENABLED is set:
//
//	mux.Handle("/debug/pprof/", obs.PprofHandler())
//
// The handler expects to see the full "/debug/pprof/..." path, which is how
// http.ServeMux dispatches a prefix pattern. Profiling must never be exposed
// on the MCP or tunnel listeners: /debug/pprof is on the absolute deny-list for
// proxied requests, and the profiles themselves contain memory contents.
func PprofHandler() http.Handler {
	mux := http.NewServeMux()
	// Index also serves the named profiles (/heap, /goroutine, ...).
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}
