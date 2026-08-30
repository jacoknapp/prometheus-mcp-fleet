// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package clusterfacts assembles the [tunnel.Facts] a spoke publishes about
// its cluster.
//
// The facts exist so that an agent can narrow a hundred clusters down to one
// or two before it spends a single query: which Prometheus flavor is behind
// this spoke, how far back its retention goes, which jobs and namespaces it
// scrapes, and — the highest-value fact of all — which metric name prefixes
// dominate, which tells a model instantly whether it is looking at a kube_,
// istio_ or jvm_ shaped cluster.
//
// No Kubernetes client. BUILD_SPEC section 1.8 ships the spoke with zero RBAC
// and automountServiceAccountToken false, so everything here comes from
// operator-supplied configuration plus PromQL and the Prometheus status
// endpoints.
//
// Failure tolerance is the design constraint. Every source is collected
// independently and a failure records a reason on that one field rather than
// blanking the rest; a cluster whose /api/v1/status/tsdb is missing still
// reports its jobs, its rules and its alert counts.
//
// Who may import it: internal/spoke. It sits at L2 and imports only
// internal/fleet, internal/tunnel, internal/promapi and internal/promclient.
//
// Concurrency: a [Collector] is safe for concurrent use. [Collector.Facts] and
// [Collector.Describe] read a cached snapshot and never perform I/O;
// [Collector.Refresh] is the only method that talks to Prometheus.
package clusterfacts
