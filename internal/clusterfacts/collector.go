// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package clusterfacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promclient"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Defaults applied when the corresponding Config field is zero.
const (
	// DefaultTopN caps every sampled list (jobs, namespaces, metric
	// prefixes). Twenty-five is enough to characterise a cluster and small
	// enough that a hundred of them still fit in an agent's context.
	DefaultTopN = 25
	// DefaultMaxFactsBytes caps the serialized facts payload. A spoke that
	// scrapes forty thousand jobs must not be able to push a megabyte of
	// registry data at the hub on every reconnect.
	DefaultMaxFactsBytes = 64 << 10
	// truncationNote is appended to the description when sampled lists had to
	// be shortened to fit MaxFactsBytes.
	truncationNote = "[facts note: sampled lists were shortened to fit the facts size cap]"
)

// defaultRefreshInterval returns the spoke's PMF_FACTS_REFRESH_INTERVAL
// default. It is evaluated in executable code so mutation testing can prove
// that the ten-minute value is asserted rather than treating const
// initialisation as permanently uncovered.
func defaultRefreshInterval() time.Duration { return 10 * time.Minute }

// clusterIDRE is the cluster identity grammar from BUILD_SPEC section 5. The
// value is advisory here — the hub overwrites it from the client certificate —
// but rejecting a malformed one at the spoke turns a silent mismatch into a
// startup error.
var clusterIDRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Config configures a [Collector]. ClusterID and Client are required.
type Config struct {
	// ClusterID is the spoke's identity. It must match
	// ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$.
	ClusterID string
	// DisplayName is the human-facing cluster name.
	DisplayName string
	// Description orients an agent, e.g. "customer-facing API tier".
	Description string
	// Labels are the operator-supplied selectors from PMF_CLUSTER_LABELS.
	Labels map[string]string
	// AgentVersion is the spoke build version.
	AgentVersion string
	// ProtocolVersion is the tunnel protocol revision the spoke speaks.
	ProtocolVersion string
	// StartedAt is the spoke process start time. Its UnixNano value becomes
	// the facts Generation, which the hub uses to resolve reconnect races.
	// Defaults to Clock().
	StartedAt time.Time
	// Client is the spoke's Prometheus client.
	Client *promclient.Client
	// RefreshInterval is how often [Collector.Run] recollects. Defaults to
	// ten minutes.
	RefreshInterval time.Duration
	// TopN caps the jobs, namespaces and metric-prefix lists. Defaults to
	// [DefaultTopN].
	TopN int
	// MaxFactsBytes caps the serialized facts. Defaults to
	// [DefaultMaxFactsBytes].
	MaxFactsBytes int

	// KubernetesVersion, KubernetesClusterUID and KubernetesNodeCount are the
	// optional operator-supplied Kubernetes facts (PMF_CLUSTER_K8S_*). They
	// take precedence over the PromQL-derived values, because an operator who
	// bothered to set them knows more than kube-state-metrics does.
	KubernetesVersion    string
	KubernetesClusterUID string
	KubernetesNodeCount  int32

	// Logger receives collection diagnostics. Defaults to a discarding logger.
	Logger *slog.Logger
	// Clock supplies the current time. Defaults to time.Now.
	Clock func() time.Time
}

// Collector caches the cluster facts and refreshes them on a schedule.
type Collector struct {
	client        *promclient.Client
	static        fleet.Cluster
	refreshEvery  time.Duration
	topN          int
	maxFactsBytes int
	k8sVersion    string
	k8sUID        string
	k8sNodeCount  int32
	generation    int64
	log           *slog.Logger
	now           func() time.Time

	// mu guards the published snapshot.
	mu          sync.RWMutex
	cluster     fleet.Cluster
	fingerprint string
	lastRefresh time.Time
}

// New validates cfg and returns a Collector holding a placeholder fact set:
// Prometheus is reported unreachable with the reason "facts have not been
// collected yet" until the first [Collector.Refresh] completes, and the two
// cardinality counts carry their -1 sentinel. That is deliberate — a spoke must
// be able to answer Describe the moment its tunnel attaches, before any
// upstream call has been made.
func New(cfg Config) (*Collector, error) {
	if !clusterIDRE.MatchString(cfg.ClusterID) {
		return nil, fmt.Errorf("clusterfacts: ClusterID %q must match %s", cfg.ClusterID, clusterIDRE)
	}
	if cfg.Client == nil {
		return nil, errors.New("clusterfacts: Client is required")
	}
	if cfg.RefreshInterval < 0 {
		return nil, fmt.Errorf("clusterfacts: RefreshInterval %s must not be negative", cfg.RefreshInterval)
	}
	if cfg.TopN < 0 {
		return nil, fmt.Errorf("clusterfacts: TopN %d must not be negative", cfg.TopN)
	}
	if cfg.MaxFactsBytes < 0 {
		return nil, fmt.Errorf("clusterfacts: MaxFactsBytes %d must not be negative", cfg.MaxFactsBytes)
	}
	if cfg.KubernetesNodeCount < 0 {
		return nil, fmt.Errorf("clusterfacts: KubernetesNodeCount %d must not be negative", cfg.KubernetesNodeCount)
	}

	c := &Collector{
		client:        cfg.Client,
		refreshEvery:  orDefault(cfg.RefreshInterval, defaultRefreshInterval()),
		topN:          orDefault(cfg.TopN, DefaultTopN),
		maxFactsBytes: orDefault(cfg.MaxFactsBytes, DefaultMaxFactsBytes),
		k8sVersion:    cfg.KubernetesVersion,
		k8sUID:        cfg.KubernetesClusterUID,
		k8sNodeCount:  cfg.KubernetesNodeCount,
		log:           cfg.Logger,
		now:           cfg.Clock,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	startedAt := cfg.StartedAt
	if startedAt.IsZero() {
		startedAt = c.now()
	}
	c.generation = startedAt.UnixNano()
	c.static = fleet.Cluster{
		ID:              cfg.ClusterID,
		DisplayName:     cfg.DisplayName,
		Description:     cfg.Description,
		Labels:          maps.Clone(cfg.Labels),
		AgentVersion:    cfg.AgentVersion,
		ProtocolVersion: cfg.ProtocolVersion,
	}

	initial := c.base()
	initial.Prometheus = fleet.PrometheusInfo{
		Reachable:         false,
		UnreachableReason: "facts have not been collected yet",
		ActiveSeries:      -1,
		MetricNames:       -1,
	}
	initial.Kubernetes = fleet.KubernetesInfo{
		Available:         false,
		UnavailableReason: reasonNoKubernetesAccess,
	}
	c.applyOperatorKubernetes(&initial.Kubernetes)
	c.publish(initial, time.Time{})
	return c, nil
}

// orDefault returns v unless it is the zero value.
func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// base returns a copy of the operator-supplied fields, which no upstream
// failure can affect.
func (c *Collector) base() fleet.Cluster {
	out := c.static
	out.Labels = maps.Clone(c.static.Labels)
	return out
}

// Generation returns the spoke's process start time in Unix nanoseconds.
func (c *Collector) Generation() int64 { return c.generation }

// RefreshInterval returns the effective refresh period.
func (c *Collector) RefreshInterval() time.Duration { return c.refreshEvery }

// LastRefresh returns when the last successful publish happened, or the zero
// time before the first one. The spoke's readiness probe uses it together with
// Facts().Cluster.Prometheus.Reachable.
func (c *Collector) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRefresh
}

// Facts returns the cached facts and their fingerprint. It never performs I/O
// and never blocks on a refresh, so a slow or hung Prometheus cannot delay the
// hub's Describe call.
func (c *Collector) Facts() tunnel.Facts {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return tunnel.Facts{
		Fingerprint: c.fingerprint,
		Changed:     true,
		Cluster:     cloneCluster(c.cluster),
		Generation:  c.generation,
	}
}

// Describe implements the spoke half of [tunnel.Handler]. When the caller's
// fingerprint already matches the current one it replies Changed=false with an
// empty cluster, which is the whole point of the fingerprint: a hub polling a
// hundred spokes every minute transfers a hash rather than a hundred fact
// documents.
//
// Describe never triggers a refresh inline. Collection is on a ticker, so a
// Describe can never be made slow by an upstream that is slow.
func (c *Collector) Describe(ctx context.Context, knownFingerprint string) (tunnel.Facts, error) {
	if err := ctx.Err(); err != nil {
		return tunnel.Facts{}, err
	}
	c.mu.RLock()
	current := c.fingerprint
	c.mu.RUnlock()
	if knownFingerprint != "" && knownFingerprint == current {
		return tunnel.Facts{
			Fingerprint: current,
			Changed:     false,
			Generation:  c.generation,
		}, nil
	}
	return c.Facts(), nil
}

// Run drives [Collector.Refresh] until ctx is done. It refreshes once
// immediately so that a freshly started spoke does not serve placeholder facts
// for a whole interval.
func (c *Collector) Run(ctx context.Context) {
	if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
		c.log.LogAttrs(ctx, slog.LevelWarn, "cluster facts refresh incomplete", slog.String("error", err.Error()))
	}
	ticker := time.NewTicker(c.refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
				c.log.LogAttrs(ctx, slog.LevelWarn, "cluster facts refresh incomplete", slog.String("error", err.Error()))
			}
		}
	}
}

// publish swaps in a new snapshot and recomputes the fingerprint.
func (c *Collector) publish(cluster fleet.Cluster, at time.Time) {
	fp := Fingerprint(cluster)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cluster = cluster
	c.fingerprint = fp
	if !at.IsZero() {
		c.lastRefresh = at
	}
}

// previous returns a copy of the currently published snapshot.
func (c *Collector) previous() fleet.Cluster {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneCluster(c.cluster)
}

// cloneCluster deep-copies the maps and slices so a caller cannot mutate the
// collector's cached snapshot.
func cloneCluster(in fleet.Cluster) fleet.Cluster {
	out := in
	out.Labels = maps.Clone(in.Labels)
	out.Prometheus.ExternalLabels = maps.Clone(in.Prometheus.ExternalLabels)
	out.Prometheus.Jobs = slices.Clone(in.Prometheus.Jobs)
	out.Prometheus.Namespaces = slices.Clone(in.Prometheus.Namespaces)
	out.Prometheus.MetricPrefixes = slices.Clone(in.Prometheus.MetricPrefixes)
	return out
}

// capSize shortens the sampled lists until the serialized facts fit within
// MaxFactsBytes, and records that it did so. Namespaces go first and metric
// prefixes last, because the prefixes are the single most informative fact an
// agent gets from a cluster it has never queried.
func (c *Collector) capSize(cluster *fleet.Cluster) {
	truncated := false
capping:
	for range 32 {
		b, err := json.Marshal(cluster)
		if err != nil || len(b) <= c.maxFactsBytes {
			break
		}
		if !shrinkSampled(cluster) {
			// Nothing sampled is left; the remainder is operator-supplied text
			// and is not ours to silently discard.
			break capping
		}
		truncated = true
	}
	// The note is appended even when the loop gave up with the payload still
	// over the cap. That is precisely the case where the most was dropped, and
	// truncation an agent cannot see is truncation it will reason past.
	if truncated {
		cluster.Description = appendNote(cluster.Description, truncationNote)
	}
}

// shrinkSampled removes half of the least valuable remaining sampled field.
// Its ordered ifs make the precedence explicit and independently testable.
func shrinkSampled(cluster *fleet.Cluster) bool {
	if len(cluster.Prometheus.Namespaces) > 0 {
		cluster.Prometheus.Namespaces = halve(cluster.Prometheus.Namespaces)
		return true
	}
	if len(cluster.Prometheus.Jobs) > 0 {
		cluster.Prometheus.Jobs = halve(cluster.Prometheus.Jobs)
		return true
	}
	if len(cluster.Prometheus.MetricPrefixes) > 0 {
		cluster.Prometheus.MetricPrefixes = halve(cluster.Prometheus.MetricPrefixes)
		return true
	}
	if len(cluster.Prometheus.ExternalLabels) > 0 {
		cluster.Prometheus.ExternalLabels = nil
		return true
	}
	return false
}

// halve returns the first half of s, or nil once a single element is left.
func halve(s []string) []string {
	if len(s) <= 1 {
		return nil
	}
	return s[:len(s)/2]
}

// appendNote adds note to a description without producing a leading space on
// an empty one.
func appendNote(desc, note string) string {
	if desc == "" {
		return note
	}
	return desc + " " + note
}
