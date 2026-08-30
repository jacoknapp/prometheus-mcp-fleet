// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Scope is the authorization document attached to an agent key. Evaluation is
// deny-by-default and deny-beats-allow: an empty Scope authorizes nothing.
type Scope struct {
	// Role sets the capability tier. See Role.
	Role Role `json:"role"`
	// Clusters restricts which clusters the key may reach.
	Clusters ClusterScope `json:"clusters"`
	// Tools restricts which MCP tools the key may call.
	Tools ToolScope `json:"tools"`
	// Limits bounds the cost of any single call.
	Limits Limits `json:"limits"`
}

// ClusterScope selects clusters by explicit name, by label selector, or both.
// Deny always wins.
type ClusterScope struct {
	// Allow lists cluster IDs. The single element "*" matches every cluster.
	Allow []string `json:"allow,omitempty"`
	// MatchLabels requires every listed label to be present and equal on the
	// cluster's registry entry.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	// Deny lists cluster IDs that are refused regardless of Allow or
	// MatchLabels. Wildcards are not honoured here: a deny must be explicit.
	Deny []string `json:"deny,omitempty"`
}

// ToolScope selects MCP tools. Allow entries are exact names or the single
// wildcard "*"; Deny entries are exact names or a "prefix.*" pattern.
type ToolScope struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Limits bounds the cost of one tool call. Zero values mean "use the hub
// default"; the hub never widens a limit beyond its own configured maximum.
type Limits struct {
	// MaxLookback is the furthest back in time a query may reach.
	MaxLookback Duration `json:"maxLookback,omitempty"`
	// MaxPoints caps (end-start)/step for range queries.
	MaxPoints int `json:"maxPoints,omitempty"`
	// MaxSeries caps how many series a result may contain before truncation.
	MaxSeries int `json:"maxSeries,omitempty"`
	// Timeout bounds a single upstream call.
	Timeout Duration `json:"timeout,omitempty"`
	// MaxResponseBytes bounds the raw upstream response body.
	MaxResponseBytes int64 `json:"maxResponseBytes,omitempty"`
	// MaxConcurrentPerCluster bounds simultaneous in-flight calls per cluster.
	MaxConcurrentPerCluster int `json:"maxConcurrentPerCluster,omitempty"`
	// RateRPS and RateBurst bound the key's overall call rate.
	RateRPS   float64 `json:"rateRps,omitempty"`
	RateBurst int     `json:"rateBurst,omitempty"`
}

// Duration is a time.Duration that marshals as a Go duration string ("30s",
// "24h") so that scope documents stay readable in the admin API and in audit
// logs.
type Duration time.Duration

// String renders the duration in Go duration syntax.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler. It accepts a duration string and,
// for convenience, a plain number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// AllowsCluster reports whether the scope permits reaching the given cluster.
// labels are the cluster's registry labels.
func (s *Scope) AllowsCluster(id string, labels map[string]string) bool {
	if s == nil {
		return false
	}
	if slices.Contains(s.Clusters.Deny, id) {
		return false
	}
	for k, want := range s.Clusters.MatchLabels {
		if labels[k] != want {
			return false
		}
	}
	if len(s.Clusters.Allow) == 0 {
		// No explicit allow list: MatchLabels alone decides, and an empty
		// MatchLabels with an empty Allow authorizes nothing.
		return len(s.Clusters.MatchLabels) > 0
	}
	return slices.Contains(s.Clusters.Allow, "*") || slices.Contains(s.Clusters.Allow, id)
}

// AllowsTool reports whether the scope permits calling the named MCP tool.
func (s *Scope) AllowsTool(name string) bool {
	if s == nil {
		return false
	}
	for _, d := range s.Tools.Deny {
		if matchToolPattern(d, name) {
			return false
		}
	}
	for _, a := range s.Tools.Allow {
		if a == "*" || a == name {
			return true
		}
	}
	return false
}

// matchToolPattern matches an exact tool name or a trailing-wildcard pattern
// such as "admin.*". A bare "*" matches everything.
func matchToolPattern(pattern, name string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, ".*"):
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	default:
		return pattern == name
	}
}

// Validate reports whether the scope is internally consistent.
func (s *Scope) Validate() error {
	if s == nil {
		return fmt.Errorf("scope is required")
	}
	if !s.Role.Valid() {
		return fmt.Errorf("invalid role %q", s.Role)
	}
	if s.Role == RoleAdmin {
		return fmt.Errorf("role %q cannot be granted to an agent key", RoleAdmin)
	}
	if len(s.Clusters.Allow) == 0 && len(s.Clusters.MatchLabels) == 0 {
		return fmt.Errorf("clusters: one of allow or matchLabels is required")
	}
	if len(s.Tools.Allow) == 0 {
		return fmt.Errorf("tools.allow is required (deny-by-default)")
	}
	if slices.Contains(s.Clusters.Deny, "*") {
		return fmt.Errorf("clusters.deny does not accept the wildcard %q", "*")
	}
	if s.Limits.MaxPoints < 0 || s.Limits.MaxSeries < 0 || s.Limits.MaxResponseBytes < 0 {
		return fmt.Errorf("limits must not be negative")
	}
	return nil
}
