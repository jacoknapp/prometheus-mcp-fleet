// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestScopeAllowsCluster(t *testing.T) {
	t.Parallel()

	prod := map[string]string{"env": "prod", "region": "us-east-1"}
	dev := map[string]string{"env": "dev", "region": "us-east-1"}

	tests := []struct {
		name   string
		scope  *Scope
		id     string
		labels map[string]string
		want   bool
	}{
		{
			name:  "nil scope authorizes nothing",
			scope: nil, id: "a", want: false,
		},
		{
			name:  "empty scope authorizes nothing",
			scope: &Scope{}, id: "a", want: false,
		},
		{
			name:  "explicit allow matches",
			scope: &Scope{Clusters: ClusterScope{Allow: []string{"a", "b"}}},
			id:    "b", want: true,
		},
		{
			name:  "explicit allow does not match a different id",
			scope: &Scope{Clusters: ClusterScope{Allow: []string{"a"}}},
			id:    "b", want: false,
		},
		{
			name:  "wildcard allow matches anything",
			scope: &Scope{Clusters: ClusterScope{Allow: []string{"*"}}},
			id:    "anything", want: true,
		},
		{
			name:  "label selector matches",
			scope: &Scope{Clusters: ClusterScope{MatchLabels: map[string]string{"env": "prod"}}},
			id:    "a", labels: prod, want: true,
		},
		{
			name:  "label selector rejects a non-match",
			scope: &Scope{Clusters: ClusterScope{MatchLabels: map[string]string{"env": "prod"}}},
			id:    "a", labels: dev, want: false,
		},
		{
			name: "every label in the selector must match",
			scope: &Scope{Clusters: ClusterScope{
				MatchLabels: map[string]string{"env": "prod", "region": "eu-west-1"},
			}},
			id: "a", labels: prod, want: false,
		},
		{
			name: "deny beats wildcard allow",
			scope: &Scope{Clusters: ClusterScope{
				Allow: []string{"*"}, Deny: []string{"pci"},
			}},
			id: "pci", want: false,
		},
		{
			name: "deny beats label selector",
			scope: &Scope{Clusters: ClusterScope{
				MatchLabels: map[string]string{"env": "prod"}, Deny: []string{"pci"},
			}},
			id: "pci", labels: prod, want: false,
		},
		{
			name: "allow and selector must both hold",
			scope: &Scope{Clusters: ClusterScope{
				Allow: []string{"a"}, MatchLabels: map[string]string{"env": "prod"},
			}},
			id: "a", labels: dev, want: false,
		},
		{
			name:  "missing label on the cluster is not a match",
			scope: &Scope{Clusters: ClusterScope{MatchLabels: map[string]string{"env": "prod"}}},
			id:    "a", labels: nil, want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.AllowsCluster(tc.id, tc.labels); got != tc.want {
				t.Errorf("AllowsCluster(%q, %v) = %v, want %v", tc.id, tc.labels, got, tc.want)
			}
		})
	}
}

func TestDurationString(t *testing.T) {
	t.Parallel()
	if got := Duration(90 * time.Second).String(); got != "1m30s" {
		t.Errorf("Duration.String() = %q, want 1m30s", got)
	}
}

func TestScopeAllowsTool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope *Scope
		tool  string
		want  bool
	}{
		{"nil scope", nil, "query", false},
		{"empty allow denies", &Scope{}, "query", false},
		{"exact allow", &Scope{Tools: ToolScope{Allow: []string{"query"}}}, "query", true},
		{"non-listed tool denied", &Scope{Tools: ToolScope{Allow: []string{"query"}}}, "targets", false},
		{"wildcard allow", &Scope{Tools: ToolScope{Allow: []string{"*"}}}, "anything", true},
		{
			"deny beats wildcard allow",
			&Scope{Tools: ToolScope{Allow: []string{"*"}, Deny: []string{"targets"}}},
			"targets", false,
		},
		{
			"prefix deny pattern",
			&Scope{Tools: ToolScope{Allow: []string{"*"}, Deny: []string{"admin.*"}}},
			"admin.rotate", false,
		},
		{
			// "administer" does not start with "admin.", so the deny pattern
			// must not swallow it and the wildcard allow still applies.
			"prefix deny does not over-match",
			&Scope{Tools: ToolScope{Allow: []string{"*"}, Deny: []string{"admin.*"}}},
			"administer", true,
		},
		{
			"deny wildcard denies everything",
			&Scope{Tools: ToolScope{Allow: []string{"query"}, Deny: []string{"*"}}},
			"query", false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.AllowsTool(tc.tool); got != tc.want {
				t.Errorf("AllowsTool(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

func TestMatchToolPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything", true},
		{"query", "query", true},
		{"query", "query_range", false},
		{"admin.*", "admin.keys", true},
		{"admin.*", "admin.", true},
		{"admin.*", "administer", false},
		{"admin.*", "admin", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if got := matchToolPattern(tc.pattern, tc.name); got != tc.want {
				t.Errorf("matchToolPattern(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
			}
		})
	}
}

func TestScopeValidate(t *testing.T) {
	t.Parallel()

	valid := func() *Scope {
		return &Scope{
			Role:     RoleViewer,
			Clusters: ClusterScope{Allow: []string{"*"}},
			Tools:    ToolScope{Allow: []string{"query"}},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Scope)
		scope   *Scope
		wantErr bool
	}{
		{name: "valid", mutate: func(*Scope) {}},
		{name: "nil scope", scope: nil, wantErr: true},
		{name: "invalid role", mutate: func(s *Scope) { s.Role = "root" }, wantErr: true},
		{name: "admin role rejected", mutate: func(s *Scope) { s.Role = RoleAdmin }, wantErr: true},
		{
			name:    "no cluster selector",
			mutate:  func(s *Scope) { s.Clusters = ClusterScope{} },
			wantErr: true,
		},
		{
			name:    "no tool allow list",
			mutate:  func(s *Scope) { s.Tools = ToolScope{} },
			wantErr: true,
		},
		{
			name:    "wildcard in cluster deny",
			mutate:  func(s *Scope) { s.Clusters.Deny = []string{"*"} },
			wantErr: true,
		},
		{
			name:    "negative limit",
			mutate:  func(s *Scope) { s.Limits.MaxPoints = -1 },
			wantErr: true,
		},
		{
			name:   "label selector alone is enough",
			mutate: func(s *Scope) { s.Clusters = ClusterScope{MatchLabels: map[string]string{"env": "prod"}} },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.scope
			if tc.mutate != nil {
				s = valid()
				tc.mutate(s)
			}
			err := s.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDurationJSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"seconds", `"30s"`, 30 * time.Second},
		{"hours", `"24h"`, 24 * time.Hour},
		{"compound", `"1h30m"`, 90 * time.Minute},
		{"null", `null`, 0},
		{"empty string", `""`, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var d Duration
			if err := json.Unmarshal([]byte(tc.in), &d); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.in, err)
			}
			if time.Duration(d) != tc.want {
				t.Fatalf("Unmarshal(%s) = %v, want %v", tc.in, time.Duration(d), tc.want)
			}
			// Re-marshalling a non-zero duration must produce a value that
			// parses back to the same duration.
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var again Duration
			if err := json.Unmarshal(b, &again); err != nil {
				t.Fatalf("Unmarshal(%s): %v", b, err)
			}
			if again != d {
				t.Fatalf("round trip changed %v to %v", d, again)
			}
		})
	}
}

func TestDurationUnmarshalRejectsGarbage(t *testing.T) {
	t.Parallel()

	var d Duration
	if err := json.Unmarshal([]byte(`"not-a-duration"`), &d); err == nil {
		t.Fatal("expected an error for an unparseable duration")
	}
}

func TestKeyLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Hour)

	tests := []struct {
		name        string
		key         Key
		wantExpired bool
		wantRevoked bool
		wantUsable  bool
	}{
		{
			name:       "live key",
			key:        Key{ExpiresAt: now.Add(time.Hour)},
			wantUsable: true,
		},
		{
			name:        "expired key",
			key:         Key{ExpiresAt: now.Add(-time.Hour)},
			wantExpired: true,
		},
		{
			name:       "zero expiry never expires",
			key:        Key{},
			wantUsable: true,
		},
		{
			name:        "revoked key",
			key:         Key{ExpiresAt: now.Add(time.Hour), RevokedAt: &revoked},
			wantRevoked: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.key.Expired(now); got != tc.wantExpired {
				t.Errorf("Expired() = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.key.Revoked(); got != tc.wantRevoked {
				t.Errorf("Revoked() = %v, want %v", got, tc.wantRevoked)
			}
			if got := tc.key.Usable(now); got != tc.wantUsable {
				t.Errorf("Usable() = %v, want %v", got, tc.wantUsable)
			}
		})
	}
}

func TestKeyMarshalOmitsSecretHMAC(t *testing.T) {
	t.Parallel()

	k := Key{KID: "abc", Class: ClassAgent, SecretHMAC: []byte("super-secret-hmac")}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// The stored HMAC must never reach an API response or a log line.
	if got := string(b); strings.Contains(got, "super-secret-hmac") ||
		strings.Contains(got, "SecretHMAC") {
		t.Fatalf("marshalled key leaked the secret HMAC: %s", got)
	}
}

func TestPrincipalString(t *testing.T) {
	t.Parallel()

	var nilPrincipal *Principal
	if got := nilPrincipal.String(); got != "anonymous" {
		t.Errorf("nil Principal.String() = %q, want %q", got, "anonymous")
	}

	p := &Principal{KID: "3Kf9aQ2mZx", Name: "sre-bot", Class: ClassAgent}
	if got := p.String(); got != "agt/3Kf9aQ2mZx(sre-bot)" {
		t.Errorf("Principal.String() = %q", got)
	}
}

func TestKeyClassAndRoleValidity(t *testing.T) {
	t.Parallel()

	for _, c := range []KeyClass{ClassAdmin, ClassAgent, ClassEnrollment} {
		if !c.Valid() {
			t.Errorf("KeyClass(%q).Valid() = false", c)
		}
	}
	if KeyClass("nope").Valid() {
		t.Error("unknown KeyClass reported valid")
	}
	for _, r := range []Role{RoleViewer, RoleOperator, RoleAdmin} {
		if !r.Valid() {
			t.Errorf("Role(%q).Valid() = false", r)
		}
	}
	if Role("root").Valid() {
		t.Error("unknown Role reported valid")
	}
}

func TestClusterHealthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state ClusterState
		want  bool
	}{
		{StateConnected, true},
		{StateDisconnected, false},
		{StateDegraded, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.state), func(t *testing.T) {
			t.Parallel()
			c := Cluster{State: tc.state}
			if got := c.Healthy(); got != tc.want {
				t.Errorf("Healthy() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestToolExplicitlyAllowed pins the by-name/wildcard distinction the role
// tier rides on: only a literal name in Allow is "explicit", and Deny beats
// an explicit allow the same way it beats everything else.
func TestToolExplicitlyAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope *Scope
		tool  string
		want  bool
	}{
		{"nil scope", nil, "targets", false},
		{"named", &Scope{Tools: ToolScope{Allow: []string{"targets"}}}, "targets", true},
		{"wildcard is not explicit", &Scope{Tools: ToolScope{Allow: []string{"*"}}}, "targets", false},
		{"absent", &Scope{Tools: ToolScope{Allow: []string{"query"}}}, "targets", false},
		{"deny beats an explicit allow", &Scope{Tools: ToolScope{Allow: []string{"targets"}, Deny: []string{"targets"}}}, "targets", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.ToolExplicitlyAllowed(tc.tool); got != tc.want {
				t.Errorf("ToolExplicitlyAllowed(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}
