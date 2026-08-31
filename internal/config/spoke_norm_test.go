// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestNormaliseSDLC pins the repairs the loader makes before validating.
//
// The stage is required and becomes a label an agent key scope selects on, so a
// fleet has to agree on one spelling. Refusing an operator's capitalisation
// would achieve that by making them retype it; normalising achieves it without
// the argument. What is NOT repaired is anything that would change the meaning
// of the value rather than its spelling — a "!" is still an error.
func TestNormaliseSDLC(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, in, want string }{
		{"already canonical", "prod", "prod"},
		{"uppercase", "PROD", "prod"},
		{"mixed case with surrounding space", "  Prod ", "prod"},
		{"internal space becomes a hyphen", "Pre Prod", "pre-prod"},
		{"underscores become hyphens", "pre_prod", "pre-prod"},
		{"runs of separators collapse", "PRE__  PROD", "pre-prod"},
		{"existing hyphen is preserved", "non-prod", "non-prod"},
		{"leading separator is dropped", "_prod", "prod"},
		{"trailing separator is dropped", "prod-", "prod"},
		{"tab is a separator", "pre\tprod", "pre-prod"},
		{"empty stays empty for Validate to reject", "   ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormaliseSDLC(tc.in); got != tc.want {
				t.Errorf("NormaliseSDLC(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLoadSpokeNormalisesSDLC proves the repair happens on the load path, not
// merely in the helper: an operator who sets PMF_CLUSTER_SDLC=PROD must end up
// with a valid config, not a validation error.
func TestLoadSpokeNormalisesSDLC(t *testing.T) {
	t.Parallel()

	c, err := LoadSpoke(nil, env(map[string]string{
		"PMF_HUB_ENDPOINTS": "wss://hub.example.com/tunnel",
		"PMF_HUB_API_URL":   "https://hub.example.com",
		"PMF_CLUSTER_ID":    "prod-us-east-1",
		"PMF_CLUSTER_SDLC":  "Pre Prod",
	}))
	if err != nil {
		t.Fatalf("LoadSpoke() error = %v", err)
	}
	if c.ClusterSDLC != "pre-prod" {
		t.Errorf("ClusterSDLC = %q, want %q", c.ClusterSDLC, "pre-prod")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a normalisable stage", err)
	}
}
