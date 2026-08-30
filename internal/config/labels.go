// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// labelKeyRE is the Prometheus label-name grammar. Cluster labels become
// selector keys and metric-adjacent identifiers, so anything outside this
// grammar is refused rather than sanitised.
var labelKeyRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// clusterIDRE is the cluster identity grammar shared with enrollment. It is
// the RFC 1123 label form: lowercase alphanumerics and dashes, 1-63 bytes,
// starting and ending with an alphanumeric.
var clusterIDRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// MaxClusterLabels bounds how many labels one spoke may declare, so that a
// mis-set variable cannot inflate the cardinality of everything the hub
// derives from cluster labels.
const MaxClusterLabels = 32

// ParseClusterLabels parses the PMF_CLUSTER_LABELS form "k=v,k=v" into a map.
//
// An empty or whitespace-only input yields a nil map and no error. Surrounding
// whitespace around a key or a value is trimmed. An empty value is accepted; an
// empty key, a duplicate key, a key outside [labelKeyRE], a pair without "=",
// and a control character anywhere in a value are all rejected. It never
// panics, whatever the input.
func ParseClusterLabels(s string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	pairs := strings.Split(s, ",")
	if len(pairs) > MaxClusterLabels {
		return nil, fmt.Errorf("%w: %d labels exceeds the limit of %d",
			ErrInvalidLabels, len(pairs), MaxClusterLabels)
	}
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			return nil, fmt.Errorf("%w: empty label pair", ErrInvalidLabels)
		}
		rawKey, rawValue, found := strings.Cut(pair, "=")
		if !found {
			return nil, fmt.Errorf("%w: %q is not in k=v form", ErrInvalidLabels, pair)
		}
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" {
			return nil, fmt.Errorf("%w: empty label key in %q", ErrInvalidLabels, pair)
		}
		if !labelKeyRE.MatchString(key) {
			return nil, fmt.Errorf("%w: label key %q must match %s",
				ErrInvalidLabels, key, labelKeyRE)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: duplicate label key %q", ErrInvalidLabels, key)
		}
		if i := strings.IndexFunc(value, isControl); i >= 0 {
			return nil, fmt.Errorf("%w: label %q has a control character at byte %d",
				ErrInvalidLabels, key, i)
		}
		out[key] = value
	}
	return out, nil
}

// FormatClusterLabels renders labels back into the "k=v,k=v" form with keys in
// sorted order, so that a logged or echoed configuration is deterministic.
func FormatClusterLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+labels[k])
	}
	return strings.Join(pairs, ",")
}

// validateClusterLabels re-checks an already-populated label map, for the case
// where a Hub or Spoke value was built in code rather than parsed.
func validateClusterLabels(labels map[string]string) error {
	if len(labels) > MaxClusterLabels {
		return fmt.Errorf("%d labels exceeds the limit of %d", len(labels), MaxClusterLabels)
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !labelKeyRE.MatchString(k) {
			return fmt.Errorf("label key %q must match %s", k, labelKeyRE)
		}
		if i := strings.IndexFunc(labels[k], isControl); i >= 0 {
			return fmt.Errorf("label %q has a control character at byte %d", k, i)
		}
	}
	return nil
}

// isControl reports whether r is a C0 or C1 control character. Those have no
// legitimate place in a configuration value and are the raw material for log
// injection.
func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }
