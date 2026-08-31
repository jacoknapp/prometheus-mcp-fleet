// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// TestAlertsInvalidFormatAndState covers the two argument-validation errors
// alerts can raise on its own, before any upstream call.
func TestAlertsInvalidFormatAndState(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, Format: "yaml"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("format terr = %v, want INVALID_ARGUMENT", terr)
	}

	_, terr = h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, State: "silenced"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("state terr = %v, want INVALID_ARGUMENT", terr)
	}
	if len(h.prom.calls) != 0 {
		t.Error("an invalid argument still reached the upstream")
	}
}

// TestAlertsAlertnameFilterSkipsNonMatches proves the alertname filter
// actually discards the alerts that do not match it, not just keeps the ones
// that do.
func TestAlertsAlertnameFilterSkipsNonMatches(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.alerts(ctx(t), h.p,
		AlertsIn{Cluster: okCluster, State: AlertAll, Alertname: "Watchdog"})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if out.Total != 1 || len(out.Alerts) != 1 || out.Alerts[0].Alertname != "Watchdog" {
		t.Fatalf("alertname filter = %+v, want exactly Watchdog", out.Alerts)
	}
}

// TestAlertsLimitTruncates proves a limit below the match count truncates and
// records the fixed firing-then-severity selection strategy.
func TestAlertsLimitTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.alerts(ctx(t), h.p,
		AlertsIn{Cluster: okCluster, State: AlertAll, Limit: 1})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if out.Truncated == nil {
		t.Fatal("a 1-of-3 result was not marked truncated")
	}
	if out.Truncated.Selection != "firing_first_then_severity" {
		t.Errorf("selection = %q", out.Truncated.Selection)
	}
	if out.Truncated.Total != 3 || out.Truncated.Returned != 1 {
		t.Errorf("truncation = %+v", out.Truncated)
	}
}

// syntheticAlerts builds an /api/v1/alerts payload with n alerts, deliberately
// including: one alert with no severity label (the "unset" bucket), two
// firing+critical alerts whose names differ only in a way that forces the
// stable sort's alertname tie-break to run, and one alert in an upstream
// state alerts never filters for ("silenced"), which normalizeAlertState must
// fold onto "inactive" rather than invent a fifth state.
func syntheticAlerts(t *testing.T, n int) []byte {
	t.Helper()
	alerts := make([]any, 0, n+4)
	alerts = append(alerts,
		map[string]any{
			"labels":      map[string]string{"alertname": "NoSeverityLabel"},
			"annotations": map[string]string{},
			"state":       "firing",
			"activeAt":    "2026-08-29T10:00:00Z",
			"value":       "1",
		},
		map[string]any{
			"labels":      map[string]string{"alertname": "ZZZLastAlphabetically", "severity": "critical"},
			"annotations": map[string]string{},
			"state":       "firing",
			"activeAt":    "2026-08-29T10:00:00Z",
			"value":       "1",
		},
		map[string]any{
			"labels":      map[string]string{"alertname": "AAAFirstAlphabetically", "severity": "critical"},
			"annotations": map[string]string{},
			"state":       "firing",
			"activeAt":    "2026-08-29T10:00:00Z",
			"value":       "1",
		},
		map[string]any{
			"labels":      map[string]string{"alertname": "SilencedOne", "severity": "warning"},
			"annotations": map[string]string{},
			"state":       "silenced",
			"activeAt":    "2026-08-29T10:00:00Z",
			"value":       "1",
		},
	)
	for i := range n {
		alerts = append(alerts, map[string]any{
			"labels": map[string]string{
				"alertname": fmt.Sprintf("BulkAlert%04d", i), "severity": "warning",
			},
			"annotations": map[string]string{
				"summary": "padding text so the payload is large enough to exceed a small token ceiling",
			},
			"state":    "firing",
			"activeAt": "2026-08-29T10:00:00Z",
			"value":    "1",
		})
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data":   map[string]any{"alerts": alerts},
	})
	if err != nil {
		t.Fatalf("marshal synthetic alerts: %v", err)
	}
	return body
}

// TestAlertsSeverityBucketTieBreakAndUnknownState covers the "unset" severity
// bucket, the alertname tie-break inside the stable sort, and an upstream
// state outside {firing, pending} folding onto AlertInactive.
func TestAlertsSeverityBucketTieBreakAndUnknownState(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointAlerts), fakeResponse{body: syntheticAlerts(t, 0)})

	out, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, State: AlertAll, Limit: 300})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if out.Summary.BySeverity["unset"] != 1 {
		t.Errorf("bySeverity = %v, want one alert bucketed under \"unset\"", out.Summary.BySeverity)
	}

	var firstCritical, secondCritical string
	for _, a := range out.Alerts {
		if a.Severity != "critical" {
			continue
		}
		if firstCritical == "" {
			firstCritical = a.Alertname
		} else if secondCritical == "" {
			secondCritical = a.Alertname
		}
	}
	if firstCritical != "AAAFirstAlphabetically" || secondCritical != "ZZZLastAlphabetically" {
		t.Errorf("critical alerts sorted as %q then %q, want the alertname tie-break to order them alphabetically",
			firstCritical, secondCritical)
	}

	var sawInactive bool
	for _, a := range out.Alerts {
		if a.Alertname == "SilencedOne" {
			if a.State != AlertInactive {
				t.Errorf("silenced upstream state normalised to %q, want %q", a.State, AlertInactive)
			}
			sawInactive = true
		}
	}
	if !sawInactive {
		t.Fatal("the silenced alert did not survive state=all filtering")
	}
}

// TestAlertsTokenCeilingEscalatesTruncation proves a result that fits under
// limit but not under the hub's token ceiling is truncated a second time, and
// that the escalation keeps the fixed selection strategy and the honest total.
func TestAlertsTokenCeilingEscalatesTruncation(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointAlerts), fakeResponse{body: syntheticAlerts(t, 200)})

	out, terr := h.tools.alerts(ctx(t), h.p,
		AlertsIn{Cluster: okCluster, State: AlertAll, Limit: 300, IncludeAnnotations: true})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Selection != "firing_first_then_severity" {
		t.Errorf("selection = %q", out.Truncated.Selection)
	}
	if out.Truncated.Total != 204 {
		t.Errorf("total = %d, want the honest 204", out.Truncated.Total)
	}
}

// TestAlertRankFullOrdering builds one alert for every (state, severity)
// bucket alertRank distinguishes, submits them out of rank order, and asserts
// the exact resulting alertname sequence. This pins both the sign of the
// alertRank(a) - alertRank(b) comparison (a subtraction, negation or
// arithmetic-base mutation there scrambles the order) and the exact +1/+2
// offsets alertRank adds for warning and other severities.
func TestAlertRankFullOrdering(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	mk := func(name, state, severity string) map[string]any {
		labels := map[string]string{"alertname": name}
		if severity != "" {
			labels["severity"] = severity
		}
		return map[string]any{
			"labels": labels, "annotations": map[string]string{},
			"state": state, "activeAt": "2026-08-29T10:00:00Z", "value": "1",
		}
	}
	// Deliberately submitted scrambled: worst-rank first, best-rank last.
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{"alerts": []any{
			mk("PendingOther", "pending", "info"),
			mk("PendingWarning", "pending", "warning"),
			mk("PendingCritical", "pending", "critical"),
			mk("FiringOther", "firing", "info"),
			mk("FiringWarning", "firing", "warning"),
			mk("FiringCritical", "firing", "critical"),
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h.prom.set(string(promapi.EndpointAlerts), fakeResponse{body: body})

	out, terr := h.tools.alerts(ctx(t), h.p, AlertsIn{Cluster: okCluster, State: AlertAll, Limit: 300})
	if terr != nil {
		t.Fatalf("alerts: %v", terr)
	}
	want := []string{
		"FiringCritical", "FiringWarning", "FiringOther",
		"PendingCritical", "PendingWarning", "PendingOther",
	}
	if len(out.Alerts) != len(want) {
		t.Fatalf("got %d alerts, want %d: %+v", len(out.Alerts), len(want), out.Alerts)
	}
	var got []string
	for _, a := range out.Alerts {
		got = append(got, a.Alertname)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("alert order = %v, want %v", got, want)
	}
}

// TestAlertRankValues pins alertRank's exact integer output for every
// state/severity combination, including the default-severity +2 offset.
func TestAlertRankValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		state    string
		severity string
		want     int
	}{
		{"firing critical", AlertFiring, "critical", 0},
		{"firing warning", AlertFiring, "warning", 1},
		{"firing other", AlertFiring, "info", 2},
		{"pending critical", AlertPending, "critical", 10},
		{"pending warning", AlertPending, "warning", 11},
		{"pending other", AlertPending, "info", 12},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := alertRank(AlertInfo{State: tc.state, Severity: tc.severity})
			if got != tc.want {
				t.Errorf("alertRank(%q, %q) = %d, want %d", tc.state, tc.severity, got, tc.want)
			}
		})
	}
}

// TestConvertAlertLabelsAndAnnotationsBoundary pins the exact len(...) > 0
// boundary convertAlert uses to decide whether Labels/Annotations is nil or
// populated: one case sits with the collection empty after filtering, the
// other with exactly one surviving entry.
func TestConvertAlertLabelsAndAnnotationsBoundary(t *testing.T) {
	t.Parallel()

	// Labels boundary: after alertname/severity are removed, nothing is left.
	bare := convertAlert(upstreamAlert{
		Labels: map[string]string{"alertname": "X", "severity": "warning"},
	}, false)
	if bare.Labels != nil {
		t.Errorf("Labels = %v, want nil with none left after alertname/severity removal", bare.Labels)
	}

	// Labels boundary: exactly one label survives.
	withOne := convertAlert(upstreamAlert{
		Labels: map[string]string{"alertname": "X", "severity": "warning", "pod": "p1"},
	}, false)
	if len(withOne.Labels) != 1 || withOne.Labels["pod"] != "p1" {
		t.Errorf("Labels = %v, want exactly {pod: p1}", withOne.Labels)
	}

	// Annotations boundary: every annotation is filtered out (one has an
	// invalid label-name key, the other sanitises to empty).
	noAnn := convertAlert(upstreamAlert{
		Annotations: map[string]string{"1bad": "value", "empty": ""},
	}, true)
	if noAnn.Annotations != nil {
		t.Errorf("Annotations = %v, want nil when every entry is filtered out", noAnn.Annotations)
	}

	// Annotations boundary: exactly one annotation survives.
	oneAnn := convertAlert(upstreamAlert{
		Annotations: map[string]string{"summary": "ok", "1bad": "value"},
	}, true)
	if len(oneAnn.Annotations) != 1 || oneAnn.Annotations["summary"] != "ok" {
		t.Errorf("Annotations = %v, want exactly {summary: ok}", oneAnn.Annotations)
	}
}

// TestRulesInvalidFormat covers rules' own argument-validation error.
func TestRulesInvalidFormat(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Format: "yaml"})
	if terr == nil || terr.Code != CodeInvalidArgument {
		t.Fatalf("terr = %v, want INVALID_ARGUMENT", terr)
	}
}

// TestRulesTypeFilterRestrictsUpstreamQuery proves a concrete (non-"all") type
// is both sent upstream and used to restrict what comes back.
func TestRulesTypeFilterRestrictsUpstreamQuery(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Type: RuleTypeAlert})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	form := h.prom.lastForm(promapi.EndpointRules)
	if len(form["type"]) != 1 || form["type"][0] != RuleTypeAlert {
		t.Errorf("form = %v, want type=alert sent upstream", form)
	}
}

// TestRulesLimitTruncates mirrors TestAlertsLimitTruncates: a limit below the
// match count truncates and records the fixed selection strategy.
func TestRulesLimitTruncates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Limit: 1})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if out.Truncated == nil {
		t.Fatal("a 1-of-4 result was not marked truncated")
	}
	if out.Truncated.Selection != "unhealthy_first_then_group_name" {
		t.Errorf("selection = %q", out.Truncated.Selection)
	}
}

// TestRulesUpstreamFailure covers the proxy-error mapping path.
func TestRulesUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointRules), fakeResponse{err: errors.New("boom")})
	_, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeUpstreamError {
		t.Fatalf("terr = %v, want UPSTREAM_ERROR", terr)
	}
}

// TestRulesMalformedUpstream covers the decode-data failure path, distinct
// from a non-JSON body: this is a well-formed envelope whose data member does
// not match the rules shape.
func TestRulesMalformedUpstream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointRules), fakeResponse{
		body: []byte(`{"status":"success","data":"not-an-object"}`),
	})
	_, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster})
	if terr == nil || terr.Code != CodeMalformedUpstream {
		t.Fatalf("terr = %v, want MALFORMED_UPSTREAM", terr)
	}
}

// TestRulesGroupFilterSkipsOtherGroups proves the group filter discards rules
// belonging to a group that does not match, not just keeps the ones that do.
func TestRulesGroupFilterSkipsOtherGroups(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	out, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Group: "node-exporter.rules"})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if len(out.Groups) != 1 || out.Groups[0].Name != "node-exporter.rules" {
		t.Fatalf("group filter = %+v, want exactly node-exporter.rules", out.Groups)
	}
	for _, r := range out.Rules {
		if r.Group != "node-exporter.rules" {
			t.Errorf("group filter leaked a rule from %q", r.Group)
		}
	}
}

// syntheticRules builds an /api/v1/rules payload with one group holding: two
// same-health, same-state rules whose names differ only to force the ruleRank
// tie-break, one rule with Health "err" (the case ruleRank ranks first), and
// n padding rules with a long expression so the payload can be pushed past a
// small token ceiling.
func syntheticRules(t *testing.T, n int) []byte {
	t.Helper()
	rules := []any{
		map[string]any{
			"name": "ZZZLastAlphabetically", "type": "recording",
			"health": "ok", "query": "up",
		},
		map[string]any{
			"name": "AAAFirstAlphabetically", "type": "recording",
			"health": "ok", "query": "up",
		},
		map[string]any{
			"name": "BrokenRule", "type": "alerting", "state": "pending",
			"health": "err", "lastError": "boom", "query": "up",
		},
	}
	for i := range n {
		rules = append(rules, map[string]any{
			"name": fmt.Sprintf("PaddingRule%04d", i), "type": "recording", "health": "ok",
			"query": "sum by (job, instance, namespace) (rate(http_requests_total[5m])) " +
				"+ padding text to inflate the estimated token count of this rule expression",
		})
	}
	body, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"groups": []any{
				map[string]any{
					"name": "synthetic-group", "file": "/etc/rules/synthetic.yaml",
					"interval": 30, "evaluationTime": 0.001, "rules": rules,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal synthetic rules: %v", err)
	}
	return body
}

// TestRulesTieBreakAndHealthRank covers the ruleRank/name tie-break in the
// stable sort and the "unhealthy first" ordering guarantee.
func TestRulesTieBreakAndHealthRank(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.prom.set(string(promapi.EndpointRules), fakeResponse{body: syntheticRules(t, 0)})

	out, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Limit: 300})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if len(out.Rules) == 0 || out.Rules[0].Name != "BrokenRule" {
		t.Fatalf("rules = %+v, want the unhealthy rule first", out.Rules)
	}
	var first, second string
	for _, r := range out.Rules {
		if r.Health != "ok" || r.Type != "recording" {
			continue
		}
		if first == "" {
			first = r.Name
		} else if second == "" {
			second = r.Name
		}
	}
	if first != "AAAFirstAlphabetically" || second != "ZZZLastAlphabetically" {
		t.Errorf("tied rules sorted as %q then %q, want alphabetical by name", first, second)
	}
}

// TestRulesTokenCeilingEscalatesTruncation mirrors the alerts equivalent:
// under the count limit, over the token ceiling.
func TestRulesTokenCeilingEscalatesTruncation(t *testing.T) {
	t.Parallel()
	const ceiling = 300
	h := newHarness(t, func(o *Options) { o.TokenCeiling = ceiling })
	h.prom.set(string(promapi.EndpointRules), fakeResponse{body: syntheticRules(t, 200)})

	out, terr := h.tools.rules(ctx(t), h.p, RulesIn{Cluster: okCluster, Limit: 300, IncludeExpr: true})
	if terr != nil {
		t.Fatalf("rules: %v", terr)
	}
	if out.Truncated == nil || out.Truncated.Reason != render.ReasonTokenCeiling {
		t.Fatalf("truncation = %+v, want reason %q", out.Truncated, render.ReasonTokenCeiling)
	}
	if out.Truncated.Selection != "unhealthy_first_then_group_name" {
		t.Errorf("selection = %q", out.Truncated.Selection)
	}
	if out.Truncated.Total != 203 {
		t.Errorf("total = %d, want the honest 203", out.Truncated.Total)
	}
}
