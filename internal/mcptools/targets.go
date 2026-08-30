// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Target health values. Closed set, matching Prometheus' own.
const (
	// HealthUp means the last scrape succeeded.
	HealthUp = "up"
	// HealthDown means the last scrape failed.
	HealthDown = "down"
	// HealthUnknown means the target has not been scraped yet.
	HealthUnknown = "unknown"
	// HealthAny is the filter value that selects every health.
	HealthAny = "any"
)

// Target state values accepted by the state filter.
const (
	// TargetStateActive selects targets currently being scraped.
	TargetStateActive = "active"
	// TargetStateDropped selects targets discovery found and relabelling
	// dropped.
	TargetStateDropped = "dropped"
	// TargetStateAny selects both.
	TargetStateAny = "any"
)

// TargetsIn is the argument object of targets.
type TargetsIn struct {
	// Cluster names the target.
	Cluster string `json:"cluster" jsonschema:"Cluster name, exactly as returned by list_clusters."`
	// State selects active or dropped targets.
	State string `json:"state,omitempty" jsonschema:"Which targets to report."`
	// Health filters by scrape health.
	Health string `json:"health,omitempty" jsonschema:"Filter by scrape health. Use \"down\" to go straight to what is broken."`
	// Job filters to one scrape job.
	Job string `json:"job,omitempty" jsonschema:"Restrict to one scrape job, matched exactly against the job label."`
	// Limit caps the returned targets.
	Limit int `json:"limit,omitempty" jsonschema:"Maximum targets to return. The summary counts every target regardless of this limit."`
	// Format selects the encoding.
	Format string `json:"format,omitempty" jsonschema:"Output encoding. table is the cheapest for this tool. format \"json\" is refused here because the raw payload carries scrape URLs, which routinely embed credentials."`
}

// TargetSummary is the fleet-cheap part of a targets result: it answers "is
// anything broken" without carrying a row per target.
type TargetSummary struct {
	// Up, Down and Unknown count every matching target, before any limit.
	Up      int `json:"up,omitempty"`
	Down    int `json:"down,omitempty"`
	Unknown int `json:"unknown,omitempty"`
	// ByJob breaks the counts down per scrape job.
	ByJob map[string]JobHealth `json:"byJob,omitempty"`
}

// JobHealth is one job's scrape health counts.
type JobHealth struct {
	Up      int `json:"up,omitempty"`
	Down    int `json:"down,omitempty"`
	Unknown int `json:"unknown,omitempty"`
}

// TargetInfo is one scrape target, redacted.
//
// There is deliberately no scrape URL here. A scrape configuration routinely
// carries a bearer token or an API key as a query parameter, and Prometheus
// reports the fully-rendered URL in scrapeUrl and globalUrl. Emitting either
// would hand a credential to a language model, which will put it in a
// transcript, which is the end of that credential. Only the host survives.
type TargetInfo struct {
	// Job is the target's job label.
	Job string `json:"job,omitempty"`
	// Instance is the target's instance label.
	Instance string `json:"instance,omitempty"`
	// Health is one of the Health constants.
	Health string `json:"health,omitempty"`
	// Pool is the scrape pool with any query string removed.
	Pool string `json:"pool,omitempty"`
	// EndpointHost is the host and port of the scrape URL, with the scheme,
	// path, credentials and query string discarded.
	EndpointHost string `json:"endpointHost,omitempty"`
	// LastScrape is when the target was last scraped, RFC 3339.
	LastScrape string `json:"lastScrape,omitempty"`
	// ScrapeDurationMs is how long the last scrape took.
	ScrapeDurationMs float64 `json:"scrapeDurationMs,omitempty"`
	// ScrapeInterval is the configured interval.
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
	// LastError is the last scrape error, sanitised and clipped. It is remote
	// data.
	LastError string `json:"lastError,omitempty"`
	// Labels are the target's own labels, minus job and instance which have
	// their own fields.
	Labels map[string]string `json:"labels,omitempty"`
}

// TargetsOut is the result of targets.
type TargetsOut struct {
	Envelope
	// Summary counts every matching target.
	Summary TargetSummary `json:"summary,omitzero"`
	// Targets are the matching targets, down ones first.
	Targets []TargetInfo `json:"targets,omitempty"`
	// Total is how many matched before truncation.
	Total int `json:"total,omitempty"`
	// Truncated is set when targets were dropped.
	Truncated *render.Truncation `json:"truncated,omitempty"`
	// Redacted names the upstream fields this hub removed, so an operator
	// comparing against a raw curl is not left wondering.
	Redacted []string `json:"redacted,omitempty"`
	// Table is the fixed-width rendering, set only for format "table".
	Table string `json:"table,omitempty"`
}

// redactedTargetFields is what never leaves the hub, named in the result.
var redactedTargetFields = []string{"scrapeUrl", "globalUrl", "discoveredLabels", "scrapePool query string"}

// upstreamTargets is the /api/v1/targets payload.
type upstreamTargets struct {
	ActiveTargets []struct {
		Labels             map[string]string `json:"labels"`
		ScrapePool         string            `json:"scrapePool"`
		ScrapeURL          string            `json:"scrapeUrl"`
		GlobalURL          string            `json:"globalUrl"`
		LastError          string            `json:"lastError"`
		LastScrape         string            `json:"lastScrape"`
		LastScrapeDuration float64           `json:"lastScrapeDuration"`
		Health             string            `json:"health"`
		ScrapeInterval     string            `json:"scrapeInterval"`
	} `json:"activeTargets"`
	DroppedTargets []struct {
		DiscoveredLabels map[string]string `json:"discoveredLabels"`
		ScrapePool       string            `json:"scrapePool"`
	} `json:"droppedTargets"`
}

// targets reports scrape target health, redacted and summarised.
func (t *Tools) targets(
	ctx context.Context, p *fleet.Principal, in TargetsIn,
) (*TargetsOut, *ToolError) {
	c, terr := t.resolveCluster(p, in.Cluster)
	if terr != nil {
		return nil, terr
	}
	// Passthrough is refused rather than redacted-and-passed-through: there is
	// no honest way to hand back "the raw Prometheus shape" once the fields
	// carrying credentials have been removed from it.
	format, terr := parseFormat(in.Format, false)
	if terr != nil {
		return nil, terr
	}
	state := in.State
	if state == "" {
		state = TargetStateActive
	}
	if !includes([]string{TargetStateActive, TargetStateDropped, TargetStateAny}, state) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("state %q is not one of active, dropped, any", render.ClipRunes(state, 32)),
			false).WithInput(map[string]any{"cluster": c.ID, "state": render.ClipRunes(state, 32)})
	}
	health := in.Health
	if health == "" {
		health = HealthAny
	}
	if !includes([]string{HealthAny, HealthUp, HealthDown, HealthUnknown}, health) {
		return nil, newError(CodeInvalidArgument,
			fmt.Sprintf("health %q is not one of any, up, down, unknown",
				render.ClipRunes(health, 32)), false).
			WithInput(map[string]any{"cluster": c.ID, "health": render.ClipRunes(health, 32)})
	}

	form := url.Values{}
	form.Set("state", state)

	env, _, terr := t.fetch(ctx, p, promproxy.Call{
		ClusterID: c.ID,
		Endpoint:  promapi.EndpointTargets,
		Form:      form,
	}, kindPlain)
	if terr != nil {
		return nil, terr
	}
	var raw upstreamTargets
	if terr := decodeData(env, c.ID, &raw); terr != nil {
		return nil, terr
	}

	out := &TargetsOut{Envelope: untrusted(), Redacted: redactedTargetFields}
	summary := TargetSummary{ByJob: map[string]JobHealth{}}
	matched := make([]TargetInfo, 0, len(raw.ActiveTargets))

	for _, at := range raw.ActiveTargets {
		ti := redactTarget(at.Labels, at.ScrapePool, at.ScrapeURL, at.Health,
			at.LastScrape, at.LastError, at.ScrapeInterval, at.LastScrapeDuration)
		if in.Job != "" && ti.Job != in.Job {
			continue
		}
		countTarget(&summary, ti)
		if health != HealthAny && ti.Health != health {
			continue
		}
		matched = append(matched, ti)
	}
	for _, dt := range raw.DroppedTargets {
		ti := redactTarget(dt.DiscoveredLabels, dt.ScrapePool, "", HealthUnknown, "", "", "", 0)
		ti.Health = HealthUnknown
		if in.Job != "" && ti.Job != in.Job {
			continue
		}
		countTarget(&summary, ti)
		if health != HealthAny && ti.Health != health {
			continue
		}
		matched = append(matched, ti)
	}

	// Down first, then by job and instance: the broken targets are why anyone
	// calls this tool, and a truncated result must not lose them.
	slices.SortStableFunc(matched, func(a, b TargetInfo) int {
		if rank := healthRank(a.Health) - healthRank(b.Health); rank != 0 {
			return rank
		}
		if v := strings.Compare(a.Job, b.Job); v != 0 {
			return v
		}
		return strings.Compare(a.Instance, b.Instance)
	})

	out.Summary = summary
	out.Total = len(matched)
	limit := clampInt(in.Limit, 50, 1, 500)
	kept, trunc := render.TruncateItems(matched, limit,
		"Filter with health \"down\" or with job rather than raising limit; the summary "+
			"already counts every target.")
	out.Truncated = trunc
	if trunc != nil {
		trunc.Selection = "down_first_then_job_instance"
	}
	fitted, hit := render.FitTokens(kept, t.tokenCeiling, func(s []TargetInfo) any {
		return &TargetsOut{Targets: s}
	})
	if hit {
		out.Truncated = trunc.Escalate(len(fitted), render.ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of limit. "+
				"Filter with health or job.", t.tokenCeiling))
		out.Truncated.Total = len(matched)
		out.Truncated.Selection = "down_first_then_job_instance"
	}
	out.Targets = fitted
	if format == render.FormatTable {
		out.Table = targetTable(fitted)
		out.Targets = nil
	}
	return out, nil
}

// redactTarget builds a [TargetInfo], dropping every field that can carry a
// credential.
func redactTarget(
	labels map[string]string, pool, scrapeURL, health, lastScrape, lastError, interval string,
	durSecs float64,
) TargetInfo {
	clean := render.Labels(labels)
	ti := TargetInfo{
		Job:              clean["job"],
		Instance:         clean["instance"],
		Health:           normalizeHealth(health),
		Pool:             redactPool(pool),
		EndpointHost:     hostOnly(scrapeURL),
		LastScrape:       render.ClipRunes(lastScrape, 40),
		ScrapeDurationMs: round2(durSecs * 1000),
		ScrapeInterval:   render.ClipRunes(interval, 32),
		LastError:        render.ScrapeError(RedactURLQueries(lastError)),
	}
	delete(clean, "job")
	delete(clean, "instance")
	// Discovery meta-labels are dropped wholesale: __param_* is where an
	// authentication parameter lands, and none of them help an agent.
	for k := range clean {
		if strings.HasPrefix(k, "__") {
			delete(clean, k)
		}
	}
	if len(clean) > 0 {
		ti.Labels = clean
	}
	return ti
}

// urlWithQueryRE matches an http or https URL carrying a query string or a
// fragment, wherever it appears inside a larger message.
var urlWithQueryRE = regexp.MustCompile(`(https?://[^\s"'` + "`" + `]*?)[?#][^\s"'` + "`" + `]*`)

// RedactURLQueries removes the query string from every URL embedded in a free
// text message.
//
// A scrape error is not a URL field, so it escapes the field-level redaction —
// but Prometheus renders the failing request into the message, and a target
// scraped with a token in its query string produces
// `Get "https://host/metrics?token=..." : dial tcp ...`. The host stays,
// because it is what makes the error diagnosable; everything after the
// question mark goes.
func RedactURLQueries(s string) string {
	return urlWithQueryRE.ReplaceAllString(s, "$1?[redacted]")
}

// redactPool strips a query string from a scrape pool name. A pool name is
// normally a service-monitor path, but a file-based or HTTP service discovery
// pool is named after its source, which can be a URL with a token in it.
func redactPool(pool string) string {
	if i := strings.IndexAny(pool, "?#"); i >= 0 {
		pool = pool[:i] + "?[redacted]"
	}
	return render.ClipRunes(pool, 200)
}

// hostOnly reduces a scrape URL to host and port. Scheme, path, user
// information and query string are all discarded; the query string is where
// the credential lives.
func hostOnly(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return render.ClipRunes(u.Host, 253)
}

// normalizeHealth maps an upstream health onto the closed set.
func normalizeHealth(h string) string {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case HealthUp:
		return HealthUp
	case HealthDown:
		return HealthDown
	default:
		return HealthUnknown
	}
}

// healthRank orders health values so down sorts first.
func healthRank(h string) int {
	switch h {
	case HealthDown:
		return 0
	case HealthUnknown:
		return 1
	default:
		return 2
	}
}

// countTarget folds one target into the summary.
func countTarget(s *TargetSummary, ti TargetInfo) {
	jh := s.ByJob[ti.Job]
	switch ti.Health {
	case HealthUp:
		s.Up++
		jh.Up++
	case HealthDown:
		s.Down++
		jh.Down++
	default:
		s.Unknown++
		jh.Unknown++
	}
	s.ByJob[ti.Job] = jh
}

// targetTable renders targets as fixed-width text.
func targetTable(ts []TargetInfo) string {
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, []string{
			t.Job, t.Instance, t.Health,
			strconv.FormatFloat(t.ScrapeDurationMs, 'f', 1, 64),
			t.LastError,
		})
	}
	return render.Table([]string{"JOB", "INSTANCE", "HEALTH", "MS", "LAST_ERROR"}, rows)
}
