// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package hubcli implements the hub binary's administrative subcommands.
//
// These exist because onboarding a cluster otherwise means hand-writing JSON
// against the admin API. The documented flow is
// `kubectl exec deploy/pmf-hub -- hub enroll create ...`, which works because
// the admin listener binds to loopback inside the hub pod and is never exposed
// through a Service: exec'ing into the pod is already the privileged path, so
// the credential never crosses the network.
//
// The commands are thin HTTP clients over the admin API rather than direct
// store access. That is deliberate. The API applies the validation, the
// revocation checks, the caps and the audit logging, and a CLI that reached
// past it into the store would be a second, weaker way to mint credentials.
package hubcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
)

// DefaultAdminURL is the hub's loopback admin listener.
const DefaultAdminURL = "http://127.0.0.1:9091"

// requestTimeout bounds a single admin call. These are local, in-pod requests
// against an API that does no long work, so a short bound is right: a CLI that
// hangs indefinitely inside `kubectl exec` is worse than one that fails.
const requestTimeout = 30 * time.Second

// ErrUsage is returned when arguments do not name a command.
var ErrUsage = errors.New("usage: hub <enroll|keys> <create> [flags]")

// Doer is the subset of *http.Client the commands need, so tests can drive
// them without a listener.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Run executes one administrative subcommand.
//
// getenv supplies PMF_ADMIN_TOKEN and optionally PMF_ADMIN_URL. client may be
// nil, in which case a default HTTP client is used.
func Run(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	if len(args) < 2 {
		return ErrUsage
	}
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	switch args[0] + " " + args[1] {
	case "enroll create":
		return enrollCreate(ctx, args[2:], getenv, stdout, client)
	case "keys create":
		return keysCreate(ctx, args[2:], getenv, stdout, client)
	default:
		return ErrUsage
	}
}

// enrollCreate mints an enrollment token bound to one cluster.
func enrollCreate(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub enroll create", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		cluster   = fs.String("cluster", "", "cluster ID the token is bound to (required)")
		labels    = fs.String("labels", "", "comma-separated k=v labels stamped on the cluster")
		name      = fs.String("name", "", "operator label for the token itself")
		owner     = fs.String("owner", "", "free-form contact information")
		ttl       = fs.Duration("ttl", 0, "token lifetime; zero means the hub's default")
		singleUse = fs.Bool("single-use", false,
			"burn the token on first redemption. Off by default: a single-use token cannot be "+
				"committed to git, cannot survive a cluster rebuild, and cannot serve several "+
				"spoke pods that start together, so in practice it works only for a human "+
				"installing one cluster by hand and watching it")
		maxRedemptions = fs.Int("max-redemptions", 0, "cap a reusable token; zero means no cap")
		quiet          = fs.Bool("quiet", false, "print only the token, for scripting")
		adminURL       = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile      = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cluster == "" {
		return errors.New("--cluster is required")
	}
	parsed, err := parseLabels(*labels)
	if err != nil {
		return err
	}
	body := hubapi.CreateEnrollmentRequest{
		ClusterID:      *cluster,
		Labels:         parsed,
		Name:           *name,
		Owner:          *owner,
		Reusable:       !*singleUse,
		MaxRedemptions: *maxRedemptions,
	}
	if *ttl > 0 {
		body.TTL = fleet.Duration(*ttl)
	}
	var out hubapi.MintedKeyResponse
	if err := post(ctx, client, resolveURL(*adminURL, getenv)+"/admin/v1/enrollments", adminToken(*tokenFile, getenv), body, &out); err != nil {
		return err
	}
	return report(stdout, out, *quiet)
}

// keysCreate mints an agent or admin key.
func keysCreate(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub keys create", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		class     = fs.String("class", "", `credential class: "agent" or "admin" (required)`)
		name      = fs.String("name", "", "operator label such as sre-oncall-bot (required)")
		owner     = fs.String("owner", "", "free-form contact information")
		ttl       = fs.Duration("ttl", 0, "key lifetime; zero means the class default")
		clusters  = fs.String("clusters", "", `comma-separated cluster selectors an agent key may reach, or "*"`)
		tools     = fs.String("tools", "", `comma-separated tool names an agent key may call, or "*"`)
		quiet     = fs.Bool("quiet", false, "print only the token, for scripting")
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	cls, err := keyClass(*class)
	if err != nil {
		return err
	}
	body := hubapi.CreateKeyRequest{Class: cls, Name: *name, Owner: *owner}
	if *ttl > 0 {
		body.TTL = fleet.Duration(*ttl)
	}
	if cls == fleet.ClassAgent {
		// An admin key is refused a scope by the API, so one is attached only
		// for an agent key rather than sent and rejected.
		body.Scope = &fleet.Scope{
			// Viewer is the least authority that can still read, which is the
			// right default for a credential minted from a one-line command.
			// Widening it is a deliberate act through the API.
			Role:     fleet.RoleViewer,
			Clusters: clusterScope(*clusters),
			Tools:    fleet.ToolScope{Allow: splitList(*tools)},
		}
	}
	var out hubapi.MintedKeyResponse
	if err := post(ctx, client, resolveURL(*adminURL, getenv)+"/admin/v1/keys", adminToken(*tokenFile, getenv), body, &out); err != nil {
		return err
	}
	return report(stdout, out, *quiet)
}

// keyClass maps the friendly command-line spelling onto the wire value.
func keyClass(s string) (fleet.KeyClass, error) {
	switch s {
	case "agent", string(fleet.ClassAgent):
		return fleet.ClassAgent, nil
	case "admin", string(fleet.ClassAdmin):
		return fleet.ClassAdmin, nil
	case "":
		return "", errors.New("--class is required: agent or admin")
	default:
		return "", fmt.Errorf("unknown class %q: want agent or admin", s)
	}
}

// clusterScope reads --clusters, which accepts exact cluster IDs and k=v label
// selectors in the same list because both spellings appear in the docs and an
// operator should not have to know which one this flag wanted. An entry with an
// "=" is a label requirement; anything else is a cluster ID.
func clusterScope(s string) fleet.ClusterScope {
	var out fleet.ClusterScope
	for _, entry := range splitList(s) {
		if k, v, ok := strings.Cut(entry, "="); ok && strings.TrimSpace(k) != "" {
			if out.MatchLabels == nil {
				out.MatchLabels = make(map[string]string)
			}
			out.MatchLabels[strings.TrimSpace(k)] = strings.TrimSpace(v)
			continue
		}
		out.Allow = append(out.Allow, entry)
	}
	return out
}

// splitList turns a comma-separated flag into a slice, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseLabels parses k=v[,k=v...] into a map.
func parseLabels(s string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("label %q is not k=v", pair)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

// resolveURL picks the admin base URL from the flag, the environment, or the
// loopback default, in that order.
func resolveURL(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/")
	}
	if env := getenv("PMF_ADMIN_URL"); env != "" {
		return strings.TrimRight(env, "/")
	}
	return DefaultAdminURL
}

// adminToken resolves the admin credential, preferring a file.
//
// The documented invocation is `kubectl exec deploy/pmf-hub -- hub enroll
// create ...`, and there is no way to set an environment variable on an exec
// without putting it in the argument list, where it lands in the node's process
// table. A file lets the credential be mounted from a Secret instead. It
// returns a func so the failure surfaces at the request, next to the URL it was
// for, rather than as a bare error with no context.
func adminToken(file string, getenv func(string) string) func() (string, error) {
	return func() (string, error) {
		if file != "" {
			raw, err := os.ReadFile(file)
			if err != nil {
				return "", fmt.Errorf("read admin token file: %w", err)
			}
			token := strings.TrimSpace(string(raw))
			if token == "" {
				return "", fmt.Errorf("admin token file %s is empty", file)
			}
			return token, nil
		}
		if token := getenv("PMF_ADMIN_TOKEN"); token != "" {
			return token, nil
		}
		return "", errors.New(
			"no admin credential: set PMF_ADMIN_TOKEN or pass --admin-token-file")
	}
}

// post sends one authenticated admin request and decodes the reply.
func post(ctx context.Context, client Doer, url string, tokenFn func() (string, error), in, out any) error {
	token, err := tokenFn()
	if err != nil {
		return err
	}
	payload, marshalErr := json.Marshal(in)
	if marshalErr != nil {
		return fmt.Errorf("encode request: %w", marshalErr)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the read: this is a trusted endpoint, but a CLI that buffers an
	// unbounded body because something else is listening on the port is a bad
	// failure mode.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var env hubapi.ErrorEnvelope
		if json.Unmarshal(body, &env) == nil && env.Error.Message != "" {
			return fmt.Errorf("%s: %s", resp.Status, env.Error.Message)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// report prints the minted credential. The token is shown once by the API and
// is never retrievable again, so --quiet exists to make piping it safe rather
// than forcing a caller to parse a human-readable block.
func report(stdout io.Writer, out hubapi.MintedKeyResponse, quiet bool) error {
	if quiet {
		_, err := fmt.Fprintln(stdout, out.Token)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "token:   %s\n", out.Token)
	fmt.Fprintf(&b, "kid:     %s\n", out.Key.KID)
	fmt.Fprintf(&b, "class:   %s\n", out.Key.Class)
	if !out.Key.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "expires: %s\n", out.Key.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if e := out.Key.Enrollment; e != nil {
		fmt.Fprintf(&b, "cluster: %s\n", e.ClusterID)
		if e.Reusable {
			limit := "unlimited"
			if e.MaxRedemptions > 0 {
				limit = fmt.Sprintf("%d", e.MaxRedemptions)
			}
			fmt.Fprintf(&b, "reusable: yes (redemptions: %s)\n", limit)
		}
		if len(e.Labels) > 0 {
			keys := make([]string, 0, len(e.Labels))
			for k := range e.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(keys))
			for _, k := range keys {
				pairs = append(pairs, k+"="+e.Labels[k])
			}
			fmt.Fprintf(&b, "labels:  %s\n", strings.Join(pairs, ","))
		}
	}
	b.WriteString("\nThis token is shown once and cannot be retrieved again.\n")
	_, err := io.WriteString(stdout, b.String())
	return err
}
