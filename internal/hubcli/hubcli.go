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
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	neturl "net/url"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubapi"
)

// DefaultAdminURL is the hub's loopback admin listener.
//
// It must track config.DefaultHubAdminAddr. It did not: this said 9091 while
// the hub listens on 9090, so every documented invocation that omitted
// --admin-url connected to nothing.
const DefaultAdminURL = "http://" + config.DefaultHubAdminAddr

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

// Nouns are the first words Run answers to. cmd/hub routes these to the CLI
// instead of the flag parser, so a noun missing here is a subcommand the
// binary refuses with the server's usage text.
var Nouns = []string{"enroll", "keys", "certs"}

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
	case "keys list":
		return keysList(ctx, args[2:], getenv, stdout, client)
	case "keys revoke":
		return keysRevoke(ctx, args[2:], getenv, stdout, client)
	case "keys rotate":
		return keysRotate(ctx, args[2:], getenv, stdout, client)
	case "enroll list":
		return enrollList(ctx, args[2:], getenv, stdout, client)
	case "enroll revoke":
		return enrollRevoke(ctx, args[2:], getenv, stdout, client)
	case "certs revoke":
		return certsRevoke(ctx, args[2:], getenv, stdout, client)
	case "certs list":
		return certsList(ctx, args[2:], getenv, stdout, client)
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
		noExpiry  = fs.Bool("no-expiry", false, "mint an agent key that never expires; revocation is then the only way to withdraw it")
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
	if *noExpiry && *ttl > 0 {
		// Caught here as well as at the hub so the contradiction is reported
		// before a round trip, with the flag spellings the operator typed.
		return errors.New("--ttl and --no-expiry are mutually exclusive")
	}
	body := hubapi.CreateKeyRequest{Class: cls, Name: *name, Owner: *owner, NoExpiry: *noExpiry}
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
			// #nosec G304 -- reading a path the operator named on their own
			// command line is the entire feature (--admin-token-file), and
			// this runs as that operator with their own privileges.
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
	return call(ctx, client, http.MethodPost, url, tokenFn, in, out)
}

// get performs an authenticated GET and decodes the response into out.
func get(ctx context.Context, client Doer, url string, tokenFn func() (string, error), out any) error {
	return call(ctx, client, http.MethodGet, url, tokenFn, nil, out)
}

// del performs an authenticated DELETE. out may be nil for the routes that
// answer 204.
func del(ctx context.Context, client Doer, url string, tokenFn func() (string, error), out any) error {
	return call(ctx, client, http.MethodDelete, url, tokenFn, nil, out)
}

// call is the one request path every subcommand goes through: attach the
// credential, bound the read, turn an error envelope back into the operator's
// message rather than a status line, and decode.
//
// in is encoded as a JSON body when non-nil; out is decoded into when non-nil,
// which the 204 routes skip.
func call(
	ctx context.Context,
	client Doer,
	method, url string,
	tokenFn func() (string, error),
	in, out any,
) error {
	token, err := tokenFn()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		payload, marshalErr := json.Marshal(in)
		if marshalErr != nil {
			return fmt.Errorf("encode request: %w", marshalErr)
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the read: this is a trusted endpoint, but a CLI that buffers an
	// unbounded body because something else is listening on the port is a bad
	// failure mode.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
	default:
		var env hubapi.ErrorEnvelope
		if json.Unmarshal(respBody, &env) == nil && env.Error.Message != "" {
			return fmt.Errorf("%s: %s", resp.Status, env.Error.Message)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	if out == nil || len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
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
	// Printed unconditionally: a key that never expires is a deliberate and
	// consequential choice, so "never" is stated rather than left to be
	// inferred from a missing line.
	if out.Key.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "expires: never\n")
	} else {
		fmt.Fprintf(&b, "expires: %s\n", out.Key.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if e := out.Key.Enrollment; e != nil {
		fmt.Fprintf(&b, "cluster: %s\n", e.ClusterID)
		if e.Reusable {
			limit := "unlimited"
			if e.MaxRedemptions > 0 {
				limit = strconv.Itoa(e.MaxRedemptions)
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

// keysList prints the stored credentials.
//
// The hub is the only place this list exists -- there is no database and the
// registry is rebuilt from reconnects -- so without this an operator's only
// route to "which keys exist" was a port-forward and curl.
func keysList(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub keys list", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		class     = fs.String("class", "", `restrict to one class: "agent", "admin" or "enrollment"`)
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	url := resolveURL(*adminURL, getenv) + "/admin/v1/keys"
	if *class != "" {
		cls, err := keyClassFilter(*class)
		if err != nil {
			return err
		}
		url += "?class=" + string(cls)
	}
	var out hubapi.KeyListResponse
	if err := get(ctx, client, url, adminToken(*tokenFile, getenv), &out); err != nil {
		return err
	}
	return printKeys(stdout, out.Keys)
}

// keysRevoke withdraws one credential.
//
// This is the control the threat model leans on: an agent key's expiry is not
// a backstop -- the default is ninety days and a key may be minted with none
// -- so revocation is what actually stops a leaked credential, and it should
// not require assembling an HTTP request by hand while under way.
func keysRevoke(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub keys revoke", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		kid    = fs.String("kid", "", "key identifier to revoke (required)")
		reason = fs.String("reason", "", "audit note recorded against the revocation")
		purge  = fs.Bool("purge", false,
			"delete the record outright instead of revoking it. Destroys the audit trail and "+
				"frees the identifier; revoking is almost always what you want")
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
	}
	url := resolveURL(*adminURL, getenv) + "/admin/v1/keys/" + neturl.PathEscape(*kid) + revokeQuery(*reason, *purge)
	if err := del(ctx, client, url, adminToken(*tokenFile, getenv), nil); err != nil {
		return err
	}
	verb := "revoked"
	if *purge {
		verb = "purged"
	}
	_, err := fmt.Fprintf(stdout, "%s %s\n", verb, *kid)
	return err
}

// keysRotate mints a replacement with the same identity and scope and revokes
// the original, as one store mutation.
//
// It is the response to a suspected compromise that does not take the caller
// offline: the replacement is live before the original stops working.
func keysRotate(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub keys rotate", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		kid       = fs.String("kid", "", "key identifier to rotate (required)")
		reason    = fs.String("reason", "", "audit note recorded against the credential being replaced")
		ttl       = fs.Duration("ttl", 0, "lifetime of the replacement; zero reuses the class default")
		noExpiry  = fs.Bool("no-expiry", false, "mint the replacement with no expiry; agent keys only")
		quiet     = fs.Bool("quiet", false, "print only the token, for scripting")
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
	}
	if *noExpiry && *ttl > 0 {
		return errors.New("--ttl and --no-expiry are mutually exclusive")
	}
	body := rotateBody{Reason: *reason, NoExpiry: *noExpiry}
	if *ttl > 0 {
		body.TTL = fleet.Duration(*ttl)
	}
	var out hubapi.MintedKeyResponse
	url := resolveURL(*adminURL, getenv) + "/admin/v1/keys/" + neturl.PathEscape(*kid) + "/rotate"
	if err := post(ctx, client, url, adminToken(*tokenFile, getenv), body, &out); err != nil {
		return err
	}
	return report(stdout, out, *quiet)
}

// rotateBody mirrors the rotate route's optional body. It is declared here
// rather than exported from hubapi because the route's own request type is
// unexported: the wire contract is the JSON, not the Go type.
type rotateBody struct {
	TTL      fleet.Duration `json:"ttl,omitempty"`
	NoExpiry bool           `json:"noExpiry,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// enrollList prints the enrollment tokens.
func enrollList(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub enroll list", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out hubapi.KeyListResponse
	url := resolveURL(*adminURL, getenv) + "/admin/v1/enrollments"
	if err := get(ctx, client, url, adminToken(*tokenFile, getenv), &out); err != nil {
		return err
	}
	return printKeys(stdout, out.Keys)
}

// enrollRevoke withdraws an enrollment token that has not been redeemed, or
// caps a reusable one that has.
func enrollRevoke(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub enroll revoke", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		kid       = fs.String("kid", "", "enrollment token identifier to revoke (required)")
		reason    = fs.String("reason", "", "audit note recorded against the revocation")
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kid == "" {
		return errors.New("--kid is required")
	}
	url := resolveURL(*adminURL, getenv) + "/admin/v1/enrollments/" + neturl.PathEscape(*kid) + revokeQuery(*reason, false)
	if err := del(ctx, client, url, adminToken(*tokenFile, getenv), nil); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "revoked %s\n", *kid)
	return err
}

// certsRevoke denies one spoke certificate by serial.
//
// Revoking a certificate also terminates the live session presenting it, so
// this is how a compromised cluster is cut off rather than merely stopped
// from reconnecting.
func certsRevoke(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub certs revoke", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		serial    = fs.String("serial", "", "certificate serial in the hub CA's notation (required)")
		reason    = fs.String("reason", "", "audit note recorded against the revocation")
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serial == "" {
		return errors.New("--serial is required")
	}
	url := resolveURL(*adminURL, getenv) + "/admin/v1/certs/" + neturl.PathEscape(*serial) + "/revoke"
	var out map[string]any
	if err := post(ctx, client, url, adminToken(*tokenFile, getenv), hubapi.RevokeCertRequest{Reason: *reason}, &out); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "revoked certificate %s\n", *serial)
	return err
}

// certsList prints the certificate revocation list.
func certsList(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer, client Doer) error {
	fs := flag.NewFlagSet("hub certs list", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		adminURL  = fs.String("admin-url", "", "admin API base URL; defaults to $PMF_ADMIN_URL or "+DefaultAdminURL)
		tokenFile = fs.String("admin-token-file", "", "read the admin credential from a file instead of $PMF_ADMIN_TOKEN")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var out hubapi.RevokedCertListResponse
	url := resolveURL(*adminURL, getenv) + "/admin/v1/certs/revoked"
	if err := get(ctx, client, url, adminToken(*tokenFile, getenv), &out); err != nil {
		return err
	}
	if len(out.Revoked) == 0 {
		_, err := fmt.Fprintln(stdout, "no revoked certificates")
		return err
	}
	rows := make([][]string, 0, len(out.Revoked))
	for _, rc := range out.Revoked {
		rows = append(rows, []string{rc.Serial, stamp(rc.RevokedAt), stamp(rc.NotAfter), rc.Reason})
	}
	return writeTable(stdout, []string{"SERIAL", "REVOKED", "EXPIRES", "REASON"}, rows)
}

// printKeys renders a credential listing.
//
// STATUS is computed rather than printed raw because it is the column an
// operator actually reads: "live" or the single reason it is not.
func printKeys(stdout io.Writer, keys []hubapi.KeyView) error {
	if len(keys) == 0 {
		_, err := fmt.Fprintln(stdout, "no credentials")
		return err
	}
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		cluster := ""
		if k.Enrollment != nil {
			cluster = k.Enrollment.ClusterID
		}
		rows = append(rows, []string{
			k.KID, string(k.Class), k.Name, keyStatus(k), expiry(k.ExpiresAt), cluster,
		})
	}
	return writeTable(stdout, []string{"KID", "CLASS", "NAME", "STATUS", "EXPIRES", "CLUSTER"}, rows)
}

// writeTable renders aligned columns.
//
// It assembles into a buffer and writes once, which is the same shape report
// uses above and exists for the same reason: a tabwriter buffers until Flush,
// so per-cell error returns are noise -- there is nothing they could report
// that the single write below will not.
func writeTable(stdout io.Writer, header []string, rows [][]string) error {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	cells := func(c []string) {
		// Writes to a strings.Builder cannot fail: Builder.Write always
		// returns a nil error, and tabwriter only forwards to it on Flush.
		_, _ = fmt.Fprintln(w, strings.Join(c, "\t"))
	}
	cells(header)
	for _, r := range rows {
		cells(r)
	}
	// Flushing cannot fail either, for the same reason: every write goes to
	// the Builder. The single write below is the only one that can, and it
	// is the one an operator would ever see fail -- a closed pipe.
	_ = w.Flush()
	_, err := io.WriteString(stdout, b.String())
	return err
}

// keyStatus is the one word that decides whether a credential still works.
func keyStatus(k hubapi.KeyView) string {
	switch {
	case k.Revoked:
		return "revoked"
	case k.Expired:
		return "expired"
	default:
		return "live"
	}
}

// expiry renders a credential expiry, where the zero time means never.
func expiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return stamp(t)
}

// stamp renders a timestamp, leaving an unset one blank rather than printing
// the zero year.
func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// revokeQuery builds the optional query string the revoke routes accept.
func revokeQuery(reason string, purge bool) string {
	q := neturl.Values{}
	if reason != "" {
		q.Set("reason", reason)
	}
	if purge {
		q.Set("purge", "true")
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// keyClassFilter maps the friendly spelling onto the wire value for a list
// filter. Unlike keyClass it accepts enrollment, because listing enrollment
// tokens is legitimate even though minting one goes through its own route.
func keyClassFilter(s string) (fleet.KeyClass, error) {
	switch s {
	case "agent", string(fleet.ClassAgent):
		return fleet.ClassAgent, nil
	case "admin", string(fleet.ClassAdmin):
		return fleet.ClassAdmin, nil
	case "enrollment", string(fleet.ClassEnrollment):
		return fleet.ClassEnrollment, nil
	default:
		return "", fmt.Errorf("unknown class %q: want agent, admin or enrollment", s)
	}
}
