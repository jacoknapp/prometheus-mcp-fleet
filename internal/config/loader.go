// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Errors reported by loading and validation. Callers branch on these with
// errors.Is.
var (
	// ErrHelp is returned when -h or --help was requested. It wraps
	// flag.ErrHelp, so callers written against either sentinel work. The
	// returned error's message is the usage text.
	ErrHelp = fmt.Errorf("config: help requested: %w", flag.ErrHelp)
	// ErrUsage is returned for an unknown flag, a malformed flag value, or a
	// stray positional argument.
	ErrUsage = errors.New("config: invalid command line")
	// ErrEnv is returned when an environment variable holds a value that
	// cannot be parsed into the type its flag expects.
	ErrEnv = errors.New("config: invalid environment variable")
	// ErrInvalid is returned by Validate for configuration that parsed but
	// cannot be run.
	ErrInvalid = errors.New("config: invalid configuration")
	// ErrInvalidLabels is returned when PMF_CLUSTER_LABELS is malformed.
	ErrInvalidLabels = errors.New("config: invalid cluster labels")
)

// envPrefix is prepended to every derived environment variable name.
const envPrefix = "PMF_"

// EnvKey returns the environment variable that backs a flag: "mcp-addr"
// becomes "PMF_MCP_ADDR". It is the single definition of that mapping, so a
// flag and its variable cannot drift apart.
func EnvKey(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// HelpError is the error returned when help was requested. Its message is the
// full usage text, and it satisfies both errors.Is(err, ErrHelp) and
// errors.Is(err, flag.ErrHelp).
type HelpError struct {
	// Usage is the rendered usage text, including every flag and the
	// environment variable that backs it.
	Usage string
}

// Error implements error, returning the usage text.
func (e *HelpError) Error() string { return e.Usage }

// Unwrap makes errors.Is(err, ErrHelp) and errors.Is(err, flag.ErrHelp) true.
func (e *HelpError) Unwrap() error { return ErrHelp }

// loader binds a FlagSet whose defaults have already been seeded from the
// environment. Because seeding happens before parsing, an explicitly passed
// flag always wins without any flag.Visit bookkeeping.
type loader struct {
	fs     *flag.FlagSet
	getenv func(string) string
	errs   []error
}

// newLoader builds a loader for the named binary. A nil getenv falls back to
// os.Getenv.
func newLoader(name string, getenv func(string) string) *loader {
	if getenv == nil {
		getenv = os.Getenv
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return &loader{fs: fs, getenv: getenv}
}

// lookup returns the environment value backing a flag, and whether it was set
// to something non-empty. An empty variable is treated as unset so that
// `FOO=` in a container manifest does not blank out a default.
func (l *loader) lookup(name string) (string, bool) {
	v := l.getenv(EnvKey(name))
	return v, v != ""
}

// fail records an environment parse failure. Loading continues so the operator
// learns about every bad variable at once.
func (l *loader) fail(name, value string, err error) {
	l.errs = append(l.errs, fmt.Errorf("%w: %s=%q: %w", ErrEnv, EnvKey(name), value, err))
}

// usage decorates a flag's help text with the variable that backs it.
func usage(name, text string) string { return text + " [" + EnvKey(name) + "]" }

// str registers a string flag.
func (l *loader) str(p *string, name, def, help string) {
	if v, ok := l.lookup(name); ok {
		def = v
	}
	l.fs.StringVar(p, name, def, usage(name, help))
}

// duration registers a time.Duration flag parsed with time.ParseDuration.
func (l *loader) duration(p *time.Duration, name string, def time.Duration, help string) {
	if v, ok := l.lookup(name); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			l.fail(name, v, errors.New("not a duration such as \"30s\" or \"1h30m\""))
		} else {
			def = d
		}
	}
	l.fs.DurationVar(p, name, def, usage(name, help))
}

// integer registers an int flag.
func (l *loader) integer(p *int, name string, def int, help string) {
	if v, ok := l.lookup(name); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			l.fail(name, v, errors.New("not an integer"))
		} else {
			def = n
		}
	}
	l.fs.IntVar(p, name, def, usage(name, help))
}

// bytesize registers an int64 flag holding a size in bytes.
func (l *loader) bytesize(p *int64, name string, def int64, help string) {
	if v, ok := l.lookup(name); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			l.fail(name, v, errors.New("not a number of bytes"))
		} else {
			def = n
		}
	}
	l.fs.Int64Var(p, name, def, usage(name, help))
}

// boolean registers a bool flag. The environment accepts anything
// strconv.ParseBool does, so "1", "true" and "TRUE" all work.
//
//nolint:unparam // def mirrors flag.BoolVar and the seven sibling helpers; that every bool flag happens to default to false today is not a property worth baking into the signature.
func (l *loader) boolean(p *bool, name string, def bool, help string) {
	if v, ok := l.lookup(name); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			l.fail(name, v, errors.New("not a boolean (\"true\", \"false\", \"1\", \"0\")"))
		} else {
			def = b
		}
	}
	l.fs.BoolVar(p, name, def, usage(name, help))
}

// ratio registers a float64 flag.
func (l *loader) ratio(p *float64, name string, def float64, help string) {
	if v, ok := l.lookup(name); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			l.fail(name, v, errors.New("not a number"))
		} else {
			def = f
		}
	}
	l.fs.Float64Var(p, name, def, usage(name, help))
}

// list registers a comma-separated string-slice flag.
func (l *loader) list(p *[]string, name string, def []string, help string) {
	*p = def
	value := &csvValue{dst: p}
	if v, ok := l.lookup(name); ok {
		_ = value.Set(v) // csvValue.Set only splits a string and cannot fail.
	}
	l.fs.Var(value, name, usage(name, help))
}

// labels registers a "k=v,k=v" map flag.
func (l *loader) labels(p *map[string]string, name, help string) {
	value := &labelsValue{dst: p}
	if v, ok := l.lookup(name); ok {
		if err := value.Set(v); err != nil {
			l.fail(name, v, err)
		}
	}
	l.fs.Var(value, name, usage(name, help))
}

// parse consumes args (which must not include the program name) and reports
// the first structural problem or the joined set of environment problems.
func (l *loader) parse(args []string) error {
	if err := l.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &HelpError{Usage: l.usageText()}
		}
		return fmt.Errorf("%w: %w\n\n%s", ErrUsage, err, l.usageText())
	}
	if l.fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q\n\n%s",
			ErrUsage, l.fs.Arg(0), l.usageText())
	}
	return errors.Join(l.errs...)
}

// usageText renders the full help, including the environment variable behind
// every flag.
func (l *loader) usageText() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Usage: %s [flags]\n\n", l.fs.Name())
	b.WriteString("Every flag --foo-bar may also be set with the environment variable\n")
	b.WriteString("PMF_FOO_BAR, shown in brackets below. Precedence: flag > environment >\n")
	b.WriteString("default.\n\nFlags:\n")
	l.fs.SetOutput(&b)
	l.fs.PrintDefaults()
	l.fs.SetOutput(io.Discard)
	return b.String()
}

// csvValue is a flag.Value holding a comma-separated list. Empty elements are
// dropped and surrounding whitespace is trimmed.
type csvValue struct{ dst *[]string }

// String implements flag.Value.
func (v *csvValue) String() string {
	if v == nil || v.dst == nil {
		return ""
	}
	return strings.Join(*v.dst, ",")
}

// Set implements flag.Value.
func (v *csvValue) Set(s string) error {
	*v.dst = splitList(s)
	return nil
}

// splitList splits a comma-separated list, trimming space and dropping empties.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// labelsValue is a flag.Value holding a "k=v,k=v" map.
type labelsValue struct{ dst *map[string]string }

// String implements flag.Value, rendering keys in sorted order.
func (v *labelsValue) String() string {
	if v == nil || v.dst == nil {
		return ""
	}
	return FormatClusterLabels(*v.dst)
}

// Set implements flag.Value.
func (v *labelsValue) Set(s string) error {
	m, err := ParseClusterLabels(s)
	if err != nil {
		return err
	}
	*v.dst = m
	return nil
}

// --- shared validation helpers -------------------------------------------

// problem formats one validation failure against a flag name.
func problem(flagName, format string, args ...any) error {
	return fmt.Errorf("%w: --%s (%s): %s", ErrInvalid, flagName, EnvKey(flagName),
		fmt.Sprintf(format, args...))
}

// checkAddr validates a "host:port" listen address. An empty host means "all
// interfaces"; port 0 means "pick an ephemeral port" and is allowed so tests
// can bind freely.
func checkAddr(flagName, addr string) error {
	if addr == "" {
		return problem(flagName, "is required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return problem(flagName, "%q is not host:port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return problem(flagName, "%q has an invalid port %q", addr, port)
	}
	if strings.ContainsAny(host, " \t") {
		return problem(flagName, "%q has an invalid host", addr)
	}
	return nil
}

// checkPath validates an absolute URL path used as a mount point. A bare "/"
// is refused: mounting the tunnel there would swallow every other route on the
// listener it shares.
func checkPath(flagName, path string) error {
	switch {
	case path == "":
		return problem(flagName, "is required")
	case !strings.HasPrefix(path, "/"):
		return problem(flagName, "%q must start with /", path)
	case path == "/":
		return problem(flagName, "must not be %q: it shares a listener with the MCP endpoint", path)
	case strings.ContainsAny(path, "?# \t"):
		return problem(flagName, "%q must be a plain path with no query or fragment", path)
	case strings.ContainsAny(path, "{}"):
		// The path is handed to http.ServeMux, whose patterns treat braces as
		// wildcards and which panics on a malformed one. A configuration typo
		// must not be able to crash the process at startup.
		return problem(flagName, "%q must not contain { or }: it is a literal mount path, not a route pattern", path)
	default:
		return nil
	}
}

// checkHubEndpoint validates one hub tunnel endpoint.
//
// Since ADR-0014 the tunnel arrives as a WebSocket on the hub's ordinary HTTP
// listener, so an endpoint is a URL. The previous release configured a
// host:port, and that form is still accepted and read as
// wss://<host:port>/tunnel — an operator upgrading a hundred spokes should not
// have to rewrite every one of them in the same change.
func checkHubEndpoint(flagName, endpoint string) error {
	if endpoint == "" {
		return problem(flagName, "is empty; expected a URL such as wss://hub.example.com/tunnel")
	}
	if !strings.Contains(endpoint, "://") {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || strings.ContainsAny(endpoint, "/?#") {
			return problem(flagName,
				"%q is neither a URL nor host:port; expected a URL such as wss://hub.example.com/tunnel",
				endpoint)
		}
		if host == "" {
			return problem(flagName, "%q has no host", endpoint)
		}
		n, cerr := strconv.Atoi(port)
		if cerr != nil || n < 1 || n > 65535 {
			return problem(flagName, "%q has an invalid port %q", endpoint, port)
		}
		return nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return problem(flagName, "%q is not a URL", redactURL(endpoint))
	}
	switch u.Scheme {
	case "ws", "wss", "http", "https":
	default:
		return problem(flagName, "%q uses the %q scheme; expected wss (or ws for a plaintext hub)",
			redactURL(endpoint), u.Scheme)
	}
	if u.Host == "" {
		return problem(flagName, "%q has no host", redactURL(endpoint))
	}
	if u.User != nil {
		return problem(flagName, "%q carries credentials in the URL, which the tunnel never uses",
			redactURL(endpoint))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return problem(flagName, "%q carries a query or fragment; expected a URL such as wss://hub.example.com/tunnel",
			redactURL(endpoint))
	}
	return nil
}

// checkURL validates an absolute http or https URL.
func checkURL(flagName, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return problem(flagName, "%q is not a URL", redactURL(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return problem(flagName, "%q must use the http or https scheme", redactURL(raw))
	}
	if u.Host == "" {
		return problem(flagName, "%q has no host", redactURL(raw))
	}
	return nil
}

// checkPositive requires a strictly positive duration.
func checkPositive(flagName string, d time.Duration) error {
	if d <= 0 {
		return problem(flagName, "must be positive, got %s", d)
	}
	return nil
}

// checkNonNegative permits zero but not a negative duration.
func checkNonNegative(flagName string, d time.Duration) error {
	if d < 0 {
		return problem(flagName, "must not be negative, got %s", d)
	}
	return nil
}

// checkPositiveInt requires a strictly positive count.
func checkPositiveInt(flagName string, n int) error {
	if n <= 0 {
		return problem(flagName, "must be positive, got %d", n)
	}
	return nil
}

// checkNonNegativeInt permits zero, which callers use to mean "no limit".
func checkNonNegativeInt(flagName string, n int) error {
	if n < 0 {
		return problem(flagName, "must not be negative, got %d", n)
	}
	return nil
}

// checkPositiveBytes requires a strictly positive byte size.
func checkPositiveBytes(flagName string, n int64) error {
	if n <= 0 {
		return problem(flagName, "must be positive, got %d", n)
	}
	return nil
}

// logLevels and logFormats are the accepted values for the shared logging
// flags. They are closed sets so a typo fails at startup instead of silently
// selecting a default.
var (
	logLevels  = []string{"debug", "info", "warn", "error"}
	logFormats = []string{"json", "text"}
)

// checkEnum requires that value is one of allowed.
func checkEnum(flagName, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return problem(flagName, "%q must be one of %s", value, strings.Join(allowed, ", "))
}

// checkRatio requires a sampling ratio within [0,1].
func checkRatio(flagName string, r float64) error {
	if r < 0 || r > 1 || r != r {
		return problem(flagName, "must be between 0 and 1, got %v", r)
	}
	return nil
}

// checkPair requires that two co-dependent file paths are either both set or
// both empty.
func checkPair(certFlag, certPath, keyFlag, keyPath string) error {
	switch {
	case certPath == "" && keyPath == "":
		return nil
	case certPath == "":
		return problem(certFlag, "is required when --%s is set", keyFlag)
	case keyPath == "":
		return problem(keyFlag, "is required when --%s is set", certFlag)
	}
	return nil
}

// redactedUserinfo replaces the credential portion of a logged URL.
const redactedUserinfo = "redacted"

// redactURL strips userinfo from a URL so a password embedded in it cannot
// reach a log line. A string that does not parse is replaced wholesale, since
// we then cannot tell where the credential ends. The replacement is a bare
// word rather than "[REDACTED]" because url.URL.String percent-escapes
// userinfo, which would render the marker unreadable.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable-url]"
	}
	if u.User != nil {
		u.User = url.User(redactedUserinfo)
	}
	return u.String()
}
