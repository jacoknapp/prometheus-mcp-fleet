// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// MaxResponseBytes bounds every response body this client will read. A Secret
// caps at 1 MiB on the API server side, so 4 MiB leaves room for metadata and
// base64 expansion while keeping a hostile or misrouted endpoint from being
// able to exhaust the hub's memory.
const MaxResponseBytes int64 = 4 << 20

// ServiceAccountDir is where the kubelet projects the service account token,
// CA bundle and namespace.
const ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Request timeouts. They are deliberately short: every call this package
// makes is a single small object read or write against an in-cluster endpoint,
// so a request that has not completed in this long is not going to.
const (
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 20 * time.Second
	requestTimeout        = 30 * time.Second
	idleConnTimeout       = 90 * time.Second
)

// userAgent identifies the hub in API server audit logs.
const userAgent = "prometheus-mcp-fleet/kube"

// nameRE is the DNS subdomain form Kubernetes requires of a Secret name. It
// is enforced here as well because these values are interpolated into a URL
// path, where a "/" or a ".." would address a different object entirely.
var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// Config configures [New].
type Config struct {
	// APIServerURL is the API server base URL, e.g.
	// "https://kubernetes.default.svc:443". Required.
	APIServerURL string
	// Namespace scopes every request. Required; nothing in this package can
	// address another namespace.
	Namespace string
	// TokenFile holds the bearer token. It is re-read as it rotates; see the
	// package documentation. Empty sends no Authorization header, which is
	// only useful against a test server.
	TokenFile string
	// CAFile is the PEM bundle the API server certificate is verified
	// against. Empty falls back to the system roots.
	CAFile string
	// HTTPClient overrides the tuned client this package builds. Tests use it
	// to point at an httptest.Server; production leaves it nil so that the
	// timeouts and the CA bundle in this file apply.
	HTTPClient *http.Client
	// Logger receives the rare non-fatal warning, such as a token file that
	// briefly vanished mid-rotation. Nil discards.
	Logger *slog.Logger
}

// Client talks to the Kubernetes API server for Secrets in one namespace. It
// is immutable after construction and safe for concurrent use.
type Client struct {
	base     string
	ns       string
	hc       *http.Client
	tokens   *tokenSource
	log      *slog.Logger
	maxBytes int64
}

// New returns a Client from an explicit configuration. It performs no I/O
// beyond reading CAFile, so it cannot detect an unreachable API server; the
// first request does that.
func New(cfg Config) (*Client, error) {
	if cfg.APIServerURL == "" {
		return nil, errors.New("kube: api server url is required")
	}
	u, err := url.Parse(cfg.APIServerURL)
	if err != nil {
		return nil, fmt.Errorf("kube: api server url %q: %w", cfg.APIServerURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("kube: api server url %q: scheme must be https (http is accepted only for tests)", cfg.APIServerURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("kube: api server url %q has no host", cfg.APIServerURL)
	}
	if err := ValidateName(cfg.Namespace); err != nil {
		return nil, fmt.Errorf("kube: namespace: %w", err)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		if hc, err = newHTTPClient(cfg.CAFile); err != nil {
			return nil, err
		}
	}
	return &Client{
		base:     strings.TrimSuffix(u.String(), "/"),
		ns:       cfg.Namespace,
		hc:       hc,
		tokens:   newTokenSource(cfg.TokenFile, DefaultTokenTTL, time.Now, log),
		log:      log,
		maxBytes: MaxResponseBytes,
	}, nil
}

// InCluster returns a Client configured from the projected service account at
// [ServiceAccountDir] plus KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT.
//
// It returns an error wrapping [ErrNotInCluster] when any of those are
// absent, which is the signal for a caller to fall back to a local backend
// rather than to fail.
func InCluster() (*Client, error) { return inCluster(ServiceAccountDir) }

// inCluster is InCluster with an injectable directory so the projected-file
// handling is testable without root.
func inCluster(dir string) (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("kube: KUBERNETES_SERVICE_HOST/PORT are not set: %w", ErrNotInCluster)
	}
	var (
		tokenFile = filepath.Join(dir, "token")
		caFile    = filepath.Join(dir, "ca.crt")
		nsFile    = filepath.Join(dir, "namespace")
	)
	nsRaw, err := os.ReadFile(nsFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("kube: %s: %w", nsFile, ErrNotInCluster)
	case err != nil:
		return nil, fmt.Errorf("kube: read %s: %w", nsFile, err)
	}
	for _, f := range []string{tokenFile, caFile} {
		if _, err := os.Stat(f); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("kube: %s: %w", f, ErrNotInCluster)
			}
			return nil, fmt.Errorf("kube: stat %s: %w", f, err)
		}
	}
	return New(Config{
		APIServerURL: "https://" + net.JoinHostPort(host, port),
		Namespace:    strings.TrimSpace(string(nsRaw)),
		TokenFile:    tokenFile,
		CAFile:       caFile,
	})
}

// Namespace returns the namespace every request is scoped to.
func (c *Client) Namespace() string { return c.ns }

// ValidateName reports whether name is a legal Kubernetes object name. It is
// exported so a caller can reject an operator-supplied Secret name at
// configuration load rather than at the first API call.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("name %q is not a DNS subdomain ([a-z0-9] with - and ., max 253)", name)
	}
	return nil
}

// newHTTPClient builds the one tuned client this package uses. The transport
// verifies the API server against caFile, or the system roots when caFile is
// empty. There is no path through this function that disables verification.
func newHTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("kube: read ca bundle %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kube: ca bundle %s contains no certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			// No Proxy: the API server is an in-cluster address, and honouring
			// HTTPS_PROXY here would route a request carrying the service
			// account token through whatever the environment names.
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       tlsCfg,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       idleConnTimeout,
			MaxIdleConnsPerHost:   4,
			ForceAttemptHTTP2:     true,
		},
	}, nil
}

// do issues one request and decodes a JSON response into out.
//
// verb is the human name of the operation ("get secret") and appears in every
// error, because "404" alone does not say what was missing.
func (c *Client) do(ctx context.Context, verb, method, path string, body, out any) error {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("kube %s: encode request: %w", verb, err)
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, payload)
	if err != nil {
		return fmt.Errorf("kube %s: build request: %w", verb, err)
	}
	token, err := c.tokens.get()
	if err != nil {
		return fmt.Errorf("kube %s: %w", verb, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("kube %s: %w", verb, err)
	}
	defer func() {
		// Drain a little so the connection can be reused, then close. The
		// body is already bounded below; this bound only covers the tail of a
		// response we stopped caring about.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return fmt.Errorf("kube %s: read response: %w", verb, err)
	}
	if int64(len(raw)) > c.maxBytes {
		return fmt.Errorf("kube %s: response exceeds %d bytes: %w", verb, c.maxBytes, ErrResponseTooLarge)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(verb, c.ns, resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("kube %s: decode response: %w", verb, err)
	}
	return nil
}

// WithNamespace returns a copy of c scoped to ns, sharing the same HTTP client
// and token source.
//
// It exists because the namespace a pod is projected into and the namespace an
// operator configures are two different facts. Rebuilding a client with [New]
// to change one of them would discard the API server address, the bearer token
// file and the CA bundle that only [InCluster] knows how to find, so this is
// the only correct way to apply a namespace override in a cluster.
func (c *Client) WithNamespace(ns string) (*Client, error) {
	if err := ValidateName(ns); err != nil {
		return nil, fmt.Errorf("kube: namespace: %w", err)
	}
	cp := *c
	cp.ns = ns
	return &cp, nil
}
