// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package wstun

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
)

// dialTimeout bounds DNS, connect, TLS and the HTTP upgrade. The handshake
// that follows has its own budget.
const dialTimeout = 15 * time.Second

// ClientConfig configures the spoke side of the WebSocket tunnel.
type ClientConfig struct {
	// URL is the hub tunnel endpoint, for example wss://hub.example.com/tunnel.
	// A bare host:port is accepted and normalised; see [NormalizeEndpoint].
	URL string
	// Certificate is the spoke's issued certificate and private key. The key
	// must implement crypto.Signer, which every key crypto/tls parses does.
	Certificate tls.Certificate
	// CABundle verifies the hub's *server* TLS — which, behind an ingress, is
	// the ingress's certificate and not the hub's. Empty uses the system pool.
	CABundle []byte
	// TLSInsecure disables that verification. It exists for lab bootstrapping
	// and is gated behind PMF_ALLOW_INSECURE.
	TLSInsecure bool
	// ClusterID is what this spoke believes it is. It is bound into the signed
	// transcript, and the hub refuses the connection if it disagrees with the
	// certificate rather than quietly preferring one.
	ClusterID string
	// AgentVersion is reported to the hub for diagnostics only.
	AgentVersion string
	// Logger receives connection lifecycle events. Defaults to slog.Default().
	Logger *slog.Logger
	// HTTPClient performs the upgrade. Nil builds one from CABundle and
	// TLSInsecure.
	HTTPClient *http.Client
	// Keepalive configures the spoke's HTTP/2 ping enforcement policy.
	Keepalive grpctun.KeepaliveParams
	// Generation is the spoke process start time in Unix nanoseconds, which is
	// how the hub resolves reconnect races.
	Generation int64
}

// Dial connects to one hub endpoint, proves this spoke's identity, and then
// serves h over the resulting connection until it drops or ctx is cancelled.
//
// It always returns a non-nil *grpctun.DialError, whose Reason is a closed-enum
// value safe to use as a metric label. Use errors.As to recover it; a reconnect
// loop needs a reason it can count, and "EOF" is not one.
func Dial(ctx context.Context, cfg ClientConfig, h tunnel.Handler) error {
	if h == nil {
		return dialErr(cfg.URL, grpctun.ReasonDial, errors.New("handler is required"))
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	target, err := NormalizeEndpoint(cfg.URL)
	if err != nil {
		return dialErr(cfg.URL, grpctun.ReasonDial, err)
	}
	signer, err := signerFor(cfg.Certificate)
	if err != nil {
		return dialErr(cfg.URL, grpctun.ReasonAuthRejected, err)
	}
	httpClient, err := cfg.httpClient()
	if err != nil {
		return dialErr(cfg.URL, grpctun.ReasonDial, err)
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()

	ws, resp, err := websocket.Dial(dialCtx, target, &websocket.DialOptions{
		HTTPClient:      httpClient,
		Subprotocols:    []string{Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return dialErr(cfg.URL, upgradeReason(ctx, resp, err), upgradeCause(target, resp, err))
	}
	if ws.Subprotocol() != Subprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, ErrSubprotocol.Error())
		return dialErr(cfg.URL, grpctun.ReasonUpgradeRejected, ErrSubprotocol)
	}

	// The connection must outlive dialCtx, but must not outlive this call.
	connCtx, cancelConn := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelConn()
	conn := websocket.NetConn(connCtx, ws, websocket.MessageBinary)

	serverID, err := clientHandshake(conn, cfg, signer)
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return dialErr(cfg.URL, grpctun.ReasonContextCancelled, ctx.Err())
		}
		return dialErr(cfg.URL, grpctun.ReasonAuthRejected, err)
	}

	// endpoint and cluster_id are already bound on the caller's logger; adding
	// them again emitted duplicate keys in every JSON line.
	log.Info("tunnel connected", "hub_server_id", serverID)

	return grpctun.ServeConn(ctx, conn, grpctun.DialerConfig{
		Endpoint:   cfg.URL,
		Logger:     log,
		Generation: cfg.Generation,
		Keepalive:  cfg.Keepalive,
	}, h)
}

// clientHandshake performs the spoke half of the exchange and reports the hub
// replica that accepted it.
func clientHandshake(conn net.Conn, cfg ClientConfig, signer crypto.Signer) (serverID string, err error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return "", fmt.Errorf("%w: set handshake deadline: %w", ErrHandshakeFailed, err)
	}

	var hello serverHello
	if err := readMessage(conn, &hello); err != nil {
		return "", err
	}
	if !compatibleVersion(hello.ProtocolVersion) {
		return "", fmt.Errorf("%w: hub speaks %q, spoke speaks %q",
			ErrProtocolVersion, hello.ProtocolVersion, ProtocolVersion)
	}
	if len(hello.Nonce) != nonceLen {
		return "", fmt.Errorf("%w: hub nonce is %d bytes, want %d",
			ErrHandshakeFailed, len(hello.Nonce), nonceLen)
	}

	sig, err := signTranscript(signer, hello.Nonce, ProtocolVersion, cfg.ClusterID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrHandshakeFailed, err)
	}
	auth := clientAuth{
		Chain:           cfg.Certificate.Certificate,
		Signature:       sig,
		ClusterID:       cfg.ClusterID,
		AgentVersion:    cfg.AgentVersion,
		ProtocolVersion: ProtocolVersion,
	}
	if err := writeMessage(conn, auth); err != nil {
		return "", fmt.Errorf("%w: %w", ErrHandshakeFailed, err)
	}

	var accept serverAccept
	if err := readMessage(conn, &accept); err != nil {
		return "", err
	}
	if !accept.Accepted {
		return "", fmt.Errorf("%w: the hub refused this spoke: %s", ErrHandshakeFailed, accept.Reason)
	}
	if accept.ClusterID != "" && accept.ClusterID != cfg.ClusterID {
		return "", fmt.Errorf("%w: hub derived %q from the certificate, spoke is configured as %q",
			ErrClusterMismatch, accept.ClusterID, cfg.ClusterID)
	}

	// A tunnel carries no deadline: it is legitimately quiet for long stretches,
	// and HTTP/2 pings are what prove it is alive.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return "", fmt.Errorf("%w: clear handshake deadline: %w", ErrHandshakeFailed, err)
	}
	return hello.ServerID, nil
}

// NormalizeEndpoint turns an operator-supplied hub endpoint into the WebSocket
// URL to dial.
//
// Both forms are accepted, because the previous release configured a host:port
// and an upgrade should not require every spoke's configuration to be rewritten
// in the same change:
//
//	hub.example.com:8443        -> wss://hub.example.com:8443/tunnel
//	https://hub.example.com     -> wss://hub.example.com/tunnel
//	wss://hub.example.com/tunnel -> unchanged
//
// A value that is neither is an error naming what a valid one looks like.
func NormalizeEndpoint(endpoint string) (string, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return "", fmt.Errorf("%w: is empty; expected a URL such as wss://hub.example.com%s",
			ErrInvalidEndpoint, DefaultPath)
	}

	if !strings.Contains(raw, "://") {
		// A bare authority. Reject anything with a path, so a typo like
		// "hub.example.com/tunnel" is not silently read as a hostname.
		if strings.ContainsAny(raw, "/?#") {
			return "", invalidEndpoint(endpoint)
		}
		if _, _, err := net.SplitHostPort(raw); err != nil {
			return "", invalidEndpoint(endpoint)
		}
		raw = "wss://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", invalidEndpoint(endpoint)
	}
	switch u.Scheme {
	case "wss", "https":
		u.Scheme = "wss"
	case "ws", "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("%w: %q uses the %q scheme; expected a URL such as wss://hub.example.com%s "+
			"(ws for a plaintext hub)", ErrInvalidEndpoint, endpoint, u.Scheme, DefaultPath)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: %q names no host; expected a URL such as wss://hub.example.com%s",
			ErrInvalidEndpoint, endpoint, DefaultPath)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: %q carries credentials in the URL, which the tunnel never uses",
			ErrInvalidEndpoint, endpoint)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: %q carries a query or fragment; expected a URL such as wss://hub.example.com%s",
			ErrInvalidEndpoint, endpoint, DefaultPath)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = DefaultPath
	}
	return u.String(), nil
}

func invalidEndpoint(endpoint string) error {
	return fmt.Errorf("%w: %q is neither a URL nor host:port; expected a URL such as wss://hub.example.com%s",
		ErrInvalidEndpoint, endpoint, DefaultPath)
}

// httpClient builds the client that performs the upgrade, unless the caller
// supplied one.
func (cfg ClientConfig) httpClient() (*http.Client, error) {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//nolint:gosec // gated behind PMF_ALLOW_INSECURE; see config.Spoke.Validate
		InsecureSkipVerify: cfg.TLSInsecure,
	}
	if len(cfg.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CABundle) {
			return nil, errors.New("the hub CA bundle contains no usable certificate")
		}
		tlsCfg.RootCAs = pool
	}
	// Client.Timeout is deliberately left at zero. It is an absolute deadline on
	// the whole exchange, and the "exchange" here is a tunnel that lives for
	// days; the upgrade is bounded by dialTimeout instead.
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			// HTTP/2 is deliberately not negotiated: RFC 6455 upgrades are an
			// HTTP/1.1 mechanism, and h2 would make the upgrade fail.
			ForceAttemptHTTP2:   false,
			TLSHandshakeTimeout: 10 * time.Second,
			Proxy:               http.ProxyFromEnvironment,
		},
	}, nil
}

// signerFor recovers the private key as a crypto.Signer.
func signerFor(cert tls.Certificate) (crypto.Signer, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no client certificate is configured; the spoke must enroll first")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the client private key of type %T cannot sign", cert.PrivateKey)
	}
	return signer, nil
}

// upgradeReason classifies why the upgrade did not happen.
func upgradeReason(ctx context.Context, resp *http.Response, err error) grpctun.Reason {
	switch {
	case ctx.Err() != nil:
		return grpctun.ReasonContextCancelled
	case resp != nil:
		// Something answered with HTTP and it was not 101.
		return grpctun.ReasonUpgradeRejected
	case isTLSError(err):
		return grpctun.ReasonTLSHandshake
	default:
		return grpctun.ReasonDial
	}
}

// isTLSError reports whether err came from TLS rather than from the socket.
func isTLSError(err error) bool {
	var ce *tls.CertificateVerificationError
	var ra tls.RecordHeaderError
	if errors.As(err, &ce) || errors.As(err, &ra) {
		return true
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci)
}

// upgradeCause turns a failed upgrade into an error an operator can act on.
//
// The single most common first-install failure is an ingress that is not
// routing the tunnel path to the hub, and its symptoms — a 404, or an HTML
// page where a protocol switch should have been — are not self-explanatory in
// a websocket library's error string. So they are explained here.
func upgradeCause(target string, resp *http.Response, err error) error {
	if resp == nil {
		return err
	}
	path := DefaultPath
	if u, perr := url.Parse(target); perr == nil && u.Path != "" {
		path = u.Path
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: the hub URL returned 404. The tunnel path %q is most likely "+
			"not routed to the hub: check that the Ingress has a rule for %q and that it "+
			"points at the hub's HTTP service (%w)", ErrUpgradeRejected, path, path, err)
	case resp.StatusCode == http.StatusOK && looksLikeHTML(resp):
		return fmt.Errorf("%w: the hub URL answered 200 with an HTML page instead of "+
			"switching protocols. Something other than the hub — an Ingress default "+
			"backend, or a login portal — is answering %q (%w)", ErrUpgradeRejected, path, err)
	default:
		return fmt.Errorf("%w: the hub URL returned %s instead of 101 Switching Protocols (%w)",
			ErrUpgradeRejected, resp.Status, err)
	}
}

// looksLikeHTML reports whether a response body is a web page rather than a
// protocol switch.
func looksLikeHTML(resp *http.Response) bool {
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}
	if resp.Body == nil {
		return false
	}
	// The library may already have closed the body; a failed read simply means
	// no extra evidence, which is fine.
	head, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(string(head))), "<")
}

// dialErr builds the *grpctun.DialError every failure path returns, so a
// reconnect loop has exactly one error shape to handle.
func dialErr(endpoint string, reason grpctun.Reason, err error) error {
	return &grpctun.DialError{Endpoint: endpoint, Reason: reason, Err: err}
}
