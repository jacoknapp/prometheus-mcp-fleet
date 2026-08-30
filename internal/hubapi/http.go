// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/authn"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// authnRequestIDHeader is the correlation header, taken from internal/authn so
// the two packages cannot drift apart.
const authnRequestIDHeader = authn.RequestIDHeader

// Field limits. They are small on purpose: every one of these values is
// operator-authored metadata that ends up in an audit log, and none of them
// has a legitimate reason to be long.
const (
	// MaxNameBytes bounds a key or enrollment name.
	MaxNameBytes = 128
	// MaxOwnerBytes bounds the owner contact string.
	MaxOwnerBytes = 256
	// MaxReasonBytes bounds a revocation reason.
	MaxReasonBytes = 256
	// MaxLabels bounds how many labels an enrollment may carry.
	MaxLabels = 32
	// MaxLabelKeyBytes and MaxLabelValueBytes bound one label.
	MaxLabelKeyBytes   = 63
	MaxLabelValueBytes = 253
	// MaxCSRBytes bounds the base64 CSR field. An 8192-bit RSA request is
	// under 2 KiB of DER, so this is generous by an order of magnitude.
	MaxCSRBytes = 32 << 10
	// MaxChainCerts bounds how many certificates a renewal may present. This
	// CA issues spoke certificates directly off the root, so a legitimate chain
	// is one certificate; the allowance exists so an intermediate could be
	// introduced without a wire change, not so a caller can hand the hub an
	// arbitrary pile of DER to parse.
	MaxChainCerts = 8
)

// labelKeyRE is the accepted label key grammar. It matches the Kubernetes
// label-name shape without the optional DNS prefix, which keeps a label from
// smuggling a path separator or whitespace into an audit line.
var labelKeyRE = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)

// serialRE is the accepted certificate serial grammar: lowercase hex, as
// ca.SerialHex renders it. Constraining it here means the value can never
// reach the store, the CRL builder or a log line as anything else.
var serialRE = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// validSerial reports whether s is an acceptable certificate serial.
//
// It is the grammar plus one arithmetic rule: the value must be non-zero. RFC
// 5280 requires a positive serial and no certificate this CA issues has a zero
// one, but the check is not cosmetic -- x509.CreateRevocationList refuses a
// non-positive entry, so accepting "00" here would let an operator write a
// record that makes the unauthenticated /pki/crl route fail with a 500 for
// every consumer, permanently, with no way to undo it through this API.
func validSerial(s string) bool {
	return serialRE.MatchString(s) && strings.Trim(s, "0") != ""
}

// decodeJSON reads a bounded, strictly typed JSON body into dst.
//
// The body is capped at [MaxBodyBytes] before a single byte is parsed, unknown
// fields are refused so a typo in a field name is an error rather than a
// silently ignored setting, and trailing content is refused so a request
// cannot smuggle a second document past a proxy that only inspected the first.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("body must contain exactly one json document")
	}
	return nil
}

// readBody decodes dst and writes the appropriate error response on failure,
// reporting whether the handler may continue.
func (s *server) readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := decodeJSON(w, r, dst)
	if err == nil {
		return true
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		s.fail(w, r, CodePayloadTooLarge, fmt.Sprintf("request body exceeds %d bytes", MaxBodyBytes))
		return false
	}
	// The decoder's own message names the offending field and nothing else, so
	// it is safe to return; it never contains a value from the body.
	s.fail(w, r, CodeInvalidRequest, "request body is not valid json for this route")
	return false
}

// writeJSON writes v as the response body with the given status.
func (s *server) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.LogAttrs(r.Context(), slog.LevelWarn, "write response",
			slog.String("path", r.URL.Path), slog.String("error", err.Error()))
	}
}

// guard refuses a mutating request while the process is draining.
//
// Shutdown ordering makes this necessary rather than merely polite: once drain
// has started the hub has a bounded grace period left, and a credential mint or
// an enrollment burn that is interrupted halfway leaves an operator holding a
// token the store never recorded, or a cluster holding a certificate whose
// token was never burned.
func (s *server) guard(w http.ResponseWriter, r *http.Request) bool {
	if s.draining() {
		s.fail(w, r, CodeUnavailable, "the hub is shutting down and is not accepting mutations")
		return false
	}
	return true
}

// security emits the audit line for a credential lifecycle event.
//
// It records the acting principal and the affected key identifier, both of
// which are public by design, and never the secret, its digest or the pepper.
// It is logged at warn so that a security event is visible in a deployment
// whose level is set above info.
func (s *server) security(r *http.Request, event string, attrs ...slog.Attr) {
	actor := authn.PrincipalFrom(r.Context())
	all := make([]slog.Attr, 0, len(attrs)+4)
	all = append(all,
		slog.String("event", event),
		slog.String("actor", actor.String()),
		slog.String("actorClass", string(actorClass(actor))),
		slog.String("remoteAddr", authn.SourceAddr(r)),
	)
	all = append(all, attrs...)
	s.log.LogAttrs(r.Context(), slog.LevelWarn, "security event", all...)
	s.metrics.SecurityEvent(event)
}

// actorClass returns the acting principal's class, or the empty class when the
// route is unauthenticated.
func actorClass(p *fleet.Principal) fleet.KeyClass {
	if p == nil {
		return ""
	}
	return p.Class
}

// validateName checks an operator-supplied key name.
func validateName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return errors.New("name is required")
	case len(name) > MaxNameBytes:
		return fmt.Errorf("name exceeds %d bytes", MaxNameBytes)
	case !printable(name):
		return errors.New("name contains control characters")
	}
	return nil
}

// validateOwner checks the optional owner contact string.
func validateOwner(owner string) error {
	switch {
	case len(owner) > MaxOwnerBytes:
		return fmt.Errorf("owner exceeds %d bytes", MaxOwnerBytes)
	case !printable(owner):
		return errors.New("owner contains control characters")
	}
	return nil
}

// validateReason checks a revocation reason.
func validateReason(reason string) error {
	switch {
	case strings.TrimSpace(reason) == "":
		return errors.New("reason is required: a revocation without one is useless in an audit")
	case len(reason) > MaxReasonBytes:
		return fmt.Errorf("reason exceeds %d bytes", MaxReasonBytes)
	case !printable(reason):
		return errors.New("reason contains control characters")
	}
	return nil
}

// validateLabels checks an enrollment's label map. Labels are stamped onto the
// cluster registry, which an agent reads, so they are constrained here at the
// only point where an operator can introduce them.
func validateLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("at most %d labels are accepted", MaxLabels)
	}
	for k, v := range labels {
		if len(k) > MaxLabelKeyBytes || !labelKeyRE.MatchString(k) {
			return fmt.Errorf("label key %q is not a valid label name", k)
		}
		if len(v) > MaxLabelValueBytes {
			return fmt.Errorf("label %q exceeds %d bytes", k, MaxLabelValueBytes)
		}
		if !printable(v) {
			return fmt.Errorf("label %q contains control characters", k)
		}
	}
	return nil
}

// printable reports whether s contains no control characters. It rejects the
// C0 and C1 ranges outright, which is what keeps an audit line from being
// forged with an embedded newline.
func printable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// resolveTTL applies the default and the maximum for a credential class.
//
// A request above the maximum is refused rather than clamped: silently
// shortening a lifetime an operator explicitly asked for produces a credential
// that expires at a time nobody expects.
func resolveTTL(want fleet.Duration, def time.Duration) (time.Duration, error) {
	d := time.Duration(want)
	switch {
	case d == 0:
		return def, nil
	case d < 0:
		return 0, errors.New("ttl must be positive")
	case d > def:
		return 0, fmt.Errorf("ttl %s exceeds the configured maximum of %s", d, def)
	default:
		return d, nil
	}
}
