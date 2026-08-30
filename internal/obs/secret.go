// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import "log/slog"

// redacted is the single placeholder every redaction path emits.
const redacted = "[REDACTED]"

// Secret is a string that cannot be printed, logged or serialised by accident.
//
// It implements fmt.Stringer, fmt.GoStringer, slog.LogValuer and
// json.Marshaler, all of which return "[REDACTED]". That covers %v, %+v, %#v,
// %s, %q, structured log attributes, a panic trace that formats a struct
// containing one, and encoding/json. The only way to obtain the underlying
// value is [Secret.Reveal], which is greppable in review.
//
// This is the project's primary control against credential leakage. Regex
// scrubbing of already-formatted log lines is explicitly not a substitute.
//
// A Secret is immutable and safe for concurrent use.
type Secret string

// String implements fmt.Stringer and always returns "[REDACTED]".
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, covering the %#v verb.
func (s Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer and always returns "[REDACTED]".
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON implements json.Marshaler and always emits "[REDACTED]".
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler, so a Secret used as a map key
// or in a text-encoding path redacts as well.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the underlying secret. Every call site is a deliberate
// decision to handle raw credential material.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is empty. It exists so callers can test
// for presence without revealing the value.
func (s Secret) IsZero() bool { return s == "" }
