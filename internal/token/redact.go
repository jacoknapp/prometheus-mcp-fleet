// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"fmt"
	"log/slog"
)

// Redacted is the placeholder every secret-bearing type in this package
// renders itself as. Regex scrubbing of already-formatted log lines is
// explicitly not a control here: the value never becomes a plain string in the
// first place unless a caller asks for it by name.
const Redacted = "[REDACTED]"

// RawToken is a complete `pmf_` credential as handed to an operator exactly
// once. It is a string underneath, but every path fmt, log/slog and
// encoding/json use to turn a value into text is overridden to emit
// [Redacted], so it cannot leak through %v, %+v, %s, %q, a structured log
// field, a JSON response body, or a panic trace that formats a struct
// containing one.
//
// Reveal is the only way out. Call it at the single point where the secret is
// delivered to its owner, never on a path that logs, serialises or errors.
type RawToken string

// String implements fmt.Stringer and returns [Redacted].
func (RawToken) String() string { return Redacted }

// GoString implements fmt.GoStringer so that %#v also redacts.
func (RawToken) GoString() string { return Redacted }

// LogValue implements slog.LogValuer and returns [Redacted].
func (RawToken) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON implements json.Marshaler and returns [Redacted] as a JSON
// string. There is deliberately no UnmarshalJSON: a redacted token must never
// round-trip through a serialised document.
func (RawToken) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// Reveal returns the underlying token text. Every call site is a place a
// secret can escape, so each one should be individually justifiable.
func (r RawToken) Reveal() string { return string(r) }

// IsZero reports whether the token is empty. It is safe to call on a value
// that must not be revealed.
func (r RawToken) IsZero() bool { return len(r) == 0 }

// Compile-time proof that the redacting interfaces are actually satisfied by
// the value type (not just the pointer), because fmt and slog will only use
// them if the method set of the value has them.
var (
	_ fmt.Stringer   = RawToken("")
	_ fmt.GoStringer = RawToken("")
	_ slog.LogValuer = RawToken("")
)
