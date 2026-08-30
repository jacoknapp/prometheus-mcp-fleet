// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package version reports the build stamps of the running binary.
//
// It sits at L0 with fleet: every package may import it and it imports nothing
// from this module. Values are injected at link time with -ldflags, and when
// they were not injected they are recovered from the VCS stamps the Go
// toolchain embeds, so a `go build` from a git checkout still produces a
// usable commit and date.
//
// All functions are safe for concurrent use; the derived [Build] is computed
// once and never mutated afterwards.
package version
