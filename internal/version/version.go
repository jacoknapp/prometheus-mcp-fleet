// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Version, Commit and Date are the build stamps. They are set at link time,
// for example:
//
//	go build -ldflags "-X github.com/jacoknapp/prometheus-mcp-fleet/internal/version.Version=1.2.3"
//
// When they are left empty [Get] recovers what it can from the VCS information
// the toolchain embeds in the binary and falls back to "dev" for the version.
var (
	// Version is the semantic version of the release, e.g. "1.2.3".
	Version string
	// Commit is the full VCS revision the binary was built from.
	Commit string
	// Date is the build date. Any RFC 3339 timestamp is normalised to
	// "2006-01-02" by [Get].
	Date string
)

// devVersion is the version reported when nothing better is known.
const devVersion = "dev"

// dirtySuffix marks a commit built from a working tree with local changes.
const dirtySuffix = "+dirty"

// shortCommitLen is how many hex characters of a revision [Build.String]
// prints.
const shortCommitLen = 7

// Build is a fully resolved set of build stamps. It is a value type and safe
// to copy.
type Build struct {
	// Version is the release version, or "dev" when unstamped.
	Version string
	// Commit is the full VCS revision, possibly suffixed with "+dirty".
	Commit string
	// Date is the build date in "2006-01-02" form when it could be parsed.
	Date string
	// GoVersion is the toolchain that produced the binary.
	GoVersion string
	// Platform is "GOOS/GOARCH".
	Platform string
}

// Get returns the resolved build stamps of the running binary. The result is
// computed once and cached.
func Get() Build { return cached() }

// cached memoises the resolution so repeated calls do not re-read the embedded
// build info.
var cached = sync.OnceValue(func() Build {
	bi, ok := debug.ReadBuildInfo()
	return resolve(Version, Commit, Date, bi, ok)
})

// resolve merges the link-time stamps with the toolchain's embedded build
// info. Link-time values always win; the build info only fills gaps.
func resolve(version, commit, date string, bi *debug.BuildInfo, ok bool) Build {
	b := Build{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if ok && bi != nil {
		var revision, vcsTime string
		var dirty bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				vcsTime = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if b.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			b.Version = bi.Main.Version
		}
		if b.Commit == "" && revision != "" {
			b.Commit = revision
			if dirty {
				b.Commit += dirtySuffix
			}
		}
		if b.Date == "" {
			b.Date = vcsTime
		}
		if bi.GoVersion != "" {
			b.GoVersion = bi.GoVersion
		}
	}
	if b.Version == "" {
		b.Version = devVersion
	}
	b.Date = normalizeDate(b.Date)
	return b
}

// normalizeDate reduces an RFC 3339 timestamp to a plain date. Anything it
// cannot parse is returned unchanged, so an operator-supplied stamp is never
// silently discarded.
func normalizeDate(date string) string {
	if date == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, date); err == nil {
		return t.UTC().Format(time.DateOnly)
	}
	return date
}

// String renders the build for a --version banner, for example
// "0.1.0 (commit abc1234, built 2026-08-29, go1.27.0, linux/amd64)". Stamps
// that are unknown are omitted rather than printed as empty fields.
func (b Build) String() string {
	version := b.Version
	if version == "" {
		version = devVersion
	}
	parts := make([]string, 0, 4)
	if b.Commit != "" {
		parts = append(parts, "commit "+shortCommit(b.Commit))
	}
	if b.Date != "" {
		parts = append(parts, "built "+b.Date)
	}
	if b.GoVersion != "" {
		parts = append(parts, b.GoVersion)
	}
	if b.Platform != "" {
		parts = append(parts, b.Platform)
	}
	if len(parts) == 0 {
		return version
	}
	return version + " (" + strings.Join(parts, ", ") + ")"
}

// shortCommit abbreviates a revision to its first seven characters, preserving
// any "+dirty" marker.
func shortCommit(commit string) string {
	rev, suffix := commit, ""
	if i := strings.IndexByte(commit, '+'); i >= 0 {
		rev, suffix = commit[:i], commit[i:]
	}
	if len(rev) > shortCommitLen {
		rev = rev[:shortCommitLen]
	}
	return rev + suffix
}

// Map renders the build as flat key/value pairs suitable for metric labels and
// structured log attributes. The keys are stable: "version", "commit", "date",
// "goversion" and "platform".
func (b Build) Map() map[string]string {
	return map[string]string{
		"version":   b.Version,
		"commit":    b.Commit,
		"date":      b.Date,
		"goversion": b.GoVersion,
		"platform":  b.Platform,
	}
}
