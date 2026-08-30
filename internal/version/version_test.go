// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	bi := func(mainVersion string, settings ...debug.BuildSetting) *debug.BuildInfo {
		info := &debug.BuildInfo{Settings: settings, GoVersion: "go1.27.0"}
		info.Main.Version = mainVersion
		return info
	}
	set := func(k, v string) debug.BuildSetting { return debug.BuildSetting{Key: k, Value: v} }

	tests := []struct {
		name                  string
		version, commit, date string
		info                  *debug.BuildInfo
		ok                    bool
		want                  Build
	}{
		{
			name:    "ldflags win over build info",
			version: "1.2.3", commit: "deadbeefdeadbeef", date: "2026-08-29",
			info: bi("v9.9.9", set("vcs.revision", "0000"), set("vcs.time", "2000-01-01T00:00:00Z")),
			ok:   true,
			want: Build{Version: "1.2.3", Commit: "deadbeefdeadbeef", Date: "2026-08-29", GoVersion: "go1.27.0", Platform: platform()},
		},
		{
			name: "build info fills gaps",
			info: bi("v0.4.0", set("vcs.revision", "abc1234def"), set("vcs.time", "2026-08-29T11:22:33Z")),
			ok:   true,
			want: Build{Version: "v0.4.0", Commit: "abc1234def", Date: "2026-08-29", GoVersion: "go1.27.0", Platform: platform()},
		},
		{
			name: "dirty tree is marked",
			info: bi("(devel)", set("vcs.revision", "abc1234def"), set("vcs.modified", "true")),
			ok:   true,
			want: Build{Version: "dev", Commit: "abc1234def+dirty", GoVersion: "go1.27.0", Platform: platform()},
		},
		{
			name: "no build info falls back to dev",
			ok:   false,
			want: Build{Version: "dev", GoVersion: runtime.Version(), Platform: platform()},
		},
		{
			name: "nil build info with ok is tolerated",
			ok:   true,
			want: Build{Version: "dev", GoVersion: runtime.Version(), Platform: platform()},
		},
		{
			name: "unparseable date is preserved",
			date: "yesterday",
			ok:   false,
			want: Build{Version: "dev", Date: "yesterday", GoVersion: runtime.Version(), Platform: platform()},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolve(tc.version, tc.commit, tc.date, tc.info, tc.ok)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("resolve() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    Build
		want string
	}{
		{
			name: "full",
			b:    Build{Version: "0.1.0", Commit: "abc1234def5678", Date: "2026-08-29", GoVersion: "go1.27.0", Platform: "linux/amd64"},
			want: "0.1.0 (commit abc1234, built 2026-08-29, go1.27.0, linux/amd64)",
		},
		{
			name: "dirty commit keeps its marker",
			b:    Build{Version: "0.1.0", Commit: "abc1234def5678+dirty", GoVersion: "go1.27.0", Platform: "linux/amd64"},
			want: "0.1.0 (commit abc1234+dirty, go1.27.0, linux/amd64)",
		},
		{
			name: "short commit is not padded",
			b:    Build{Version: "dev", Commit: "abc", Platform: "linux/amd64"},
			want: "dev (commit abc, linux/amd64)",
		},
		{
			name: "empty version defaults to dev",
			b:    Build{Platform: "linux/amd64"},
			want: "dev (linux/amd64)",
		},
		{
			name: "nothing known",
			b:    Build{},
			want: "dev",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.b.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildMap(t *testing.T) {
	t.Parallel()

	b := Build{Version: "1.0.0", Commit: "abc", Date: "2026-08-29", GoVersion: "go1.27.0", Platform: "linux/amd64"}
	want := map[string]string{
		"version":   "1.0.0",
		"commit":    "abc",
		"date":      "2026-08-29",
		"goversion": "go1.27.0",
		"platform":  "linux/amd64",
	}
	if diff := cmp.Diff(want, b.Map()); diff != "" {
		t.Errorf("Map() mismatch (-want +got):\n%s", diff)
	}
}

func TestGetIsCachedAndPopulated(t *testing.T) {
	t.Parallel()

	got := Get()
	if got.Version == "" {
		t.Error("Get().Version is empty; it must never be")
	}
	if got.GoVersion == "" || !strings.HasPrefix(got.GoVersion, "go") {
		t.Errorf("Get().GoVersion = %q, want a go toolchain version", got.GoVersion)
	}
	if got.Platform != platform() {
		t.Errorf("Get().Platform = %q, want %q", got.Platform, platform())
	}
	if diff := cmp.Diff(got, Get()); diff != "" {
		t.Errorf("Get() is not stable across calls (-first +second):\n%s", diff)
	}
}

func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
