// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGeneratePepper(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		p, err := GeneratePepper()
		if err != nil {
			t.Fatalf("GeneratePepper: %v", err)
		}
		if len(p) != MinPepperBytes {
			t.Fatalf("pepper length = %d, want %d", len(p), MinPepperBytes)
		}
		if _, dup := seen[string(p)]; dup {
			t.Fatalf("duplicate pepper after %d draws", i)
		}
		seen[string(p)] = struct{}{}
		if bytes.Equal(p, make([]byte, MinPepperBytes)) {
			t.Fatal("pepper is all zeroes")
		}
		if _, err := NewHasher(p); err != nil {
			t.Fatalf("GeneratePepper output rejected by NewHasher: %v", err)
		}
	}
}

func TestLoadOrCreatePepperCreates(t *testing.T) {
	t.Parallel()
	// Nested path proves the parent directory is created.
	path := filepath.Join(t.TempDir(), "data", "nested", "pepper.key")

	first, err := LoadOrCreatePepper(path)
	if err != nil {
		t.Fatalf("LoadOrCreatePepper: %v", err)
	}
	if len(first) != MinPepperBytes {
		t.Fatalf("pepper length = %d, want %d", len(first), MinPepperBytes)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != PepperFileMode {
		t.Errorf("file mode = %04o, want %04o", got, PepperFileMode)
	}
	if got := info.Size(); got != int64(MinPepperBytes) {
		t.Errorf("file size = %d, want %d (raw bytes, no encoding or newline)", got, MinPepperBytes)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("directory mode = %04o, want 0700", got)
	}

	second, err := LoadOrCreatePepper(path)
	if err != nil {
		t.Fatalf("LoadOrCreatePepper (reload): %v", err)
	}
	if diff := cmp.Diff(first, second); diff != "" {
		t.Errorf("reload returned different bytes (-first +second):\n%s", diff)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if diff := cmp.Diff(first, onDisk); diff != "" {
		t.Errorf("returned pepper differs from the file contents (-returned +file):\n%s", diff)
	}
}

func TestLoadOrCreatePepperRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		wantErr error
	}{
		{
			name:    "empty path",
			setup:   func(*testing.T, string) string { return "" },
			wantErr: nil, // any error; asserted separately below
		},
		{
			name: "group readable",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				writeFile(t, p, bytes.Repeat([]byte{1}, MinPepperBytes), 0o640)
				return p
			},
			wantErr: ErrInsecurePepperFile,
		},
		{
			name: "world readable",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				writeFile(t, p, bytes.Repeat([]byte{1}, MinPepperBytes), 0o644)
				return p
			},
			wantErr: ErrInsecurePepperFile,
		},
		{
			name: "world writable",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				writeFile(t, p, bytes.Repeat([]byte{1}, MinPepperBytes), 0o602)
				return p
			},
			wantErr: ErrInsecurePepperFile,
		},
		{
			name: "too short",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				writeFile(t, p, bytes.Repeat([]byte{1}, MinPepperBytes-1), 0o600)
				return p
			},
			wantErr: ErrShortPepper,
		},
		{
			name: "empty file",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				writeFile(t, p, nil, 0o600)
				return p
			},
			wantErr: ErrShortPepper,
		},
		{
			name: "path is a directory",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "pepper.key")
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				return p
			},
			wantErr: fs.ErrInvalid,
		},
		{
			name: "parent is a file",
			setup: func(t *testing.T, dir string) string {
				blocker := filepath.Join(dir, "blocker")
				writeFile(t, blocker, []byte("x"), 0o600)
				return filepath.Join(blocker, "pepper.key")
			},
			wantErr: nil, // ENOTDIR from MkdirAll; any error is acceptable
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := tc.setup(t, t.TempDir())
			p, err := LoadOrCreatePepper(path)
			if err == nil {
				t.Fatalf("LoadOrCreatePepper(%q) = %v, want an error", path, p)
			}
			if p != nil {
				t.Errorf("LoadOrCreatePepper returned %d bytes alongside an error", len(p))
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestCreatePepperLosesRace covers the branch taken when another process wins
// the exclusive create between the load attempt and the create attempt.
func TestCreatePepperLosesRace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "pepper.key")
	winner := bytes.Repeat([]byte{0x7e}, MinPepperBytes)
	writeFile(t, path, winner, 0o600)

	got, err := createPepper(path)
	if err != nil {
		t.Fatalf("createPepper: %v", err)
	}
	if diff := cmp.Diff(winner, got); diff != "" {
		t.Errorf("race loser did not adopt the winner's pepper (-want +got):\n%s", diff)
	}
}

// TestCreatePepperLosesRaceToBadFile proves the loser still validates what it
// finds rather than trusting it blindly.
func TestCreatePepperLosesRaceToBadFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "pepper.key")
	writeFile(t, path, []byte("short"), 0o600)

	if _, err := createPepper(path); !errors.Is(err, ErrShortPepper) {
		t.Fatalf("createPepper error = %v, want ErrShortPepper", err)
	}
}

func TestReadPepperUnreadableFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny reads")
	}
	path := filepath.Join(t.TempDir(), "pepper.key")
	writeFile(t, path, bytes.Repeat([]byte{1}, MinPepperBytes), 0o200)
	if _, err := readPepper(path); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("readPepper error = %v, want a permission error", err)
	}
}

func writeFile(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// WriteFile applies the umask; force the exact mode the test needs.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}
