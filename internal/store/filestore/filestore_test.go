// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/filestore"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store/storetest"
)

// tBase is the fixed reference time used by the tests that need one.
var tBase = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// TestConformance is the whole contract; everything below it tests only what
// is specific to a file on disk.
func TestConformance(t *testing.T) {
	t.Parallel()
	storetest.RunSuite(t, func(t *testing.T) store.Store {
		t.Helper()
		return open(t, filepath.Join(t.TempDir(), "state.json"))
	})
}

func open(t *testing.T, path string) *filestore.Store {
	t.Helper()
	s, err := filestore.Open(filestore.Options{Path: path, Clock: func() time.Time { return tBase }})
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestOpen(t *testing.T) {
	t.Parallel()

	t.Run("creates the file and the directory", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "nested", "dir", "state.json")
		s := open(t, path)
		if s.Path() != path {
			t.Errorf("Path() = %q, want %q", s.Path(), path)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != filestore.FileMode {
			t.Errorf("file mode = %#o, want %#o", perm, filestore.FileMode)
		}
		di, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("stat dir: %v", err)
		}
		if perm := di.Mode().Perm(); perm != filestore.DirMode {
			t.Errorf("directory mode = %#o, want %#o", perm, filestore.DirMode)
		}
		if s.Size() == 0 {
			t.Error("Size() = 0 for a freshly created document")
		}
	})

	t.Run("requires a path", func(t *testing.T) {
		t.Parallel()
		if _, err := filestore.Open(filestore.Options{}); err == nil {
			t.Error("Open with no path = nil, want an error")
		}
	})

	t.Run("rejects a corrupt document", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := filestore.Open(filestore.Options{Path: path})
		if !errors.Is(err, store.ErrCorrupt) {
			t.Errorf("Open error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("rejects a newer schema", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(`{"schemaVersion":99}`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := filestore.Open(filestore.Options{Path: path})
		if !errors.Is(err, store.ErrSchemaTooNew) {
			t.Errorf("Open error = %v, want ErrSchemaTooNew", err)
		}
	})

	t.Run("rejects insecure permissions", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(`{"schemaVersion":1}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := filestore.Open(filestore.Options{Path: path})
		if !errors.Is(err, filestore.ErrInsecureFile) {
			t.Errorf("Open error = %v, want ErrInsecureFile", err)
		}
	})

	t.Run("reports an unusable directory", func(t *testing.T) {
		t.Parallel()
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := filestore.Open(filestore.Options{Path: filepath.Join(blocker, "state.json")}); err == nil {
			t.Error("Open under a regular file = nil, want an error")
		}
	})
}

// TestPersistenceAcrossReopen is the property the whole package exists for.
func TestPersistenceAcrossReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	s := open(t, path)

	key := &fleet.Key{
		KID:        "agent0001",
		Class:      fleet.ClassAgent,
		Name:       "sre-oncall-bot",
		SecretHMAC: []byte{0x00, 0x01, 0xfe, 0xff},
		Scope: &fleet.Scope{
			Role:     fleet.RoleViewer,
			Clusters: fleet.ClusterScope{Allow: []string{"prod-eu-1"}},
			Tools:    fleet.ToolScope{Allow: []string{"prom.query"}},
		},
		CreatedAt: tBase,
		ExpiresAt: tBase.Add(720 * time.Hour),
	}
	if err := s.PutKey(t.Context(), key); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	if err := s.RevokeCert(t.Context(), store.RevokedCert{Serial: "0a", RevokedAt: tBase, NotAfter: tBase}); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	wantEpoch, err := s.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened := open(t, path)
	got, err := reopened.GetKey(t.Context(), key.KID)
	if err != nil {
		t.Fatalf("GetKey after reopen: %v", err)
	}
	if diff := cmp.Diff(key, got); diff != "" {
		t.Errorf("key did not survive a reopen (-want +got):\n%s", diff)
	}
	gotEpoch, err := reopened.Epoch(t.Context())
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if gotEpoch != wantEpoch {
		t.Errorf("epoch = %d after reopen, want %d: a reset epoch would silently un-revoke every cached credential",
			gotEpoch, wantEpoch)
	}
	certs, err := reopened.ListRevokedCerts(t.Context())
	if err != nil {
		t.Fatalf("ListRevokedCerts: %v", err)
	}
	if len(certs) != 1 || certs[0].Serial != "0a" {
		t.Errorf("revoked certificates = %+v, want the one entry", certs)
	}
}

func TestWritesAreAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := open(t, path)
	for i := range 5 {
		if err := s.PutKey(t.Context(), &fleet.Key{
			KID:       "agent" + string(rune('a'+i)),
			Class:     fleet.ClassAgent,
			CreatedAt: tBase,
		}); err != nil {
			t.Fatalf("PutKey: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file %s left behind; every write must rename or clean up", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want just the state file", len(entries))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != filestore.FileMode {
		t.Errorf("file mode after a rename = %#o, want %#o", perm, filestore.FileMode)
	}
	if s.Size() != int(fi.Size()) {
		t.Errorf("Size() = %d, want the file's %d", s.Size(), fi.Size())
	}
}

func TestWriteFailureIsReported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := open(t, path)
	// Removing the directory makes the temp-file creation fail, which is the
	// only failure mode reachable without root.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove dir: %v", err)
	}
	err := s.PutKey(t.Context(), &fleet.Key{KID: "agent0001", Class: fleet.ClassAgent, CreatedAt: tBase})
	if err == nil {
		t.Fatal("PutKey = nil, want the write failure to surface")
	}
	if !strings.Contains(err.Error(), "temp file") {
		t.Errorf("error = %v, want it to name the failed write", err)
	}
}

func TestStateTooLarge(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := filestore.Open(filestore.Options{Path: path, MaxBytes: 400, Clock: func() time.Time { return tBase }})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var last error
	for i := range 20 {
		last = s.PutKey(t.Context(), &fleet.Key{
			KID:       "agent" + string(rune('a'+i)),
			Class:     fleet.ClassAgent,
			Name:      strings.Repeat("x", 40),
			CreatedAt: tBase,
		})
		if last != nil {
			break
		}
	}
	if !errors.Is(last, store.ErrStateTooLarge) {
		t.Fatalf("error = %v, want ErrStateTooLarge", last)
	}
	for _, want := range []string{"400 byte limit", "keys"} {
		if !strings.Contains(last.Error(), want) {
			t.Errorf("error %q does not contain %q", last, want)
		}
	}
	// The refused write must not have been persisted.
	reopened := open(t, path)
	if _, err := reopened.Epoch(t.Context()); err != nil {
		t.Fatalf("the refused write corrupted the file: %v", err)
	}
}

func TestUnboundedSize(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := filestore.Open(filestore.Options{Path: path, MaxBytes: -1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.PutKey(t.Context(), &fleet.Key{
		KID:       "agent0001",
		Class:     fleet.ClassAgent,
		Name:      strings.Repeat("x", 2<<20),
		CreatedAt: tBase,
	}); err != nil {
		t.Errorf("PutKey with MaxBytes -1 = %v, want no limit", err)
	}
}

func TestCorruptionAfterOpenIsReported(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	s := open(t, path)
	// Simulate an operator editing the file underneath a running hub. The
	// in-memory copy is authoritative, so this cannot corrupt reads; it is
	// the reopen that must refuse.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.Epoch(t.Context()); err != nil {
		t.Errorf("Epoch after an external edit = %v, want the in-memory document", err)
	}
	if _, err := filestore.Open(filestore.Options{Path: path}); !errors.Is(err, store.ErrCorrupt) {
		t.Errorf("Open error = %v, want ErrCorrupt", err)
	}
}

func TestSizeAfterClose(t *testing.T) {
	t.Parallel()
	s := open(t, filepath.Join(t.TempDir(), "state.json"))
	before := s.Size()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.Size(); got != before {
		t.Errorf("Size() = %d after Close, want the last known %d", got, before)
	}
}
