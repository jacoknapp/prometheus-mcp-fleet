// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// PepperFileMode is the permission bitmask a pepper file must be created with
// and must still carry when it is read back.
const PepperFileMode fs.FileMode = 0o600

// ErrInsecurePepperFile reports a pepper file readable or writable by anyone
// other than its owner. The hub refuses to start rather than key every stored
// digest with a secret the whole machine can read.
var ErrInsecurePepperFile = errors.New("pepper file has insecure permissions")

// GeneratePepper returns [MinPepperBytes] fresh bytes from the system CSPRNG.
func GeneratePepper() ([]byte, error) {
	p := make([]byte, MinPepperBytes)
	if _, err := randRead(p); err != nil {
		return nil, fmt.Errorf("generate pepper: %w", err)
	}
	return p, nil
}

// LoadOrCreatePepper reads the pepper at path, creating it if it does not
// exist.
//
// The file holds raw bytes, not text: no encoding, no trailing newline, no
// framing. That keeps "what is the key" unambiguous, which matters because a
// pepper that changes by one byte invalidates every credential in the
// database at once.
//
// On creation it makes the parent directory 0700 and the file [PepperFileMode]
// with O_EXCL, so two hubs racing to initialise the same data directory cannot
// both win. On load it refuses a file whose group or other bits are set
// ([ErrInsecurePepperFile]) and a file shorter than [MinPepperBytes]
// ([ErrShortPepper]).
func LoadOrCreatePepper(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("pepper path is empty")
	}
	p, err := readPepper(path)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	return createPepper(path)
}

// createPepper generates a pepper and writes it to path exclusively. If
// another process won the creation race it reads that process's bytes instead,
// so two hubs initialising the same data directory converge on one pepper
// rather than each keying its digests differently.
func createPepper(path string) ([]byte, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("pepper directory %s: %w", dir, err)
		}
	}
	fresh, err := GeneratePepper()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, PepperFileMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readPepper(path)
		}
		return nil, fmt.Errorf("create pepper %s: %w", path, err)
	}
	if _, err := f.Write(fresh); err != nil {
		f.Close()
		return nil, fmt.Errorf("write pepper %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close pepper %s: %w", path, err)
	}
	return fresh, nil
}

// readPepper loads and validates an existing pepper file.
func readPepper(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("pepper %s: %w", path, fs.ErrInvalid)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("pepper %s is mode %04o, want %04o: %w",
			path, perm, PepperFileMode, ErrInsecurePepperFile)
	}
	p, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pepper %s: %w", path, err)
	}
	if len(p) < MinPepperBytes {
		return nil, fmt.Errorf("pepper %s is %d bytes, need at least %d: %w",
			path, len(p), MinPepperBytes, ErrShortPepper)
	}
	return p, nil
}
