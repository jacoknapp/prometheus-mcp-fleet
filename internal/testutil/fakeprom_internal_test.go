// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestMustFixtureRejectsMissingName(t *testing.T) {
	t.Parallel()
	defer func() {
		if got := recover(); got == nil {
			t.Fatal("mustFixture accepted a missing embedded fixture")
		}
	}()
	mustFixture("does-not-exist.json")
}

func TestInjectMemberLeavesNonObjectUnchanged(t *testing.T) {
	t.Parallel()
	in := []byte(`[1,2,3]`)
	if got := injectMember(in, `"x":1`); string(got) != string(in) {
		t.Errorf("injectMember(non-object) = %s, want %s", got, in)
	}
}

func TestWriteBodyStopsAfterWriterFailure(t *testing.T) {
	t.Parallel()
	w := &failingResponseWriter{header: make(http.Header)}
	f := &FakePrometheus{opts: FakeOptions{SlowBody: time.Nanosecond}}
	f.writeBody(w, make([]byte, 8192))
	if w.writes != 1 {
		t.Errorf("writeBody attempted %d writes after the first failure, want 1", w.writes)
	}
}

type failingResponseWriter struct {
	header http.Header
	writes int
}

func (w *failingResponseWriter) Header() http.Header { return w.header }
func (*failingResponseWriter) WriteHeader(int)       {}
func (w *failingResponseWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("injected write failure")
}
