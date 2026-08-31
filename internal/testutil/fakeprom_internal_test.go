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

// TestInjectMemberAtIndexZero pins the boundary of injectMember's own guard,
// "i < 0": when the last (and only) '}' sits at index 0, i is 0, not
// negative, and injection must still happen there. This is the only body
// shape distinguishing "i < 0" from the off-by-one "i <= 0", since any other
// body either has no '}' at all (i stays -1, already covered by
// TestInjectMemberLeavesNonObjectUnchanged) or has one at a positive index.
func TestInjectMemberAtIndexZero(t *testing.T) {
	t.Parallel()
	got := injectMember([]byte("}"), `"x":1`)
	want := `,"x":1}`
	if string(got) != want {
		t.Errorf(`injectMember("}", ...) = %q, want %q`, got, want)
	}
}

// TestIsJSONHandlesEmptyBodyWithoutPanicking pins the boundary of isJSON's
// short-circuit, "len(body) > 0 &&...": a widened ">= 0" would always be
// true, reaching body[0] on a zero-length slice and panicking instead of
// reporting false.
func TestIsJSONHandlesEmptyBodyWithoutPanicking(t *testing.T) {
	t.Parallel()
	if isJSON(nil) {
		t.Error("isJSON(nil) = true, want false")
	}
	if isJSON([]byte{}) {
		t.Error("isJSON([]byte{}) = true, want false")
	}
}

// recordingResponseWriter records every Write call's size, so a test can
// assert on writeBody's chunking behaviour rather than only on the bytes a
// client eventually reassembles from them.
type recordingResponseWriter struct {
	header  http.Header
	writes  []int
	written int
}

func (w *recordingResponseWriter) Header() http.Header { return w.header }
func (*recordingResponseWriter) WriteHeader(int)       {}
func (w *recordingResponseWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, len(p))
	w.written += len(p)
	return len(p), nil
}

// TestWriteBodyIsUnchunkedWhenSlowBodyIsZero pins the boundary of writeBody's
// fast-path guard, "SlowBody <= 0": at exactly zero, the whole body must go
// out in a single Write, not through the chunked, per-chunk-sleeping path a
// widened "SlowBody < 0" would fall through to.
func TestWriteBodyIsUnchunkedWhenSlowBodyIsZero(t *testing.T) {
	t.Parallel()
	w := &recordingResponseWriter{header: make(http.Header)}
	f := &FakePrometheus{opts: FakeOptions{SlowBody: 0}}
	body := make([]byte, 8192) // more than one 4096-byte chunk.
	f.writeBody(w, body)
	if len(w.writes) != 1 {
		t.Fatalf("writeBody with SlowBody=0 made %d Write calls, want exactly 1", len(w.writes))
	}
	if w.written != len(body) {
		t.Errorf("bytes written = %d, want %d", w.written, len(body))
	}
}

// TestWriteBodyChunksAnExactMultipleWithNoTrailingEmptyWrite pins the
// boundary of the chunk loop's own condition, "off < len(body)": when the
// body length is an exact multiple of the chunk size, the loop must stop the
// moment off reaches len(body), not run one further, empty iteration that an
// off-by-one "off <= len(body)" would add (with its own pointless Write and
// SlowBody sleep).
func TestWriteBodyChunksAnExactMultipleWithNoTrailingEmptyWrite(t *testing.T) {
	t.Parallel()
	w := &recordingResponseWriter{header: make(http.Header)}
	f := &FakePrometheus{opts: FakeOptions{SlowBody: time.Nanosecond}}
	body := make([]byte, 8192) // exactly two 4096-byte chunks.
	f.writeBody(w, body)
	if len(w.writes) != 2 {
		t.Fatalf("writeBody wrote in %d calls, want exactly 2 (no trailing empty write); sizes = %v",
			len(w.writes), w.writes)
	}
	for i, n := range w.writes {
		if n != 4096 {
			t.Errorf("write %d was %d bytes, want 4096", i, n)
		}
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
