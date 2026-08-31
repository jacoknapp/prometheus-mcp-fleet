// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"errors"
	"testing"
)

func TestSessionHandlerFuncAdaptsFunction(t *testing.T) {
	t.Parallel()

	want := errors.New("handled")
	called := false
	h := SessionHandlerFunc(func(ctx context.Context, s Session) (func(), error) {
		called = true
		if ctx != t.Context() || s != nil {
			t.Fatalf("callback received ctx=%v session=%v", ctx, s)
		}
		return nil, want
	})
	release, err := h.OnSession(t.Context(), nil)
	if !called || release != nil || !errors.Is(err, want) {
		t.Fatalf("OnSession release non-nil=%v err=%v called=%v", release != nil, err, called)
	}
}
