// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestAPIErrorUnwrap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  APIError
		want error
	}{
		{"not found", APIError{Status: http.StatusNotFound}, ErrNotFound},
		{"forbidden", APIError{Status: http.StatusForbidden}, ErrForbidden},
		{"unauthorized", APIError{Status: http.StatusUnauthorized}, ErrUnauthorized},
		{"create conflict by reason", APIError{Status: http.StatusConflict, Reason: reasonAlreadyExists, Verb: verbUpdateSecret}, ErrAlreadyExists},
		{"update conflict by reason", APIError{Status: http.StatusConflict, Reason: reasonConflict, Verb: verbCreateSecret}, ErrConflict},
		{"create conflict by verb", APIError{Status: http.StatusConflict, Verb: verbCreateSecret}, ErrAlreadyExists},
		{"update conflict by verb", APIError{Status: http.StatusConflict, Verb: verbUpdateSecret}, ErrConflict},
		{"unmapped status", APIError{Status: http.StatusInternalServerError}, nil},
		{"gateway timeout", APIError{Status: http.StatusGatewayTimeout}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.err.Unwrap()
			if !errors.Is(got, tc.want) && (got != nil || tc.want != nil) {
				t.Errorf("Unwrap() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPIErrorMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		err      APIError
		contains []string
		absent   []string
	}{
		{
			name:     "falls back to the status text",
			err:      APIError{Verb: verbGetSecret, Status: http.StatusBadGateway},
			contains: []string{"get secret", "502", "Bad Gateway"},
		},
		{
			name:     "carries the api server message and reason",
			err:      APIError{Verb: verbUpdateSecret, Status: http.StatusConflict, Reason: reasonConflict, Message: "the object has been modified"},
			contains: []string{"update secret", "409", "the object has been modified", "reason Conflict"},
			absent:   []string{"RoleBinding"},
		},
		{
			name:     "names the missing rule",
			err:      APIError{Verb: verbGetSecret, Status: http.StatusForbidden, Namespace: "monitoring"},
			contains: []string{"secrets get/create/update in namespace monitoring", "RoleBinding"},
		},
		{
			name:     "names the rule even without a namespace",
			err:      APIError{Verb: verbGetSecret, Status: http.StatusForbidden},
			contains: []string{"secrets get/create/update in namespace <namespace>"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.err.Error()
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want it to contain %q", got, want)
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(got, unwanted) {
					t.Errorf("Error() = %q, want it not to contain %q", got, unwanted)
				}
			}
		})
	}
}

func TestStatusErrorTolerAtesAnUnparseableBody(t *testing.T) {
	t.Parallel()
	e := statusError(verbGetSecret, "monitoring", http.StatusInternalServerError, []byte("<html>oops</html>"))
	if e.Message != "" || e.Reason != "" {
		t.Errorf("parsed message %q reason %q from a non-Status body", e.Message, e.Reason)
	}
	if !strings.Contains(e.Error(), "Internal Server Error") {
		t.Errorf("Error() = %q, want the standard status text", e.Error())
	}
}
