// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package testutil holds the fakes every other package's tests share: a
// Prometheus HTTP API server backed by realistic fixtures, and a manually
// advanced clock.
//
// It sits at the top of the dependency graph. It may import anything; nothing
// outside a _test.go file may import it. It deliberately depends on no other
// internal package, so a fake can never be broken by a change to the code it is
// used to test.
//
// Concurrency: [FakePrometheus] is safe for concurrent use by many requests and
// by a test goroutine calling [FakePrometheus.Requests]. [Clock] is safe for
// concurrent use.
package testutil
