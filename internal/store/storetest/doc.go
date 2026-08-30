// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package storetest is the behavioural conformance suite every store.Store
// implementation must pass.
//
// The point of the suite is that the contract lives in exactly one place. Each
// backend's test file is a single call to [RunSuite], and any behaviour it
// gets wrong -- ordering, idempotency, epoch bumping, copy semantics, the
// atomicity of BurnEnrollment under concurrency, ErrClosed after Close --
// fails there rather than in production. It is what makes the claim "the
// Kubernetes Secret backend and the file backend are interchangeable" a
// tested fact rather than an intention.
//
// The suite covers only behaviour visible through the [store.Store]
// interface. Backend-specific properties -- the file backend's atomic rename
// and permission checks, the Secret backend's resourceVersion retry loop and
// size ceiling -- are tested in those packages.
//
// It is a non-test package so that other modules and future backends can
// import it. It may be imported only from tests.
package storetest
