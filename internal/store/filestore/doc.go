// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package filestore is the local-development store.Store backend: one JSON
// file on local disk.
//
// # Responsibility
//
// It owns durability for a single process. The document format, every
// mutation and every semantic guarantee belong to internal/store; this
// package only decides where the bytes live and how they get written.
//
// # Guarantees
//
// The file is created 0600 in a 0700 directory and is refused on load if its
// group or other permission bits are set, because it holds the HMAC of every
// issued credential. Every write goes to a temporary file in the same
// directory, is fsynced, and is then renamed over the target, so a crash
// mid-write leaves either the previous document or the new one and never a
// truncated file. The parent directory is fsynced afterwards so the rename
// itself survives a power loss.
//
// # Scope
//
// It is deliberately single-process: concurrency is an in-process mutex, not
// a file lock, and a second process writing the same path will lose writes.
// Production is internal/store/secretstore, whose compare-and-swap works
// across hub replicas. Use this backend for local runs, for tests, and for a
// single-replica deployment that refuses any Kubernetes RBAC.
//
// # Importers and concurrency
//
// Layer L1. May be imported by the hub composition root and by tests. A
// [Store] is safe for concurrent use by multiple goroutines.
package filestore
