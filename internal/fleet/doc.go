// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package fleet holds the domain types shared by the hub and the spoke.
//
// It is the root of the dependency graph: every other internal package may
// import fleet, and fleet imports nothing from this module. Keeping it free of
// behaviour (no I/O, no clients, no config parsing) is what prevents import
// cycles between the authentication, tunnel, registry and MCP layers.
package fleet
