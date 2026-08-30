// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the runtime configuration of both
// binaries from command-line flags and the environment.
//
// It sits at L0: it may be imported by anything and imports nothing from this
// module. It uses the standard library's flag package only — no viper, no
// cobra, no struct-tag reflection.
//
// # Flags, environment and precedence
//
// Every flag --foo-bar is also readable from the environment variable
// PMF_FOO_BAR. The mapping is computed mechanically by [EnvKey] from the flag
// name, so a flag and its variable cannot drift apart.
//
// Precedence is flag > environment > default. It is implemented by seeding the
// FlagSet's defaults from the environment before parsing, so an explicitly
// passed flag always wins and no flag.Visit bookkeeping is needed.
//
// # Secrets
//
// No secret value is ever configured inline: credentials are always named by
// file path (PMF_PEPPER_FILE, PMF_ENROLLMENT_TOKEN_FILE,
// PMF_PROMETHEUS_BEARER_TOKEN_FILE) and this package never opens those files.
// Paths are therefore safe to log; [Hub.LogValue] and [Spoke.LogValue] still
// strip URL userinfo, which is the one place a password can hide in a value
// this package does hold.
//
// Loading is not safe for concurrent use with respect to the getenv function
// supplied by the caller; the resulting *Hub and *Spoke are read-only values
// and are safe to share once loaded.
package config
