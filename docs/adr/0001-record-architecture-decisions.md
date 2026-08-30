# 0001. Record architecture decisions

* Status: Accepted
* Date: 2026-08-29

## Context

This project makes several choices that look wrong at first glance: it inverts
gRPC's client/server roles, it refuses to parse PromQL, it declines a database,
and it deliberately does not implement OAuth for an MCP server. Each is
defensible, and each will look like a bug to someone reading the code cold.

Code comments explain *what* a line does. They are a poor place for the three
paragraphs of trade-off reasoning behind a structural choice, and they rot when
the code moves.

## Decision

We keep Architecture Decision Records in `docs/adr/`, numbered sequentially,
using the template in the README of that directory. A pull request that changes
a structural decision must add or supersede a record; the pull request template
asks for it.

Records are immutable. A reversal is a new record that supersedes the old, and
the old one stays in place.

## Consequences

Reviewers get a place to argue about design without blocking on implementation
detail. New contributors can read thirteen short documents instead of
reverse-engineering intent from a diff. The cost is discipline: a record that is
written after the fact to justify a decision already shipped is worse than none,
because it launders an accident into a rationale.

## Alternatives considered

* **A design document in a wiki.** Drifts from the code, is not reviewed with
  the change that invalidates it, and is invisible in `git log`.
* **Comments only.** Fine for local reasoning, hopeless for a decision that
  spans six packages and two charts.
* **Nothing.** The default, and the reason most projects cannot explain
  themselves after eighteen months.
