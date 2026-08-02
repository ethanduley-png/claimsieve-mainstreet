# ADR-002: Single-successor campaign history

**Status:** Accepted for v0.31 reference

## Context

Two permit requests could be derived from the same campaign predecessor, defeating cumulative limits.

## Decision

Commit the exact predecessor-to-successor transition through compare-and-swap before permit issuance. A stale predecessor fails closed.

## Consequences

The reference blocks forks in one process. Production requires a linearizable, durable backend with fencing and crash tests.
