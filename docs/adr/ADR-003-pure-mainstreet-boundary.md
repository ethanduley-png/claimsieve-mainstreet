# ADR-003: Pure MainStreet proposal boundary

**Status:** Accepted

## Context

An injected transport inside the MainStreet bridge created a direct side-effect seam and made capability review dependent on caller behavior.

## Decision

The production bridge only prepares proposals and validates acknowledgments. Transport and OpenClaw integration live outside the trusted module and receive no ClaimSieve authority.

## Consequences

The boundary is easier to test and audit. A separate intake service must handle communication and must itself be treated as untrusted.
