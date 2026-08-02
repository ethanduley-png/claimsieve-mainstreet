# ADR-007: Founder OS Reuses the v0.33 Authority Boundary

## Status

Accepted for v0.34.0.

## Context

The Founder OS v0.1 starter contained its own HMAC permit authority, in-memory replay set, adapter, and outcome classifier. The v0.33 baseline already contains stronger signed policy, signed evidence, exact permits, durable campaign state, reservations, fencing, restricted execution, and independent observation.

## Decision

Do not merge the starter authority into the active runtime. Preserve it as provenance and migrate only its product requirements onto the v0.33 components.

## Consequences

- No second permit issuer is introduced.
- Founder OS inherits v0.33 unknown-outcome and durable-state semantics.
- The product slice remains provider neutral even though GitHub is the first connector target.
- The restricted GitHub adapter reuses this authority boundary; one authorized canary later exercised the exact-action path without introducing a second issuer.
