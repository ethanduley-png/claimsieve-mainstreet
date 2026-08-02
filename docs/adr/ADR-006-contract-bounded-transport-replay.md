# ADR-006: Contract-Bounded Transport Replay

**Status:** Accepted for the v0.33 reference model

## Context

A network error can leave a request outcome unknown. A blanket no-retry rule can prevent a provider's documented idempotency mechanism from being used to obtain the original response. A blanket retry rule can create duplicate effects.

## Decision

Permit a transport replay only as a continuation of the same dispatch when reservation, idempotency key, canonical request, endpoint, account, active authority, provider guarantee, retention window, and replay budget remain exact.

The replay is not a new logical attempt and does not issue or consume a new permit.

A 500 remains indeterminate. Reuse outside the guaranteed retention window is denied.

## Consequences

* provider-specific semantics become explicit policy inputs;
* replay behavior can be tested against published contracts;
* revocation can stop a replay even when the provider would accept it;
* live provider behavior still requires separate validation.
