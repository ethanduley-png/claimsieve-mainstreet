# ADR-001: External role-scoped trust root

**Status:** Accepted for v0.31 reference

## Context

The v0.30 portable bundle supplied the public keys used to verify itself. A forged but internally consistent bundle could therefore establish its own trust universe.

## Decision

The verifier requires a separately supplied trust-root object. Keys are assigned to explicit roles, and mutually exclusive roles must use distinct raw key material.

## Consequences

Bundle portability now depends on trusted root distribution. The CLI cannot determine whether an operator chose the legitimate root, so deployment must provide out-of-band pinning, rotation, and rollback protection.
