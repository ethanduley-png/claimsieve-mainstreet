# Founder OS Merge Report

## Decision

The Founder OS v0.1 starter is merged as a product-specific vertical slice over the v0.33 ClaimSieve authority and durable outcome boundary.

It is **not** retained as a second permit system.

## Why the original implementation was not adopted directly

The starter package was useful as a work order and product sketch, but its executable reference was materially weaker than v0.33:

- HMAC permit signing used a secret held by the same in-process authority and adapter.
- Replay state existed only in an in-memory set.
- The adapter directly classified a provider response as confirmed or failed.
- Campaign state, revocation, reservation, fencing, durable recovery, signed evidence, signed policy, and independent observation were absent.
- The JSONL ledger was a single reference utility rather than the four-role ledger model.

Preserving that code as an active path would create a parallel and weaker authority boundary.

## What was preserved

- The product goal: use MainStreet to operate the company itself.
- The first narrow action: propose creation of one GitHub issue in one approved repository.
- Exact repository, title, body, evidence, policy, approval, expiry, and single-use requirements.
- Plain-language user states: ready for review, blocked, attempted, confirmed, and outcome uncertain.
- The rule that an executor statement is not independent outcome truth.

## Active integration

The merged vertical slice uses:

- `mainstreet/src/founder-os.js` for proposal-only product construction.
- `python/founder_os/workflow.py` for the deterministic reference composition.
- The existing v0.33 `Authority` for permit issuance.
- The existing `DurableStateService` for campaign succession and reservations.
- The existing `DurableExecutor` for dispatch.
- The existing `IndependentObserver` for outcome classification.
- The existing four signed ledgers.

There is one active permit authority implementation and one durable execution semantics implementation in the package.

## Source provenance

The unchanged input archives are retained under `provenance/inputs/` with SHA-256 hashes. They are evidence of the merge inputs, not executable dependencies of the active Founder OS path.
