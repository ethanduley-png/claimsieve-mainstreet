# Open-Source Readiness Review

Date: 2026-08-17

Scope: review of the current `claimsieve-mainstreet` v0.34 engineering corpus as a foundation for a provider-neutral open execution-assurance project.

## Bottom line

The repository already contains enough real engineering to justify extracting an open execution-assurance project. The strongest assets are not the Founder OS product surface; they are the exact-action permit model, durable one-use execution boundary, independent outcome semantics, evidence and policy bindings, separate ledgers, adversarial tests, Rust implementation work, and Rocq proof work.

The repository is **not yet an open-source project**. It is a private research/product repository with an all-rights-reserved license and product-specific packaging.

## Existing assets worth preserving

### Authority separation

The active path keeps proposal, policy decision, permit issuance, execution, observation, and containment as distinct authority roles. MainStreet and OpenClaw remain proposal-only for consequential actions.

### Exact permits

The permit schema binds proposal, action, destination, parameters, policy, signed policy, evidence, decision, approval, predecessor state, successor state, validity, nonce, and one-use authority.

### Durable execution semantics

The Python durable boundary has explicit reservation, fencing, revocation checks, dispatch commit semantics, crash recovery state, and `OUTCOME_UNKNOWN` handling.

### Independent outcome semantics

The durable observer uses independently readable provider state rather than treating executor output as terminal truth. It correctly distinguishes exact success, confirmed rejection, unknown outcome, contradictory provider evidence, and divergent effects. The review found one important parity gap: contradictory provider evidence triggers durable campaign containment, while a plain `DIVERGENT_EFFECT` is detected but does not yet suspend the campaign in the durable Founder OS path. The older in-memory runtime does suspend on divergence.

### Evidence architecture

The repository carries separate proposal, evidence, decision, and execution ledgers plus portable evidence bundles and an external trust-root model.

### Assurance tooling

The repository includes Python, Node, Rust, Rocq, adversarial, mutation, provider-contract, semantic-divergence, source-gate, and packaging tests. The prior v0.34 report records 170 Python tests, 23 Node tests, 28 Rust tests, four compiled Rocq files, and zero surviving bypasses in the documented red-team suites, subject to the stated limitations.

## Blockers before calling the project open source

### 1. License

`LICENSE` currently states all rights reserved and grants no patent rights. That is not an open-source license.

Do not describe the repository as open source until a deliberate license and patent policy are selected. Licensing should be treated as a founder/legal decision rather than silently changed by engineering automation.

### 2. Repository boundary

`claimsieve-mainstreet` combines the assurance kernel with MainStreet / Founder OS product material. A standalone open project should have a smaller trust and review surface.

The existing empty `claimsieve` repository is a natural future destination, but this review does not move code automatically.

### 3. Stable public specification

The repository has strong schemas and architecture documents, but it did not expose one concise provider-neutral conformance contract before this review. `docs/OPEN_EXECUTION_ASSURANCE_PROFILE.md` and `vectors/execution_assurance_profile_v1.json` are the first candidate extraction.

### 4. Durable divergence-containment parity

The conformance gate originally exposed a real semantic inconsistency: the durable Python observer classified an independently observed mutated effect as `DIVERGENT_EFFECT` but did not suspend the campaign. That parity gap is now closed in the reference implementation.

Python reconciliation and containment are committed in one SQLite transaction. First containment advances the containment epoch once, repeated terminal divergence is idempotent, and campaign status is rechecked at reservation, executor claim, and dispatch. The conformance tests include a reservation that was already executing before another action exposed divergence.

### 5. Cross-language receipt parity

Rust observer receipts now use the same v2 field contract and `observer-receipt-v2` signing domain as the durable Python boundary and authoritative JSON schema. A shared Python-generated signed v2 vector is consumed by the Rust verifier. Explicit v1 read compatibility remains for older bundles.

This closes the identified receipt-shape parity gap for the tested contract; it does not prove provider correctness, cryptographic implementation security, transport integrity, or infrastructure independence.

### 6. Portable verifier receipt parity

The portable Python and Rust verifier paths now validate observer receipt v2 while retaining deliberate v1 compatibility. The durable red-team gate checks the shared v2 vector against the authoritative schema and portable verifier instead of carrying a static parity claim.

### 7. Infrastructure independence

The reference observer is separately keyed but not deployed in an independent infrastructure failure domain. A production profile should distinguish logical separation, process separation, host separation, administrative separation, and organization-level independence.

### 8. Public API and compatibility policy

The current code is release-oriented rather than library-oriented. A public project needs stable package boundaries, semantic versioning rules, deprecation policy, and conformance-vector compatibility rules.

### 9. Reproducible supply chain

The repository has manifests, lockfiles, provenance templates, and release evidence, but independently reproduced binaries, signed build provenance, and transparency-log publication remain unfinished.

## Recommended open project shape

The existing code suggests five separable layers:

```text
claimsieve-spec
  schemas, canonicalization rules, execution-assurance profile,
  conformance vectors, threat model

claimsieve-core
  deterministic policy/evidence evaluation and exact permit verification

claimsieve-gateway
  durable reservation, credential boundary, restricted execution,
  independent observation, reconciliation

claimsieve-conformance
  provider-neutral behavioral tests, adversarial vectors,
  cross-language differential tests

claimsieve-formal
  Rocq models and proof obligations for the smallest auditable kernel
```

MainStreet / Founder OS should consume these layers as a product, not define their authority semantics.

## What should remain enterprise or operational rather than required for the open core

A credible open core can remain fully functional while commercial offerings provide managed operations such as:

- hosted control plane;
- enterprise identity integration;
- hardware-backed signing and key management;
- high availability and multi-region state;
- managed provider connectors;
- policy lifecycle and approvals administration;
- evidence retention and search;
- security monitoring and incident response integrations;
- insurer, auditor, and procurement reporting;
- certified builds and support.

The open version must still be capable of enforcing real consequential actions locally. Otherwise the community cannot independently validate the security model.

## Immediate engineering order

1. Keep the execution-assurance profile executable in CI and preserve remaining gaps explicitly.
2. Add cross-language conformance vectors for all provider outcome classes, not only the current shared v2 success fixture and adversarial receipt cases.
3. Define a minimal gateway interface that owns credentials and accepts only valid exact-action authority.
4. Split the provider-neutral assurance code from MainStreet product code.
5. Add independently operated observer deployment guidance and failure-domain tests.
6. Add configured release signing and independently reproduced cross-host build evidence.
7. Choose an open-source license and patent policy before making the standalone repository public.

## Claim discipline

Until those steps are complete, use wording such as:

> ClaimSieve is developing a provider-neutral execution-assurance architecture with an open conformance profile.

Do not yet claim:

> ClaimSieve is a production-ready open-source alternative to Microsoft or Google.

The current repository is a strong engineering basis for that direction, but the licensing, packaging, parity, deployment, and public compatibility boundaries still need to be completed.
