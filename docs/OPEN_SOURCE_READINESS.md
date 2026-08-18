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

The durable observer uses independently readable provider state rather than treating executor output as terminal truth. Divergent effects and contradictory provider evidence are contained rather than normalized into success.

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

The repository has strong schemas and architecture documents, but it does not yet expose one concise provider-neutral conformance contract. `docs/OPEN_EXECUTION_ASSURANCE_PROFILE.md` and `vectors/execution_assurance_profile_v1.json` are the first candidate extraction.

### 4. Cross-language parity

The documented Rust observer receipt is still v1 while the durable Python path and JSON schema use v2. The v2 receipt adds reservation, campaign, provider-record digest, and conflict bindings. This should be closed before Rust is presented as a full portable implementation of the durable outcome boundary.

### 5. Portable verifier receipt parity

The portable bundle and verifier path still contain v1 receipt assumptions in places. The receipt protocol should be versioned deliberately rather than allowing the runtime, schema, and bundle verifier to drift independently.

### 6. Infrastructure independence

The reference observer is separately keyed but not deployed in an independent infrastructure failure domain. A production profile should distinguish logical separation, process separation, host separation, administrative separation, and organization-level independence.

### 7. Public API and compatibility policy

The current code is release-oriented rather than library-oriented. A public project needs stable package boundaries, semantic versioning rules, deprecation policy, and conformance-vector compatibility rules.

### 8. Reproducible supply chain

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

1. Make the execution-assurance profile executable in CI.
2. Close Rust observer-receipt v2 parity.
3. Add cross-language conformance vectors for all provider outcome classes.
4. Make the portable verifier accept and validate the durable v2 receipt contract.
5. Define a minimal gateway interface that owns credentials and accepts only valid exact-action authority.
6. Split the provider-neutral assurance code from MainStreet product code.
7. Choose an open-source license and patent policy before making the standalone repository public.

## Claim discipline

Until those steps are complete, use wording such as:

> ClaimSieve is developing a provider-neutral execution-assurance architecture with an open conformance profile.

Do not yet claim:

> ClaimSieve is a production-ready open-source alternative to Microsoft or Google.

The current repository is a strong engineering basis for that direction, but the licensing, packaging, parity, deployment, and public compatibility boundaries still need to be completed.
