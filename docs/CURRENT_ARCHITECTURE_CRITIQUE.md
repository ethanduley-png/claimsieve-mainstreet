# Current Architecture Critique

## Decision

The v0.30 composition had the correct high-level instinct—proposal, authorization, execution, observation, and audit should be separate—but several implementation details collapsed those boundaries. The strongest defects were not “missing AI guardrails.” They were ordinary distributed-systems and trust-root failures.

## What survived inspection

- MainStreet and OpenClaw should remain untrusted proposal generators.
- Consequential side effects belong behind a narrow executor.
- A policy verdict is not a permit.
- Permits should be exact, short-lived, one-use, and purpose-bound.
- Campaign limits must outlive sessions and sandboxes.
- Unknown outcomes must be quarantined.
- Proposal, evidence, decision, and execution records should be separately attributable.
- Formal proof should target only a small kernel.
- Python is useful as an executable oracle; Rust is a reasonable candidate for the enforcement path.

## What failed

### 1. Campaign state was not a single history

The v0.30 authority could evaluate two proposals against the same predecessor and issue permits for both. The campaign ledger therefore behaved like a forkable document rather than a serialized state machine. This defeated cumulative limits and made restart resistance largely documentary.

**Patch:** The authority now commits the exact predecessor-to-successor transition through compare-and-swap before issuing a permit. Only one candidate from a predecessor can win in the Python reference.

**Remaining gap:** The store is in-process memory and does not prove crash-safe or distributed linearizability.

### 2. Policy had no independent provenance

The authority reconstructed an `ALLOW`, but it reconstructed it using the caller-selected policy object. Independent calculation over attacker-controlled inputs is still attacker-controlled authorization.

**Patch:** Policy is a signed envelope. The authority and verifier accept it only under a separately configured policy-authority key. The permit binds the signed policy digest.

### 3. Evidence identity was semantic text, not cryptographic role

An evidence record could name a source without proving which source produced it.

**Patch:** Evidence is signed by type-scoped issuer keys. The policy pins allowed key IDs by evidence type, and the verifier requires the proposal’s evidence references to equal the exact signed snapshot.

### 4. The verifier trusted the thing it was verifying

The bundle contained its own public keys, so an attacker could produce a self-consistent forged bundle.

**Patch:** Verification requires a separate trust-root document. Bundle keys are treated as artifacts to compare against externally trusted role bindings, not as roots of trust.

**Remaining gap:** The local CLI cannot establish that the operator chose the correct organizational root. Deployment needs out-of-band root distribution and rotation.

### 5. Separation of observer and executor was nominal

The executor held the observer private key. A compromised executor could therefore attest to its own success.

**Patch:** Executor and Observer are separate objects with disjoint keys. The observer reads the simulated external system independently. The containment controller also retains its private key; the executor receives only a read-only view.

**Remaining gap:** The simulation shares one Python process. There is no host-, kernel-, provider-, or account-independent observer yet.

### 6. MainStreet had an injected side-effect seam

The proposal bridge accepted a caller-supplied transport. Even if only one method was retained, constructing the object could expose arbitrary side effects or unexpected capabilities.

**Patch:** The production bridge is pure. It prepares a canonical proposal and validates a returned acknowledgment. Transport belongs in a separate untrusted intake adapter and is not present in this module.

### 7. JavaScript graph handling was incomplete

Shared references and dangerous keys could cross the boundary even though cycles and accessors were rejected.

**Patch:** MainStreet rejects shared references, `__proto__`, `prototype`, and `constructor` recursively, plus the existing restricted object and number classes.

### 8. Sequence checks allowed replay of the same logical instant

Equal sequence values passed the monotonicity condition.

**Patch:** A sequence must be strictly greater than the durable prior sequence. Equal or lower values receive `NON_SUCCESSOR_SEQUENCE`.

### 9. Witness and release provenance were descriptive

The witness key was unused, and provenance files were templates.

**Patch:** The portable bundle includes a witness signature over the release manifest and ledger heads. Deterministic packaging and checksums are generated.

**Remaining gap:** There is no independent witness deployment, transparency log, signed build attestation, or SLSA level evidence.

### 10. Retry semantics conflicted with the safety thesis

`ConfirmedFailure` could authorize automatic retry even though provider failure can still be semantically ambiguous and every new attempt is a new consequential action.

**Patch:** No outcome independently authorizes an automatic retry. A new attempt requires a new proposal and new permit.

## Trusted computing base after the patch

The intended trusted computing base is still larger than desired:

- canonical parser and hashing profile;
- policy kernel;
- campaign state compare-and-swap semantics;
- authority key service;
- reservation store;
- executor binding and connector dispatch;
- containment state;
- trust-root distribution;
- ledger and witness key custody;
- verifier semantics.

The next reduction should be to move only canonicalization, decision reconstruction, campaign transition, permit issuance, reservation, last-moment validation, and ledger commitment into small Rust services. MainStreet, OpenClaw, document extraction, workflow planning, and natural-language explanation should remain outside.

## Strongest remaining architectural risk

The strongest remaining bypass is **state split-brain outside the reference process**. If two authority instances can each see themselves as the current campaign owner, or if reservation state is lost after an external action, the system can still issue or execute duplicates despite perfect signatures. This requires infrastructure-level evidence: a linearizable durable state machine, fencing tokens, crash tests, failover tests, and provider reconciliation.
