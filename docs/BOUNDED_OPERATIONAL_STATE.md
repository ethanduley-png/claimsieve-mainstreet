# Bounded Operational State

## Status

This document describes an experimental vNext proposal-side primitive implemented in `python/mainstreet_runtimes/operational_state.py`. It does **not** replace the v0.33/v0.34 durable campaign, permit, evidence, decision, execution, or outcome boundaries.

The first implementation supplies a deterministic bounded state object, digest-bound compare-and-swap patches, explicit compaction by root deletion, constant byte/key budgets, and transition receipts. It is not yet wired into every model prompt or persisted as authoritative runtime state.

## Design input

Badhe, Tiwari, and Chung, **“SKILL.state: Scalable Long-Horizon Agent Skills,”** arXiv:2608.26263v2, 2026, accepted at EMNLP: <https://arxiv.org/abs/2608.26263>.

The paper replaces growing conversational history with an explicit execution state. At each step the model receives the procedure, current structured state, and newest observation, then proposes a validated state update. ClaimSieve adopts the bounded-state principle while preserving a separate assurance and evidence architecture.

## ClaimSieve distinction

ClaimSieve separates two kinds of memory that must not be conflated.

### 1. Operational state

Operational state is compact, mutable, and optimized for the next reasoning step.

```text
P + Sigma_t + O_t -> model -> proposed Delta Sigma_t + proposed action
```

Operational state is **untrusted proposal-side data**. It may summarize what the worker currently believes, what it plans to do, and what it thinks is relevant.

It is not permission and it is not evidence.

### 2. Assurance and evidence history

Proposal, evidence, decision, execution, durable campaign state, provider observations, and terminal outcome remain in their existing ClaimSieve boundaries and ledgers.

They are not discarded merely because the model no longer needs the full history in its prompt.

This gives the target property:

> bounded operational context + independently retained audit evidence

## Invariants implemented in the first slice

### B1 — Constant state budget

A state is rejected if its canonical JSON exceeds the configured byte budget or top-level-key budget. A patch also has an independent byte budget.

The default reference limits are:

* state: 32,768 canonical UTF-8 bytes;
* top-level roots: 64;
* patch changes: 8,192 canonical UTF-8 bytes;
* deletions per patch: 64.

These are reference values, not production sizing recommendations.

The bounded-context claim is therefore conditional and precise: prompt-state growth is O(1) with respect to execution horizon **only while these fixed budgets remain invariant**.

### B2 — Stale writes fail closed

Each patch binds both:

* the predecessor revision; and
* the predecessor canonical state digest.

A patch prepared from an older or different predecessor is rejected rather than merged opportunistically.

This is compare-and-swap behavior for proposal-side working state. It is useful for concurrent or multi-agent work, but it is not distributed consensus.

### B3 — Canonical deterministic representation

State and patch material use the existing ClaimSieve canonical JSON profile before hashing. Equivalent object ordering therefore yields the same state digest.

### B4 — No authority roots

Working state cannot occupy reserved top-level namespaces that look like ClaimSieve authority or durable truth, including permits, approvals, evidence, execution receipts, durable campaign state, ledgers, revocations, or the internal `_claimsieve*` namespace.

A worker may retain explicitly non-authoritative summaries such as `evidence_summary` or `approval_summary`. Downstream authority code must still treat every operational-state field as untrusted.

### B5 — Actor identity is provenance, not permission

A patch includes an actor label so its origin can later be bound into audit records. Calling an actor `authority`, `supervisor`, or any other privileged name grants nothing.

### B6 — Explicit compaction

State does not grow by silently appending history. Patches may replace top-level values and explicitly delete obsolete roots. The post-merge state must still fit the same fixed budget.

### B7 — Transition receipts are non-authoritative

Applying a patch produces a transition receipt containing predecessor version/digest, patch digest, actor, and successor version/digest.

That receipt can later be referenced from an evidence or proposal ledger. By itself it proves only the deterministic working-state transition; it does not prove the truth of the state contents or authorize an external action.

## What this does not do

The first slice does not establish that:

* the model selected the correct facts to keep in working state;
* every important observation was captured as independent evidence;
* the working state is true;
* a patch is policy compliant merely because it is structurally valid;
* an action is authorized merely because its state transition succeeded;
* distributed agents have consensus;
* bounded state alone prevents prompt injection or semantic poisoning;
* Deep Agents or another runtime is already forced to use only this state representation.

Those remain separate engineering obligations.

## Target execution path

```text
immutable procedure P
        +
bounded operational state Sigma_t
        +
latest observation O_t
        |
        v
untrusted model / worker
        |
        +---- proposed state patch Delta Sigma_t
        |             |
        |             v
        |      deterministic state gate
        |      - canonicalize
        |      - stale predecessor check
        |      - protected-root check
        |      - fixed budget check
        |             |
        |             v
        |         Sigma_(t+1)
        |
        +---- proposed consequential action
                      |
                      v
              ClaimSieve intake
              policy + evidence
              independent authority
              durable state boundary
              restricted executor
              independent observer
              existing ledgers
```

The key rule is that the operational-state gate is **not inserted as a new authority layer**. It is a proposal-side consistency and context-management layer upstream of ClaimSieve adjudication.

## Evidence capture rule

A model deciding that an observation is unimportant must not be allowed to erase the underlying evidence needed for audit, replay, dispute resolution, or later re-evaluation.

Therefore:

```text
observation -> evidence capture / reference
            -> optional projection into bounded operational state
```

Evidence retention policy and state projection policy are separate decisions.

## Multi-agent rule

Multiple workers may propose from the same predecessor. Only a patch whose base version and base digest still match the current state may commit. Losers must refresh state and propose again.

This prevents silent lost updates in the reference state object. A future multi-process or distributed implementation will require a storage-level atomic compare-and-swap mechanism and must not claim stronger consistency than it actually provides.

## Test coverage in this branch

`python/tests/test_operational_state.py` covers:

* versioned deterministic transition;
* canonical digest stability;
* stale revision rejection;
* same-revision / wrong-digest rejection;
* protected authority-root rejection;
* non-authoritative summary allowance;
* post-merge byte-budget rejection;
* top-level-key-budget rejection;
* explicit deletion/compaction;
* change/delete conflict rejection;
* caller-mutation isolation; and
* forged state-digest rejection.

## Next benchmark

The useful experiment is a three-way comparison rather than a demo that measures only token savings:

1. append-only transcript runtime;
2. bounded-state runtime without ClaimSieve assurance;
3. bounded-state runtime with ClaimSieve assurance.

Measure at minimum:

* task accuracy;
* cumulative input/output tokens;
* latency by horizon;
* state-budget pressure and compaction frequency;
* stale-write conflicts;
* unauthorized transition attempts;
* consequential-action block/allow correctness;
* evidence completeness;
* replay/reconstruction success;
* unknown-outcome handling; and
* multi-agent conflict behavior.

The benchmark should separately score **working-state quality** and **assurance correctness** so context efficiency cannot hide lost evidence or unsafe execution behavior.
