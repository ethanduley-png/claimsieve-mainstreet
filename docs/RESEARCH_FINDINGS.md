# Research Findings — v0.33.0

## Finding 1: authentication and truth are different properties

The concrete v0.32 trace used a legitimate executor key. Signature validation succeeded while the semantic claim was false. Therefore outcome authority cannot be assigned merely by verifying executor origin.

## Finding 2: the safest patch removed trust

A second receipt verifier would not solve the semantic problem. Removing executor receipts from terminal classification reduced the trusted computing base and the assumptions needed for outcome correctness.

## Finding 3: unknown-outcome policy must distinguish logical action from transport replay

A blanket retry prohibition is too coarse for providers that publish idempotency guarantees. A blanket retry permission is unsafe. The relevant distinction is whether the same already-authorized dispatch is being transported again under exact binding and retention conditions, or whether a new logical action is being created.

## Finding 4: provider contracts are executable assumptions

Provider behavior should be represented as versioned, sourced contract clauses with discriminating tests. The model must remain explicitly separate from live-provider evidence.

## Finding 5: semantic divergence is more informative than nominal agreement

Python, Rust, Rocq, schemas, and prose can use the same word while binding different fields or assumptions. The identified Rust observer-receipt v1/v2 divergence is more valuable than a broad claim that the implementations agree.

## Finding 6: formal models need constructor-refinement scrutiny

The Rocq theorem can correctly state that `NoProviderRecord` maps to unknown while implementation code incorrectly decides what counts as a provider record. The high-risk bridge is often the mapping from messy implementation state into clean formal constructors.
