# Production Reconciliation Composition v1

## Scope

This increment tests the production Rust composition from an observer-authentication guard through independent-provider classification and durable state mutation.

The public entry point under test is `DurableState::reconcile_observation`. The tests do not invoke the private already-classified transition.

## Enforced properties

The dedicated composition gate checks that:

1. an unauthenticated observation is rejected without any durable state mutation;
2. an unknown observation remains nonterminal and may later resolve from new authenticated provider evidence;
3. confirmed success and confirmed failure cannot be rewritten through the public boundary;
4. a divergent provider effect suspends the campaign and blocks a preexisting reservation from crossing the dispatch commit point;
5. conflicting independent provider evidence remains unknown while still suspending the campaign; and
6. an exact confirmed success does not itself force containment.

The first two semantic corrections align Rust with the existing Rocq definitions `terminal`, `rewrite_allowed`, and `observation_requires_containment`.

## Preserved evidence

The refinement workflow runs the dedicated Rust integration test with the locked workspace and uploads `RECONCILIATION_COMPOSITION.txt` beside the Rust and Rocq-derived OCaml classifier outputs and fixture digest.

## Claim boundary

A green gate establishes executable composition behavior for the in-memory Rust transition model over the listed discriminating cases.

It does not prove observer authentication, cryptography, canonical parsing, database linearizability, crash recovery, networking, concurrency, provider authenticity, deployment separation, or complete Rust refinement against Rocq. Authentication remains represented by a boolean guard supplied by a trusted boundary.
