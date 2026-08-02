# Rocq Assurance Report — v0.33.0

## Status

Formally modeled source, not compiler accepted in the originating environment.

## Modeled properties

`rocq/DurableState.v` states narrow properties for:

* freeze and revocation before dispatch;
* strict sequence monotonicity;
* fencing monotonicity;
* terminal outcome immutability;
* no automatic logical retry from any outcome;
* request mutation changing reservation identity;
* authenticated executor command and observer outcome guards;
* permit time bounds;
* no provider record remaining unknown regardless of executor claim;
* executor rejection being unable to confirm failure without provider evidence;
* contradictory provider evidence remaining unknown;
* revocation, request mutation, and retention expiry blocking transport replay.

`rocq/CheckDurableState.v` requests `Print Assumptions` output for the named theorems.

## Static evidence

The source gate found none of the configured escape terms:

* `Admitted`
* `admit`
* `Axiom`
* `Parameter`
* `Abort`

This is only a source scan.

## Outside the proof boundary

The model does not establish:

* JSON parsing or canonicalization;
* signature verification or key custody;
* database transactions or crash durability;
* provider record authenticity;
* network transport;
* clock correctness;
* workload identity;
* account or endpoint selection;
* deployment separation;
* Rust or Python refinement;
* human approval validity.

The key semantic risk is constructor selection: the theorem can correctly map `NoProviderRecord` to `OutcomeUnknown` while implementation code incorrectly labels executor-controlled data as an independent provider observation.

## Required next evidence

1. Compile unchanged files with a pinned Rocq release.
2. Preserve compiler output.
3. Run `Check.v` and `CheckDurableState.v` and preserve assumption output.
4. Compare theorem preconditions to executable guards field by field.
5. Add refinement tests or extracted decision tables where practical.
6. Do not expand the proof claim beyond the modeled transition system.
