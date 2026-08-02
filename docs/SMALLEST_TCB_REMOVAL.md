# Smallest Trusted Component Removed

## Removed trust

The v0.32 observer trusted the executor receipt and therefore needed:

* the executor public key;
* executor-receipt signature verification;
* executor-receipt parsing and binding logic;
* the semantic assumption that a signed executor status accurately described the external world.

The smallest effective reduction was to remove the executor receipt from the terminal-outcome decision path.

## New boundary

The executor still produces a signed attempt receipt. That receipt records what the executor claims it attempted and what response it claims it observed. It is retained for:

* audit;
* attribution;
* conflict detection;
* incident investigation;
* comparison against provider evidence.

It cannot establish `CONFIRMED_SUCCESS` or `CONFIRMED_FAILURE`.

The independent observer requires only:

1. the durable reservation and exact authorized action;
2. a read-only provider observation source;
3. its own observer signing key;
4. containment authority for contradiction or divergence.

## Why this is smaller than adding a second verifier

Adding another executor-receipt verifier would leave the same semantic dependency in place. Both verifiers would still be checking whether the executor correctly signed its own assertion.

The patch instead removes the assertion from the proof obligation for terminal outcome.

## Security consequence

After the reduction, executor compromise alone can still:

* refuse to dispatch;
* attempt to lie in its receipt;
* mishandle its own credentials;
* cause local availability failures.

Executor compromise alone should not be able to:

* declare the external action successful;
* declare the external action failed;
* authorize a new logical attempt;
* sign the observer receipt;
* select the observer trust root.

## Residual assumptions

The observer path still trusts:

* provider read credentials and account selection;
* provider record semantics;
* canonical action comparison;
* durable reservation integrity;
* observer key custody;
* deployment isolation;
* clocks and sequence sources where used.

Those assumptions are visible and remain future reduction targets.
