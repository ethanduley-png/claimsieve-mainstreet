# v0.33 independent outcome proof scope

`DurableState.v` models a narrow transition system for:

* revocation and freeze checks before dispatch;
* strict sequence and fencing monotonicity;
* terminal outcome immutability;
* no automatic logical retry from any outcome;
* executor claims being unable to establish terminal outcome without independent provider evidence;
* contradictory provider evidence remaining unknown;
* bounded same dispatch transport replay guards.

The model intentionally excludes cryptography, JSON parsing, database semantics, provider APIs, networks, clocks, operators, key custody, and deployment isolation. `CheckDurableState.v` requests assumption output for the named theorems.

The files were not compiled in the originating build environment because `rocq` and `coqc` were unavailable. Static absence of `Admitted` or `Axiom` is not proof acceptance.
