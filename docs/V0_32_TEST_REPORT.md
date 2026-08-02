# v0.32 Test Report

## Executed in the authoring environment

| Gate | Result |
|---|---|
| Python unit and adversarial tests | 132 passed |
| MainStreet Node tests | 18 passed |
| Source and schema gate | Passed |
| Portable bundle verification | Passed against external fixture trust root |
| Durable execution vector generation | Passed |
| Durable journal verification | Passed |
| Inherited red-team suite | 58 total, 52 blocked or detected, 0 bypasses, 6 limitations |
| Durable-state red-team suite | 29 total, 25 blocked or detected, 0 bypasses, 4 limitations |
| Synthetic tax-notice success path | Confirmed success in simulator |
| Synthetic tax-notice ambiguous path | Preserved `OUTCOME_UNKNOWN` |

## Durable-state test groups

### Durability and restart

* campaign state survives database reopening;
* permit record survives database reopening;
* revocation survives restart;
* freeze survives restart;
* campaign suspension survives restart;
* recovery queue preserves incomplete work.

### Concurrency

* one campaign successor wins across sixteen processes;
* one reservation wins across twenty-four processes;
* duplicate reservation is rejected;
* fencing tokens increase monotonically.

### Crash injection

* after reservation;
* after executor claim;
* after dispatch commit;
* after provider effect before local receipt;
* after provider result persistence.

### Provider reconciliation

* accepted effect;
* rejection;
* timeout before commit;
* timeout after commit;
* divergent effect;
* conflicting response and stored effect;
* exact idempotent replay;
* idempotency parameter mutation;
* stale fencing token.

### Integrity

* durable operational journal verifies;
* journal mutation is detected;
* forged executor receipt is rejected;
* terminal outcome cannot be rewritten.

### Partition model

* minority cannot commit;
* majority can elect and advance after leader loss;
* stale log candidate cannot win;
* healed nodes converge to the modeled committed index.

### Signed-role and expiry checks

* unsigned executor claim is rejected;
* executor ownership is bound through dispatch;
* unsigned observer outcome is rejected;
* permit validity is rechecked at reservation and dispatch.

## Not executed

* Rust formatting, Clippy, build, or tests;
* Rocq compilation or `Print Assumptions` audit;
* real etcd or PostgreSQL failover;
* real network partitions;
* filesystem power-loss testing;
* real provider idempotency contracts;
* independent observer host or account;
* live OpenClaw or government portal integration.

Source inspection is not reported as native execution.
