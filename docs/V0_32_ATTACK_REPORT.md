# v0.32 Attack Report

## Decision

The durable-state attack suite found no surviving bypass in the executable reference. This does not establish distributed safety. Four infrastructure-dependent limitations remain outside the executed environment.

## Executed durable-state scenarios

The suite contains 29 named scenarios. Twenty-five were blocked or detected and four were classified as infrastructure limitations.

### Strongest attacks exercised

| Attack | Actual result | Classification |
|---|---|---|
| Process restart resets campaign or loses permit | Campaign sequence and permit survived reopening | Blocked |
| Duplicate reservation | Unique permit constraint produced one reservation | Blocked |
| Crash after reservation | Durable `RESERVED` item appeared in recovery queue | Blocked |
| Crash after provider commit | Provider query reconciled success without a new action | Blocked |
| Timeout before provider commit | Remained `OUTCOME_UNKNOWN`; no auto retry | Blocked |
| Timeout after provider commit | Independent query confirmed success | Blocked |
| Revocation before dispatch | Dispatch transaction rejected revoked permit | Blocked |
| Revocation after dispatch | Marked in flight and reconciled; no false prevention claim | Detected |
| Global freeze before dispatch | Dispatch transaction rejected frozen execution | Blocked |
| Stale fencing token | Provider rejected older token after newer token | Blocked |
| Same idempotency key, altered request | Provider rejected request-digest mismatch | Blocked |
| Conflicting provider response and effect | Observer reported confirmed effect plus receipt conflict | Detected |
| Forged stored executor receipt | Observer rejected invalid signature | Blocked |
| Divergent external effect | Observer reported `DIVERGENT_EFFECT` | Detected |
| Terminal outcome rewrite | State service rejected conflicting terminal result | Blocked |
| State journal tampering | Hash-chain verification failed | Detected |
| Unauthenticated executor command | Signed executor command required | Blocked |
| Expired permit reservation | Durable validity check rejected it | Blocked |
| Permit expires before dispatch | Dispatch commit rejected it | Blocked |
| Forged provider-attempt receipt | Executor signature verification rejected it | Blocked |
| Unauthenticated observer outcome | Trusted observer signature required | Blocked |
| Minority partition commit | Quorum model rejected write | Blocked in model |
| Majority failover | New term advanced commit index and fence | Blocked in model |
| Stale log election | Quorum model rejected candidate | Blocked in model |

## Cross-process tests

Separate process races were executed for:

* campaign predecessor-to-successor permit issuance;
* reservation of one permit.

The campaign race produced one committed successor and fifteen rejected stale candidates. The reservation race produced one winner and twenty-three rejected duplicates.

## Strongest remaining bypass class

The strongest remaining risk is a real multi-node split-brain or failover error in the production state backend. The deterministic model constrains the intended semantics but does not provide a networked consensus implementation.

A second irreducible boundary is the remote side-effect gap. Once `DISPATCH_COMMIT_POINT` has committed and a request may be on the network, a later revocation cannot prove prevention. The system must preserve in-flight uncertainty and reconcile independently.

## Reproducible evidence

* `scripts/run_durable_red_team.py`
* `evidence/DURABLE_RED_TEAM_REPORT.json`
* `evidence/DURABLE_RED_TEAM_OUTPUT.txt`
* `python/tests/test_durable_state.py`
