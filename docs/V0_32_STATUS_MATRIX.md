# v0.32 Claim Status Matrix

| Claim | Status | Evidence |
|---|---|---|
| Campaign state survives process restart | Implemented and tested | SQLite reopen and recovery tests |
| Permit is committed with campaign successor before return | Implemented and tested | Durable authority integration and restart tests |
| One permit creates at most one reservation across local processes | Implemented and tested | 24-process race |
| One predecessor creates at most one campaign successor across local processes | Implemented and tested | 16-process race |
| Fencing tokens are monotonic | Implemented and tested | Unit and provider tests |
| Provider rejects a stale fence after observing a newer fence | Implemented and tested in simulator | Durable red-team trace |
| Revocation blocks before dispatch commit point | Implemented and tested | Deterministic race test |
| Revocation after dispatch is represented as in flight | Implemented and tested | Durable red-team trace |
| Unknown outcome survives restart | Implemented and tested | Crash and timeout tests |
| Independent reconciliation can resolve timeout after commit | Implemented and tested in simulator | Provider read-back test |
| Signed executor command required | Implemented and tested | Unauthorized claim test |
| Permit expiry rechecked at dispatch | Implemented and tested | Reservation-to-dispatch expiry test |
| Signed observer outcome required | Implemented and tested | Unsigned outcome test |
| Executor receipt tampering is detected | Implemented and tested | Signature mutation test |
| Operational journal detects mutation | Implemented and tested | Hash-chain mutation test |
| Three-node quorum safety | Designed and executed as deterministic model | `QuorumStateMachineSimulator` |
| Networked multi-node consensus | Designed but not implemented | Outside release scope |
| Rust durable-state transition semantics | Implemented but not executed | `rust/crates/durable-state` |
| Rocq durable-state properties | Formally modeled but not compiled | `rocq/DurableState.v` |
| Live provider reconciliation | Assumed contract, not implemented | Simulator only |
| Live tax filing | Not implemented | Explicitly disabled |
| Production workload identity and key custody | Not implemented | Fixture keys only |
