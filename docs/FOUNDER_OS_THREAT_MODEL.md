# Founder OS Threat Model

## Protected assets

- Founder approval authority
- Repository selection
- Exact issue title and body
- Work-item purpose
- GitHub credentials
- Permit uniqueness
- Campaign limits
- Outcome truth
- Audit history

## Principal attacks

| Attack | Control in this release |
|---|---|
| Repository substitution | Exact destination digest, signed repository-registry evidence, and local Founder OS allowlist |
| Title or body mutation | Proposal, parameter, decision, approval, and permit digest bindings |
| Stale approval | Logical-sequence validity and signature verification |
| Permit replay | Durable one-use reservation |
| Restart-based replay | SQLite durable state and committed permit record |
| Policy substitution | Signed policy plus permit policy digest |
| Direct MainStreet execution | Proposal-only JavaScript module with no transport or credential capability |
| Executor false success or failure | Independent observer ignores executor claims as terminal authority |
| Timeout after possible effect | `OUTCOME_UNKNOWN` until provider readback |
| Duplicate issue after timeout | Automatic retry is false; production requires correlation-based reconciliation |
| Credential discovery | No credential path exists in the MainStreet module; deployment isolation remains required |

## Residual risks

- One authorized live GitHub canary exercised the narrow issue-create and delayed read-back path. It does not establish general provider behavior, fault handling, or production safety.
- The local simulator provides idempotency and fencing that GitHub does not natively promise for issue creation.
- A privileged host can compromise fixture keys, the local database, or both.
- The observer is logically separate but not deployed in a separate failure domain.
- The Python composition is a reference implementation, not a production service topology.
- Rust and Rocq remain subject to the native-toolchain status described elsewhere in the release.
