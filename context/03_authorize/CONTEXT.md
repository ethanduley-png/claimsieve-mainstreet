# 03_authorize — mint exact, bounded authority

## Purpose
Convert a successful adjudication plus any required human approval into a narrowly scoped permit.

## Inputs
- Working: exact proposal
- Working: adjudication decision and evidence references
- Working: required approval artifact, if policy requires it
- Reference: permit schema and runtime authority implementation
- Reference: `security/INVARIANTS.md`

## Authority
- May: issue a permit only through the active ClaimSieve authority path.
- Must not: broaden scope, change destination or parameters, bypass approval, execute, or infer provider outcome.

## Invariants
1. One active permit authority: the v0.33 ClaimSieve authority path.
2. Permit binds exact repository/destination, action, parameters, policy, evidence, approval, campaign state, and expected effect.
3. Freshness and expiry are checked at issuance and again where runtime requires before execution.
4. Approval reuse across materially different actions is forbidden.

## Outputs
- Exact action-scoped permit, or denial.

## Evidence produced
- Permit/decision trace sufficient to reconstruct why authority existed.

## Tests
- `python/tests/test_kernel.py`
- `python/tests/test_runtime.py`
- `evidence/V033_PATCHED_TRACE_PROBE.py`
- `scripts/run_red_team.py`

## Human gate
A human approval must bind the same material action fields the permit binds. Any material mutation after approval requires re-adjudication/re-approval.