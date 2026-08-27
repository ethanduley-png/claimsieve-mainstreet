# 04_execute — perform only the permitted effect

## Purpose
Execute an action only after independently validating a current permit and exact action bindings.

## Inputs
- Working: exact permit
- Working: exact requested action and parameters
- Reference: restricted executor interface
- Reference: `security/INVARIANTS.md`
- Reference: `docs/DURABLE_STATE_BOUNDARY.md`

## Authority
- May: perform the one effect explicitly permitted.
- Must not: reinterpret intent, widen scope, retry ambiguous consequential effects automatically, or decide provider outcome from a timeout.

## Invariants
1. Exact binding equality is checked at the execution boundary.
2. Provider code sits behind the restricted executor interface.
3. No generic network egress or provider SDK calls are added to `mainstreet/`.
4. A request that may have left the executor enters an uncertain state until independently observed.
5. No automatic retry after ambiguous delivery of a consequential action.

## Outputs
- Dispatch record / provider request identifier where available.
- Explicit execution state: not-sent, sent/awaiting-observation, or locally failed-before-send.

## Evidence produced
- Executor trace binding permit to the exact outbound request.

## Tests
- `mainstreet/test/*.test.js`
- `scripts/source_gate.py`
- `scripts/provider_contract_gate.py`
- `scripts/run_red_team.py`
- `scripts/run_durable_red_team.py`

## Human gate
Any request to broaden or repeat a consequential effect after uncertainty returns to adjudication/approval rather than being silently retried.