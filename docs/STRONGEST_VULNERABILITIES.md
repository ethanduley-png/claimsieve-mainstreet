# Strongest Vulnerabilities Found in v0.30

The following findings were reproduced against the supplied archive. The original probes and JSON traces are preserved in `evidence/original-v0.30-probes/`.

| Rank | Vulnerability | Concrete test | Actual v0.30 result | Impact | v0.31 response |
|---:|---|---|---|---|---|
| 1 | Campaign predecessor fork | Issue two proposals from the same prior campaign state | Both could receive permits | Bypass cumulative limits, double authority, inconsistent history | Atomic compare-and-swap successor commit before permit issuance |
| 2 | Self-asserted verifier trust | Replace bundle keys and signatures with attacker-generated equivalents | Self-consistent forged bundle verified | Entire audit universe can be forged | Verifier requires a separately supplied role-scoped trust root |
| 3 | Caller-selected unsigned policy | Re-evaluate a proposal under a substituted policy and request a permit | Authority accepted reconstructed result under attacker policy | Policy downgrade and arbitrary authorization | Signed policy envelope pinned to trusted policy authority |
| 4 | Observer key in executor | Inspect executor object and use observer key material | Executor possessed observer private key | Executor can attest to its own success | Separate Observer object and key; executor receives no observer signer |
| 5 | Equal sequence reuse | Submit a new action at the last accepted sequence | Sequence was accepted | Replay, state ambiguity, race amplification | Strictly greater sequence required |
| 6 | MainStreet transport injection | Construct bridge with an object whose transport performs arbitrary work | Side-effect seam was accepted | Direct effects outside ClaimSieve | Pure proposal bridge; transport removed from production module |
| 7 | Unsigned evidence | Alter source or data while recomputing ordinary hashes | Source identity was not cryptographically established | Fabricated evidence can influence decisions | Type-scoped signed evidence envelopes |
| 8 | Shared-reference and dangerous-key graph | Submit shared objects and own `__proto__`/`constructor` keys | Boundary accepted cases inconsistent with documentation | Parser differentials and prototype abuse | Recursive rejection of shared references and dangerous keys |
| 9 | Missing witness binding | Inspect bundle and witness role | No witness signature bound release and heads | Local writer can rewrite a self-consistent history | Signed witness statement over release manifest and ledger heads |
| 10 | Automatic retry after confirmed failure | Evaluate retry policy for `ConfirmedFailure` | Returned true | Duplicate external effects after incorrect failure classification | Every retry requires a new authorization lifecycle |

## Classification

- Findings 1–3 were **critical authorization failures**.
- Findings 4–7 were **high-impact separation or evidence failures**.
- Findings 8–10 were **important integrity and lifecycle failures**.

## Reproducibility

Run the retained probes against the unmodified v0.30 extraction, not the patched release:

```bash
PYTHONPATH=python python3 evidence/original-v0.30-probes/phase4_original_attack_probe.py
node evidence/original-v0.30-probes/phase4_mainstreet_probe.mjs
```

The v0.31 red-team harness converts these and additional attacks into structured records with expected result, actual result, impact, trace, fix, and coverage classification.
