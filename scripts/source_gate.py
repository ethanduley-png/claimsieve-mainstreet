#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from claimsieve_ref.canonical import loads_strict  # noqa: E402
from claimsieve_ref.verifier import verify_bundle  # noqa: E402

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def scan_text(path: Path, patterns: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for label, pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            fail(f"{path.relative_to(ROOT)}: forbidden {label}")


for path in (ROOT / "mainstreet" / "src").rglob("*.js"):
    scan_text(path, [
        ("child_process import", r"from\s+['\"]node:child_process"),
        ("filesystem import", r"from\s+['\"]node:fs"),
        ("generic fetch call", r"\bfetch\s*\("),
        ("dynamic evaluation", r"\b(eval|Function)\s*\("),
        ("provider SDK", r"\b(twilio|stripe|aws-sdk|@aws-sdk)\b"),
    ])

for path in (ROOT / "rust" / "crates").rglob("*.rs"):
    text = path.read_text(encoding="utf-8")
    if "#![forbid(unsafe_code)]" not in text:
        fail(f"{path.relative_to(ROOT)}: missing forbid(unsafe_code)")
    production = text.split("#[cfg(test)]", 1)[0]
    for label, pattern in [
        ("unsafe block", r"\bunsafe\s*\{"), ("unwrap", r"\.unwrap\s*\("),
        ("expect", r"\.expect\s*\("), ("panic macro", r"\bpanic!\s*\("),
        ("todo macro", r"\btodo!\s*\("), ("unimplemented macro", r"\bunimplemented!\s*\("),
    ]:
        if re.search(pattern, production):
            fail(f"{path.relative_to(ROOT)}: forbidden {label} in production source")

# Trust-boundary structural checks that token presence alone cannot establish.
runtime_path = ROOT / "rust" / "crates" / "runtime" / "src" / "lib.rs"
runtime_text = runtime_path.read_text(encoding="utf-8")
executor_match = re.search(
    r"pub struct Executor<'a,.*?\n}\n\nimpl<'a,", runtime_text, re.DOTALL
)
if executor_match is None:
    fail("rust/crates/runtime/src/lib.rs: unable to locate Executor boundary")
elif "observer_signing_key" in executor_match.group(0):
    fail("rust/crates/runtime/src/lib.rs: Executor must not possess observer signing material")
if "let retry_allowed = reconciliation == Reconciliation::ConfirmedFailure" in runtime_text:
    fail("rust/crates/runtime/src/lib.rs: confirmed failure must not authorize automatic retry")

for path in (ROOT / "rocq").glob("*.v"):
    scan_text(path, [
        ("Admitted", r"\bAdmitted\b"), ("admit tactic", r"\badmit\b"),
        ("Axiom declaration", r"^\s*Axiom\b"), ("Parameter declaration", r"^\s*Parameter\b"),
        ("Abort", r"\bAbort\b"),
    ])

# Every JSON file must satisfy the restricted parse profile.
for path in ROOT.rglob("*.json"):
    if any(
        part in {"node_modules", ".git", "target", "__pycache__", ".pytest_cache"}
        for part in path.parts
    ):
        continue
    try:
        loads_strict(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path.relative_to(ROOT)}: invalid restricted JSON: {exc}")

try:
    bundle = json.loads((ROOT / "vectors" / "valid_evidence_bundle.json").read_text())
    trust = json.loads((ROOT / "trust" / "fixture-trust-root.json").read_text())
    schema_map = {
        "evidence-bundle.schema.json": bundle,
        "proposal.schema.json": bundle["proposal"],
        "signed-policy.schema.json": bundle["signed_policy"],
        "policy.schema.json": bundle["signed_policy"]["policy"],
        "decision.schema.json": bundle["decision"],
        "permit.schema.json": bundle["permit"],
        "trust-root.schema.json": trust,
    }
    for name, instance in schema_map.items():
        schema = json.loads((ROOT / "schemas" / name).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(instance, schema)
    evidence_schema = json.loads((ROOT / "schemas" / "evidence.schema.json").read_text())
    ledger_schema = json.loads((ROOT / "schemas" / "ledger-record.schema.json").read_text())
    for item in bundle["evidence"]:
        jsonschema.validate(item, evidence_schema)
    for records in bundle["ledgers"].values():
        for record in records:
            jsonschema.validate(record, ledger_schema)
    for error in verify_bundle(bundle, trust):
        fail(f"valid evidence vector failed portable verification: {error}")

    durable = json.loads((ROOT / "vectors" / "durable_execution_vector.json").read_text())
    durable_schema_map = {
        "dispatch-ticket.schema.json": durable["dispatch_ticket"],
        "executor-command.schema.json": durable["executor_command"],
        "reservation.schema.json": durable["reservation"],
        "executor-receipt-v2.schema.json": durable["executor_receipt"],
        "observer-receipt-v2.schema.json": durable["observer_receipt"],
    }
    for name, instance in durable_schema_map.items():
        schema = json.loads((ROOT / "schemas" / name).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(instance, schema)
    if durable.get("journal_verified") is not True:
        fail("durable execution vector journal did not verify")
except Exception as exc:
    fail(f"schema/vector gate failed: {exc}")


# Founder OS must reuse the baseline authority rather than importing its preserved starter implementation.
for path in list((ROOT / "python" / "founder_os").rglob("*.py")) + list((ROOT / "mainstreet" / "src").rglob("*.js")):
    text = path.read_text(encoding="utf-8")
    if "claimsieve_founder_os_codex_v0_1" in text or "from founder_os.core" in text:
        fail(f"{path.relative_to(ROOT)}: active code imports the preserved weaker Founder OS authority")

try:
    founder_policy = json.loads((ROOT / "policies" / "founder_os_github_issue_policy_v1.json").read_text())
    policy_schema = json.loads((ROOT / "schemas" / "policy.schema.json").read_text())
    jsonschema.validate(founder_policy, policy_schema)
except Exception as exc:
    fail(f"Founder OS policy schema gate failed: {exc}")

required_source_tokens = {
    ROOT / "python" / "claimsieve_ref" / "runtime.py": [
        "compare_and_swap", "campaign state fork or concurrent successor",
        "automatic_retry_allowed", "class Observer", "class ContainmentView",
    ],
    ROOT / "python" / "claimsieve_ref" / "verifier.py": [
        "external trust root is required", "witness statement manifest binding mismatch",
        "proposal evidence references do not exactly match the snapshot",
    ],
    ROOT / "mainstreet" / "src" / "index.js": [
        "DANGEROUS_PROPERTY", "SHARED_REFERENCE", "prepare_canonicalizable_proposal",
    ],
    ROOT / "mainstreet" / "src" / "founder-os.js": [
        "prepareGitHubIssue", "run_connector", "github_api_execution",
    ],
    ROOT / "python" / "founder_os" / "workflow.py": [
        "FounderOSReferenceWorkflow", "DurableStateService", "IndependentObserver",
        "destination_registry", "automatic_retry_allowed",
    ],
    ROOT / "rust" / "crates" / "runtime" / "src" / "lib.rs": [
        "CampaignState", "permit_identity_digest", "pub struct IndependentObserver",
        "classify_provider_observation", "transport_replay_allowed",
        "PROVIDER_EVIDENCE_CONFLICT", "automatic_retry_allowed",
    ],
    ROOT / "python" / "claimsieve_ref" / "durable_state.py": [
        "BEGIN IMMEDIATE", "DISPATCH_COMMIT_POINT", "fencing_token",
        "OUTCOME_UNKNOWN", "class QuorumStateMachineSimulator",
        "signed executor command required", "observer_keys", "executor_keys",
        "classify_provider_evidence", "PROVIDER_EVIDENCE_CONFLICT",
    ],
    ROOT / "rust" / "crates" / "durable-state" / "src" / "lib.rs": [
        "LinearizableStateStore", "ReservationPhase", "claim_dispatch",
        "TerminalOutcomeRewrite",
    ],
    ROOT / "python" / "claimsieve_ref" / "provider_contracts.py": [
        "StripeIdempotencyContractModel", "authorize_stripe_transport_replay",
        "STRIPE_MINIMUM_SAFE_RETENTION_SECONDS",
    ],
    ROOT / "python" / "claimsieve_ref" / "github_provider.py": [
        "class GitHubIssueProvider", "read and write tokens must be distinct",
        "observation preflight", "timeout_unknown", "claimsieve-v1",
        "GitHub API base URL must be exactly https://api.github.com",
    ],
    ROOT / "scripts" / "provider_contract_gate.py": [
        "connection_drop_exact_replay", "retention_expiry_duplicate_risk",
        "cached_500_is_indeterminate", "revocation_and_binding_guards",
    ],
    ROOT / "rocq" / "DurableState.v": [
        "revocation_before_dispatch_blocks", "stale_fence_rejected",
        "no_outcome_authorizes_automatic_retry",
        "unauthenticated_executor_command_blocked",
        "unauthenticated_observer_outcome_blocked",
        "permit_after_expiry_invalid",
        "no_provider_record_is_unknown_regardless_of_executor_claim",
        "conflicting_provider_evidence_remains_unknown",
        "transport_replay_allowed",
    ],
}
for path, tokens in required_source_tokens.items():
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            fail(f"{path.relative_to(ROOT)}: missing hardened-boundary sentinel {token!r}")

if errors:
    print("SOURCE GATE: FAIL")
    for error in errors:
        print(f"- {error}")
    raise SystemExit(1)
print("SOURCE GATE: PASS")
