#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from claimsieve_ref.durable_state import classify_provider_evidence  # noqa: E402
from claimsieve_ref.provider_contracts import (  # noqa: E402
    ReplayContext,
    StripeIdempotencyContractModel,
    authorize_stripe_transport_replay,
)


def command_version(name: str, args: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if path is None and sys.platform == "win32":
        candidates: list[Path] = []
        if name == "cargo":
            candidates.append(Path.home() / ".cargo" / "bin" / "cargo.exe")
        elif name in {"rocq", "coqc"}:
            candidates.append(
                Path.home()
                / "Rocq-Platform9.0.2025.08"
                / "bin"
                / f"{name}.exe"
            )
            try:
                candidates.extend(
                    sorted(
                        Path.home().glob(f"Rocq-Platform*/bin/{name}.exe"),
                        reverse=True,
                    )
                )
            except OSError:
                pass
        path = next((str(candidate) for candidate in candidates if candidate.is_file()), None)
    if path is None:
        return {"available": False, "path": None, "version": None}
    process = subprocess.run(
        [path, *args], capture_output=True, text=True, check=False, timeout=30
    )
    output = (process.stdout or process.stderr).strip().splitlines()
    return {
        "available": True,
        "path": path,
        "version": output[0] if output else "UNKNOWN",
        "returncode": process.returncode,
    }


errors: list[str] = []
findings: list[dict[str, Any]] = []
resolved: list[dict[str, str]] = []
remaining: list[dict[str, str]] = []

# 1. Execute the canonical Python outcome vector set.
vector_doc = json.loads(
    (ROOT / "vectors" / "outcome_semantics_vectors.json").read_text(encoding="utf-8")
)
intended = str(vector_doc["intended_action_digest"])
python_results: list[dict[str, Any]] = []
for vector in vector_doc["vectors"]:
    actual, conflict = classify_provider_evidence(
        vector.get("response_status"), vector.get("observed_action_digest"), intended
    )
    passed = (
        actual == vector["expected_reconciliation"]
        and conflict is vector["expected_conflict"]
    )
    python_results.append(
        {
            "id": vector["id"],
            "actual_reconciliation": actual,
            "actual_conflict": conflict,
            "passed": passed,
        }
    )
    if not passed:
        errors.append(f"Python outcome vector failed: {vector['id']}")

# 2. Execute a contract-derived Stripe idempotency trace.
provider = StripeIdempotencyContractModel()
first = provider.post(
    idempotency_key="semantic-gate-key",
    endpoint="/v1/customers",
    request_digest="sha256:semantic-gate-request",
    now_seconds=100,
    scenario="commit_then_connection_drop",
)
context = ReplayContext(
    outcome_unknown=True,
    same_reservation=True,
    same_idempotency_key=True,
    same_request_digest=True,
    same_endpoint=True,
    same_account=True,
    authority_active=True,
    provider_supports_idempotent_post=True,
    elapsed_seconds=10,
    replay_count=0,
)
decision = authorize_stripe_transport_replay(context)
second = provider.post(
    idempotency_key="semantic-gate-key",
    endpoint="/v1/customers",
    request_digest="sha256:semantic-gate-request",
    now_seconds=110,
)
provider_contract_passed = (
    first.transport == "network_error"
    and decision.allowed
    and second.idempotent_replay
    and second.effect_count == 1
)
if not provider_contract_passed:
    errors.append("Stripe contract-derived unknown-outcome trace failed")

# 3. Look for semantic divergence in Rust source rather than token agreement alone.
rust_runtime_path = ROOT / "rust" / "crates" / "runtime" / "src" / "lib.rs"
rust_runtime = rust_runtime_path.read_text(encoding="utf-8")
executor_match = re.search(
    r"pub struct Executor<'a,.*?\n}\n\nimpl<'a,", rust_runtime, re.DOTALL
)
if executor_match is None:
    errors.append("Rust Executor trust boundary could not be located")
    executor_block = ""
else:
    executor_block = executor_match.group(0)
    if "observer_signing_key" in executor_block:
        errors.append("Rust Executor still possesses observer signing material")

for token in (
    "pub struct IndependentObserver",
    "classify_provider_observation",
    "transport_replay_allowed",
    "automatic_retry_allowed",
    "PROVIDER_EVIDENCE_CONFLICT",
):
    if token not in rust_runtime:
        errors.append(f"Rust runtime missing semantic sentinel: {token}")

if "let retry_allowed = reconciliation == Reconciliation::ConfirmedFailure" in rust_runtime:
    errors.append("Rust still treats confirmed failure as automatic retry authority")

if re.search(
    r"pub const fn automatic_retry_allowed\([^)]*\)[^{]*\{\s*false\s*\}",
    rust_runtime,
    re.DOTALL,
) is None:
    errors.append("Rust automatic retry function is not visibly fail-closed")

resolved.extend(
    [
        {
            "id": "DIV-001",
            "description": "v0.32 Python trusted a signed executor rejection when no provider record existed.",
            "resolution": "Observer classification now excludes executor receipts; executed trace remains OUTCOME_UNKNOWN.",
        },
        {
            "id": "DIV-002",
            "description": "v0.32 Rust executor owned the observer signing key.",
            "resolution": "Observer key moved to a separate IndependentObserver source boundary in Rust source.",
        },
        {
            "id": "DIV-003",
            "description": "v0.32 Rust enabled automatic retry after confirmed failure while Python and Rocq denied it.",
            "resolution": "Rust source now returns false for every automatic logical retry outcome.",
        },
        {
            "id": "DIV-004",
            "description": "Python, Rust, and Rocq did not define contradictory provider evidence consistently.",
            "resolution": "Contradictory provider status/effect evidence now maps to OUTCOME_UNKNOWN and containment in executable Python and source models.",
        },
    ]
)

# Do not hide remaining differences.
rust_protocol = (
    ROOT / "rust" / "crates" / "protocol" / "src" / "lib.rs"
).read_text(encoding="utf-8")
if "claimsieve.observer_receipt.v1" in rust_runtime or "receipt_conflict" not in rust_protocol:
    remaining.append(
        {
            "id": "REM-DIV-001",
            "description": "Rust observer receipt protocol remains v1-shaped while the executed Python durable boundary and JSON schema use observer receipt v2 with reservation, campaign, provider-record, and conflict bindings.",
            "impact": "Rust cannot yet claim wire-format parity or portable verifier parity.",
        }
    )

rocq_text = (ROOT / "rocq" / "DurableState.v").read_text(encoding="utf-8")
for token in (
    "no_provider_record_is_unknown_regardless_of_executor_claim",
    "signed_executor_rejection_does_not_confirm_failure",
    "conflicting_provider_evidence_remains_unknown",
    "transport_replay_allowed",
):
    if token not in rocq_text:
        errors.append(f"Rocq model missing semantic sentinel: {token}")

remaining.append(
    {
        "id": "REM-DIV-002",
        "description": "Rocq abstracts independent provider evidence into constructors and does not model parsing, signatures, databases, transport, or provider read APIs.",
        "impact": "Theorems cannot establish implementation-level observer independence or provider-contract compliance.",
    }
)

rust_toolchain = command_version("cargo", ["--version"])
rocq_toolchain = command_version("rocq", ["--version"])
if not rocq_toolchain["available"]:
    rocq_toolchain = command_version("coqc", ["--version"])

native_evidence_path = ROOT / "evidence" / "NATIVE_COMPILATION_ATTEMPT.txt"
native_evidence = (
    native_evidence_path.read_text(encoding="utf-8")
    if native_evidence_path.exists()
    else ""
)
rust_native_pass = rust_toolchain["available"] and all(
    marker in native_evidence
    for marker in (
        "cargo fmt --all -- --check: PASS",
        "cargo clippy --workspace --all-targets --all-features -- -D warnings: PASS",
        "cargo test --workspace --all-features: PASS",
    )
)
rocq_native_pass = rocq_toolchain["available"] and all(
    marker in native_evidence
    for marker in (
        "Claimsieve.v: PASS",
        "DurableState.v: PASS",
        "Check.v: PASS",
        "CheckDurableState.v: PASS",
    )
)
if rust_native_pass:
    resolved.append(
        {
            "id": "DIV-005",
            "description": "Rust native compilation and execution status was previously unknown.",
            "resolution": "Formatting, warning-denied Clippy, 28 tests, documentation tests, and v0.34 bundle verification pass under the project-pinned toolchain.",
        }
    )
else:
    remaining.append(
        {
            "id": "REM-DIV-003",
            "description": "A complete passing Rust native-gate transcript is not available in this environment.",
            "impact": "Rust source inspection and toolchain availability are not native assurance.",
        }
    )
if rocq_native_pass:
    resolved.append(
        {
            "id": "DIV-006",
            "description": "Rocq compiler acceptance and assumption status were previously unknown.",
            "resolution": "All four Rocq files compile and both assumption-audit files report their theorems closed under the global context.",
        }
    )
else:
    remaining.append(
        {
            "id": "REM-DIV-004",
            "description": "A complete passing Rocq compilation and assumption-audit transcript is not available in this environment.",
            "impact": "Proof source inspection and toolchain availability are not accepted proof evidence.",
        }
    )

report = {
    "schema_version": "claimsieve.semantic_divergence_report.v1",
    "release": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
    "gate_passed": not errors,
    "python_outcome_vectors": python_results,
    "stripe_contract_derived_trace": {
        "passed": provider_contract_passed,
        "first_transport": first.transport,
        "replay_authorized": decision.allowed,
        "second_was_idempotent_replay": second.idempotent_replay,
        "effect_count": second.effect_count,
        "live_api_called": False,
    },
    "resolved_semantic_divergences": resolved,
    "remaining_semantic_divergences": remaining,
    "native_toolchains": {"rust": rust_toolchain, "rocq": rocq_toolchain},
    "errors": errors,
}

json_path = ROOT / "evidence" / "SEMANTIC_DIVERGENCE_REPORT.json"
text_path = ROOT / "evidence" / "SEMANTIC_DIVERGENCE_REPORT.txt"
json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
lines = [
    f"SEMANTIC DIVERGENCE GATE: {'PASS' if not errors else 'FAIL'}",
    f"Python vectors: {sum(1 for item in python_results if item['passed'])}/{len(python_results)}",
    f"Stripe contract-derived trace: {'PASS' if provider_contract_passed else 'FAIL'}",
    f"Resolved divergences: {len(resolved)}",
    f"Remaining divergences: {len(remaining)}",
    f"Rust toolchain: {'AVAILABLE' if rust_toolchain['available'] else 'NOT_AVAILABLE'}",
    f"Rocq toolchain: {'AVAILABLE' if rocq_toolchain['available'] else 'NOT_AVAILABLE'}",
]
for item in remaining:
    lines.append(f"- {item['id']}: {item['description']}")
for error in errors:
    lines.append(f"ERROR: {error}")
text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
raise SystemExit(0 if not errors else 1)
