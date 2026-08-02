#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from claimsieve_ref.provider_contracts import (  # noqa: E402
    ProviderContractError,
    ReplayContext,
    STRIPE_MINIMUM_SAFE_RETENTION_SECONDS,
    StripeIdempotencyContractModel,
    authorize_stripe_transport_replay,
)


def base_context(**changes: Any) -> ReplayContext:
    values: dict[str, Any] = {
        "outcome_unknown": True,
        "same_reservation": True,
        "same_idempotency_key": True,
        "same_request_digest": True,
        "same_endpoint": True,
        "same_account": True,
        "authority_active": True,
        "provider_supports_idempotent_post": True,
        "elapsed_seconds": 10,
        "replay_count": 0,
    }
    values.update(changes)
    return ReplayContext(**values)


def connection_drop_exact_replay() -> dict[str, Any]:
    provider = StripeIdempotencyContractModel()
    first = provider.post(
        idempotency_key="contract-key-1",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=100,
        scenario="commit_then_connection_drop",
    )
    authorization = authorize_stripe_transport_replay(base_context())
    second = provider.post(
        idempotency_key="contract-key-1",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=110,
    )
    passed = (
        first.transport == "network_error"
        and first.effect_count == 1
        and authorization.allowed
        and not authorization.creates_new_logical_attempt
        and second.idempotent_replay
        and second.effect_count == 1
    )
    return {
        "passed": passed,
        "first_transport": first.transport,
        "replay_authorized": authorization.allowed,
        "creates_new_logical_attempt": authorization.creates_new_logical_attempt,
        "idempotent_replay": second.idempotent_replay,
        "effect_count": second.effect_count,
    }


def parameter_mutation_rejected() -> dict[str, Any]:
    provider = StripeIdempotencyContractModel()
    provider.post(
        idempotency_key="contract-key-2",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=100,
    )
    claimsieve = authorize_stripe_transport_replay(
        base_context(same_request_digest=False)
    )
    provider_rejected = False
    message = None
    try:
        provider.post(
            idempotency_key="contract-key-2",
            endpoint="/v1/customers",
            request_digest="sha256:request-b",
            now_seconds=110,
        )
    except ProviderContractError as exc:
        provider_rejected = True
        message = str(exc)
    return {
        "passed": not claimsieve.allowed and provider_rejected,
        "claimsieve_allowed": claimsieve.allowed,
        "provider_rejected": provider_rejected,
        "provider_error": message,
    }


def validation_failure_not_cached() -> dict[str, Any]:
    provider = StripeIdempotencyContractModel()
    first = provider.post(
        idempotency_key="contract-key-3",
        endpoint="/v1/customers",
        request_digest="sha256:bad",
        now_seconds=100,
        scenario="validation_error",
    )
    second = provider.post(
        idempotency_key="contract-key-3",
        endpoint="/v1/customers",
        request_digest="sha256:bad",
        now_seconds=110,
        scenario="success",
    )
    return {
        "passed": (
            first.status_code == 400
            and first.effect_count == 0
            and not second.idempotent_replay
            and second.effect_count == 1
        ),
        "first_status": first.status_code,
        "second_idempotent_replay": second.idempotent_replay,
        "effect_count": second.effect_count,
    }


def retention_expiry_duplicate_risk() -> dict[str, Any]:
    provider = StripeIdempotencyContractModel()
    first = provider.post(
        idempotency_key="contract-key-4",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=0,
    )
    authorization = authorize_stripe_transport_replay(
        base_context(elapsed_seconds=STRIPE_MINIMUM_SAFE_RETENTION_SECONDS)
    )
    bypass = provider.post(
        idempotency_key="contract-key-4",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=STRIPE_MINIMUM_SAFE_RETENTION_SECONDS,
    )
    return {
        "passed": (
            first.effect_count == 1
            and not authorization.allowed
            and not bypass.idempotent_replay
            and bypass.effect_count == 2
        ),
        "claimsieve_replay_allowed": authorization.allowed,
        "bypassed_idempotent_replay": bypass.idempotent_replay,
        "effect_count_after_bypass": bypass.effect_count,
    }


def cached_500_is_indeterminate() -> dict[str, Any]:
    provider = StripeIdempotencyContractModel()
    first = provider.post(
        idempotency_key="contract-key-5",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=100,
        scenario="server_500_with_effect",
    )
    replay = provider.post(
        idempotency_key="contract-key-5",
        endpoint="/v1/customers",
        request_digest="sha256:request-a",
        now_seconds=110,
    )
    return {
        "passed": (
            first.status_code == 500
            and replay.status_code == 500
            and replay.idempotent_replay
            and replay.effect_count == 1
            and "possible_object_id" in (replay.body or {})
        ),
        "first_status": first.status_code,
        "replay_status": replay.status_code,
        "idempotent_replay": replay.idempotent_replay,
        "effect_count": replay.effect_count,
        "terminal_outcome_established": False,
    }


def revocation_and_binding_guards() -> dict[str, Any]:
    mutations = {
        "revoked": {"authority_active": False},
        "reservation": {"same_reservation": False},
        "key": {"same_idempotency_key": False},
        "request": {"same_request_digest": False},
        "endpoint": {"same_endpoint": False},
        "account": {"same_account": False},
        "provider_guarantee": {"provider_supports_idempotent_post": False},
        "budget": {"replay_count": 2},
    }
    decisions = {
        name: authorize_stripe_transport_replay(base_context(**change)).allowed
        for name, change in mutations.items()
    }
    return {"passed": not any(decisions.values()), "allowed_by_mutation": decisions}


SCENARIOS: dict[str, Callable[[], dict[str, Any]]] = {
    "connection_drop_exact_replay": connection_drop_exact_replay,
    "parameter_mutation_rejected": parameter_mutation_rejected,
    "validation_failure_not_cached": validation_failure_not_cached,
    "retention_expiry_duplicate_risk": retention_expiry_duplicate_risk,
    "cached_500_is_indeterminate": cached_500_is_indeterminate,
    "revocation_and_binding_guards": revocation_and_binding_guards,
}

contract_path = ROOT / "research" / "stripe_idempotency_contract.json"
contract = json.loads(contract_path.read_text(encoding="utf-8"))
source_ids = {item["id"] for item in contract["sources"]}
errors: list[str] = []
for clause in contract["clauses"]:
    unknown_sources = set(clause.get("source_ids", [])) - source_ids
    if unknown_sources:
        errors.append(f"{clause['id']} has unknown sources: {sorted(unknown_sources)}")
    scenario = clause.get("executable_scenario")
    if scenario not in SCENARIOS:
        errors.append(f"{clause['id']} has no executable scenario: {scenario}")

results = {name: function() for name, function in SCENARIOS.items()}
for name, result in results.items():
    if not result.get("passed"):
        errors.append(f"scenario failed: {name}")

report = {
    "schema_version": "claimsieve.provider_contract_test_report.v1",
    "release": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
    "contract_id": contract["contract_id"],
    "provider": contract["provider"],
    "live_api_called": False,
    "external_effects_created": False,
    "contract_source_count": len(contract["sources"]),
    "contract_clause_count": len(contract["clauses"]),
    "scenario_count": len(results),
    "passed_scenarios": sum(bool(item.get("passed")) for item in results.values()),
    "results": results,
    "errors": errors,
    "gate_passed": not errors,
}
out_json = ROOT / "evidence" / "PROVIDER_CONTRACT_TEST_REPORT.json"
out_txt = ROOT / "evidence" / "PROVIDER_CONTRACT_TEST_REPORT.txt"
out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
lines = [
    f"PROVIDER CONTRACT GATE: {'PASS' if not errors else 'FAIL'}",
    f"Contract: {report['contract_id']}",
    f"Clauses mapped: {report['contract_clause_count']}",
    f"Scenarios passed: {report['passed_scenarios']}/{report['scenario_count']}",
    "Live API called: NO",
    "External effects created: NO",
]
for error in errors:
    lines.append(f"ERROR: {error}")
out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
raise SystemExit(0 if not errors else 1)
