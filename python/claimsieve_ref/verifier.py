from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from .canonical import CanonicalizationError, digest, loads_strict
from .crypto import PublicKey
from .ledger import Ledger
from .model import (
    action_digest,
    approval_digest,
    approval_signing_subject,
    destination_digest,
    display_digest,
    evidence_root,
    parameter_digest,
    proposal_digest,
)
from .trust import (
    TrustError,
    evidence_signing_subject,
    policy_signing_subject,
    public_keys_from_trust_root,
    role_key_ids,
    verify_signed_evidence,
    verify_signed_policy,
    witness_signing_subject,
)

LEDGER_IDS = ("proposal", "evidence", "decision", "execution")


def _role_allowed(trust_root: Mapping[str, Any], role: str, key_id: Any) -> bool:
    try:
        return isinstance(key_id, str) and key_id in role_key_ids(trust_root, role)
    except TrustError:
        return False


def _payload_digests(ledgers: dict[str, Any], ledger_id: str, record_type: str) -> list[str]:
    result: list[str] = []
    records = ledgers.get(ledger_id, [])
    if not isinstance(records, list):
        return result
    for record in records:
        if isinstance(record, dict) and record.get("record_type") == record_type:
            try:
                result.append(digest(record.get("payload")))
            except CanonicalizationError:
                pass
    return result


def _require_recorded(
    errors: list[str], ledgers: dict[str, Any], ledger_id: str,
    record_type: str, artifact: Any, label: str,
) -> None:
    try:
        target = digest(artifact)
    except CanonicalizationError as exc:
        errors.append(f"{label} cannot be canonicalized: {exc}")
        return
    if target not in _payload_digests(ledgers, ledger_id, record_type):
        errors.append(f"{label} is not recorded in the {ledger_id} ledger")


def _verify_signature(
    errors: list[str], keys: Mapping[str, PublicKey], trust_root: Mapping[str, Any],
    role: str, key_id: Any, domain: str, unsigned: dict[str, Any], signature: Any,
    label: str,
) -> None:
    if not _role_allowed(trust_root, role, key_id):
        errors.append(f"{label} key is not trusted for role {role}")
        return
    key = keys.get(key_id)
    if key is None or not key.verify(domain, unsigned, str(signature or "")):
        errors.append(f"{label} signature invalid")


def verify_json(text: str, trust_root: dict[str, Any]) -> list[str]:
    value = loads_strict(text)
    if not isinstance(value, dict):
        return ["evidence bundle must be a JSON object"]
    return verify_bundle(value, trust_root)


def verify_bundle(bundle: dict[str, Any], trust_root: dict[str, Any] | None = None) -> list[str]:
    """Verify a bundle against an independently supplied trust root.

    Deliberately refuses self-contained key trust. A key registry embedded in the
    bundle may aid transport, but it is never an authority source.
    """
    if trust_root is None:
        return ["external trust root is required"]
    errors: list[str] = []
    try:
        keys = public_keys_from_trust_root(trust_root)
    except TrustError as exc:
        return [str(exc)]
    if bundle.get("schema_version") != "claimsieve.evidence_bundle.v2":
        return ["unsupported evidence bundle schema"]

    proposal = bundle.get("proposal")
    signed_policy = bundle.get("signed_policy")
    evidence = bundle.get("evidence")
    decision = bundle.get("decision")
    campaign_state = bundle.get("campaign_state")
    permit = bundle.get("permit")
    ledgers = bundle.get("ledgers")
    receipts = bundle.get("receipts")
    manifest = bundle.get("manifest")
    witness = bundle.get("witness_statement")
    if not isinstance(proposal, dict):
        return ["proposal must be an object"]
    if not isinstance(signed_policy, dict):
        return ["signed_policy must be an object"]
    if not isinstance(evidence, list) or not all(isinstance(item, dict) for item in evidence):
        return ["evidence must be an array of objects"]
    if not isinstance(decision, dict):
        return ["decision must be an object"]
    if not isinstance(campaign_state, dict):
        return ["campaign_state must be an object"]
    if permit is not None and not isinstance(permit, dict):
        return ["permit must be null or an object"]
    if not isinstance(ledgers, dict) or not isinstance(receipts, list):
        return ["ledgers and receipts must have valid container types"]
    if not isinstance(manifest, dict) or not isinstance(witness, dict):
        return ["manifest and witness_statement must be objects"]

    policy_key_map = {
        key_id: keys[key_id]
        for key_id in role_key_ids(trust_root, "policy_signers")
        if key_id in keys
    }
    evidence_key_map = {
        key_id: keys[key_id]
        for key_id in role_key_ids(trust_root, "evidence_signers")
        if key_id in keys
    }
    try:
        policy = verify_signed_policy(signed_policy, policy_key_map)
    except TrustError as exc:
        errors.append(str(exc))
        policy = signed_policy.get("policy") if isinstance(signed_policy.get("policy"), dict) else {}
    try:
        verify_signed_evidence(evidence, evidence_key_map, policy)
    except TrustError as exc:
        errors.append(str(exc))

    trace_id = bundle.get("trace_id")
    if trace_id != proposal.get("trace_id"):
        errors.append("bundle trace does not match proposal")
    if decision.get("trace_id") != trace_id:
        errors.append("decision trace mismatch")
    available_refs = [digest(item) for item in evidence]
    proposal_refs = proposal.get("evidence_refs")
    if (
        not isinstance(proposal_refs, list)
        or not all(isinstance(item, str) for item in proposal_refs)
        or len(proposal_refs) != len(set(proposal_refs))
        or len(available_refs) != len(set(available_refs))
        or set(proposal_refs) != set(available_refs)
    ):
        errors.append("proposal evidence references do not exactly match the snapshot")
    expected_decision = {
        "proposal_digest": proposal_digest(proposal),
        "approval_digest": approval_digest(proposal),
        "policy_digest": digest(policy),
        "evidence_root": evidence_root(evidence),
        "campaign_state_digest": digest(campaign_state),
    }
    for field, value in expected_decision.items():
        if decision.get(field) != value:
            errors.append(f"decision {field.replace('_', '-')} mismatch")
    if not isinstance(decision.get("prior_campaign_state_digest"), str):
        errors.append("decision predecessor campaign-state commitment missing")

    approval = proposal.get("approval")
    if isinstance(approval, dict):
        key_id = approval.get("approver_key_id")
        _verify_signature(
            errors, keys, trust_root, "approval_signers", key_id, "approval-v1",
            approval_signing_subject(approval), approval.get("signature"), "approval",
        )
        if approval.get("proposal_digest") != proposal_digest(proposal):
            errors.append("approval proposal binding mismatch")
        if approval.get("display_digest") != display_digest(proposal):
            errors.append("approval display binding mismatch")

    if permit is not None:
        unsigned = {key: value for key, value in permit.items() if key != "signature"}
        _verify_signature(
            errors, keys, trust_root, "authority_signers", permit.get("authority_key_id"),
            "permit-v1", unsigned, permit.get("signature"), "permit",
        )
        expected_permit = {
            "trace_id": trace_id,
            "tenant_id": proposal.get("tenant_id"),
            "campaign_id": proposal.get("campaign_id"),
            "principal": proposal.get("principal"),
            "proposal_digest": proposal_digest(proposal),
            "action_digest": action_digest(proposal),
            "destination_digest": destination_digest(proposal),
            "parameter_digest": parameter_digest(proposal),
            "policy_digest": digest(policy),
            "signed_policy_digest": digest(signed_policy),
            "evidence_root": evidence_root(evidence),
            "decision_digest": digest(decision),
            "approval_digest": approval_digest(proposal),
            "prior_campaign_state_digest": decision.get("prior_campaign_state_digest"),
            "campaign_state_digest": digest(campaign_state),
            "valid_from_seq": decision.get("decided_at_seq"),
            "max_uses": 1,
        }
        for field, value in expected_permit.items():
            if permit.get(field) != value:
                errors.append(f"permit binding mismatch: {field}")
        valid_from = permit.get("valid_from_seq")
        expires = permit.get("expires_at_seq")
        if (
            isinstance(valid_from, bool) or isinstance(expires, bool)
            or not isinstance(valid_from, int) or not isinstance(expires, int)
            or not 1 <= expires - valid_from <= 5
        ):
            errors.append("permit validity window invalid")

    if set(ledgers) != set(LEDGER_IDS):
        errors.append("bundle must contain exactly four named ledgers")
    role_for_ledger = {
        "proposal": "proposal_ledger_writers",
        "evidence": "evidence_ledger_writers",
        "decision": "decision_ledger_writers",
        "execution": "execution_ledger_writers",
    }
    for ledger_id in LEDGER_IDS:
        records = ledgers.get(ledger_id, [])
        if not isinstance(records, list):
            errors.append(f"{ledger_id} ledger must be an array")
            continue
        allowed_ids = set(role_key_ids(trust_root, role_for_ledger[ledger_id]))
        for record in records:
            if isinstance(record, dict) and record.get("writer_key_id") not in allowed_ids:
                errors.append(f"{ledger_id} ledger writer is outside external trust root")
        errors.extend(
            f"{ledger_id} ledger: {error}"
            for error in Ledger.verify(records, keys, ledger_id)
        )
        if not any(isinstance(record, dict) and record.get("trace_id") == trace_id for record in records):
            errors.append(f"missing trace in {ledger_id} ledger")

    _require_recorded(errors, ledgers, "proposal", "PROPOSAL_SUBMITTED", proposal, "proposal")
    _require_recorded(errors, ledgers, "decision", "SIGNED_POLICY_RECORDED", signed_policy, "signed policy")
    for item in evidence:
        _require_recorded(errors, ledgers, "evidence", "EVIDENCE_RECORDED", item, "evidence item")
    _require_recorded(errors, ledgers, "decision", "DECISION_RECORDED", decision, "decision")
    if permit is not None:
        _require_recorded(errors, ledgers, "decision", "PERMIT_ISSUED", permit, "permit")

    reservation_records = [
        record for record in ledgers.get("execution", [])
        if isinstance(record, dict) and record.get("record_type") == "PERMIT_RESERVED"
    ]
    reservation_ids = [
        record.get("payload", {}).get("permit_id") for record in reservation_records
        if isinstance(record.get("payload"), dict)
    ]
    for permit_id, count in Counter(reservation_ids).items():
        if permit_id is not None and count > 1:
            errors.append(f"duplicate permit reservation: {permit_id}")

    executor_receipts: list[dict[str, Any]] = []
    observer_receipts: list[dict[str, Any]] = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            errors.append("receipt must be an object")
            continue
        schema = receipt.get("schema_version")
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        if schema == "claimsieve.executor_receipt.v1":
            executor_receipts.append(receipt)
            _verify_signature(
                errors, keys, trust_root, "executor_signers", receipt.get("executor_key_id"),
                "executor-receipt-v1", unsigned, receipt.get("signature"), "executor receipt",
            )
            _require_recorded(errors, ledgers, "execution", "EXECUTOR_RECEIPT", receipt, "executor receipt")
        elif schema == "claimsieve.observer_receipt.v1":
            observer_receipts.append(receipt)
            _verify_signature(
                errors, keys, trust_root, "observer_signers", receipt.get("observer_key_id"),
                "observer-receipt-v1", unsigned, receipt.get("signature"), "observer receipt",
            )
            _require_recorded(errors, ledgers, "execution", "OBSERVER_RECEIPT", receipt, "observer receipt")
        elif schema == "claimsieve.containment_receipt.v1":
            _verify_signature(
                errors, keys, trust_root, "containment_signers", receipt.get("controller_key_id"),
                "containment-v1", unsigned, receipt.get("signature"), "containment receipt",
            )
            _require_recorded(errors, ledgers, "execution", "CONTAINMENT_RECEIPT", receipt, "containment receipt")
        else:
            errors.append(f"unsupported receipt schema: {schema}")

    if permit is not None and receipts:
        if len(executor_receipts) != 1 or len(observer_receipts) != 1:
            errors.append("executed permit requires one executor and one observer receipt")
        if executor_receipts and executor_receipts[0].get("action_digest") != permit.get("action_digest"):
            errors.append("executor receipt action digest mismatch")
        if executor_receipts and observer_receipts:
            if observer_receipts[0].get("executor_receipt_digest") != digest(executor_receipts[0]):
                errors.append("observer receipt is not bound to executor receipt")
            observed = observer_receipts[0].get("observed_action_digest")
            reconciliation = observer_receipts[0].get("reconciliation")
            exact = digest(proposal.get("action"))
            if reconciliation == "CONFIRMED_SUCCESS" and observed != exact:
                errors.append("successful observation does not match authorized action")
            if reconciliation == "DIVERGENT_EFFECT" and observed in {None, exact}:
                errors.append("divergent observation lacks a divergent action digest")
            if reconciliation in {"CONFIRMED_FAILURE", "OUTCOME_UNKNOWN"} and observed is not None:
                errors.append("non-observed outcome unexpectedly contains an action digest")

    unsigned_manifest = {key: value for key, value in manifest.items() if key != "bundle_digest"}
    if manifest.get("bundle_digest") != digest(unsigned_manifest):
        errors.append("manifest digest mismatch")
    if manifest.get("trace_id") != trace_id:
        errors.append("manifest trace mismatch")
    expected_heads = {
        ledger_id: ledgers[ledger_id][-1].get("record_hash") if isinstance(ledgers.get(ledger_id), list) and ledgers[ledger_id] else None
        for ledger_id in LEDGER_IDS
    }
    if manifest.get("ledger_heads") != expected_heads:
        errors.append("manifest ledger heads mismatch")
    expected_counts = {
        ledger_id: len(ledgers.get(ledger_id, [])) if isinstance(ledgers.get(ledger_id), list) else 0
        for ledger_id in LEDGER_IDS
    }
    if manifest.get("record_counts") != expected_counts:
        errors.append("manifest record counts mismatch")

    witness_unsigned = {key: value for key, value in witness.items() if key != "signature"}
    _verify_signature(
        errors, keys, trust_root, "witness_signers", witness.get("witness_key_id"),
        "witness-v1", witness_unsigned, witness.get("signature"), "witness statement",
    )
    if witness.get("manifest_digest") != digest(manifest):
        errors.append("witness statement manifest binding mismatch")

    # Key identifiers and raw material are both required to be distinct across
    # the authority-bearing roles used in this bundle.
    used = [
        signed_policy.get("signer_key_id"),
        permit.get("authority_key_id") if isinstance(permit, dict) else None,
        approval.get("approver_key_id") if isinstance(approval, dict) else None,
        *(receipt.get("executor_key_id") for receipt in executor_receipts),
        *(receipt.get("observer_key_id") for receipt in observer_receipts),
        witness.get("witness_key_id"),
    ]
    used_ids = [value for value in used if isinstance(value, str)]
    if len(used_ids) != len(set(used_ids)):
        errors.append("security role key identifier reused")
    used_material = [keys[key_id].raw for key_id in used_ids if key_id in keys]
    if len(used_material) != len(set(used_material)):
        errors.append("security role key material reused")

    return sorted(set(errors))
