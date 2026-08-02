from __future__ import annotations

import json
from pathlib import Path

from claimsieve_ref.canonical import digest
from claimsieve_ref.fixtures import evidence, keypairs, signed_policy, proposal, trust_root
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.ledger import Ledger
from claimsieve_ref.runtime import (
    Authority,
    CampaignStateStore,
    ContainmentController,
    Executor,
    Observer,
    ReservationStore,
    SimulatedConnector,
    SimulatedExternalSystem,
)
from claimsieve_ref.trust import sign_witness
from claimsieve_ref.verifier import verify_bundle

ROOT = Path(__file__).resolve().parents[1]


def build_bundle() -> dict:
    keys = keypairs()
    ev = evidence(10)
    signed_pol = signed_policy()
    pol = signed_pol["policy"]
    prop = proposal(ev, 10, approve=True)
    states = CampaignStateStore()
    prior = states.read(prop["campaign_id"])
    decision = evaluate(prop, pol, ev, prior, 10)
    authority = Authority(
        keys["authority"],
        {keys["approver"].key_id: keys["approver"].public},
        {keys["policy_authority"].key_id: keys["policy_authority"].public},
        {
            keys[name].key_id: keys[name].public
            for name in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")
        },
        states,
    )
    permit = authority.issue(
        prop, signed_pol, ev, decision.document, 10, nonce="11" * 24
    )
    committed_state = states.read(prop["campaign_id"])

    ledgers = {
        "proposal": Ledger("proposal", keys["proposal"]),
        "evidence": Ledger("evidence", keys["evidence"]),
        "decision": Ledger("decision", keys["decision"]),
        "execution": Ledger("execution", keys["execution"]),
    }
    ledgers["proposal"].append(prop["trace_id"], "PROPOSAL_SUBMITTED", prop)
    for item in ev:
        ledgers["evidence"].append(prop["trace_id"], "EVIDENCE_RECORDED", item)
    ledgers["decision"].append(prop["trace_id"], "SIGNED_POLICY_RECORDED", signed_pol)
    ledgers["decision"].append(prop["trace_id"], "DECISION_RECORDED", decision.document)
    ledgers["decision"].append(prop["trace_id"], "PERMIT_ISSUED", permit)

    system = SimulatedExternalSystem("success")
    connector = SimulatedConnector(system)
    containment = ContainmentController(keys["containment"])
    executor = Executor(
        authority_keys={keys["authority"].key_id: keys["authority"].public},
        executor_key=keys["executor"],
        reservations=ReservationStore(),
        containment=containment.view(),
        connector=connector,
    )
    execution = executor.execute(
        permit, prop, signed_pol, ev, decision.document, committed_state, 11
    )
    observer = Observer(
        keys["observer"],
        {keys["executor"].key_id: keys["executor"].public},
        system,
    )
    observation = observer.observe(
        permit, prop, execution["executor_receipt"], 12
    )
    containment_receipt = containment.apply_observation(
        observation,
        {keys["observer"].key_id: keys["observer"].public},
        12,
    )

    ledgers["execution"].append(prop["trace_id"], "PERMIT_RESERVED", execution["reservation"])
    ledgers["execution"].append(prop["trace_id"], "EXECUTOR_RECEIPT", execution["executor_receipt"])
    ledgers["execution"].append(prop["trace_id"], "OBSERVER_RECEIPT", observation)
    receipts = [execution["executor_receipt"], observation]
    if containment_receipt is not None:
        ledgers["execution"].append(prop["trace_id"], "CONTAINMENT_RECEIPT", containment_receipt)
        receipts.append(containment_receipt)

    ledger_records = {name: ledger.records for name, ledger in ledgers.items()}
    unsigned_manifest = {
        "schema_version": "claimsieve.bundle_manifest.v2",
        "release_id": "claimsieve-mainstreet-0.33.0-independent-outcome-boundary",
        "trace_id": prop["trace_id"],
        "canonical_profile": "claimsieve.restricted-json.v1",
        "hash_algorithm": "sha256",
        "signature_algorithm": "ed25519",
        "trust_root_id": trust_root()["root_id"],
        "ledger_heads": {
            name: records[-1]["record_hash"] if records else None
            for name, records in ledger_records.items()
        },
        "record_counts": {name: len(records) for name, records in ledger_records.items()},
    }
    manifest = {**unsigned_manifest, "bundle_digest": digest(unsigned_manifest)}
    witness = sign_witness(
        digest(manifest), unsigned_manifest["release_id"], keys["witness"]
    )
    return {
        "schema_version": "claimsieve.evidence_bundle.v2",
        "trace_id": prop["trace_id"],
        "proposal": prop,
        "signed_policy": signed_pol,
        "evidence": ev,
        "decision": decision.document,
        "campaign_state": committed_state.as_canonical(),
        "permit": permit,
        "ledgers": ledger_records,
        "receipts": receipts,
        "manifest": manifest,
        "witness_statement": witness,
    }


def main() -> None:
    bundle = build_bundle()
    root = trust_root()
    errors = verify_bundle(bundle, root)
    if errors:
        raise SystemExit("bundle verification failed: " + "; ".join(errors))
    vector_path = ROOT / "vectors" / "valid_evidence_bundle.json"
    trust_path = ROOT / "trust" / "fixture-trust-root.json"
    trust_path.parent.mkdir(parents=True, exist_ok=True)
    vector_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trust_path.write_text(json.dumps(root, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(vector_path)
    print(trust_path)
    print(digest(bundle))


if __name__ == "__main__":
    main()
