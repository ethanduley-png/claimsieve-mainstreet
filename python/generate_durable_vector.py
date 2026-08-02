#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from claimsieve_ref.durable_state import (
    DurableCampaignStateStore,
    DurableExecutor,
    DurableProviderSimulator,
    DurableStateService,
    IndependentObserver,
)
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.runtime import Authority

ROOT = Path(__file__).resolve().parents[1]


def build_vector() -> dict:
    keys = keypairs()
    with tempfile.TemporaryDirectory() as temp:
        state = DurableStateService(
            Path(temp) / "state.sqlite3",
            executor_keys={keys["executor"].key_id: keys["executor"].public},
            observer_keys={keys["observer"].key_id: keys["observer"].public},
        )
        provider = DurableProviderSimulator(Path(temp) / "provider.sqlite3", "success")
        ev = evidence(10)
        prop = proposal(ev, 10)
        signed = signed_policy()
        prior = state.read_campaign("campaign-001").state
        decision = evaluate(prop, policy(), ev, prior, 10)
        authority = Authority(
            keys["authority"],
            {keys["approver"].key_id: keys["approver"].public},
            {keys["policy_authority"].key_id: keys["policy_authority"].public},
            {
                keys[name].key_id: keys[name].public
                for name in (
                    "crm_evidence",
                    "registry_evidence",
                    "deployment_evidence",
                    "epoch_evidence",
                )
            },
            DurableCampaignStateStore(state),
        )
        permit = authority.issue(
            prop, signed, ev, decision.document, 10, nonce="88" * 24
        )
        executor = DurableExecutor(
            state,
            provider,
            {keys["authority"].key_id: keys["authority"].public},
            keys["executor"],
        )
        result = executor.execute(permit, prop, signed, ev, decision.document, 11)
        observer = IndependentObserver(
            state,
            provider,
            keys["observer"],
        )
        observation = observer.reconcile(
            result["reservation"]["reservation_id"], prop, 12
        )
        dispatch_event = next(
            event for event in state.journal() if event["event_type"] == "DISPATCH_COMMIT_POINT"
        )
        ticket = dict(dispatch_event["payload"])
        ticket.pop("sequence", None)
        reservation = state.get_reservation(result["reservation"]["reservation_id"])
        return {
            "schema_version": "claimsieve.durable_execution_vector.v1",
            "proposal": prop,
            "permit": permit,
            "decision": decision.document,
            "dispatch_ticket": ticket,
            "executor_command": executor._signed_command(
                "CLAIM_DISPATCH", reservation["reservation_id"], 11
            ),
            "reservation": reservation,
            "executor_receipt": result["executor_receipt"],
            "observer_receipt": observation,
            "journal_head": state.journal()[-1]["event_hash"],
            "journal_verified": state.verify_journal(),
        }


if __name__ == "__main__":
    output = ROOT / "vectors" / "durable_execution_vector.json"
    output.write_text(json.dumps(build_vector(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
