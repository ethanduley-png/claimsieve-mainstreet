from __future__ import annotations
import json, tempfile
from pathlib import Path
from claimsieve_ref.durable_state import DurableStateService, DurableProviderSimulator, DurableExecutor, IndependentObserver
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.runtime import Authority
from claimsieve_ref.durable_state import DurableCampaignStateStore
from claimsieve_ref.model import action_digest

keys = keypairs()
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    state = DurableStateService(
        root / 'state.sqlite3',
        executor_keys={keys['executor'].key_id: keys['executor'].public},
        observer_keys={keys['observer'].key_id: keys['observer'].public},
    )
    ev = evidence(10)
    prop = proposal(ev, 10)
    pol = policy()
    signed = signed_policy()
    current = state.read_campaign(prop['campaign_id']).state
    decision = evaluate(prop, pol, ev, current, 10)
    authority = Authority(
        keys['authority'],
        {keys['approver'].key_id: keys['approver'].public},
        {keys['policy_authority'].key_id: keys['policy_authority'].public},
        {
            keys['crm_evidence'].key_id: keys['crm_evidence'].public,
            keys['registry_evidence'].key_id: keys['registry_evidence'].public,
            keys['deployment_evidence'].key_id: keys['deployment_evidence'].public,
            keys['epoch_evidence'].key_id: keys['epoch_evidence'].public,
        },
        DurableCampaignStateStore(state),
    )
    permit = authority.issue(prop, signed, ev, decision.document, 10, nonce='11' * 24)
    provider = DurableProviderSimulator(root / 'provider.sqlite3', 'success')
    executor = DurableExecutor(
        state,
        provider,
        {keys['authority'].key_id: keys['authority'].public},
        keys['executor'],
    )
    observer = IndependentObserver(
        state,
        provider,
        keys['observer'],
        {keys['executor'].key_id: keys['executor'].public},
    )
    reservation = state.reserve(permit, prop, 11)
    assert reservation is not None
    ticket = executor.claim_reservation_for_dispatch(reservation['reservation_id'], 11)

    # Compromised executor fabricates a semantically false but correctly signed rejection.
    provider_result = {'status': 'rejected', 'provider_id': None}
    unsigned = {
        'schema_version': 'claimsieve.executor_receipt.v2',
        'trace_id': prop['trace_id'],
        'campaign_id': prop['campaign_id'],
        'permit_id': permit['permit_id'],
        'reservation_id': ticket.reservation_id,
        'action_digest': action_digest(prop),
        'request_digest': ticket.request_digest,
        'idempotency_key': ticket.idempotency_key,
        'fencing_token': ticket.fencing_token,
        'containment_epoch': ticket.containment_epoch,
        'provider_status': 'rejected',
        'provider_id': None,
        'attempted_at_seq': 11,
        'executor_key_id': keys['executor'].key_id,
    }
    receipt = {**unsigned, 'signature': keys['executor'].sign('executor-receipt-v2', unsigned)}
    state.persist_provider_attempt(ticket.reservation_id, provider_result, receipt, 11)

    assert provider.query(ticket.idempotency_key) is None
    observation = observer.reconcile(ticket.reservation_id, prop, 12)
    final = state.get_reservation(ticket.reservation_id)
    trace = {
        'invariant': 'I-032 Unknown is not failure; observation must be independent',
        'provider_record': None,
        'executor_claim': 'rejected (valid signature, false semantics)',
        'observer_reconciliation': observation['reconciliation'],
        'final_outcome': final['outcome'],
        'violation': observation['reconciliation'] == 'CONFIRMED_FAILURE',
    }
    print(json.dumps(trace, indent=2, sort_keys=True))
