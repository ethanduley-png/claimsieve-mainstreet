from __future__ import annotations
import copy, json, sys
from pathlib import Path
ROOT=Path('/mnt/data/claimsieve_v030_inspection/claimsieve_mainstreet_v0_30_containment')
sys.path.insert(0,str(ROOT/'python'))
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.runtime import Authority, ReservationStore, ContainmentController, Executor, SimulatedConnector
from claimsieve_ref.canonical import digest
from claimsieve_ref.model import approval_signing_subject, display_digest, proposal_digest
from claimsieve_ref.crypto import KeyPair
from claimsieve_ref.verifier import verify_bundle
import importlib.util

results=[]
def rec(name, expected, actual, impact, passed):
    results.append({"attack":name,"expected":expected,"actual":actual,"impact":impact,"test_passed":passed})

# 1 campaign fork: max_actions=1, same prior state, two sibling decisions/permits both execute.
keys=keypairs(); ev=evidence(10)
pol=policy(campaign_limits={**policy()['campaign_limits'], 'max_actions':1})
prior=CampaignState('campaign-001')
authority=Authority(keys['authority'],{keys['approver'].key_id:keys['approver'].public})
props=[]; decisions=[]; permits=[]
for i,body in enumerate(['message one','message two'],1):
    p=proposal(ev,10,approve=False, proposal_id=f'proposal-fork-{i}', trace_id=f'trace-fork-{i}', action={**proposal(ev,10,approve=False)['action'], 'parameters':{'body':body}})
    # fresh signed approval
    unsigned={
      'schema_version':'claimsieve.approval.v1','approval_id':f'approval-fork-{i}',
      'approver':'spiffe://mainstreet.local/tenant-demo/human/owner',
      'proposal_digest':proposal_digest(p),'display_digest':display_digest(p),
      'approved_at_seq':10,'expires_at_seq':15,'approver_key_id':keys['approver'].key_id,
    }
    p['approval']={**unsigned,'signature':keys['approver'].sign('approval-v1',approval_signing_subject(unsigned))}
    d=evaluate(p,pol,ev,prior,10)
    permit=authority.issue(p,pol,ev,d.document,prior,10,nonce=f'{i:02x}'*24)
    props.append(p); decisions.append(d); permits.append(permit)
store=ReservationStore(); containment=ContainmentController(keys['containment'])
executor=Executor({keys['authority'].key_id:keys['authority'].public},keys['executor'],keys['observer'],store,containment,SimulatedConnector('success'))
executed=[]
for p,d,permit in zip(props,decisions,permits):
    r=executor.execute(permit,p,pol,ev,d.document,d.next_state,11)
    executed.append(r['reconciliation'])
rec('CAMPAIGN_STATE_FORK', 'second sibling permit denied because max_actions=1 and first transition consumed the parent state', {'decision_verdicts':[d.document['verdict'] for d in decisions], 'executed':executed, 'reservations':store.count()}, 'CRITICAL: cumulative campaign limits can be bypassed through sibling issuance from the same prior state', len(executed)==2)

# 2 unsigned policy substitution: caller supplies a widened policy and matching unsigned evidence.
ev2=evidence(10)
ev2[3]['content']['policy_version']=2
pol2=policy(version=2, allowed_action_kinds=['delete_record'], allowed_subgoals=['erase_customer_record'], approval_required_for=[])
base=proposal(ev2,10,approve=False)
base['proposal_id']='proposal-policy-sub'; base['trace_id']='trace-policy-sub'
base['objective']['subgoal']='erase_customer_record'; base['objective']['expected_effect']='A customer record is deleted.'
base['action']['kind']='delete_record'; base['action']['parameters']={'record_id':'lead-123'}; base['approval']=None
base['evidence_refs']=[digest(x) for x in ev2]
d2=evaluate(base,pol2,ev2,CampaignState('campaign-001'),10)
issued=False
try:
    authority.issue(base,pol2,ev2,d2.document,CampaignState('campaign-001'),10,nonce='aa'*24)
    issued=True
except Exception as exc:
    err=str(exc)
rec('UNSIGNED_POLICY_SUBSTITUTION','authority rejects policy not signed by an externally trusted policy authority',{'verdict':d2.document['verdict'],'permit_issued':issued},'CRITICAL: caller-controlled policy can widen authority',issued)

# 3 observer role collapse: executor owns observer private key and can sign arbitrary observations.
executor2=Executor({keys['authority'].key_id:keys['authority'].public},keys['executor'],keys['observer'],ReservationStore(),ContainmentController(keys['containment']),SimulatedConnector('failure'))
forged_unsigned={
 'schema_version':'claimsieve.observer_receipt.v1','trace_id':'trace-forged','permit_id':'permit-forged',
 'observed_action_digest':'sha256:'+'1'*64,'reconciliation':'CONFIRMED_SUCCESS','observed_at_seq':11,
 'observer_key_id':executor2.observer_key.key_id,
}
forged_sig=executor2.observer_key.sign('observer-receipt-v1',forged_unsigned)
rec('OBSERVER_KEY_CUSTODY_COLLAPSE','executor process cannot access observer signing key',{'executor_has_observer_private_key':True,'forged_signature_prefix':forged_sig[:16]},'HIGH: compromised executor can forge independent observation',True)

# 4 portable bundle self-trust: attacker-generated rootless bundle verifies.
spec=importlib.util.spec_from_file_location('gb',ROOT/'python/generate_bundle.py')
gb=importlib.util.module_from_spec(spec); spec.loader.exec_module(gb)
attacker_names=['proposal','evidence','decision','execution','authority','approver','executor','observer','containment','witness']
attacker_keys={name:KeyPair.from_seed(f'attacker-{name}-key',bytes([100+i])*32) for i,name in enumerate(attacker_names)}
orig_gb=gb.keypairs
import claimsieve_ref.fixtures as fx
orig_fx=fx.keypairs
gb.keypairs=lambda:attacker_keys
fx.keypairs=lambda:attacker_keys
try:
    bundle=gb.build_bundle()
finally:
    gb.keypairs=orig_gb; fx.keypairs=orig_fx
errors=verify_bundle(bundle)
rec('SELF_ASSERTED_BUNDLE_KEYS','offline verifier rejects a bundle unless signatures chain to an external pinned trust root',{'verification_errors':errors,'attacker_key_ids':sorted(bundle['public_keys'])[:3]},'CRITICAL: a fully re-signed fabricated history is internally valid and accepted',errors==[])

# 5 sequence reuse explicitly allowed.
st=CampaignState('campaign-001'); first=evaluate(proposal(ev,10,approve=True),policy(),ev,st,10)
second=evaluate(proposal(ev,10,approve=True,proposal_id='p2',trace_id='t2'),policy(),ev,first.next_state,10)
rec('NON_STRICT_SEQUENCE_REUSE','second transition at the same logical sequence is denied',{'first':first.document['verdict'],'first_last_sequence':first.next_state.last_sequence,'second':second.document['verdict'],'second_reasons':second.document['reason_codes']},'HIGH: same-sequence transitions permit ambiguous ordering and facilitate state forks',second.document['verdict']=='ALLOW')

print(json.dumps({'schema_version':'claimsieve.original_attack_probe.v1','results':results},indent=2,sort_keys=True))
