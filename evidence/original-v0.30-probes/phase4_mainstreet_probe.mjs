import { ProposalOnlyBridge } from '/mnt/data/claimsieve_v030_inspection/claimsieve_mainstreet_v0_30_containment/mainstreet/src/index.js';
const identity={tenant_id:'tenant-demo',principal:'spiffe://mainstreet.local/tenant-demo/agent/openclaw'};
function draft(){return {
 proposal_id:'p',trace_id:'t',tenant_id:'tenant-demo',campaign_id:'c',session_id:'s',parent_action_id:null,
 objective:{root:'r',subgoal:'respond_to_lead',expected_effect:'e',constraints:[]},
 action:{kind:'send_message',effect_class:'external_write',destination:{scheme:'sms',authority:'+1',resource:'lead',trust_domain:'sms-provider'},method:'SEND',parameters:{},reversibility:'compensable'},
 evidence_refs:['sha256:a'],requested_at_seq:1,risk_tags:[]
};}
function transport(){return {async submitProposal(p){return {schema_version:'claimsieve.intake_ack.v1',proposal_id:p.proposal_id,trace_id:p.trace_id,intake_status:'RECORDED'};}}}
const results=[];
{
 const d=draft(); const shared={secret:'x'}; d.action.parameters={left:shared,right:shared};
 let accepted=false; try{await new ProposalOnlyBridge({transport:transport(),identity}).propose(d);accepted=true}catch(e){}
 results.push({attack:'DUPLICATE_OBJECT_REFERENCE',expected:'reject shared object identity as serialization-ambiguous',actual:{accepted},impact:'MEDIUM: docs claim rejection, but aliasing crosses the boundary',test_passed:accepted});
}
{
 const d=draft(); d.action.parameters=JSON.parse('{"__proto__":{"polluted":true}}');
 let accepted=false; try{await new ProposalOnlyBridge({transport:transport(),identity}).propose(d);accepted=true}catch(e){}
 results.push({attack:'PROTOTYPE_POLLUTION_KEY',expected:'reject dangerous property names at every depth',actual:{accepted,globalPolluted:({}).polluted===true},impact:'MEDIUM: dangerous keys can reach downstream JavaScript consumers',test_passed:accepted});
}
{
 let sideEffect=0;
 const maliciousTransport={async submitProposal(p){sideEffect++; return {schema_version:'claimsieve.intake_ack.v1',proposal_id:p.proposal_id,trace_id:p.trace_id,intake_status:'RECORDED'};}};
 const bridge=new ProposalOnlyBridge({transport:maliciousTransport,identity});
 await bridge.propose(draft());
 results.push({attack:'SINGLE_CALLABLE_AMBIENT_AUTHORITY',expected:'proposal bridge cannot be injected with an arbitrary effectful function',actual:{sideEffect},impact:'HIGH: source-level shape checks cannot constrain the injected function; OS/network isolation is mandatory',test_passed:sideEffect===1});
}
console.log(JSON.stringify({schema_version:'mainstreet.original_probe.v1',results},null,2));
