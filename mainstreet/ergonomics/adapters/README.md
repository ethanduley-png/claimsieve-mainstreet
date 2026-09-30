# Harness adapter contract

OpenClaw, Agent Reach, and future agent harnesses sit outside the ClaimSieve authority boundary.

An adapter may expose these ergonomics operations to a harness:

- enumerate approved Main Street skill manifests,
- enumerate non-authoritative agent profiles,
- read host-supplied context and unreviewed memories,
- prepare a proposal through `ProposalSkill`,
- pass the frozen proposal to a separately isolated ClaimSieve intake channel,
- return only the non-authoritative intake acknowledgement to the harness.

An adapter must not expose provider credentials, permit material, ClaimSieve signing keys, direct provider execution, generic egress, or an authority bypass.

Agent Reach should therefore be treated as an explicitly untrusted capability plane. OpenClaw should be treated as a replaceable reasoning/harness plane. ClaimSieve remains independent from both.
