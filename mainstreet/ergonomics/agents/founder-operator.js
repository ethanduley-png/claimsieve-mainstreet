export const founderOperatorAgent = Object.freeze({
  schema_version: "mainstreet.agent.v1",
  id: "founder.operator",
  version: 1,
  title: "Founder Operator",
  purpose: "Select bounded Main Street skills, gather context, and prepare non-authoritative proposals for ClaimSieve.",
  skills: ["founder.github.issue.create"],
  capabilities: [
    "read_context",
    "select_skill",
    "prepare_proposal",
    "validate_acknowledgement",
    "record_observation"
  ],
  authority: {
    mode: "proposal_only",
    adjudicator: "claimsieve",
    direct_execution: false
  }
});
