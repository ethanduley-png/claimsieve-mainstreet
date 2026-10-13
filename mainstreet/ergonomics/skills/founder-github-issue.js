export const founderGitHubIssueSkill = Object.freeze({
  schema_version: "mainstreet.skill.v1",
  id: "founder.github.issue.create",
  version: 2,
  title: "Propose GitHub issue",
  description: "Prepare a bounded GitHub issue proposal through the existing Founder OS builder for ClaimSieve adjudication. This skill cannot execute GitHub actions.",
  triggers: ["create project issue", "capture governed work item"],
  authority: {
    mode: "proposal_only",
    adjudicator: "claimsieve",
    direct_execution: false
  },
  objective: {
    root: "Operate the ClaimSieve and Main Street company through reviewable governed work.",
    subgoal: "create_project_issue",
    expected_effect: "Exactly one GitHub issue is proposed for the bound repository.",
    constraints: [
      "Reuse FounderOSProposalBuilder validation",
      "No direct GitHub credential access",
      "No repository substitution after adjudication",
      "No caller supplied correlation marker",
      "No payload mutation after adjudication",
      "Ambiguous execution outcomes remain unknown"
    ]
  },
  action: {
    kind: "run_connector",
    effect_class: "external_write",
    method: "CREATE",
    reversibility: "compensable",
    destination: {
      scheme: "github",
      trust_domain: "github.com",
      authority_from: "repository",
      resource: "issues"
    },
    parameter_fields: ["title", "body", "work_item_id"]
  },
  evidence: {
    required: true,
    minimum_refs: 1
  },
  risk_tags: []
});
