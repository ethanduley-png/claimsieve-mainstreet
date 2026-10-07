import { normalizeAgentManifest, normalizeSkillManifest } from "../src/ergonomics.js";
import { founderOperatorAgent } from "./agents/founder-operator.js";
import { founderGitHubIssueSkill } from "./skills/founder-github-issue.js";

const skills = [normalizeSkillManifest(founderGitHubIssueSkill)];
const agents = [normalizeAgentManifest(founderOperatorAgent)];

export const MAINSTREET_SKILLS = Object.freeze(skills);
export const MAINSTREET_AGENTS = Object.freeze(agents);

export function getSkillManifest(skillId) {
  return MAINSTREET_SKILLS.find((skill) => skill.id === skillId) ?? null;
}

export function getAgentManifest(agentId) {
  return MAINSTREET_AGENTS.find((agent) => agent.id === agentId) ?? null;
}

export function ergonomicCatalogSnapshot() {
  return Object.freeze({
    schema_version: "mainstreet.ergonomics_catalog.v1",
    authority: "non_authoritative",
    skills: MAINSTREET_SKILLS,
    agents: MAINSTREET_AGENTS
  });
}
