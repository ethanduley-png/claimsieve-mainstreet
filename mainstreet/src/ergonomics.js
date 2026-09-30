import { ProposalBoundaryError, ProposalOnlyBridge } from "./index.js";

const SKILL_FIELDS = new Set([
  "schema_version", "id", "version", "title", "description", "triggers",
  "authority", "objective", "action", "evidence", "risk_tags"
]);
const AUTHORITY_FIELDS = new Set(["mode", "adjudicator", "direct_execution"]);
const OBJECTIVE_FIELDS = new Set(["root", "subgoal", "expected_effect", "constraints"]);
const ACTION_FIELDS = new Set([
  "kind", "effect_class", "method", "reversibility", "destination", "parameter_fields"
]);
const DESTINATION_TEMPLATE_FIELDS = new Set([
  "scheme", "trust_domain", "authority", "authority_from", "resource", "resource_from"
]);
const EVIDENCE_FIELDS = new Set(["required", "minimum_refs"]);
const AGENT_FIELDS = new Set([
  "schema_version", "id", "version", "title", "purpose", "skills", "capabilities", "authority"
]);
const MEMORY_INPUT_FIELDS = new Set([
  "id", "created_at_seq", "source", "scope", "content", "evidence_refs"
]);
const SAFE_AGENT_CAPABILITIES = new Set([
  "read_context",
  "select_skill",
  "prepare_proposal",
  "validate_acknowledgement",
  "record_observation"
]);
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export class ErgonomicsBoundaryError extends ProposalBoundaryError {
  constructor(code, message) {
    super(code, message);
    this.name = "ErgonomicsBoundaryError";
  }
}

function fail(code, message) {
  throw new ErgonomicsBoundaryError(code, message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function assertObject(value, path) {
  if (!isPlainObject(value)) fail("INVALID_ERGONOMIC_OBJECT", `${path} must be a plain object`);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || FORBIDDEN_KEYS.has(key)) {
      fail("DANGEROUS_ERGONOMIC_KEY", `${path} contains a forbidden property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      fail("NON_DATA_ERGONOMIC_PROPERTY", `${path}.${key} must be an enumerable data property`);
    }
  }
}

function rejectUnknown(value, allowed, path) {
  assertObject(value, path);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail("UNKNOWN_ERGONOMIC_FIELD", `${path}.${key} is not allowed`);
  }
}

function text(value, path, maximum = 4096) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    fail("INVALID_ERGONOMIC_STRING", `${path} must be a non-empty bounded string`);
  }
  if (/\p{Cc}/u.test(value)) fail("CONTROL_CHARACTER", `${path} contains a control character`);
  if (value !== value.normalize("NFC")) fail("NON_NFC_STRING", `${path} must be NFC-normalized`);
  return value;
}

function identifier(value, path) {
  const result = text(value, path, 128);
  if (!IDENTIFIER.test(result)) fail("INVALID_ERGONOMIC_ID", `${path} must be a lowercase stable identifier`);
  return result;
}

function sequence(value, path) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail("INVALID_ERGONOMIC_SEQUENCE", `${path} must be a non-negative safe integer`);
  }
  return value;
}

function stringList(value, path, { maximum = 128, allowEmpty = true } = {}) {
  if (!Array.isArray(value) || value.length > maximum || (!allowEmpty && value.length === 0)) {
    fail("INVALID_ERGONOMIC_LIST", `${path} must be a bounded array`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key)) {
      fail("INVALID_ERGONOMIC_LIST", `${path} contains a non-index property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      fail("NON_DATA_ERGONOMIC_PROPERTY", `${path}[${key}] must be an enumerable data property`);
    }
  }
  if (Object.keys(value).length !== value.length) {
    fail("INVALID_ERGONOMIC_LIST", `${path} must not contain holes`);
  }
  const copy = value.map((item, index) => text(item, `${path}[${index}]`, 4096));
  if (new Set(copy).size !== copy.length) fail("DUPLICATE_ERGONOMIC_ITEM", `${path} contains duplicates`);
  return copy;
}

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freeze(child);
  }
  return value;
}

function normalizeAuthority(authority, path) {
  rejectUnknown(authority, AUTHORITY_FIELDS, path);
  if (authority.mode !== "proposal_only") {
    fail("AUTHORITY_ESCALATION", `${path}.mode must be proposal_only`);
  }
  if (authority.adjudicator !== "claimsieve") {
    fail("AUTHORITY_ESCALATION", `${path}.adjudicator must be claimsieve`);
  }
  if (authority.direct_execution !== false) {
    fail("AUTHORITY_ESCALATION", `${path}.direct_execution must be false`);
  }
  return { mode: "proposal_only", adjudicator: "claimsieve", direct_execution: false };
}

function normalizeDestinationTemplate(destination) {
  rejectUnknown(destination, DESTINATION_TEMPLATE_FIELDS, "skill.action.destination");
  const hasStaticAuthority = Object.hasOwn(destination, "authority");
  const hasAuthorityInput = Object.hasOwn(destination, "authority_from");
  const hasStaticResource = Object.hasOwn(destination, "resource");
  const hasResourceInput = Object.hasOwn(destination, "resource_from");

  if (hasStaticAuthority === hasAuthorityInput) {
    fail("INVALID_DESTINATION_TEMPLATE", "destination must declare exactly one of authority or authority_from");
  }
  if (hasStaticResource === hasResourceInput) {
    fail("INVALID_DESTINATION_TEMPLATE", "destination must declare exactly one of resource or resource_from");
  }

  return {
    scheme: text(destination.scheme, "skill.action.destination.scheme", 128),
    trust_domain: text(destination.trust_domain, "skill.action.destination.trust_domain", 512),
    ...(hasStaticAuthority
      ? { authority: text(destination.authority, "skill.action.destination.authority", 2048) }
      : { authority_from: identifier(destination.authority_from, "skill.action.destination.authority_from") }),
    ...(hasStaticResource
      ? { resource: text(destination.resource, "skill.action.destination.resource", 2048) }
      : { resource_from: identifier(destination.resource_from, "skill.action.destination.resource_from") })
  };
}

export function normalizeSkillManifest(input) {
  rejectUnknown(input, SKILL_FIELDS, "skill");
  if (input.schema_version !== "mainstreet.skill.v1") {
    fail("UNSUPPORTED_SKILL_SCHEMA", "skill.schema_version must be mainstreet.skill.v1");
  }
  const version = sequence(input.version, "skill.version");
  if (version === 0) fail("INVALID_SKILL_VERSION", "skill.version must be at least 1");

  rejectUnknown(input.objective, OBJECTIVE_FIELDS, "skill.objective");
  rejectUnknown(input.action, ACTION_FIELDS, "skill.action");
  rejectUnknown(input.evidence, EVIDENCE_FIELDS, "skill.evidence");

  if (typeof input.evidence.required !== "boolean") {
    fail("INVALID_EVIDENCE_POLICY", "skill.evidence.required must be boolean");
  }
  const minimumRefs = sequence(input.evidence.minimum_refs, "skill.evidence.minimum_refs");
  if (input.evidence.required && minimumRefs < 1) {
    fail("INVALID_EVIDENCE_POLICY", "required evidence must require at least one reference");
  }

  const manifest = {
    schema_version: "mainstreet.skill.v1",
    id: identifier(input.id, "skill.id"),
    version,
    title: text(input.title, "skill.title", 256),
    description: text(input.description, "skill.description", 4096),
    triggers: stringList(input.triggers, "skill.triggers", { allowEmpty: false }),
    authority: normalizeAuthority(input.authority, "skill.authority"),
    objective: {
      root: text(input.objective.root, "skill.objective.root", 4096),
      subgoal: text(input.objective.subgoal, "skill.objective.subgoal", 1024),
      expected_effect: text(input.objective.expected_effect, "skill.objective.expected_effect", 4096),
      constraints: stringList(input.objective.constraints, "skill.objective.constraints")
    },
    action: {
      kind: text(input.action.kind, "skill.action.kind", 512),
      effect_class: text(input.action.effect_class, "skill.action.effect_class", 512),
      method: text(input.action.method, "skill.action.method", 128),
      reversibility: text(input.action.reversibility, "skill.action.reversibility", 128),
      destination: normalizeDestinationTemplate(input.action.destination),
      parameter_fields: stringList(input.action.parameter_fields, "skill.action.parameter_fields", { allowEmpty: false })
        .map((field) => identifier(field, "skill.action.parameter_fields[]"))
    },
    evidence: { required: input.evidence.required, minimum_refs: minimumRefs },
    risk_tags: stringList(input.risk_tags, "skill.risk_tags")
  };

  return freeze(manifest);
}

function exactKeys(object, requiredKeys, path) {
  assertObject(object, path);
  const actual = Object.keys(object);
  for (const key of actual) {
    if (!requiredKeys.includes(key)) fail("UNDECLARED_ERGONOMIC_INPUT", `${path}.${key} is not declared by the skill`);
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(object, key)) fail("MISSING_ERGONOMIC_INPUT", `${path}.${key} is required by the skill`);
  }
}

function resolveDestination(template, bindings) {
  const required = [];
  if (Object.hasOwn(template, "authority_from")) required.push(template.authority_from);
  if (Object.hasOwn(template, "resource_from")) required.push(template.resource_from);
  exactKeys(bindings, required, "bindings");

  return {
    scheme: template.scheme,
    authority: Object.hasOwn(template, "authority")
      ? template.authority
      : text(bindings[template.authority_from], `bindings.${template.authority_from}`, 2048),
    resource: Object.hasOwn(template, "resource")
      ? template.resource
      : text(bindings[template.resource_from], `bindings.${template.resource_from}`, 2048),
    trust_domain: template.trust_domain
  };
}

export class ProposalSkill {
  #bridge;
  #manifest;

  constructor({ bridge, manifest }) {
    if (!(bridge instanceof ProposalOnlyBridge)) {
      fail("INVALID_PROPOSAL_BRIDGE", "ProposalSkill requires the baseline ProposalOnlyBridge");
    }
    this.#bridge = bridge;
    this.#manifest = normalizeSkillManifest(manifest);
    Object.freeze(this);
  }

  get manifest() {
    return this.#manifest;
  }

  prepare({
    proposalId,
    traceId,
    tenantId,
    campaignId,
    sessionId,
    parentActionId = null,
    bindings = {},
    parameters,
    evidenceRefs = [],
    requestedAtSeq,
    riskTags = []
  }) {
    exactKeys(parameters, this.#manifest.action.parameter_fields, "parameters");
    const refs = stringList(evidenceRefs, "evidenceRefs");
    if (this.#manifest.evidence.required && refs.length < this.#manifest.evidence.minimum_refs) {
      fail("INSUFFICIENT_EVIDENCE_REFS", `skill requires at least ${this.#manifest.evidence.minimum_refs} evidence reference(s)`);
    }

    const combinedRiskTags = [...this.#manifest.risk_tags, ...stringList(riskTags, "riskTags")];
    if (new Set(combinedRiskTags).size !== combinedRiskTags.length) {
      fail("DUPLICATE_RISK_TAG", "risk tags must remain unique after skill defaults are applied");
    }

    return this.#bridge.prepare({
      proposal_id: text(proposalId, "proposalId", 512),
      trace_id: text(traceId, "traceId", 512),
      tenant_id: text(tenantId, "tenantId", 512),
      campaign_id: text(campaignId, "campaignId", 512),
      session_id: text(sessionId, "sessionId", 512),
      parent_action_id: parentActionId === null ? null : text(parentActionId, "parentActionId", 512),
      objective: this.#manifest.objective,
      action: {
        kind: this.#manifest.action.kind,
        effect_class: this.#manifest.action.effect_class,
        destination: resolveDestination(this.#manifest.action.destination, bindings),
        method: this.#manifest.action.method,
        parameters,
        reversibility: this.#manifest.action.reversibility
      },
      evidence_refs: refs,
      requested_at_seq: sequence(requestedAtSeq, "requestedAtSeq"),
      risk_tags: combinedRiskTags
    });
  }
}

export function normalizeAgentManifest(input) {
  rejectUnknown(input, AGENT_FIELDS, "agent");
  if (input.schema_version !== "mainstreet.agent.v1") {
    fail("UNSUPPORTED_AGENT_SCHEMA", "agent.schema_version must be mainstreet.agent.v1");
  }
  const capabilities = stringList(input.capabilities, "agent.capabilities", { allowEmpty: false });
  for (const capability of capabilities) {
    if (!SAFE_AGENT_CAPABILITIES.has(capability)) {
      fail("AGENT_CAPABILITY_ESCALATION", `agent capability ${capability} is not allowed in Main Street`);
    }
  }
  const version = sequence(input.version, "agent.version");
  if (version === 0) fail("INVALID_AGENT_VERSION", "agent.version must be at least 1");

  return freeze({
    schema_version: "mainstreet.agent.v1",
    id: identifier(input.id, "agent.id"),
    version,
    title: text(input.title, "agent.title", 256),
    purpose: text(input.purpose, "agent.purpose", 4096),
    skills: stringList(input.skills, "agent.skills", { allowEmpty: false }).map((skill) => identifier(skill, "agent.skills[]")),
    capabilities,
    authority: normalizeAuthority(input.authority, "agent.authority")
  });
}

export function createUnreviewedMemory(input) {
  rejectUnknown(input, MEMORY_INPUT_FIELDS, "memory");
  const record = {
    schema_version: "mainstreet.memory.v1",
    id: identifier(input.id, "memory.id"),
    created_at_seq: sequence(input.created_at_seq, "memory.created_at_seq"),
    source: text(input.source, "memory.source", 1024),
    scope: text(input.scope, "memory.scope", 512),
    trust: "unreviewed",
    status: "active",
    content: text(input.content, "memory.content", 32_768),
    evidence_refs: stringList(input.evidence_refs, "memory.evidence_refs")
  };
  return freeze(record);
}

export const ergonomicsCapabilityManifest = freeze({
  schema_version: "mainstreet.ergonomics_capability_manifest.v1",
  role: "non_authoritative_agent_ergonomics",
  allowed: [
    "normalize_skill_manifest",
    "normalize_agent_manifest",
    "prepare_claimsieve_proposal",
    "create_unreviewed_memory"
  ],
  forbidden: [
    "provider_credentials",
    "provider_execution",
    "permit_signing",
    "permit_reservation",
    "approval_issuance",
    "memory_to_policy_promotion",
    "generic_network_egress",
    "shell_execution",
    "filesystem_write",
    "dynamic_code_loading"
  ]
});
