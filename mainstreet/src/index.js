/**
 * MainStreet proposal-only boundary.
 *
 * This module intentionally has no provider SDK, shell, filesystem, dynamic
 * import, credential, or generic network capability. A deployment injects one
 * narrow ClaimSieve intake function. The agent can submit a proposal and
 * receive a non-authoritative intake acknowledgement only.
 */

const TOP_LEVEL_FIELDS = new Set([
  "proposal_id",
  "trace_id",
  "tenant_id",
  "campaign_id",
  "session_id",
  "parent_action_id",
  "objective",
  "action",
  "evidence_refs",
  "requested_at_seq",
  "risk_tags"
]);
const IDENTITY_FIELDS = new Set(["tenant_id", "principal"]);
const OBJECTIVE_FIELDS = new Set(["root", "subgoal", "expected_effect", "constraints"]);
const ACTION_FIELDS = new Set([
  "kind",
  "effect_class",
  "destination",
  "method",
  "parameters",
  "reversibility"
]);
const DESTINATION_FIELDS = new Set(["scheme", "authority", "resource", "trust_domain"]);

const MAX_DEPTH = 16;
const MAX_CONTAINER_ITEMS = 256;
const MAX_TOTAL_NODES = 10_000;
const MAX_TOTAL_STRING_UNITS = 1_048_576;
const FORBIDDEN_PROPERTY_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export class ProposalBoundaryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProposalBoundaryError";
    this.code = code;
  }
}

function containsUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xD800 && code <= 0xDBFF) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) return true;
      index += 1;
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      return true;
    }
  }
  return false;
}

function inspectDataProperties(value, path, { array = false } = {}) {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "symbol") {
      throw new ProposalBoundaryError("SYMBOL_PROPERTY", `${path} contains a symbol property`);
    }
    if (array && key === "length") continue;
    if (FORBIDDEN_PROPERTY_KEYS.has(key)) {
      throw new ProposalBoundaryError("DANGEROUS_PROPERTY", `${path}.${key} is forbidden`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw new ProposalBoundaryError(
        "NON_DATA_PROPERTY",
        `${path}.${key} must be an enumerable data property`
      );
    }
    if (array && !/^(0|[1-9][0-9]*)$/.test(key)) {
      throw new ProposalBoundaryError("ARRAY_PROPERTY", `${path}.${key} is not an array index`);
    }
  }
}

function assertPlainObject(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProposalBoundaryError("INVALID_OBJECT", `${path} must be an object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ProposalBoundaryError("INVALID_PROTOTYPE", `${path} must be a plain object`);
  }
  inspectDataProperties(value, path);
}

function rejectUnknownFields(value, allowed, path) {
  assertPlainObject(value, path);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new ProposalBoundaryError("UNKNOWN_FIELD", `${path}.${key} is not allowed`);
    }
  }
}

function requireString(value, path, maxLength = 4096) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new ProposalBoundaryError("INVALID_STRING", `${path} must be a non-empty bounded string`);
  }
  if (/\p{Cc}/u.test(value)) {
    throw new ProposalBoundaryError("CONTROL_CHARACTER", `${path} contains a control character`);
  }
  if (containsUnpairedSurrogate(value)) {
    throw new ProposalBoundaryError("INVALID_UNICODE", `${path} contains an unpaired surrogate`);
  }
  if (value !== value.normalize("NFC")) {
    throw new ProposalBoundaryError("NON_NFC_STRING", `${path} must already be NFC-normalized`);
  }
  return value;
}

function requireSequence(value, path) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ProposalBoundaryError("INVALID_SEQUENCE", `${path} must be a non-negative safe integer`);
  }
  return value;
}

function addBudget(stats, path, stringUnits = 0) {
  stats.nodes += 1;
  stats.stringUnits += stringUnits;
  if (stats.nodes > MAX_TOTAL_NODES) {
    throw new ProposalBoundaryError("MAX_NODES", `${path} exceeds the total node budget`);
  }
  if (stats.stringUnits > MAX_TOTAL_STRING_UNITS) {
    throw new ProposalBoundaryError("MAX_STRING_BUDGET", `${path} exceeds the total string budget`);
  }
}

function validateJsonValue(
  value,
  path,
  depth = 0,
  stats = { nodes: 0, stringUnits: 0 },
  seen = new WeakSet(),
  active = new WeakSet()
) {
  if (depth > MAX_DEPTH) {
    throw new ProposalBoundaryError("MAX_DEPTH", `${path} exceeds the maximum tree depth`);
  }
  if (value === null || typeof value === "boolean") {
    addBudget(stats, path);
    return;
  }
  if (typeof value === "string") {
    requireString(value, path, 32_768);
    addBudget(stats, path, value.length);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ProposalBoundaryError("FLOAT_OR_UNSAFE_NUMBER", `${path} must be a safe integer`);
    }
    addBudget(stats, path);
    return;
  }
  if (typeof value !== "object") {
    throw new ProposalBoundaryError("INVALID_JSON_VALUE", `${path} is not valid protocol JSON`);
  }
  if (active.has(value)) {
    throw new ProposalBoundaryError("CYCLIC_VALUE", `${path} contains a cycle`);
  }
  if (seen.has(value)) {
    throw new ProposalBoundaryError("SHARED_REFERENCE", `${path} reuses an object reference`);
  }
  seen.add(value);
  active.add(value);
  addBudget(stats, path);

  if (Array.isArray(value)) {
    inspectDataProperties(value, path, { array: true });
    if (Object.keys(value).length !== value.length) {
      throw new ProposalBoundaryError("SPARSE_ARRAY", `${path} must not contain holes`);
    }
    if (value.length > MAX_CONTAINER_ITEMS) {
      throw new ProposalBoundaryError("MAX_ARRAY", `${path} has too many items`);
    }
    value.forEach((item, index) => validateJsonValue(item, `${path}[${index}]`, depth + 1, stats, seen, active));
    active.delete(value);
    return;
  }

  assertPlainObject(value, path);
  const entries = Object.entries(value);
  if (entries.length > MAX_CONTAINER_ITEMS) {
    throw new ProposalBoundaryError("MAX_OBJECT", `${path} has too many fields`);
  }
  for (const [key, item] of entries) {
    requireString(key, `${path}.<key>`, 256);
    stats.stringUnits += key.length;
    if (stats.stringUnits > MAX_TOTAL_STRING_UNITS) {
      throw new ProposalBoundaryError("MAX_STRING_BUDGET", `${path} exceeds the total string budget`);
    }
    validateJsonValue(item, `${path}.${key}`, depth + 1, stats, seen, active);
  }
  active.delete(value);
}

function requireStringArray(value, path, { unique = false, maxItems = MAX_CONTAINER_ITEMS } = {}) {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new ProposalBoundaryError("INVALID_LIST", `${path} must be a bounded array`);
  }
  const result = value.map((item, index) => requireString(item, `${path}[${index}]`, 4096));
  if (unique && new Set(result).size !== result.length) {
    throw new ProposalBoundaryError("DUPLICATE_LIST_ITEM", `${path} must not contain duplicates`);
  }
  return result;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function copyJson(value) {
  if (typeof structuredClone !== "function") {
    throw new ProposalBoundaryError("RUNTIME_UNSUPPORTED", "structuredClone is required");
  }
  return structuredClone(value);
}

function normalizeIdentity(identity) {
  rejectUnknownFields(identity, IDENTITY_FIELDS, "identity");
  const principal = requireString(identity.principal, "identity.principal", 2048);
  const tenantId = requireString(identity.tenant_id, "identity.tenant_id", 512);
  if (!principal.startsWith("spiffe://")) {
    throw new ProposalBoundaryError("INVALID_IDENTITY", "principal must be a SPIFFE workload identity");
  }
  return deepFreeze({ principal, tenant_id: tenantId });
}

function normalizeDraft(draft, identity) {
  rejectUnknownFields(draft, TOP_LEVEL_FIELDS, "proposal");
  rejectUnknownFields(draft.objective, OBJECTIVE_FIELDS, "proposal.objective");
  rejectUnknownFields(draft.action, ACTION_FIELDS, "proposal.action");
  rejectUnknownFields(draft.action.destination, DESTINATION_FIELDS, "proposal.action.destination");
  validateJsonValue(draft, "proposal");

  if (draft.tenant_id !== identity.tenant_id) {
    throw new ProposalBoundaryError("TENANT_MISMATCH", "proposal tenant is not the authenticated tenant");
  }
  assertPlainObject(draft.action.parameters, "proposal.action.parameters");

  const constraints = requireStringArray(draft.objective.constraints, "proposal.objective.constraints");
  const evidenceRefs = requireStringArray(draft.evidence_refs, "proposal.evidence_refs", { unique: true });
  const riskTags = requireStringArray(draft.risk_tags, "proposal.risk_tags", { unique: true });

  const proposal = {
    schema_version: "claimsieve.proposal.v1",
    proposal_id: requireString(draft.proposal_id, "proposal.proposal_id", 512),
    trace_id: requireString(draft.trace_id, "proposal.trace_id", 512),
    tenant_id: identity.tenant_id,
    campaign_id: requireString(draft.campaign_id, "proposal.campaign_id", 512),
    session_id: requireString(draft.session_id, "proposal.session_id", 512),
    parent_action_id: draft.parent_action_id === null
      ? null
      : requireString(draft.parent_action_id, "proposal.parent_action_id", 512),
    principal: identity.principal,
    objective: {
      root: requireString(draft.objective.root, "proposal.objective.root"),
      subgoal: requireString(draft.objective.subgoal, "proposal.objective.subgoal", 1024),
      expected_effect: requireString(draft.objective.expected_effect, "proposal.objective.expected_effect"),
      constraints: copyJson(constraints)
    },
    action: {
      kind: requireString(draft.action.kind, "proposal.action.kind", 512),
      effect_class: requireString(draft.action.effect_class, "proposal.action.effect_class", 512),
      destination: {
        scheme: requireString(draft.action.destination.scheme, "proposal.action.destination.scheme", 128),
        authority: requireString(draft.action.destination.authority, "proposal.action.destination.authority", 2048),
        resource: requireString(draft.action.destination.resource, "proposal.action.destination.resource", 2048),
        trust_domain: requireString(draft.action.destination.trust_domain, "proposal.action.destination.trust_domain", 512)
      },
      method: requireString(draft.action.method, "proposal.action.method", 128),
      parameters: copyJson(draft.action.parameters),
      reversibility: requireString(draft.action.reversibility, "proposal.action.reversibility", 128)
    },
    evidence_refs: copyJson(evidenceRefs),
    approval: null,
    requested_at_seq: requireSequence(draft.requested_at_seq, "proposal.requested_at_seq"),
    risk_tags: copyJson(riskTags)
  };

  return deepFreeze(proposal);
}

/**
 * Pure proposal boundary. It deliberately has no transport or injected
 * callable. The operating environment must move the returned frozen proposal
 * over a separately isolated, identity-authenticated intake channel.
 */
export class ProposalOnlyBridge {
  #identity;

  constructor({ identity }) {
    this.#identity = normalizeIdentity(identity);
    deepFreeze(this);
  }

  prepare(draft) {
    return normalizeDraft(draft, this.#identity);
  }

  validateAcknowledgement(proposal, acknowledgement) {
    const allowed = new Set(["schema_version", "proposal_id", "trace_id", "intake_status"]);
    rejectUnknownFields(acknowledgement, allowed, "acknowledgement");
    if (acknowledgement.schema_version !== "claimsieve.intake_ack.v1") {
      throw new ProposalBoundaryError("INVALID_ACK", "unsupported acknowledgement schema");
    }
    if (acknowledgement.proposal_id !== proposal.proposal_id ||
        acknowledgement.trace_id !== proposal.trace_id) {
      throw new ProposalBoundaryError("ACK_BINDING_MISMATCH", "acknowledgement is not bound to the proposal");
    }
    if (!new Set(["RECORDED", "REJECTED_AT_INTAKE"]).has(acknowledgement.intake_status)) {
      throw new ProposalBoundaryError("INVALID_ACK", "invalid intake status");
    }
    return deepFreeze(copyJson(acknowledgement));
  }
}

export const capabilityManifest = deepFreeze({
  schema_version: "mainstreet.capability_manifest.v1",
  role: "proposal_only_agent_adapter",
  allowed: ["prepare_canonicalizable_proposal", "validate_non_authoritative_acknowledgement"],
  forbidden: [
    "provider_credentials",
    "provider_execution",
    "permit_signing",
    "permit_reservation",
    "human_approval_fabrication",
    "generic_network_egress",
    "shell_execution",
    "filesystem_write",
    "dynamic_code_loading"
  ],
  production_runtime: {
    openclaw: "pinned build required",
    node: ">=24 recommended by upstream",
    egress: "none in this module; isolated intake adapter required"
  }
});
