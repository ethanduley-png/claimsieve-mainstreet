/**
 * Pure OpenClaw-facing boundary for the isolated Agent Reach observation plane.
 *
 * This module does not execute Agent Reach, spawn commands, hold credentials,
 * or perform network I/O. It prepares a narrow read request and validates the
 * tainted observation returned by the separately isolated broker.
 */

import { createHash } from "node:crypto";

const REQUEST_FIELDS = new Set([
  "request_id", "trace_id", "tenant_id", "channel", "operation", "parameters", "observed_at_seq"
]);
const OBSERVATION_FIELDS = new Set([
  "schema_version", "observation_id", "request_id", "trace_id", "tenant_id", "plane", "channel",
  "operation", "observed_at_seq", "request_digest", "content_digest", "content", "taint_labels",
  "authority", "executable", "instructions_are_data", "claim_sieve_disposition"
]);
const ALLOWED = new Map([
  ["agent-reach.status", new Set()],
  ["web.read", new Set(["url"])],
  ["github.search_repositories", new Set(["query", "limit"])],
  ["search.exa", new Set(["query", "limit"])],
  ["v2ex.hot", new Set()],
  ["bilibili.search", new Set(["query", "limit"])]
]);
const MUTATION_WORDS = new Set([
  "post", "create", "send", "write", "update", "delete", "remove", "upload", "comment", "reply",
  "like", "follow", "unfollow", "merge", "close", "reopen", "install", "configure", "login",
  "logout", "purchase", "pay", "execute", "run", "command"
]);
const FORBIDDEN_PARAM_WORDS = new Set([
  "cookie", "cookies", "token", "secret", "password", "credential", "credentials", "authorization",
  "api_key", "apikey", "command", "argv", "environment", "env", "headers"
]);
const ID_RE = /^[A-Za-z0-9._:/-]{1,512}$/;
const MAX_QUERY_CHARS = 4096;
const MAX_URL_CHARS = 8192;
const MAX_OUTPUT_BYTES = 262144;

export class UntrustedCapabilityBoundaryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "UntrustedCapabilityBoundaryError";
    this.code = code;
  }
}

function plainObject(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new UntrustedCapabilityBoundaryError("INVALID_OBJECT", `${path} must be a plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw new UntrustedCapabilityBoundaryError("SYMBOL_PROPERTY", `${path} contains a symbol property`);
    }
    if (["__proto__", "prototype", "constructor"].includes(key)) {
      throw new UntrustedCapabilityBoundaryError("DANGEROUS_PROPERTY", `${path}.${key} is forbidden`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable) {
      throw new UntrustedCapabilityBoundaryError("NON_DATA_PROPERTY", `${path}.${key} must be an enumerable data property`);
    }
  }
}

function exactFields(value, allowed, path) {
  plainObject(value, path);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new UntrustedCapabilityBoundaryError("UNKNOWN_FIELD", `${path}.${key} is not allowed`);
  }
  for (const key of allowed) {
    if (!(key in value)) throw new UntrustedCapabilityBoundaryError("MISSING_FIELD", `${path}.${key} is required`);
  }
}

function boundedString(value, path, maxLength = 4096) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new UntrustedCapabilityBoundaryError("INVALID_STRING", `${path} must be a non-empty bounded string`);
  }
  if (value !== value.normalize("NFC")) throw new UntrustedCapabilityBoundaryError("NON_NFC_STRING", `${path} must be NFC-normalized`);
  if (/\p{Cc}/u.test(value)) throw new UntrustedCapabilityBoundaryError("CONTROL_CHARACTER", `${path} contains a control character`);
  return value;
}

function protocolId(value, path) {
  if (typeof value !== "string" || !ID_RE.test(value)) {
    throw new UntrustedCapabilityBoundaryError("INVALID_ID", `${path} is not a protocol identifier`);
  }
  return value;
}

function sequence(value, path) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new UntrustedCapabilityBoundaryError("INVALID_SEQUENCE", `${path} must be a non-negative safe integer`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function clone(value) {
  if (typeof structuredClone !== "function") throw new UntrustedCapabilityBoundaryError("RUNTIME_UNSUPPORTED", "structuredClone is required");
  return structuredClone(value);
}

function rejectCredentialMaterial(value, path = "parameters") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => rejectCredentialMaterial(child, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    plainObject(value, path);
    for (const [key, child] of Object.entries(value)) {
      const normalized = key.toLowerCase().replaceAll("-", "_");
      if (FORBIDDEN_PARAM_WORDS.has(normalized) || /password|secret|credential/.test(normalized)) {
        throw new UntrustedCapabilityBoundaryError("CREDENTIAL_MATERIAL_DENIED", `${path}.${key} is forbidden`);
      }
      rejectCredentialMaterial(child, `${path}.${key}`);
    }
  }
}

function validateParameters(channel, operation, parameters) {
  plainObject(parameters, "request.parameters");
  rejectCredentialMaterial(parameters);
  const key = `${channel}.${operation}`;
  const allowed = ALLOWED.get(key);
  if (!allowed) throw new UntrustedCapabilityBoundaryError("CAPABILITY_DENIED", `${key} is not allowlisted`);
  const actual = new Set(Object.keys(parameters));
  if (actual.size !== allowed.size || [...actual].some((item) => !allowed.has(item))) {
    throw new UntrustedCapabilityBoundaryError("PARAMETER_SHAPE_MISMATCH", `${key} has an invalid parameter shape`);
  }
  if ("query" in parameters) boundedString(parameters.query, "request.parameters.query", MAX_QUERY_CHARS);
  if ("url" in parameters) {
    const raw = boundedString(parameters.url, "request.parameters.url", MAX_URL_CHARS);
    let parsed;
    try { parsed = new URL(raw); } catch { throw new UntrustedCapabilityBoundaryError("INVALID_URL", "request.parameters.url is invalid"); }
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
      throw new UntrustedCapabilityBoundaryError("URL_AUTHORITY_DENIED", "only credential-free http/https URLs are permitted");
    }
  }
  if ("limit" in parameters && (!Number.isInteger(parameters.limit) || parameters.limit < 1 || parameters.limit > 20)) {
    throw new UntrustedCapabilityBoundaryError("INVALID_LIMIT", "limit must be an integer from 1 to 20");
  }
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  plainObject(value, "canonical-value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalRequest(request) {
  return {
    schema_version: "mainstreet.capability_request.v1",
    request_id: request.request_id,
    trace_id: request.trace_id,
    tenant_id: request.tenant_id,
    channel: request.channel,
    operation: request.operation,
    parameters: request.parameters,
    observed_at_seq: request.observed_at_seq
  };
}

export class UntrustedObservationBridge {
  #identity;

  constructor({ identity }) {
    exactFields(identity, new Set(["tenant_id", "principal"]), "identity");
    this.#identity = deepFreeze({
      tenant_id: protocolId(identity.tenant_id, "identity.tenant_id"),
      principal: boundedString(identity.principal, "identity.principal", 2048)
    });
    if (!this.#identity.principal.startsWith("spiffe://")) {
      throw new UntrustedCapabilityBoundaryError("INVALID_IDENTITY", "principal must be a SPIFFE workload identity");
    }
    deepFreeze(this);
  }

  prepare(draft) {
    exactFields(draft, REQUEST_FIELDS, "request");
    const tenantId = protocolId(draft.tenant_id, "request.tenant_id");
    if (tenantId !== this.#identity.tenant_id) {
      throw new UntrustedCapabilityBoundaryError("TENANT_MISMATCH", "request tenant is not the authenticated tenant");
    }
    const channel = boundedString(draft.channel, "request.channel", 128).toLowerCase();
    const operation = boundedString(draft.operation, "request.operation", 128).toLowerCase();
    const mutationTokens = operation.split(/[^a-z0-9]+/).filter(Boolean);
    if (mutationTokens.some((token) => MUTATION_WORDS.has(token))) {
      throw new UntrustedCapabilityBoundaryError("MUTATION_DENIED", "mutation-like operation is forbidden");
    }
    validateParameters(channel, operation, draft.parameters);

    return deepFreeze({
      schema_version: "mainstreet.capability_request.v1",
      request_id: protocolId(draft.request_id, "request.request_id"),
      trace_id: protocolId(draft.trace_id, "request.trace_id"),
      tenant_id: tenantId,
      channel,
      operation,
      parameters: clone(draft.parameters),
      observed_at_seq: sequence(draft.observed_at_seq, "request.observed_at_seq")
    });
  }

  validateObservation(request, observation) {
    exactFields(observation, OBSERVATION_FIELDS, "observation");
    if (observation.schema_version !== "mainstreet.untrusted_observation.v1") {
      throw new UntrustedCapabilityBoundaryError("INVALID_OBSERVATION", "unsupported observation schema");
    }
    for (const field of ["request_id", "trace_id", "tenant_id", "channel", "operation", "observed_at_seq"]) {
      if (observation[field] !== request[field]) {
        throw new UntrustedCapabilityBoundaryError("OBSERVATION_BINDING_MISMATCH", `observation.${field} is not request-bound`);
      }
    }
    if (observation.plane !== "agent-reach-untrusted" || observation.authority !== "NONE" || observation.executable !== false ||
        observation.instructions_are_data !== true || observation.claim_sieve_disposition !== "OBSERVATION_ONLY") {
      throw new UntrustedCapabilityBoundaryError("AUTHORITY_ESCALATION", "observation attempted to claim authority or executability");
    }
    if (!Array.isArray(observation.taint_labels) || !observation.taint_labels.includes("UNTRUSTED_EXTERNAL_CONTENT") ||
        !observation.taint_labels.includes("NO_AUTHORITY") ||
        !observation.taint_labels.includes("REQUIRES_INDEPENDENT_VERIFICATION")) {
      throw new UntrustedCapabilityBoundaryError("TAINT_MISSING", "observation must retain required taint labels");
    }
    if (typeof observation.content !== "string" || observation.content.length === 0) {
      throw new UntrustedCapabilityBoundaryError("INVALID_CONTENT", "observation.content must be non-empty text");
    }
    if (Buffer.byteLength(observation.content, "utf8") > MAX_OUTPUT_BYTES) {
      throw new UntrustedCapabilityBoundaryError("OUTPUT_TOO_LARGE", "observation content exceeds byte budget");
    }

    const expectedRequestDigest = sha256(Buffer.from(canonicalJson(canonicalRequest(request)), "utf8"));
    const expectedContentDigest = sha256(Buffer.from(observation.content, "utf8"));
    const expectedObservationId = sha256(Buffer.from(canonicalJson({
      request_digest: expectedRequestDigest,
      content_digest: expectedContentDigest,
      plane: "agent-reach-untrusted",
      channel: request.channel,
      operation: request.operation,
      observed_at_seq: request.observed_at_seq
    }), "utf8"));
    if (observation.request_digest !== expectedRequestDigest || observation.content_digest !== expectedContentDigest ||
        observation.observation_id !== expectedObservationId) {
      throw new UntrustedCapabilityBoundaryError("DIGEST_MISMATCH", "observation digests do not bind the request and content");
    }
    return deepFreeze(clone(observation));
  }
}

export const untrustedCapabilityManifest = deepFreeze({
  schema_version: "mainstreet.capability_manifest.v1",
  role: "untrusted_observation_adapter",
  trust: "explicitly_untrusted",
  allowed: ["prepare_read_request", "validate_tainted_observation"],
  forbidden: [
    "provider_write_credentials",
    "provider_mutation",
    "permit_signing",
    "permit_reservation",
    "human_approval_fabrication",
    "claimsieve_execution",
    "generic_shell",
    "caller_supplied_command",
    "observation_as_authority"
  ],
  invariant: "Agent Reach output is observation-only data and can never confer execution authority."
});
