import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const ASSURANCE_RANK = Object.freeze({ aal1: 1, aal2: 2, aal3: 3 });
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/;

function boundedText(name, value, max = 128) {
  if (typeof value !== "string" || value.length < 2 || value.length > max || !ID_PATTERN.test(value)) {
    throw new TypeError(`${name} must be a bounded opaque identifier`);
  }
  return value;
}

function safeInteger(name, value) {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  return value;
}

export function normalizeAuthnAssurance(
  input,
  { nowEpochSeconds = Math.floor(Date.now() / 1000) } = {}
) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("authentication assurance is required");
  }

  const assuranceLevel = input.assuranceLevel;
  if (!Object.hasOwn(ASSURANCE_RANK, assuranceLevel)) {
    throw new Error("unsupported authentication assurance level");
  }

  const authenticatedAt = safeInteger("authenticatedAt", input.authenticatedAt);
  safeInteger("nowEpochSeconds", nowEpochSeconds);
  if (authenticatedAt > nowEpochSeconds + 60) {
    throw new Error("authentication time is in the future");
  }

  if (!Array.isArray(input.methods) || input.methods.length < 1 || input.methods.length > 8) {
    throw new TypeError("authentication methods must be a bounded non-empty array");
  }
  const methods = Object.freeze(
    [...new Set(input.methods.map((value) => boundedText("authentication method", value, 64)))].sort()
  );

  const mfaSatisfied = input.mfaSatisfied === true;
  if (ASSURANCE_RANK[assuranceLevel] >= ASSURANCE_RANK.aal2 && !mfaSatisfied) {
    throw new Error("aal2 or stronger requires an explicit MFA assertion");
  }

  return Object.freeze({ assuranceLevel, authenticatedAt, methods, mfaSatisfied });
}

export function requireRecentStepUp(
  assuranceInput,
  {
    minimumAssurance = "aal2",
    maxAgeSeconds = 600,
    nowEpochSeconds = Math.floor(Date.now() / 1000),
  } = {}
) {
  if (!Object.hasOwn(ASSURANCE_RANK, minimumAssurance)) {
    throw new Error("unsupported minimum assurance level");
  }
  safeInteger("maxAgeSeconds", maxAgeSeconds);
  safeInteger("nowEpochSeconds", nowEpochSeconds);
  if (maxAgeSeconds < 1 || maxAgeSeconds > 86400) {
    throw new Error("step-up freshness must be between 1 second and 24 hours");
  }

  const assurance = normalizeAuthnAssurance(assuranceInput, { nowEpochSeconds });
  if (ASSURANCE_RANK[assurance.assuranceLevel] < ASSURANCE_RANK[minimumAssurance]) {
    throw new Error("step-up authentication required");
  }
  if (nowEpochSeconds - assurance.authenticatedAt > maxAgeSeconds) {
    throw new Error("step-up authentication is stale");
  }
  return assurance;
}

export function createOpaqueSessionSecret() {
  return randomBytes(32).toString("base64url");
}

export function hashSessionSecret(secret) {
  if (typeof secret !== "string" || secret.length < 32 || secret.length > 256) {
    throw new TypeError("session secret must be a bounded opaque string");
  }
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

export function verifySessionSecret(secret, expectedHash) {
  if (typeof expectedHash !== "string" || !/^[0-9a-f]{64}$/.test(expectedHash)) {
    return false;
  }
  let actual;
  try {
    actual = hashSessionSecret(secret);
  } catch {
    return false;
  }
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expectedHash, "hex"));
}

export function buildSessionCookie(
  secret,
  { name = "__Host-mainstreet_session", maxAgeSeconds = 43200 } = {}
) {
  hashSessionSecret(secret);
  if (!/^__Host-[A-Za-z0-9_-]{2,64}$/.test(name)) {
    throw new TypeError("session cookie must use a bounded __Host- name");
  }
  safeInteger("maxAgeSeconds", maxAgeSeconds);
  if (maxAgeSeconds < 60 || maxAgeSeconds > 604800) {
    throw new Error("session cookie lifetime must be between 1 minute and 7 days");
  }
  return `${name}=${secret}; Path=/; Max-Age=${maxAgeSeconds}; Secure; HttpOnly; SameSite=Lax`;
}

export function clearSessionCookie({ name = "__Host-mainstreet_session" } = {}) {
  if (!/^__Host-[A-Za-z0-9_-]{2,64}$/.test(name)) {
    throw new TypeError("session cookie must use a bounded __Host- name");
  }
  return `${name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}
