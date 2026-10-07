const ROLE_PERMISSIONS = Object.freeze({
  owner: Object.freeze([
    "business.read",
    "business.manage",
    "team.read",
    "team.manage",
    "assistant.use",
    "notes.capture",
    "approvals.review",
    "audit.read",
  ]),
  admin: Object.freeze([
    "business.read",
    "business.manage",
    "team.read",
    "team.manage",
    "assistant.use",
    "notes.capture",
    "approvals.review",
    "audit.read",
  ]),
  staff: Object.freeze([
    "business.read",
    "team.read",
    "assistant.use",
    "notes.capture",
  ]),
  viewer: Object.freeze([
    "business.read",
    "team.read",
  ]),
});

export const ROLES = Object.freeze(Object.keys(ROLE_PERMISSIONS));
export const PERMISSIONS = Object.freeze(
  [...new Set(Object.values(ROLE_PERMISSIONS).flat())].sort()
);

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/;

function text(name, value, max = 256) {
  if (typeof value !== "string" || value.length < 2 || value.length > max || !ID_PATTERN.test(value)) {
    throw new TypeError(`${name} must be a bounded opaque identifier`);
  }
  return value;
}

function integer(name, value) {
  if (!Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  return value;
}

export function normalizeAuthnIdentity(input, { nowEpochSeconds = Math.floor(Date.now() / 1000) } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("authenticated identity is required");
  }
  const userId = text("userId", input.userId);
  const authProvider = text("authProvider", input.authProvider);
  const authSubject = text("authSubject", input.authSubject);
  const sessionId = text("sessionId", input.sessionId);
  const issuedAt = integer("issuedAt", input.issuedAt);
  const expiresAt = integer("expiresAt", input.expiresAt);
  integer("nowEpochSeconds", nowEpochSeconds);

  if (issuedAt > nowEpochSeconds + 60) {
    throw new Error("authentication assertion issued in the future");
  }
  if (expiresAt <= issuedAt) {
    throw new Error("authentication assertion expiry must follow issuance");
  }
  if (expiresAt <= nowEpochSeconds) {
    throw new Error("authentication assertion is expired");
  }

  return Object.freeze({
    userId,
    authProvider,
    authSubject,
    sessionId,
    issuedAt,
    expiresAt,
  });
}

export function normalizeMembership(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("tenant membership is required");
  }
  const userId = text("membership.userId", input.userId);
  const tenantId = text("membership.tenantId", input.tenantId);
  const role = input.role;
  if (!ROLES.includes(role)) {
    throw new Error("membership role is not supported");
  }
  if (input.status !== "active") {
    throw new Error("tenant membership is not active");
  }
  return Object.freeze({ userId, tenantId, role, status: "active" });
}

export function resolveTenantContext(identityInput, membershipInput, options = {}) {
  const identity = normalizeAuthnIdentity(identityInput, options);
  const membership = normalizeMembership(membershipInput);
  if (identity.userId !== membership.userId) {
    throw new Error("authenticated identity does not match tenant membership");
  }
  return Object.freeze({
    userId: identity.userId,
    tenantId: membership.tenantId,
    role: membership.role,
    sessionId: identity.sessionId,
    authProvider: identity.authProvider,
    authSubject: identity.authSubject,
    expiresAt: identity.expiresAt,
  });
}

export function hasPermission(context, permission) {
  if (!context || typeof context !== "object") {
    return false;
  }
  const permissions = ROLE_PERMISSIONS[context.role];
  return Array.isArray(permissions) && permissions.includes(permission);
}

export function requirePermission(context, permission) {
  if (!PERMISSIONS.includes(permission)) {
    throw new Error("unknown permission");
  }
  if (!hasPermission(context, permission)) {
    throw new Error("permission denied");
  }
  return context;
}

export function assertResourceTenant(context, resourceTenantId) {
  if (!context || typeof context.tenantId !== "string") {
    throw new Error("tenant context is required");
  }
  if (context.tenantId !== resourceTenantId) {
    throw new Error("cross-tenant access denied");
  }
  return true;
}
