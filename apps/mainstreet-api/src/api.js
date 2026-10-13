import {
  normalizeAuthnIdentity,
  normalizeMembership,
  resolveTenantContext,
} from "./authz.js";

function response(status, body) {
  return Object.freeze({
    status,
    body: body === null ? null : Object.freeze(body),
  });
}

function header(headers, name) {
  if (!headers || typeof headers !== "object") return undefined;
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return value;
  }
  return undefined;
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : "request failed";
  if (/permission denied|membership|cross-tenant|not active/.test(message)) {
    return "forbidden";
  }
  return message;
}

function normalizeBusinessMemberships(identity, memberships) {
  if (!Array.isArray(memberships)) {
    throw new Error("membership adapter returned invalid result");
  }
  const normalized = memberships.map((membership) => normalizeMembership(membership));
  if (normalized.some((membership) => membership.userId !== identity.userId)) {
    throw new Error("membership adapter returned another user's membership");
  }
  const byTenant = new Map();
  for (const membership of normalized) {
    if (byTenant.has(membership.tenantId)) {
      throw new Error("membership adapter returned duplicate tenant membership");
    }
    byTenant.set(membership.tenantId, membership);
  }
  return Object.freeze(
    [...byTenant.values()]
      .sort((a, b) => a.tenantId.localeCompare(b.tenantId))
      .map((membership) =>
        Object.freeze({
          tenantId: membership.tenantId,
          role: membership.role,
        })
      )
  );
}

export function createCustomerApi({
  authenticate,
  listMemberships,
  resolveMembership,
  application,
  nowEpochSeconds,
}) {
  if (typeof authenticate !== "function") {
    throw new TypeError("authenticate adapter is required");
  }
  if (typeof listMemberships !== "function") {
    throw new TypeError("listMemberships adapter is required");
  }
  if (typeof resolveMembership !== "function") {
    throw new TypeError("resolveMembership adapter is required");
  }
  if (!application) {
    throw new TypeError("application is required");
  }

  return Object.freeze({
    async handle(request) {
      if (!request || typeof request !== "object") {
        return response(400, { error: "invalid request" });
      }
      const method = String(request.method ?? "GET").toUpperCase();
      const path = String(request.path ?? "/");

      if (method === "GET" && path === "/healthz") {
        return response(200, { ok: true });
      }

      let rawIdentity;
      try {
        rawIdentity = await authenticate(request);
      } catch {
        return response(401, { error: "unauthenticated" });
      }
      if (!rawIdentity) {
        return response(401, { error: "unauthenticated" });
      }

      let identity;
      try {
        identity = normalizeAuthnIdentity(rawIdentity, {
          ...(nowEpochSeconds === undefined ? {} : { nowEpochSeconds }),
        });
      } catch {
        return response(401, { error: "unauthenticated" });
      }

      if (method === "GET" && path === "/v1/businesses") {
        try {
          const memberships = normalizeBusinessMemberships(
            identity,
            await listMemberships(identity)
          );
          return response(200, { businesses: memberships });
        } catch {
          return response(403, { error: "forbidden" });
        }
      }

      const requestedTenantId = header(request.headers, "x-mainstreet-tenant");
      if (typeof requestedTenantId !== "string" || !requestedTenantId.trim()) {
        return response(400, { error: "business selection required" });
      }

      let membership;
      try {
        membership = await resolveMembership(identity, requestedTenantId.trim());
      } catch {
        return response(403, { error: "forbidden" });
      }
      if (!membership) {
        return response(403, { error: "forbidden" });
      }

      let context;
      try {
        context = resolveTenantContext(identity, membership, {
          ...(nowEpochSeconds === undefined ? {} : { nowEpochSeconds }),
        });
      } catch (error) {
        return response(403, { error: safeMessage(error) });
      }

      try {
        if (method === "GET" && path === "/v1/session") {
          return response(200, application.getSessionSummary(context));
        }
        if (method === "GET" && path === "/v1/today") {
          return response(200, application.getToday(context));
        }
        if (method === "POST" && path === "/v1/assistant/requests") {
          return response(202, application.startAssistantRequest(context, request.body));
        }
        return response(404, { error: "not found" });
      } catch (error) {
        const message = safeMessage(error);
        if (message === "forbidden") {
          return response(403, { error: message });
        }
        if (error instanceof TypeError || /size limit|exceeds/.test(message)) {
          return response(400, { error: "invalid request" });
        }
        return response(500, { error: "internal error" });
      }
    },
  });
}
