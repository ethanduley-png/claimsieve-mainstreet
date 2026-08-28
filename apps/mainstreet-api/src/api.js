import { resolveTenantContext } from "./authz.js";

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

export function createCustomerApi({ authenticate, resolveMembership, application, nowEpochSeconds }) {
  if (typeof authenticate !== "function") {
    throw new TypeError("authenticate adapter is required");
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

      let identity;
      try {
        identity = await authenticate(request);
      } catch {
        return response(401, { error: "unauthenticated" });
      }
      if (!identity) {
        return response(401, { error: "unauthenticated" });
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
