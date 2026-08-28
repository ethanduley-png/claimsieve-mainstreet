import { requirePermission } from "./authz.js";

export class MainStreetApplication {
  constructor({ repository }) {
    if (!repository) {
      throw new TypeError("repository is required");
    }
    this.repository = repository;
  }

  getSessionSummary(context) {
    return Object.freeze({
      userId: context.userId,
      tenantId: context.tenantId,
      role: context.role,
      expiresAt: context.expiresAt,
    });
  }

  getBusiness(context) {
    return this.repository.getBusiness(context);
  }

  updateBusiness(context, patch) {
    return this.repository.updateBusiness(context, patch);
  }

  getToday(context) {
    requirePermission(context, "business.read");
    return Object.freeze({
      tenantId: context.tenantId,
      items: Object.freeze(this.repository.listDashboard(context)),
    });
  }

  startAssistantRequest(context, request) {
    requirePermission(context, "assistant.use");
    if (!request || typeof request !== "object" || typeof request.text !== "string" || !request.text.trim()) {
      throw new TypeError("assistant request text is required");
    }
    if (request.text.length > 32_000) {
      throw new Error("assistant request exceeds size limit");
    }
    return Object.freeze({
      tenantId: context.tenantId,
      principalId: context.userId,
      text: request.text.trim(),
      executionAuthority: false,
      nextBoundary: "mainstreet-proposal-only",
    });
  }
}
