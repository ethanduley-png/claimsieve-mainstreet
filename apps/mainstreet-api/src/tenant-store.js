import { assertResourceTenant, requirePermission } from "./authz.js";

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function boundedDisplayName(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 160) {
    throw new TypeError("displayName must be non-empty and at most 160 characters");
  }
  return value.trim();
}

/**
 * Test/reference repository only.
 *
 * Production uses PostgreSQL. This class exists to make the tenant boundary
 * executable without requiring a database in baseline assurance tests.
 */
export class MemoryTenantRepository {
  #businesses = new Map();
  #dashboard = new Map();

  seedBusiness(record) {
    if (!record || typeof record !== "object") {
      throw new TypeError("business record is required");
    }
    if (typeof record.tenantId !== "string" || !record.tenantId) {
      throw new TypeError("seed record tenantId is required");
    }
    this.#businesses.set(record.tenantId, clone(record));
  }

  seedDashboardItem(tenantId, item) {
    if (typeof tenantId !== "string" || !tenantId) {
      throw new TypeError("tenantId is required");
    }
    const existing = this.#dashboard.get(tenantId) ?? [];
    existing.push(clone(item));
    this.#dashboard.set(tenantId, existing);
  }

  getBusiness(context) {
    requirePermission(context, "business.read");
    const record = this.#businesses.get(context.tenantId);
    if (!record) return null;
    assertResourceTenant(context, record.tenantId);
    return clone(record);
  }

  updateBusiness(context, patch) {
    requirePermission(context, "business.manage");
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
      throw new TypeError("business patch is required");
    }
    if (Object.prototype.hasOwnProperty.call(patch, "tenantId")) {
      throw new Error("tenantId is context-bound and cannot be patched");
    }
    const current = this.#businesses.get(context.tenantId);
    if (!current) {
      throw new Error("business not found");
    }
    const next = {
      ...current,
      ...(Object.prototype.hasOwnProperty.call(patch, "displayName")
        ? { displayName: boundedDisplayName(patch.displayName) }
        : {}),
    };
    assertResourceTenant(context, next.tenantId);
    this.#businesses.set(context.tenantId, clone(next));
    return clone(next);
  }

  listDashboard(context) {
    requirePermission(context, "business.read");
    return clone(this.#dashboard.get(context.tenantId) ?? []);
  }

  /**
   * Deliberately returns no global iterator or caller-selected tenant lookup.
   * Cross-tenant support tooling must live behind a separately audited admin
   * boundary rather than being smuggled into ordinary customer repositories.
   */
}
