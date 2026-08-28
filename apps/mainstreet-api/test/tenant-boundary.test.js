import test from "node:test";
import assert from "node:assert/strict";

import {
  hasPermission,
  normalizeAuthnIdentity,
  requirePermission,
  resolveTenantContext,
  assertResourceTenant,
} from "../src/authz.js";
import { MainStreetApplication } from "../src/service.js";
import { MemoryTenantRepository } from "../src/tenant-store.js";

const NOW = 2_000_000_000;

function identity(userId = "user:alice") {
  return {
    userId,
    authProvider: "oidc:example",
    authSubject: `subject:${userId}`,
    sessionId: `session:${userId}`,
    issuedAt: NOW - 30,
    expiresAt: NOW + 3600,
  };
}

function membership(userId, tenantId, role = "owner") {
  return { userId, tenantId, role, status: "active" };
}

function context(userId, tenantId, role = "owner") {
  return resolveTenantContext(identity(userId), membership(userId, tenantId, role), {
    nowEpochSeconds: NOW,
  });
}

test("expired authentication assertion is rejected", () => {
  const value = identity();
  value.expiresAt = NOW;
  assert.throws(
    () => normalizeAuthnIdentity(value, { nowEpochSeconds: NOW }),
    /expired/
  );
});

test("future authentication assertion is rejected", () => {
  const value = identity();
  value.issuedAt = NOW + 61;
  value.expiresAt = NOW + 3600;
  assert.throws(
    () => normalizeAuthnIdentity(value, { nowEpochSeconds: NOW }),
    /future/
  );
});

test("membership must belong to authenticated user", () => {
  assert.throws(
    () =>
      resolveTenantContext(
        identity("user:alice"),
        membership("user:bob", "tenant:aj-gym"),
        { nowEpochSeconds: NOW }
      ),
    /does not match/
  );
});

test("inactive membership is rejected", () => {
  assert.throws(
    () =>
      resolveTenantContext(
        identity(),
        { ...membership("user:alice", "tenant:aj-gym"), status: "suspended" },
        { nowEpochSeconds: NOW }
      ),
    /not active/
  );
});

test("staff cannot manage business profile", () => {
  const ctx = context("user:staff", "tenant:aj-gym", "staff");
  assert.equal(hasPermission(ctx, "business.read"), true);
  assert.equal(hasPermission(ctx, "business.manage"), false);
  assert.throws(() => requirePermission(ctx, "business.manage"), /permission denied/);
});

test("owner can review approvals but viewer cannot", () => {
  assert.equal(hasPermission(context("user:owner", "tenant:a", "owner"), "approvals.review"), true);
  assert.equal(hasPermission(context("user:viewer", "tenant:a", "viewer"), "approvals.review"), false);
});

test("resource tenant mismatch fails closed", () => {
  const ctx = context("user:alice", "tenant:a");
  assert.throws(() => assertResourceTenant(ctx, "tenant:b"), /cross-tenant/);
});

test("repository read is scoped only by resolved tenant context", () => {
  const repo = new MemoryTenantRepository();
  repo.seedBusiness({ tenantId: "tenant:a", displayName: "A Co" });
  repo.seedBusiness({ tenantId: "tenant:b", displayName: "B Co" });

  const app = new MainStreetApplication({ repository: repo });
  assert.equal(app.getBusiness(context("user:a", "tenant:a")).displayName, "A Co");
  assert.equal(app.getBusiness(context("user:b", "tenant:b")).displayName, "B Co");
});

test("ordinary repository exposes no caller-selected tenant lookup", () => {
  const repo = new MemoryTenantRepository();
  assert.equal(typeof repo.getByTenantId, "undefined");
  assert.equal(typeof repo.listAll, "undefined");
});

test("tenant identifier cannot be changed through business update", () => {
  const repo = new MemoryTenantRepository();
  repo.seedBusiness({ tenantId: "tenant:a", displayName: "A Co" });
  const app = new MainStreetApplication({ repository: repo });

  assert.throws(
    () => app.updateBusiness(context("user:a", "tenant:a"), { tenantId: "tenant:b" }),
    /context-bound/
  );
  assert.equal(app.getBusiness(context("user:a", "tenant:a")).displayName, "A Co");
});

test("staff cannot update business even inside own tenant", () => {
  const repo = new MemoryTenantRepository();
  repo.seedBusiness({ tenantId: "tenant:a", displayName: "A Co" });
  const app = new MainStreetApplication({ repository: repo });
  assert.throws(
    () => app.updateBusiness(context("user:staff", "tenant:a", "staff"), { displayName: "Changed" }),
    /permission denied/
  );
});

test("dashboard cannot leak items from another tenant", () => {
  const repo = new MemoryTenantRepository();
  repo.seedBusiness({ tenantId: "tenant:a", displayName: "A Co" });
  repo.seedBusiness({ tenantId: "tenant:b", displayName: "B Co" });
  repo.seedDashboardItem("tenant:a", { id: "item:a", title: "Call Alice" });
  repo.seedDashboardItem("tenant:b", { id: "item:b", title: "Private B item" });
  const app = new MainStreetApplication({ repository: repo });

  const today = app.getToday(context("user:a", "tenant:a"));
  assert.deepEqual(today.items.map((item) => item.id), ["item:a"]);
});

test("assistant request remains proposal-only and tenant-bound", () => {
  const repo = new MemoryTenantRepository();
  const app = new MainStreetApplication({ repository: repo });
  const result = app.startAssistantRequest(
    context("user:staff", "tenant:a", "staff"),
    { text: "  follow up with the lead  " }
  );
  assert.equal(result.tenantId, "tenant:a");
  assert.equal(result.principalId, "user:staff");
  assert.equal(result.text, "follow up with the lead");
  assert.equal(result.executionAuthority, false);
  assert.equal(result.nextBoundary, "mainstreet-proposal-only");
});

test("viewer cannot invoke assistant", () => {
  const repo = new MemoryTenantRepository();
  const app = new MainStreetApplication({ repository: repo });
  assert.throws(
    () =>
      app.startAssistantRequest(
        context("user:viewer", "tenant:a", "viewer"),
        { text: "hello" }
      ),
    /permission denied/
  );
});
