import test from "node:test";
import assert from "node:assert/strict";

import { createCustomerApi } from "../src/api.js";
import { MainStreetApplication } from "../src/service.js";
import { MemoryTenantRepository } from "../src/tenant-store.js";

const NOW = 2_000_000_000;

function identity(userId = "user:alice") {
  return {
    userId,
    authProvider: "oidc:test",
    authSubject: `subject:${userId}`,
    sessionId: `session:${userId}`,
    issuedAt: NOW - 10,
    expiresAt: NOW + 3600,
  };
}

function makeApi({ user = identity(), memberships = new Map() } = {}) {
  const repo = new MemoryTenantRepository();
  repo.seedBusiness({ tenantId: "tenant:a", displayName: "A Co" });
  repo.seedBusiness({ tenantId: "tenant:b", displayName: "B Co" });
  repo.seedDashboardItem("tenant:a", { id: "a:1", title: "A only" });
  repo.seedDashboardItem("tenant:b", { id: "b:1", title: "B only" });

  const application = new MainStreetApplication({ repository: repo });
  return createCustomerApi({
    application,
    nowEpochSeconds: NOW,
    authenticate: async (request) => {
      if (request.headers?.authorization !== "Bearer valid") {
        throw new Error("bad token");
      }
      return user;
    },
    resolveMembership: async (authenticated, requestedTenantId) => {
      const membership = memberships.get(requestedTenantId);
      if (!membership || membership.userId !== authenticated.userId) return null;
      return membership;
    },
  });
}

test("health endpoint does not require authentication", async () => {
  const api = makeApi();
  assert.deepEqual(await api.handle({ method: "GET", path: "/healthz" }), {
    status: 200,
    body: { ok: true },
  });
});

test("customer routes require authenticated identity", async () => {
  const api = makeApi();
  const result = await api.handle({
    method: "GET",
    path: "/v1/session",
    headers: { authorization: "Bearer wrong", "x-mainstreet-tenant": "tenant:a" },
  });
  assert.equal(result.status, 401);
  assert.deepEqual(result.body, { error: "unauthenticated" });
});

test("authenticated user must select a business", async () => {
  const api = makeApi();
  const result = await api.handle({
    method: "GET",
    path: "/v1/session",
    headers: { authorization: "Bearer valid" },
  });
  assert.equal(result.status, 400);
  assert.deepEqual(result.body, { error: "business selection required" });
});

test("caller-selected tenant is not authority without active membership", async () => {
  const memberships = new Map([
    ["tenant:a", { userId: "user:alice", tenantId: "tenant:a", role: "owner", status: "active" }],
  ]);
  const api = makeApi({ memberships });
  const result = await api.handle({
    method: "GET",
    path: "/v1/today",
    headers: { authorization: "Bearer valid", "x-mainstreet-tenant": "tenant:b" },
  });
  assert.equal(result.status, 403);
  assert.deepEqual(result.body, { error: "forbidden" });
});

test("active membership resolves tenant context and returns only that business data", async () => {
  const memberships = new Map([
    ["tenant:a", { userId: "user:alice", tenantId: "tenant:a", role: "owner", status: "active" }],
  ]);
  const api = makeApi({ memberships });
  const result = await api.handle({
    method: "GET",
    path: "/v1/today",
    headers: { authorization: "Bearer valid", "x-mainstreet-tenant": "tenant:a" },
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.tenantId, "tenant:a");
  assert.deepEqual(result.body.items.map((item) => item.id), ["a:1"]);
});

test("assistant endpoint remains proposal-only after authentication and tenancy resolution", async () => {
  const memberships = new Map([
    ["tenant:a", { userId: "user:alice", tenantId: "tenant:a", role: "staff", status: "active" }],
  ]);
  const api = makeApi({ memberships });
  const result = await api.handle({
    method: "POST",
    path: "/v1/assistant/requests",
    headers: { authorization: "Bearer valid", "x-mainstreet-tenant": "tenant:a" },
    body: { text: "Call the new lead" },
  });
  assert.equal(result.status, 202);
  assert.equal(result.body.tenantId, "tenant:a");
  assert.equal(result.body.executionAuthority, false);
  assert.equal(result.body.nextBoundary, "mainstreet-proposal-only");
});

test("viewer membership cannot use assistant", async () => {
  const memberships = new Map([
    ["tenant:a", { userId: "user:alice", tenantId: "tenant:a", role: "viewer", status: "active" }],
  ]);
  const api = makeApi({ memberships });
  const result = await api.handle({
    method: "POST",
    path: "/v1/assistant/requests",
    headers: { authorization: "Bearer valid", "x-mainstreet-tenant": "tenant:a" },
    body: { text: "Call the new lead" },
  });
  assert.equal(result.status, 403);
  assert.deepEqual(result.body, { error: "forbidden" });
});

test("membership resolver cannot substitute a different user", async () => {
  const memberships = new Map([
    ["tenant:a", { userId: "user:bob", tenantId: "tenant:a", role: "owner", status: "active" }],
  ]);
  const api = makeApi({ memberships });
  const result = await api.handle({
    method: "GET",
    path: "/v1/session",
    headers: { authorization: "Bearer valid", "x-mainstreet-tenant": "tenant:a" },
  });
  assert.equal(result.status, 403);
});
