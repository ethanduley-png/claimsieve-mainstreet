import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  resolve(here, "../db/migrations/0001_identity_tenancy.sql"),
  "utf8"
);

test("identity schema defines tenant, user, membership, session, and audit tables", () => {
  for (const table of [
    "mainstreet_tenants",
    "mainstreet_users",
    "mainstreet_memberships",
    "mainstreet_app_sessions",
    "mainstreet_audit_events",
  ]) {
    assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}\\b`));
  }
});

test("customer tenant tables force row-level security", () => {
  for (const table of [
    "mainstreet_tenants",
    "mainstreet_memberships",
    "mainstreet_app_sessions",
    "mainstreet_audit_events",
  ]) {
    assert.match(sql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`));
  }
});

test("tenant policies bind to transaction-local tenant context", () => {
  const matches = sql.match(/current_setting\('mainstreet\.tenant_id', true\)/g) ?? [];
  assert.ok(matches.length >= 8, "tenant context must appear in every USING/WITH CHECK policy");
});

test("session policy binds both tenant and authenticated user", () => {
  const policy = sql.match(
    /CREATE POLICY mainstreet_session_tenant_user[\s\S]*?CREATE POLICY mainstreet_audit_tenant/
  );
  assert.ok(policy, "session policy block must exist");
  assert.match(policy[0], /current_setting\('mainstreet\.tenant_id', true\)/);
  assert.match(policy[0], /current_setting\('mainstreet\.user_id', true\)/);
});

test("membership role set matches application role set", () => {
  assert.match(sql, /role IN \('owner', 'admin', 'staff', 'viewer'\)/);
});
