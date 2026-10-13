import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const read = (name) => readFileSync(resolve(here, `../public/${name}`), "utf8");
const html = read("index.html");
const app = read("app.js");
const sw = read("sw.js");
const manifest = JSON.parse(read("manifest.webmanifest"));

test("web shell delegates sign-in rather than collecting passwords", () => {
  assert.match(html, /href="\/auth\/login\?return_to=%2F"/);
  assert.doesNotMatch(html, /type=["']password["']/i);
  assert.doesNotMatch(app, /password/i);
});

test("browser never stores or handles bearer tokens", () => {
  assert.doesNotMatch(app, /Bearer\s/i);
  assert.doesNotMatch(app, /localStorage/);
  assert.match(app, /credentials:\s*"include"/);
});

test("web shell discovers memberships before selecting a tenant", () => {
  assert.match(app, /api\("\/v1\/businesses", \{\}, null\)/);
  assert.match(app, /x-mainstreet-tenant/);
  assert.match(app, /state\.businesses\.some/);
});

test("assistant surface explicitly consumes proposal-only response", () => {
  assert.match(app, /executionAuthority === false/);
  assert.match(app, /governed authorization path/);
});

test("PWA service worker never caches API or auth routes", () => {
  assert.match(sw, /url\.pathname\.startsWith\("\/v1\/"\)/);
  assert.match(sw, /url\.pathname\.startsWith\("\/auth\/"\)/);
  const shellAssets = sw.match(/const SHELL_ASSETS = Object\.freeze\(\[([\s\S]*?)\]\);/);
  assert.ok(shellAssets, "shell asset list must exist");
  assert.doesNotMatch(shellAssets[1], /\/v1\//);
  assert.doesNotMatch(shellAssets[1], /\/auth\//);
});

test("manifest is installable standalone shell", () => {
  assert.equal(manifest.name, "MainStreet");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.start_url, "/");
});

test("phone navigation includes launch surfaces", () => {
  for (const label of ["Today", "Ask", "Inbox", "Tasks", "Notes", "Approvals", "Activity"]) {
    assert.match(html, new RegExp(`>${label}<`));
  }
});
