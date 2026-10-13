import assert from "node:assert/strict";
import test from "node:test";

import {
  buildSessionCookie,
  clearSessionCookie,
  createOpaqueSessionSecret,
  hashSessionSecret,
  normalizeAuthnAssurance,
  requireRecentStepUp,
  verifySessionSecret,
} from "../src/session-security.js";

test("opaque session secrets are random, hashable, and never stored as plaintext", () => {
  const first = createOpaqueSessionSecret();
  const second = createOpaqueSessionSecret();
  assert.notEqual(first, second);
  assert.match(hashSessionSecret(first), /^[0-9a-f]{64}$/);
  assert.equal(verifySessionSecret(first, hashSessionSecret(first)), true);
  assert.equal(verifySessionSecret(second, hashSessionSecret(first)), false);
});

test("session cookies are host-only secure HttpOnly cookies", () => {
  const secret = createOpaqueSessionSecret();
  const cookie = buildSessionCookie(secret, { maxAgeSeconds: 3600 });
  assert.match(cookie, /^__Host-mainstreet_session=/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.doesNotMatch(cookie, /Domain=/i);
  assert.equal(clearSessionCookie().includes("Max-Age=0"), true);
});

test("aal2 requires the provider to explicitly assert MFA", () => {
  assert.throws(
    () => normalizeAuthnAssurance({
      assuranceLevel: "aal2",
      authenticatedAt: 1000,
      methods: ["password", "totp"],
      mfaSatisfied: false,
    }, { nowEpochSeconds: 1000 }),
    /explicit MFA assertion/
  );

  const normalized = normalizeAuthnAssurance({
    assuranceLevel: "aal2",
    authenticatedAt: 1000,
    methods: ["totp", "password", "totp"],
    mfaSatisfied: true,
  }, { nowEpochSeconds: 1000 });
  assert.deepEqual(normalized.methods, ["password", "totp"]);
  assert.equal(normalized.mfaSatisfied, true);
});

test("recent step-up accepts fresh aal2 and rejects weak or stale authentication", () => {
  const fresh = {
    assuranceLevel: "aal2",
    authenticatedAt: 950,
    methods: ["passkey"],
    mfaSatisfied: true,
  };
  assert.equal(
    requireRecentStepUp(fresh, { nowEpochSeconds: 1000, maxAgeSeconds: 60 }).assuranceLevel,
    "aal2"
  );

  assert.throws(
    () => requireRecentStepUp({
      assuranceLevel: "aal1",
      authenticatedAt: 999,
      methods: ["federated"],
      mfaSatisfied: false,
    }, { nowEpochSeconds: 1000 }),
    /step-up authentication required/
  );

  assert.throws(
    () => requireRecentStepUp({
      assuranceLevel: "aal2",
      authenticatedAt: 900,
      methods: ["passkey"],
      mfaSatisfied: true,
    }, { nowEpochSeconds: 1000, maxAgeSeconds: 60 }),
    /step-up authentication is stale/
  );
});

test("cookie policy refuses non __Host names and excessive lifetimes", () => {
  const secret = createOpaqueSessionSecret();
  assert.throws(() => buildSessionCookie(secret, { name: "session" }), /__Host-/);
  assert.throws(() => buildSessionCookie(secret, { maxAgeSeconds: 604801 }), /7 days/);
});
