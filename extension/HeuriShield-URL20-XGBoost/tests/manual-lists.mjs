import assert from "node:assert/strict";
const store = new Map();
globalThis.chrome = { storage: { local: {
  async get(values) { return Object.fromEntries(Object.entries(values).map(([key, fallback]) =>
    [key, store.has(key) ? store.get(key) : fallback])); },
  async set(values) { for (const [key, value] of Object.entries(values)) store.set(key, value); }
} } };
const settings = await import("../src/storage/settings.js");
const n = settings.normalizeManualDomain;
// Lists work on the registrable domain: any subdomain maps to its main domain.
assert.equal(n("https://www.example.com/login"), "example.com");
assert.equal(n("portal.example.com"), "example.com");
assert.equal(n("gemini.google.com"), "google.com");
assert.equal(n("https://mail.google.com/mail/u/0"), "google.com");
assert.equal(n("www.bca.co.id"), "bca.co.id");
assert.equal(n("ibank.klikbca.com"), "klikbca.com");
// Public-suffix and shared-hosting tenants stay separate from their platform.
assert.equal(n("user.github.io"), "user.github.io");
assert.equal(n("evil.vercel.app"), "evil.vercel.app");
assert.equal(n("a.b.firebaseapp.com"), "b.firebaseapp.com");
assert.equal(n("192.168.1.10"), "192.168.1.10");
assert.equal(n("localhost"), "localhost");
await settings.addToAllowlist("https://gemini.google.com/app");
assert.deepEqual(await settings.getAllowlist(), ["google.com"]);
await settings.addToBlacklist("www.google.com");
assert.deepEqual(await settings.getBlacklist(), ["google.com"]);
assert.deepEqual(await settings.getAllowlist(), [], "a domain is on at most one list");
await settings.addToAllowlist("portal.example.com");
assert.deepEqual(await settings.getAllowlist(), ["example.com"]);
// Entries saved by older versions (full hostnames) are read as main domains.
store.set("heurishieldAllowlist", ["gemini.google.com", "docs.google.com", "user.github.io"]);
assert.deepEqual(await settings.getAllowlist(), ["google.com", "user.github.io"]);
console.log("Manual lists: registrable-domain matching and tenant separation OK");
