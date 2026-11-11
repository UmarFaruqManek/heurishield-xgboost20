import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl20Features } from "../src/analyzer/url/url20-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { judge } from "./pipeline.js";

const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url20.json", import.meta.url)));
const url = "https://antigravity.google/docs/changelog";
const probability = predictProbability(model, extractUrl20Features(url));
assert.ok(probability >= 0 && probability <= 1);
const snapshot = { page_origin: "https://antigravity.google",
  title: "Changelog | Google Antigravity", headings: [{ text: "Changelog" }],
  logos: [{ text: "Google Antigravity", context: "primary" }],
  controls: [], forms: [], password_fields: [], sensitive_fields: [], inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true,
  candidates: token === "antigravity" || token === "google" ?
    [{ name: "Google Antigravity", domain: "antigravity.google", verified: true }] : [] });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup });
const dom = analyzeDomEvidence([snapshot]);
assert.equal(brand.official_domain_match, true);
// Verified official domain showing its brand, no credential request, domain older than 365 days.
const docs = judge({ urlClass: "DANGEROUS", dom, brand, domainAgeDays: 400 });
assert.deepEqual(docs.matched, ["L1"]);
assert.equal(docs.verdict, "SAFE");

// Safeguards: each missing condition keeps the URL class.
const formlessPassword = analyzeDomEvidence([{ ...snapshot, password_fields: [{ form_index: -1 }] }]);
assert.equal(formlessPassword.form_cross_domain, "unknown", "A password field outside a form has an unobserved destination");
for (const [name, badDom, badBrand, age] of [
  ["formless password", formlessPassword, brand, 400],
  ["sensitive input observed", analyzeDomEvidence([{ ...snapshot, sensitive_fields: [{ type: "otp" }] }]), brand, 400],
  ["official domain unknown", dom, { ...brand, official_domain_match: "unknown" }, 400],
  ["domain age unknown", dom, brand, null],
  ["young domain", dom, brand, 200]
]) assert.equal(judge({ urlClass: "DANGEROUS", dom: badDom, brand: badBrand, domainAgeDays: age }).verdict, "DANGEROUS", name);

// The same documentation copied to another domain is not the official site.
const copyUrl = "https://antigravity-docs.example.test/docs/changelog";
const copy = { ...snapshot, page_origin: "https://antigravity-docs.example.test" };
const copyBrand = await analyzeBrandEvidence(copy, copyUrl, { lookup });
assert.notEqual(copyBrand.official_domain_match, true);
assert.equal(judge({ urlClass: "DANGEROUS", dom: analyzeDomEvidence([copy]), brand: copyBrand, domainAgeDays: 4000 }).verdict, "DANGEROUS");
console.log("Verified documentation correction (L1) and safeguards OK");
