import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl20Features } from "../src/analyzer/url/url20-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";
import { judge } from "./pipeline.js";

// Long Google search URLs can cross the URL threshold. A verified official
// domain that shows its brand and requests no observed credentials is L1;
// there is no path-specific (/search) rule.
const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url20.json", import.meta.url)));
const url = "https://www.google.com/search?q=bca&oq=bca&gs_lcrp=EgZjaHJvbWUqBwgAEAAYjwIyBwgAEAAYjwIyFggBEC4YgwEYxwEYsQMYyQMY0QMYgAQyDQgCEAAYgwEYsQMYgAQyDQgDEAAYgwEYsQMYgAQyDQgEEAAYkgMYgAQYigUyDQgFEAAYkgMYgAQYigUyCggGEAAYsQMYgAQyDQgHEAAYgwEYsQMYgAQyCggIEAAYsQMYgAQyCggJEAAYsQMYgATSAQc0NjRqMGo3qAIAsAIA&sourceid=chrome&source=chrome.ob&ie=UTF-8";
const probability = predictProbability(model, extractUrl20Features(url));
assert.ok(probability >= 0 && probability <= 1);
const snapshot = { page_origin: "https://www.google.com", title: "bca - Google Search",
  headings: [{ text: "Search results" }], logos: [{ text: "Google", context: "primary" }],
  controls: [], forms: [{ relevant: false, action_known: true, action_origin: "https://www.google.com" }],
  password_fields: [], sensitive_fields: [], inaccessible_frames: 0 };
const lookup = async token => ({ lookup_success: true, candidates: token === "google"
  ? [{ name: "Google", domain: "google.com", verified: true }] : [] });
const brand = await analyzeBrandEvidence(snapshot, url, { lookup });
const dom = analyzeDomEvidence([snapshot]);
assert.equal(brand.official_domain_match, true);
const search = judge({ urlClass: "DANGEROUS", dom, brand, domainAgeDays: 10658 });
assert.deepEqual(search.matched, ["L1"]);
const explanation = buildAnalysisExplanation({ url, final_url: url, verdict: search.verdict,
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" }, decision_policy: search.decision,
  matched_rules: search.rules.filter(rule => rule.status === "matched"), brand_features: brand, dom_features: dom });
assert.match(explanation.summary, /mengoreksi penilaian alamat menjadi legitimate/);

// A matching brand name on a different host cannot undo the URL model.
const copyUrl = "https://google.com.example.test/search?q=bca";
const copy = await analyzeBrandEvidence({ ...snapshot, page_origin: "https://google.com.example.test" }, copyUrl, { lookup });
assert.equal(copy.official_domain_match, false);
assert.equal(judge({ urlClass: "DANGEROUS", dom, brand: copy, domainAgeDays: 10658 }).verdict, "DANGEROUS");

// An unreadable cross-origin iframe leaves credential fields unknown. That is
// "not observed", so the verified search page is still corrected (L1).
const kendariUrl = "https://www.google.com/search?q=kendari&oq=kendari&gs_lcrp=EgZjaHJvbWUqDQgAEAAY4wIYsQMYgAQyDQgAEAAY4wIYsQMYgAQyCggBEC4YsQMYgAQyCggCEAAYsQMYgAQyBwgDEAAYgAQyDQgEEAAYgwEYsQMYgAQyBggFEEUYPDIGCAYQRRg8MgYIBxBFGDzSAQgxMDE5ajBqN6gCALACAA&sourceid=chrome&source=chrome.ob&ie=UTF-8";
const incompleteSnapshot = { ...snapshot, title: "kendari - Google Search", logos: [], inaccessible_frames: 1 };
const incompleteBrand = await analyzeBrandEvidence(incompleteSnapshot, kendariUrl, { lookup });
assert.equal(incompleteBrand.brand_in_title, true);
const incompleteDom = analyzeDomEvidence([incompleteSnapshot]);
assert.equal(incompleteDom.has_password_field, "unknown");
assert.equal(incompleteDom.form_cross_domain, "unknown");
const corrected = judge({ urlClass: "DANGEROUS", dom: incompleteDom, brand: incompleteBrand, domainAgeDays: 10658 });
assert.equal(corrected.verdict, "SAFE");
const correctedText = buildAnalysisExplanation({ url: kendariUrl, final_url: kendariUrl, verdict: corrected.verdict,
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" }, decision_policy: corrected.decision,
  brand_features: incompleteBrand, dom_features: incompleteDom });
assert.match(correctedText.limitation, /Sebagian isi halaman tidak dapat diperiksa/i);

// Search results can mention another verified brand in title and heading.
// That name is the subject of the search, not the site's identity.
const prabowoUrl = "https://www.google.com/search?q=prabowo&gs_lcrp=EgZjaHJvbWUqEAgAEAAYgwEY4wIYsQMYgAQyEAgAEAAYgwEY4wIYsQMYgAQ";
const searchSnapshot = { ...incompleteSnapshot, title: "prabowo - Google Search", headings: [{ text: "Prabowo" }],
  forms: [{ relevant: true, action_known: false, action_origin: null }] };
const searchLookup = async token => ({ lookup_success: true, candidates:
  token === "google" ? [{ name: "Google", domain: "google.com", verified: true }]
    : token === "prabowo" ? [{ name: "Prabowo", domain: "prabowo.id", verified: true }] : [] });
const searchBrand = await analyzeBrandEvidence(searchSnapshot, prabowoUrl, { lookup: searchLookup });
const searchDom = analyzeDomEvidence([searchSnapshot]);
assert.equal(searchBrand.official_domain_match, true);
assert.equal(searchDom.form_cross_domain, "unknown");
assert.equal(judge({ urlClass: "DANGEROUS", dom: searchDom, brand: searchBrand, domainAgeDays: 10658 }).verdict, "SAFE");

// Safeguards: observed credentials, unverified domain, unknown age, or no
// readable page (no brand shown) keep the URL class.
const withPassword = analyzeDomEvidence([{ ...incompleteSnapshot, password_fields: [{ form_index: -1 }] }]);
const withOtp = analyzeDomEvidence([{ ...incompleteSnapshot, sensitive_fields: [{ type: "otp" }] }]);
for (const [name, badDom, badBrand, age] of [
  ["password observed", withPassword, incompleteBrand, 10658],
  ["OTP observed", withOtp, incompleteBrand, 10658],
  ["official domain unknown", incompleteDom, { ...incompleteBrand, official_domain_match: "unknown" }, 10658],
  ["domain age unknown", incompleteDom, incompleteBrand, null],
  ["no readable page", analyzeDomEvidence([]), await analyzeBrandEvidence(null, kendariUrl, { lookup }), 10658]
]) assert.equal(judge({ urlClass: "DANGEROUS", dom: badDom, brand: badBrand, domainAgeDays: age }).verdict, "DANGEROUS", name);
console.log("Official search page correction (L1) and safeguards OK");
