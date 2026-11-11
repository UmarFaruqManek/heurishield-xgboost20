import assert from "node:assert/strict";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { judge } from "./pipeline.js";

// Ordinary content pages on a verified first-party domain (L1) correct a URL false positive.
for (const url of ["https://liquipedia.net/valorant/VCT/2027/Pacific/Kickoff",
  "https://liquipedia.net/valorant/VCT/2026/Pacific_League/Stage_2"]) {
  const snapshot = { page_origin: "https://liquipedia.net", title: "VCT Pacific - Liquipedia VALORANT Wiki",
    headings: [{ text: "VCT Pacific" }], logos: [], forms: [], password_fields: [], sensitive_fields: [],
    controls: [], inaccessible_frames: 0, document_ready_state: "complete" };
  const brand = await analyzeBrandEvidence(snapshot, url, {
    domainSearch: async () => ({ found: true, lookup_success: true,
      candidates: [{ name: "Liquipedia", domain: "liquipedia.net", verified: false }] }),
    lookup: async () => ({ lookup_success: true, candidates: [] })
  });
  const dom = analyzeDomEvidence([snapshot]);
  const page = judge({ urlClass: "DANGEROUS", dom, brand, domainAgeDays: 6000 });
  assert.deepEqual(page.matched, ["L1"]);
  for (const [name, badDom, badBrand, age] of [
    ["password observed", analyzeDomEvidence([{ ...snapshot, password_fields: [{ form_index: -1 }] }]), brand, 6000],
    ["official domain unknown", dom, { ...brand, official_domain_match: "unknown" }, 6000],
    ["brand not shown", dom, { ...brand, brand_in_title: false, brand_in_heading: false, brand_in_logo: false }, 6000],
    ["domain age unknown", dom, brand, null],
    ["young domain", dom, brand, 90]
  ]) assert.equal(judge({ urlClass: "DANGEROUS", dom: badDom, brand: badBrand, domainAgeDays: age }).verdict, "DANGEROUS", name);
}
console.log("Verified content pages correct URL false positives; sensitive, unverified, unshown and young cases stay blocked.");
