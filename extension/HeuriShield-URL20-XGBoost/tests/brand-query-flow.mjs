import assert from "node:assert/strict";
import { brandHostQueries, analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { judge } from "./pipeline.js";

const catalog = {
  google: [{ name: "Google", domain: "google.com", verified: true }],
  oogle: [{ name: "Google", domain: "google.com", verified: true }],
  example: [{ name: "Example", domain: "example.com", verified: true }],
  facebook: [{ name: "Facebook", domain: "facebook.com", verified: true }],
  dicoding: [{ name: "Dicoding", domain: "dicoding.com", verified: true }],
  uho: [{ name: "UHO", domain: "uho.ac.id", verified: true }],
  bca: [{ name: "BCA", domain: "bca.co.id", verified: true }]
};
const lookup = async token => ({ lookup_success: true, candidates: catalog[token] || [] });
const page = (title, heading, extras = {}) => ({ page_origin: "https://google-login.example.test", title,
  headings: [{ text: heading, in_main: true }], logos: [], controls: [{ type: "native_login" }],
  forms: [], password_fields: [{ form_index: 0 }], sensitive_fields: [], inaccessible_frames: 0, ...extras });

assert.deepEqual(brandHostQueries("https://google-login.example.test"), ["google", "example"]);
assert.deepEqual(brandHostQueries("https://google.com.example.test"), ["google", "example"]);
assert.deepEqual(brandHostQueries("https://facebook-247-support.blogspot.com"), ["facebook"]);
assert.deepEqual(brandHostQueries("https://app.dicoding.com"), ["dicoding"]);
assert.deepEqual(brandHostQueries("https://gemini.google.com"), ["gemini", "google"]);
assert.deepEqual(brandHostQueries("https://kkn.uho.ac.id"), ["kkn", "uho"]);
assert.deepEqual(brandHostQueries("https://bca.bank.com"), ["bca", "bank"]);
const generic = await analyzeBrandEvidence(page("Sign in", "Sign in"), "https://google-login.example.test", { lookup });
assert.deepEqual(generic.searched_tokens.map(x => x.token), ["google", "example"]);
assert.equal(generic.claimed_brand, null); // Hostname alone is a candidate, not proof of page identity.
assert.equal(generic.hostname_brand_candidates[0].name, "Google");
assert.deepEqual(generic.mentioned_brands, []);
const impersonation = await analyzeBrandEvidence(page("Google Login", "Sign in to Google"), "https://google-login.example.test", { lookup });
assert.equal(impersonation.claimed_brand.name, "Google");
assert.equal(impersonation.official_domain_match, false);
assert.equal("authorized_domain_match" in impersonation, false);
assert.equal(impersonation.brand_domain_mismatch, true);
const dom = analyzeDomEvidence([page("Google Login", "Sign in to Google")]);
assert.deepEqual(judge({ urlClass: "SAFE", dom, brand: impersonation }).matched, ["P1"]);
const typo = await analyzeBrandEvidence(page("Google Login", "Sign in to Google"), "https://oogle-login.example.test", { lookup });
assert.equal(typo.claimed_brand.name, "Google");
assert.equal(typo.candidates.find(c => c.name === "Google").approximate, true);
const oauth = await analyzeBrandEvidence(page("Sign in with Google", "Continue with Google", {
  controls: [{ type: "oauth_login", provider: "Google" }], password_fields: []
}), "https://shop.example.test", { lookup });
assert.equal(oauth.claimed_brand, null);
const bcaUrl = "https://bca.bank.com/login";
const bcaPage = page("Login BCA", "Masuk ke BCA", { page_origin: "https://bca.bank.com" });
const bcaBrand = await analyzeBrandEvidence(bcaPage, bcaUrl, { lookup });
const bcaDom = analyzeDomEvidence([bcaPage]);
assert.equal(bcaBrand.claimed_brand?.name, "BCA");
assert.equal(bcaBrand.official_domain_match, false);
assert.equal(bcaBrand.host_brand_claim, "subdomain_exact");
assert.equal(bcaBrand.brand_domain_mismatch, true);
assert.equal(judge({ urlClass: "SAFE", dom: bcaDom, brand: bcaBrand }).verdict, "DANGEROUS");
const bcaMention = page("BCA", "Informasi BCA", { page_origin: "https://bca.bank.com",
  password_fields: [], controls: [] });
const bcaMentionBrand = await analyzeBrandEvidence(bcaMention, bcaUrl, { lookup });
// v0.7: the page claims BCA (title + heading) on a hostname carrying "bca" outside
// bca.co.id. That is brand impersonation on the address even without a login form.
assert.equal(bcaMentionBrand.brand_domain_mismatch, true);
assert.equal(judge({ urlClass: "SAFE", dom: analyzeDomEvidence([bcaMention]), brand: bcaMentionBrand }).verdict, "DANGEROUS");
const bcaUnverified = await analyzeBrandEvidence(bcaPage, bcaUrl, { lookup: async token => ({
  lookup_success: true, candidates: token === "bca" ? [{ name: "BCA", domain: "bca.co.id",
    verified: false }] : [] }) });
assert.equal(bcaUnverified.official_domain_match, "unknown");
assert.equal(bcaUnverified.candidate_reference_domain, "bca.co.id");
assert.equal(bcaUnverified.brand_domain_mismatch, "unknown");
assert.equal(judge({ urlClass: "SAFE", dom: bcaDom, brand: bcaUnverified }).verdict, "SAFE");
const geminiUrl = "https://gemini.google.com/app";
const geminiPage = page("Gemini", "Ask Gemini", { page_origin: "https://gemini.google.com",
  password_fields: [], controls: [] });
const geminiBrand = await analyzeBrandEvidence(geminiPage, geminiUrl, { lookup });
assert.equal(geminiBrand.official_domain_match, true);
assert.equal(judge({ urlClass: "SAFE", dom: analyzeDomEvidence([geminiPage]), brand: geminiBrand }).verdict, "SAFE");
const lookupUnverified = async token => ({ lookup_success: true, candidates:
  token === "roblox" ? [{ name: "Roblox", domain: "roblox.com", verified: false }] : [] });
const verifyRoblox = async () => ({ lookup_success: true,
  candidates: [{ name: "Roblox", domain: "roblox.com", verified: true }] });
const profile = (origin, title = "Player - Roblox") => page(title, "Roblox profile", {
  page_origin: origin, password_fields: [], controls: [], forms: [] });
const official = await analyzeBrandEvidence(profile("https://www.roblox.com"), "https://www.roblox.com", {
  lookup: lookupUnverified, verifyLookup: verifyRoblox });
assert.equal(official.official_domain_match, true);
assert.equal(official.candidate_domain_match, true);
assert.equal(official.domain_matched_candidate.domain, "roblox.com");
assert.equal(official.brand_domain_mismatch, false);
const community = await analyzeBrandEvidence(page("Roblox community guide", "Roblox community", {
  page_origin: "https://fans.example.test", password_fields: [], controls: [] }),
  "https://fans.example.test", { lookup: lookupUnverified, verifyLookup: verifyRoblox });
// A fan page that only mentions Roblox makes no identity claim, so no conflict.
assert.equal(community.claimed_brand, null);
assert.notEqual(community.brand_domain_mismatch, true);
const clone = await analyzeBrandEvidence(profile("https://www.roblox.com.et"), "https://www.roblox.com.et", {
  lookup: lookupUnverified, verifyLookup: verifyRoblox });
assert.equal(clone.official_domain_match, false);
assert.equal(clone.brand_domain_mismatch, true);
assert.equal(judge({ urlClass: "SAFE", dom: analyzeDomEvidence([profile("https://www.roblox.com.et")]), brand: clone }).verdict, "DANGEROUS");
const unverified = await analyzeBrandEvidence(profile("https://www.roblox.com.et"), "https://www.roblox.com.et", {
  lookup: lookupUnverified, verifyLookup: async () => ({ lookup_success: false, candidates: [] }) });
// The hostname embeds the full reference domain (www.roblox.com.et), which is
// itself the claim, so the unverified directory reference is still compared.
assert.equal(unverified.official_domain_match, false);
assert.equal(unverified.candidate_domain_match, false);
assert.equal(unverified.reference_status, "directory_candidate");
assert.equal(unverified.brand_domain_mismatch, true);
const unverifiedOwnDomain = await analyzeBrandEvidence(page("Sign in", "Sign in", {
  page_origin: "https://app.dicoding.com", password_fields: [] }),
"https://app.dicoding.com", { lookup: async token => ({ lookup_success: true,
  candidates: token === "dicoding" ? [{ name: "Dicoding", domain: "dicoding.com",
    verified: false, source: "clearbit" }] : [] }) });
assert.equal(unverifiedOwnDomain.candidate_domain_match, true);
assert.equal(unverifiedOwnDomain.domain_matched_candidate.name, "Dicoding");
assert.equal(unverifiedOwnDomain.official_domain_match, true);
assert.equal(unverifiedOwnDomain.claimed_brand.name, "Dicoding");
const dicodingLoginUrl = "https://app.dicoding.com/login";
const dicodingLoginPage = page("Login Dicoding", "Masuk ke Dicoding", {
  page_origin: "https://app.dicoding.com",
  forms: [{ relevant: true, action_known: true, same_origin: true,
    action_origin: "https://app.dicoding.com" }] });
const dicodingLoginBrand = await analyzeBrandEvidence(dicodingLoginPage,
  dicodingLoginUrl, { lookup });
const dicodingLoginDom = analyzeDomEvidence([dicodingLoginPage]);
assert.equal(dicodingLoginBrand.official_domain_match, true);
const dicodingLogin = judge({ urlClass: "DANGEROUS", dom: dicodingLoginDom, brand: dicodingLoginBrand,
  domainAgeDays: 1752 });
assert.deepEqual(dicodingLogin.matched, ["L2"]);
assert.equal(dicodingLogin.decision.source, "brand_dom_legitimate");
const typoProfile = await analyzeBrandEvidence(profile("https://r.oblox.com.et"), "https://r.oblox.com.et", {
  lookup: async token => ({ lookup_success: true, candidates: token === "oblox" ?
    [{ name: "Roblox", domain: "roblox.com", verified: false }] : [] }), verifyLookup: verifyRoblox });
assert.equal(typoProfile.host_brand_claim, "lookalike");
assert.equal(typoProfile.brand_domain_mismatch, true);
console.log("Brand query flow OK: PSL, host tokens, claim context, mismatch, typo, OAuth");
