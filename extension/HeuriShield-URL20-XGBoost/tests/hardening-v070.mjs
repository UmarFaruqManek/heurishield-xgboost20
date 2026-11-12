import assert from "node:assert/strict";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { isPathHostedUserContent } from "../src/analyzer/brand/shared-hosting.js";
import { EXECUTABLE_FILE_EXTENSIONS } from "../src/analyzer/url/download-file-extension.js";
import { judge } from "./pipeline.js";

const page = (origin, title, heading, extra = {}) => ({ page_origin: origin, title, headings: [{ text: heading }],
  logos: [], controls: [], password_fields: [], sensitive_fields: [], forms: [], inaccessible_frames: 0,
  document_ready_state: "complete", ...extra });
const none = async () => ({ lookup_success: true, candidates: [] });

// A. Self-reference: a bare directory entry for the visited domain is not ownership.
// Spotify is NOT in the local registry, so only the self-reference guard applies.
const spotifySearch = domain => async () => ({ lookup_success: true, found: true,
  candidates: [{ name: "Spotify", domain, verified: false, source: "fixture" }] });
const spotifyName = async token => ({ lookup_success: true, candidates: token === "spotify"
  ? [{ name: "Spotify", domain: "spotify.com", verified: false }] : [] });
// Same label, other suffix: may be a country domain, so ownership is unknown (no L1).
const suffix = await analyzeBrandEvidence(page("https://spotify.com.ml", "Spotify - Web Player", "Spotify"),
  "https://spotify.com.ml/", { domainSearch: spotifySearch("spotify.com.ml"), lookup: spotifyName });
assert.equal(suffix.official_domain_match, "unknown");
assert.equal(suffix.self_reference_conflict, "spotify.com");
assert.equal(judge({ urlClass: "DANGEROUS", dom: analyzeDomEvidence([page("https://spotify.com.ml", "x", "x")]),
  brand: suffix, domainAgeDays: 4000 }).verdict, "DANGEROUS");
// Label imitating the name (spotlfy vs spotify): the name points elsewhere, so not official (P1).
const imitation = await analyzeBrandEvidence(page("https://spotlfy.com", "Spotify - Web Player", "Spotify"),
  "https://spotlfy.com/", { domainSearch: spotifySearch("spotlfy.com"), lookup: spotifyName });
assert.equal(imitation.official_domain_match, false);
assert.equal(imitation.verified_reference_domain, "spotify.com");
assert.equal(imitation.host_brand_claim, "lookalike");
assert.equal(imitation.brand_domain_mismatch, true);
assert.deepEqual(judge({ urlClass: "SAFE", dom: analyzeDomEvidence([page("https://spotlfy.com", "x", "x")]),
  brand: imitation }).matched, ["P1"]);
// Imitation whose canonical name cannot be looked up stays unknown, never official.
const unresolved = await analyzeBrandEvidence(page("https://spotlfy.com", "Spotify - Web Player", "Spotify"),
  "https://spotlfy.com/", { domainSearch: spotifySearch("spotlfy.com"), lookup: none });
assert.equal(unresolved.official_domain_match, "unknown");
// The real domain is unaffected.
const real = await analyzeBrandEvidence(page("https://open.spotify.com", "Spotify - Web Player", "Spotify"),
  "https://open.spotify.com/", { domainSearch: spotifySearch("spotify.com"), lookup: spotifyName });
assert.equal(real.official_domain_match, true);

// A. User content on a platform path cannot borrow the platform's identity.
assert.ok(isPathHostedUserContent("https://docs.google.com/forms/d/e/abc/viewform"));
assert.ok(isPathHostedUserContent("https://sharemyhtml.com/p/ZCGu1pkn73"));
assert.ok(!isPathHostedUserContent("https://docs.google.com/"));
assert.ok(!isPathHostedUserContent("https://www.google.com/search?q=x"));
const googleLookup = async token => ({ lookup_success: true, candidates: token === "google"
  ? [{ name: "Google", domain: "google.com", verified: true }] : [] });
const form = await analyzeBrandEvidence(page("https://docs.google.com", "Google Forms", "Google"),
  "https://docs.google.com/forms/d/e/abc/viewform", { lookup: googleLookup });
assert.equal(form.official_domain_match, "unknown");
assert.equal(form.self_reference_conflict, "path_hosted_user_content");
assert.ok(!judge({ urlClass: "DANGEROUS", dom: analyzeDomEvidence([page("https://docs.google.com", "x", "x")]),
  brand: form, domainAgeDays: 9000 }).matched.includes("L1"));

// C. Local brand registry: lookalike host recognized without any API result.
const shopee = await analyzeBrandEvidence(page("https://shoopee.co.id", "Shopee Indonesia", "Shopee"),
  "https://shoopee.co.id/", { lookup: none });
assert.equal(shopee.claimed_brand.name, "Shopee");
assert.equal(shopee.official_domain_match, false);
assert.equal(shopee.host_brand_claim, "lookalike");
assert.deepEqual(judge({ urlClass: "SAFE", dom: analyzeDomEvidence([page("https://shoopee.co.id", "x", "x")]),
  brand: shopee }).matched, ["P1"]);
// A brand is official on any of its registered domains.
const klikbca = await analyzeBrandEvidence(page("https://ibank.klikbca.com", "BCA - Internet Banking", "BCA"),
  "https://ibank.klikbca.com/", { lookup: none });
assert.equal(klikbca.official_domain_match, true);
const bca = await analyzeBrandEvidence(page("https://www.bca.co.id", "BCA - Beranda", "BCA"),
  "https://www.bca.co.id/", { lookup: none });
assert.equal(bca.official_domain_match, true);

// D. Credentials with a known script data-collection endpoint go to another domain.
const kit = page("https://secure-update.example", "Login", "Login", {
  password_fields: [{ form_index: -1, visible: true }], credential_exfil_endpoints: ["api.telegram.org"] });
const kitDom = analyzeDomEvidence([kit]);
assert.equal(kitDom.form_cross_domain, true);
assert.deepEqual(kitDom.credential_exfil_endpoints, ["api.telegram.org"]);
// Without credentials the endpoint alone says nothing about account data.
const blog = analyzeDomEvidence([page("https://blog.example", "Blog", "Blog", { credential_exfil_endpoints: ["api.telegram.org"] })]);
assert.equal(blog.form_cross_domain, false);
// Without the endpoint, scripted credentials keep an unknown destination.
assert.equal(analyzeDomEvidence([{ ...kit, credential_exfil_endpoints: [] }]).form_cross_domain, "unknown");

// G. Archive, disk-image and shortcut carriers count as runnable downloads.
for (const ext of ["zip", "rar", "7z", "iso", "img", "lnk", "hta", "js"]) assert.ok(EXECUTABLE_FILE_EXTENSIONS.has(ext), ext);
for (const ext of ["pdf", "docx", "png"]) assert.ok(!EXECUTABLE_FILE_EXTENSIONS.has(ext), ext);
console.log("Hardening v0.7: self-reference, path hosting, brand registry, script exfiltration, archive downloads OK");
