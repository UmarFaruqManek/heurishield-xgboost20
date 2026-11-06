import assert from "node:assert/strict";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";

const base = {
  url: "https://example.test/login",
  final_url: "https://example.test/login",
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: { source: "url_model" },
  verdict: "DANGEROUS"
};

const unavailable = buildAnalysisExplanation(base);
assert.deepEqual(unavailable.reasons, [
  "Alamat: dinilai phishing oleh model.",
  "Identitas situs: belum dapat diperiksa.",
  "Formulir: halaman belum dapat diperiksa."
]);
assert.ok(!unavailable.reasons.join(" ").includes("domain resmi"));

const official = buildAnalysisExplanation({ ...base, verdict: "SAFE",
  model_result: { ...base.model_result, verdict: "SAFE" },
  brand_features: { claimed_brand: { name: "Example" },
    verified_reference_domain: "example.test", official_domain_match: true },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.ok(official.reasons[1].includes("domain cocok dengan brand Example"));
assert.ok(official.reasons[2].includes("domain halaman ini"));

const impersonation = buildAnalysisExplanation({ ...base, verdict: "DANGEROUS",
  model_result: { ...base.model_result, verdict: "SAFE" },
  decision_policy: { source: "confirmed_credential_impersonation" },
  brand_features: { claimed_brand: { name: "Example" },
    verified_reference_domain: "example.org", official_domain_match: false },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: true, forms: [{ relevant: true, cross_domain: true,
      destination_verification: false, destination_registrable_domain: "receiver.test" }] } });
assert.ok(impersonation.summary.includes("mengubah penilaian alamat menjadi phishing"));
assert.ok(impersonation.reasons[1].includes("example.org"));
assert.ok(impersonation.reasons[2].includes("receiver.test"));

const unverifiedBrand = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand: { name: "Example" },
    official_domain_match: "unknown" } });
assert.ok(unverifiedBrand.reasons[1].includes("belum dapat diverifikasi"));
assert.ok(!unverifiedBrand.reasons[1].includes("domain resmi Example"));

const oauth = buildAnalysisExplanation({ ...base,
  dom_features: { observed_frame_count: 1, navigation: {
    observed: true, destination_type: "official_provider" }, forms: [] } });
assert.ok(oauth.reasons[2].includes("penyedia identitas resmi"));
assert.ok(oauth.reasons[2].includes("tidak membuktikan situs asal aman"));
assert.equal(oauth.title, "Terindikasi phishing");

const unknown = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand_status: "unknown" },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.equal(unknown.reasons.length, 2);
assert.ok(!unknown.reasons.join(" ").includes("merek yang digunakan"));
const localReview = buildAnalysisExplanation({ ...base, verdict: "DANGEROUS",
  decision_policy: { source: "url_model", review_candidate: true,
    review_reason: "local_login_unverified" },
  brand_features: { claimed_brand_status: "unknown" },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.equal(localReview.title, "Terindikasi phishing");
assert.equal(localReview.reasons.length, 2);
assert.ok(localReview.limitation.includes("identitas situs belum terverifikasi"));

console.log("Explanation OK: unavailable evidence, verified domain, impersonation, OAuth");

const noForms = buildAnalysisExplanation({...base,
  brand_features:{claimed_brand:{name:"Liquipedia"},official_domain_match:true,
    verification_basis:"api_domain_match",verified_reference_domain:"liquipedia.net"},
  dom_features:{observed_frame_count:1,forms:[],has_password_field:false,
    has_sensitive_input:false,form_cross_domain:false,unresolved_checks:[]}});
assert.equal(noForms.reasons[1],"Identitas situs: domain cocok dengan brand Liquipedia.");
assert.equal(noForms.reasons[2],"Formulir: tidak ditemukan pada halaman yang diperiksa.");
assert.ok(!noForms.reasons.join(" ").includes("API"));
const ordinaryForm = buildAnalysisExplanation({...base,
  dom_features:{observed_frame_count:1,forms:[{relevant:false}],has_password_field:false,
    has_sensitive_input:false,form_cross_domain:false,unresolved_checks:[]}});
assert.equal(ordinaryForm.reasons.at(-1),"Formulir: tidak ditemukan formulir yang meminta data akun.");
const incompleteForms = buildAnalysisExplanation({...base,
  dom_features:{observed_frame_count:1,forms:[],has_password_field:"unknown",
    has_sensitive_input:"unknown",form_cross_domain:"unknown",unresolved_checks:["inaccessible_iframe"]}});
assert.ok(incompleteForms.reasons.at(-1).includes("belum dapat diperiksa"));
