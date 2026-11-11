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
  "Alamat: dinilai phishing oleh model."
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
  decision_policy: { source: "brand_dom_phishing", reasons: ["P2"] },
  matched_rules: [{ id: "P2", status: "matched", reason: "Formulir data akun dikirim ke domain lain." }],
  brand_features: { claimed_brand: { name: "Example" },
    verified_reference_domain: "example.org", official_domain_match: false },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: true, forms: [{ relevant: true, cross_domain: true,
      destination_registrable_domain: "receiver.test" }] } });
// Order: URL class, deciding rule, brand identity, form finding.
assert.equal(impersonation.summary, "Pemeriksaan brand dan halaman menemukan indikasi phishing.");
assert.equal(impersonation.reasons[1], "Aturan P2: Formulir data akun dikirim ke domain lain.");
assert.equal(impersonation.reasons[2], "Identitas situs: halaman menampilkan Example, tetapi domain yang dibuka berbeda dari domain resminya (example.org).");
assert.ok(impersonation.reasons[3].includes("receiver.test"));
assert.ok(impersonation.reasons[3].includes('berbeda dari domain halaman (example.test)'));

{
  const result = buildAnalysisExplanation({ ...base,
    dom_features: { observed_frame_count: 1, has_password_field: true, form_cross_domain: true,
      forms: [{ relevant: true, cross_domain: true, action_origin: 'https://form-receiver.example.net',
        source_registrable_domain: 'example.test', destination_registrable_domain: 'example.net' }] } });
  const reason = result.reasons.at(-1);
  assert.ok(reason.includes('form-receiver.example.net'), 'Show the actual target hostname, not only its parent domain');
  assert.ok(reason.includes('berbeda dari domain halaman (example.test)'));
}

const unverifiedBrand = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand: { name: "Example" },
    official_domain_match: "unknown" } });
assert.equal(unverifiedBrand.reasons[1],"Identitas situs: nama brand Example ditemukan.");
assert.ok(!unverifiedBrand.reasons[1].includes("domain resmi Example"));

const oauth = buildAnalysisExplanation({ ...base,
  dom_features: { observed_frame_count: 1, navigation: {
    observed: true, destination_type: "official_provider" }, forms: [] } });
assert.ok(oauth.reasons[1].includes("penyedia identitas resmi"));
assert.ok(oauth.reasons[1].includes("tidak membuktikan situs asal aman"));
assert.equal(oauth.title, "Terindikasi phishing");

const unknown = buildAnalysisExplanation({ ...base,
  brand_features: { claimed_brand_status: "unknown" },
  dom_features: { observed_frame_count: 1, has_password_field: true,
    form_cross_domain: false, forms: [{ relevant: true, cross_domain: false }] } });
assert.equal(unknown.reasons.length, 2);
assert.ok(!unknown.reasons.join(" ").includes("merek yang digunakan"));
assert.equal(unavailable.summary, "Brand dan halaman tidak memberikan alasan khusus; keputusan mengikuti penilaian alamat.");
// A legitimate reason that overrides a phishing URL class is called a correction.
const corrected = buildAnalysisExplanation({ ...base, verdict: "SAFE",
  decision_policy: { source: "brand_dom_legitimate", reasons: ["L1"] },
  matched_rules: [{ id: "L1", status: "matched", reason: "Domain resmi brand yang ditampilkan." }] });
assert.match(corrected.summary, /mengoreksi penilaian alamat menjadi legitimate/);
assert.equal(corrected.reasons[1], "Aturan L1: Domain resmi brand yang ditampilkan.");

console.log("Explanation OK: unavailable evidence, verified domain, impersonation, OAuth");

const noForms = buildAnalysisExplanation({...base,
  brand_features:{claimed_brand:{name:"Liquipedia"},official_domain_match:true,
    verification_basis:"api_domain_match",verified_reference_domain:"liquipedia.net"},
  dom_features:{observed_frame_count:1,forms:[],has_password_field:false,
    has_sensitive_input:false,form_cross_domain:false,unresolved_checks:[]}});
assert.equal(noForms.reasons[1],"Identitas situs: domain cocok dengan brand Liquipedia.");
assert.equal(noForms.reasons.length,2);
assert.ok(!noForms.reasons.some(reason=>reason.startsWith('Formulir:')));
assert.ok(!noForms.reasons.join(" ").includes("API"));
const ordinaryForm = buildAnalysisExplanation({...base,
  dom_features:{observed_frame_count:1,forms:[{relevant:false}],has_password_field:false,
    has_sensitive_input:false,form_cross_domain:false,unresolved_checks:[]}});
assert.deepEqual(ordinaryForm.reasons,["Alamat: dinilai phishing oleh model."]);
const incompleteForms = buildAnalysisExplanation({...base,
  dom_features:{observed_frame_count:1,forms:[],has_password_field:"unknown",
    has_sensitive_input:"unknown",form_cross_domain:"unknown",unresolved_checks:["inaccessible_iframe"]}});
assert.deepEqual(incompleteForms.reasons,["Alamat: dinilai phishing oleh model."]);
assert.equal(incompleteForms.limitation,"Sebagian isi halaman tidak dapat diperiksa.");

const hiddenFields = { observed_frame_count:1,has_password_field:true,has_sensitive_input:false,
  password_fields:[{visible:false,form_index:-1},{visible:false,form_index:-1}],
  sensitive_fields:[],forms:[],form_cross_domain:false,unresolved_checks:[] };
const ambiguousHome=buildAnalysisExplanation({...base,
  brand_features:{claimed_brand_status:'ambiguous',claimed_brand:null},dom_features:hiddenFields});
assert.deepEqual(ambiguousHome.reasons,["Alamat: dinilai phishing oleh model."]);
const openedModal=buildAnalysisExplanation({...base,
  brand_features:{claimed_brand_status:'ambiguous',claimed_brand:null},
  dom_features:{...hiddenFields,password_fields:[{visible:true,form_index:-1},{visible:false,form_index:-1}]}});
assert.equal(openedModal.reasons.length,2);
assert.equal(openedModal.reasons[1],"Formulir: ditemukan kolom data akun; tujuan pengirimannya belum teramati.");
const hiddenForm=buildAnalysisExplanation({...base,dom_features:{...hiddenFields,
  forms:[{relevant:true,cross_domain:true,action_origin:'https://receiver.example.net',visible:false}]}});
assert.deepEqual(hiddenForm.reasons,["Alamat: dinilai phishing oleh model."]);
const unavailableSafe=buildAnalysisExplanation({...base,verdict:'SAFE',
  model_result:{model_family:'XGBoost',verdict:'SAFE'}});
assert.deepEqual(unavailableSafe.reasons,["Alamat: dinilai legitimate oleh model."]);
console.log('Optional explanations: URL-only, unknown/ambiguous brand, hidden modal, opened login and positive form findings passed.');
