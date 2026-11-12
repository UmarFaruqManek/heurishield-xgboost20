import assert from "node:assert/strict";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";

// Explanations are for ordinary users: each reason is "Label: plain sentence"
// with real facts, and an optional rule code "[P1]" at the end.
const base = {
  url: "https://example.test/login",
  final_url: "https://example.test/login",
  model_result: { model_family: "XGBoost", verdict: "DANGEROUS" },
  decision_policy: { source: "url_model" },
  verdict: "DANGEROUS"
};
const login = (target = null, sameDomain = false) => ({ observed_frame_count: 1, has_password_field: true,
  password_fields: [{ visible: true, form_index: 0 }], sensitive_fields: [],
  form_cross_domain: target ? true : sameDomain ? false : "unknown",
  forms: [{ relevant: true, cross_domain: target ? true : sameDomain ? false : "unknown",
    action_origin: target ? `https://${target}` : "https://example.test" }] });

// URL model only: one honest sentence about the address pattern.
const urlOnly = buildAnalysisExplanation(base);
assert.deepEqual(urlOnly.reasons, ["Pola alamat: susunan alamat situs ini mirip dengan alamat phishing yang dikenali sistem."]);
assert.equal(urlOnly.summary, "Alamat situs ini memiliki pola yang mirip dengan alamat phishing.");
const urlOnlySafe = buildAnalysisExplanation({ ...base, verdict: "SAFE", model_result: { model_family: "XGBoost", verdict: "SAFE" } });
assert.deepEqual(urlOnlySafe.reasons, ["Pola alamat: susunan alamat situs ini tidak menunjukkan ciri phishing."]);
assert.equal(urlOnlySafe.title, "Tidak ditemukan indikasi phishing");

// P1 + P2: the deciding reasons come first, name the brand, official domain and
// data destination, and the URL line explains a disagreeing address model.
const impersonation = buildAnalysisExplanation({ ...base, url: "https://paypal.login.com/", final_url: "https://paypal.login.com/",
  model_result: { model_family: "XGBoost", verdict: "SAFE" },
  decision_policy: { source: "brand_dom_phishing", reasons: ["P1", "P2"] },
  matched_rules: [{ id: "P1" }, { id: "P2" }],
  brand_features: { claimed_brand: { name: "PayPal" }, verified_reference_domain: "paypal.com",
    official_domain_match: false, host_brand_claim: "subdomain_exact" },
  dom_features: login("receiver.example.net") });
assert.equal(impersonation.summary, "Situs ini meniru PayPal dan bukan situs resminya.");
assert.equal(impersonation.reasons[0],
  "Peniruan alamat: alamat paypal.login.com memakai nama PayPal, padahal situs resmi PayPal adalah paypal.com. [P1]");
assert.equal(impersonation.reasons[1],
  "Pengiriman data: kata sandi yang Anda ketik akan dikirim ke receiver.example.net, bukan ke situs resmi PayPal. [P2]");
assert.equal(impersonation.reasons[2], "Pola alamat: sekilas alamatnya terlihat biasa, tetapi isi halaman menunjukkan penipuan.");
assert.equal(impersonation.reasons.length, 3, "brand and form findings are not repeated");
assert.match(impersonation.action, /paypal\.com/);

// Lookalike address wording.
const lookalike = buildAnalysisExplanation({ ...base, url: "https://t0kopedia.com/", final_url: "https://t0kopedia.com/",
  decision_policy: { source: "brand_dom_phishing" }, matched_rules: [{ id: "P1" }],
  brand_features: { claimed_brand: { name: "Tokopedia" }, verified_reference_domain: "tokopedia.com",
    official_domain_match: false, host_brand_claim: "lookalike" } });
assert.equal(lookalike.reasons[0], "Peniruan alamat: alamat t0kopedia.com dibuat mirip dengan tokopedia.com, situs resmi Tokopedia. [P1]");

// P2 via a script endpoint names the service; P3 states the real domain age.
const telegram = buildAnalysisExplanation({ ...base, decision_policy: { source: "brand_dom_phishing" },
  matched_rules: [{ id: "P2" }, { id: "P3" }], rdap_features: { page_domain_age_days: 42 },
  brand_features: { claimed_brand: { name: "BCA" }, verified_reference_domain: "bca.co.id", official_domain_match: false },
  dom_features: { ...login(), sensitive_fields: [{ type: "otp", visible: true }], credential_exfil_endpoints: ["api.telegram.org"] } });
assert.match(telegram.reasons[0], /^Pengiriman data: kata sandi dan kode OTP .* Telegram \(api\.telegram\.org\)/);
assert.equal(telegram.reasons[1], "Situs baru: situs ini baru dibuat 42 hari lalu, tetapi sudah meminta kata sandi dan kode OTP atas nama BCA. [P3]");

// P4: file type, age and brand in one sentence; download action.
const download = buildAnalysisExplanation({ ...base, decision_policy: { source: "brand_dom_phishing" },
  matched_rules: [{ id: "P4" }], rdap_features: { page_domain_age_days: 150 },
  brand_features: { claimed_brand: { name: "BCA" }, verified_reference_domain: "bca.co.id", official_domain_match: false },
  dom_features: { observed_frame_count: 1, has_download_link: true, download_file_extensions: ["zip"] } });
assert.match(download.reasons[0], /^Unduhan berbahaya: situs yang baru dibuat 5 bulan lalu ini menawarkan file \.zip atas nama BCA/);
assert.match(download.summary, /file berbahaya atas nama BCA/);
assert.match(download.action, /Jangan unduh/);

// Legitimate decisions are explained too, including a corrected address score.
const official = buildAnalysisExplanation({ ...base, url: "https://www.google.com/search?q=x", final_url: "https://www.google.com/search?q=x",
  verdict: "SAFE", decision_policy: { source: "brand_dom_legitimate", reasons: ["L1"] }, matched_rules: [{ id: "L1" }],
  rdap_features: { page_domain_age_days: 10658 },
  brand_features: { claimed_brand: { name: "Google" }, verified_reference_domain: "google.com", official_domain_match: true } });
assert.equal(official.summary, "Ini situs resmi Google.");
assert.equal(official.reasons[0], "Situs resmi: www.google.com adalah situs resmi Google, sudah ada sejak 29 tahun lalu, dan tidak meminta data akun. [L1]");
assert.equal(official.reasons[1], "Pola alamat: susunan alamatnya sempat terlihat mencurigakan, tetapi pemeriksaan halaman memastikan ini situs resmi.");
const officialLogin = buildAnalysisExplanation({ ...base, verdict: "SAFE", model_result: { model_family: "XGBoost", verdict: "SAFE" },
  decision_policy: { source: "brand_dom_legitimate" }, matched_rules: [{ id: "L2" }], rdap_features: { page_domain_age_days: 1752 },
  brand_features: { claimed_brand: { name: "Example" }, official_domain_match: true }, dom_features: login(null, true) });
assert.match(officialLogin.reasons[0], /^Login resmi: ini halaman login resmi Example; .* sejak 4 tahun lalu\. \[L2\]$/);

// Supporting findings when the URL model decides.
const unknownTarget = buildAnalysisExplanation({ ...base, dom_features: login() });
assert.equal(unknownTarget.reasons[1], "Data akun: halaman meminta kata sandi; tujuan pengirimannya belum dapat dipastikan.");
const platform = buildAnalysisExplanation({ ...base, url: "https://docs.google.com/forms/d/e/x/viewform",
  final_url: "https://docs.google.com/forms/d/e/x/viewform", verdict: "SAFE", model_result: { model_family: "XGBoost", verdict: "SAFE" },
  brand_features: { claimed_brand: { name: "Google" }, official_domain_match: "unknown", self_reference_conflict: "path_hosted_user_content" } });
assert.equal(platform.reasons[1], "Platform: halaman ini dibuat oleh pengguna di layanan Google, bukan oleh Google sendiri.");
// Hidden credential fields (closed modal) and ambiguous brands add nothing.
const hidden = buildAnalysisExplanation({ ...base, brand_features: { claimed_brand_status: "ambiguous" },
  dom_features: { ...login(), password_fields: [{ visible: false, form_index: -1 }], forms: [] } });
assert.equal(hidden.reasons.length, 1);
// Limitations are stated plainly.
const limited = buildAnalysisExplanation({ ...base, rule_results: [{ id: "P3", status: "undetermined" }],
  dom_features: { observed_frame_count: 1, unresolved_checks: ["inaccessible_iframe"], forms: [] } });
assert.match(limited.limitation, /Sebagian isi halaman tidak dapat diperiksa/);
assert.match(limited.limitation, /Umur situs tidak dapat diperiksa/);
// No technical jargon in user text.
for (const e of [urlOnly, impersonation, telegram, download, official, officialLogin, platform])
  assert.ok(!/model|XGBoost|parameter|API|undetermined|Aturan /.test([e.summary, ...e.reasons, e.action].join(" ")), e.summary);
console.log("Explanation: plain-language phishing and legitimate reasons with real facts and rule codes OK");
