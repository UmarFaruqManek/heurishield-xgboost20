/*
 * Rule heuristik brand/DOM. Setiap rule adalah konjungsi logis atas parameter
 * utama (lihat parameters.js) dengan logika tiga nilai: true, false, unknown.
 * Tidak ada bobot, skor, atau probabilitas; kelas URL tidak dibaca di sini.
 *
 * Status rule: matched (kondisi terpenuhi), not_matched (terbukti tidak
 * terpenuhi), undetermined (informasi belum cukup). Hanya matched yang
 * dipakai decision policy.
 */
import { EXECUTABLE_FILE_EXTENSIONS } from "../url/download-file-extension.js";
import { UNKNOWN } from "./parameters.js";

// Batas umur domain adalah konfigurasi heuristik, bukan hasil pelatihan model.
export const NEW_DOMAIN_MAX_DAYS = 365;

const and = (...values) => values.includes(false) ? false : values.every(v => v === true) ? true : UNKNOWN;
const or = (...values) => values.includes(true) ? true : values.every(v => v === false) ? false : UNKNOWN;
const not = value => value === UNKNOWN ? UNKNOWN : !value;
const is = (value, expected) => value === UNKNOWN || value === null ? UNKNOWN : value === expected;

// "Not observed" is definite: unknown counts as not observed (used only with a verified official site).
const notObserved = value => value !== true;
const credentialRequested = p => or(is(p.has_password_field, true), is(p.has_sensitive_input, true));
const pageShowsBrand = p => or(is(p.brand_in_title, true), is(p.brand_in_heading, true), is(p.brand_in_logo, true));
const domainAgeAtMost = (p, days) => p.domain_age_days === null ? UNKNOWN : p.domain_age_days <= days;
const officialSite = p => and(p.claimed_brand_status === "identified", is(p.official_domain_match, true), pageShowsBrand(p));

function executableOffered(p) {
  const pageList = p.download_file_extensions;
  const page = pageList === UNKNOWN ? UNKNOWN
    : pageList.some(ext => EXECUTABLE_FILE_EXTENSIONS.has(ext)) ? true
      : pageList.includes(UNKNOWN) ? UNKNOWN : false;
  const url = p.url_file_extension === UNKNOWN ? UNKNOWN : EXECUTABLE_FILE_EXTENSIONS.has(p.url_file_extension);
  return or(page, url);
}

export const RULES = Object.freeze([
  // brand_domain_mismatch already requires the brand name on the hostname of a
  // domain that is not the brand's official domain (see brand-evidence.js).
  { id: "P1", decision: "phishing", name: "hostname_brand_impersonation",
    reason: "Alamat memuat nama brand yang domain resminya berbeda.",
    evaluate: p => is(p.brand_domain_mismatch, true) },
  { id: "P2", decision: "phishing", name: "credential_form_to_other_domain",
    reason: "Formulir data akun dikirim ke domain lain, dan domain halaman bukan domain resmi brand yang ditampilkan.",
    evaluate: p => and(credentialRequested(p), is(p.form_cross_domain, true), is(p.official_domain_match, false)) },
  { id: "P3", decision: "phishing", name: "new_domain_credential_brand_conflict",
    reason: `Domain berumur paling lama ${NEW_DOMAIN_MAX_DAYS} hari meminta data akun atas nama brand lain.`,
    evaluate: p => and(domainAgeAtMost(p, NEW_DOMAIN_MAX_DAYS), is(p.official_domain_match, false), credentialRequested(p)) },
  { id: "P4", decision: "phishing", name: "new_domain_download_brand_conflict",
    reason: `Domain berumur paling lama ${NEW_DOMAIN_MAX_DAYS} hari menawarkan file yang dapat dijalankan (atau arsip pembawanya) atas nama brand lain.`,
    evaluate: p => and(domainAgeAtMost(p, NEW_DOMAIN_MAX_DAYS), is(p.official_domain_match, false), executableOffered(p)) },
  { id: "L1", decision: "legitimate", name: "verified_official_site",
    reason: "Domain resmi brand yang ditampilkan, tanpa permintaan data akun yang teramati.",
    evaluate: p => and(officialSite(p), notObserved(p.has_password_field), notObserved(p.has_sensitive_input),
      not(domainAgeAtMost(p, NEW_DOMAIN_MAX_DAYS))) },
  { id: "L2", decision: "legitimate", name: "verified_official_login",
    reason: "Login pada domain resmi brand yang ditampilkan, dengan formulir tetap pada domain tersebut.",
    evaluate: p => and(officialSite(p), is(p.has_password_field, true), is(p.form_cross_domain, false),
      not(domainAgeAtMost(p, NEW_DOMAIN_MAX_DAYS))) }
]);

const status = value => value === true ? "matched" : value === false ? "not_matched" : "undetermined";

export function evaluateRules(parameters) {
  return RULES.map(rule => ({ id: rule.id, decision: rule.decision, name: rule.name,
    reason: rule.reason, status: status(rule.evaluate(parameters)) }));
}
