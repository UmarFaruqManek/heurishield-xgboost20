/*
 * Parameter utama yang boleh dibaca rule: 9 parameter brand, 8 parameter DOM,
 * dan 2 informasi URL pendukung. Metadata lain (kandidat, detail form, snapshot)
 * hanya menjelaskan asal nilai parameter dan tidak diteruskan ke rule.
 */
export const UNKNOWN = "unknown";

export const BRAND_PARAMETERS = Object.freeze([
  "brand_in_title", "brand_in_heading", "brand_in_logo", "claimed_brand", "claimed_brand_status",
  "verified_reference_domain", "host_brand_claim", "official_domain_match", "brand_domain_mismatch"
]);
export const DOM_PARAMETERS = Object.freeze([
  "has_password_field", "has_sensitive_input", "form_cross_domain", "login_button_detected",
  "login_redirect_detected", "has_download_link", "download_file_extensions", "download_target_cross_domain"
]);
export const SUPPORTING_URL_PARAMETERS = Object.freeze(["domain_age_days", "url_file_extension"]);

const known = value => value === undefined || value === null ? UNKNOWN : value;

// urlFileExtension: an extension string, null when the URL path has no file
// extension (definitely no file in the URL), or "unknown"/omitted when unread.
export function collectParameters({ brand = null, dom = null, domainAgeDays = null, urlFileExtension = UNKNOWN } = {}) {
  // An incomplete download scan cannot prove that no executable is offered,
  // so the observed list is marked with an "unknown" entry.
  const scanIncomplete = (dom?.download_unresolved_checks || []).includes("download_scan_incomplete");
  const extensions = !Array.isArray(dom?.download_file_extensions) ? UNKNOWN
    : scanIncomplete ? [...dom.download_file_extensions, UNKNOWN] : [...dom.download_file_extensions];
  return Object.freeze({
    brand_in_title: known(brand?.brand_in_title),
    brand_in_heading: known(brand?.brand_in_heading),
    brand_in_logo: known(brand?.brand_in_logo),
    claimed_brand: brand?.claimed_brand?.name || null,
    claimed_brand_status: known(brand?.claimed_brand_status),
    verified_reference_domain: brand?.verified_reference_domain || null,
    host_brand_claim: known(brand?.host_brand_claim),
    official_domain_match: known(brand?.official_domain_match),
    brand_domain_mismatch: known(brand?.brand_domain_mismatch),
    has_password_field: known(dom?.has_password_field),
    has_sensitive_input: known(dom?.has_sensitive_input),
    form_cross_domain: known(dom?.form_cross_domain),
    login_button_detected: known(dom?.login_button_detected),
    login_redirect_detected: known(dom?.login_redirect_detected),
    has_download_link: known(dom?.has_download_link),
    download_file_extensions: extensions,
    download_target_cross_domain: known(dom?.download_target_cross_domain),
    domain_age_days: Number.isFinite(domainAgeDays) && domainAgeDays >= 0 ? domainAgeDays : null,
    url_file_extension: urlFileExtension === undefined || urlFileExtension === "" ? UNKNOWN : urlFileExtension
  });
}
