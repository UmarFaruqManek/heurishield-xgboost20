import assert from 'node:assert/strict';
import { evaluateRules, RULES, NEW_DOMAIN_MAX_DAYS } from '../src/analyzer/rules/heuristic-rules.js';
import { BRAND_PARAMETERS, DOM_PARAMETERS, SUPPORTING_URL_PARAMETERS, collectParameters } from '../src/analyzer/rules/parameters.js';

const ALLOWED = new Set([...BRAND_PARAMETERS, ...DOM_PARAMETERS, ...SUPPORTING_URL_PARAMETERS]);
assert.equal(BRAND_PARAMETERS.length, 9);
assert.equal(DOM_PARAMETERS.length, 8);
assert.equal(SUPPORTING_URL_PARAMETERS.length, 2);
assert.equal(NEW_DOMAIN_MAX_DAYS, 365);

// Baseline: an old, verified official page with no credentials or downloads.
const base = { brand_in_title: true, brand_in_heading: false, brand_in_logo: false, claimed_brand: 'Example',
  claimed_brand_status: 'identified', verified_reference_domain: 'example.com', host_brand_claim: 'exact',
  official_domain_match: true, brand_domain_mismatch: false, has_password_field: false, has_sensitive_input: false,
  form_cross_domain: false, login_button_detected: false, login_redirect_detected: 'unknown',
  has_download_link: false, download_file_extensions: [], download_target_cross_domain: false,
  domain_age_days: 4000, url_file_extension: null };
// Rules may read only the fixed parameters; anything else throws.
const guarded = values => new Proxy(values, { get(target, key) {
  if (!ALLOWED.has(key)) throw new Error(`Rule read non-parameter ${String(key)}`);
  return target[key];
} });
const run = changes => Object.fromEntries(evaluateRules(guarded({ ...base, ...changes })).map(r => [r.id, r.status]));
const matched = changes => Object.entries(run(changes)).filter(([, s]) => s === 'matched').map(([id]) => id);

assert.deepEqual(matched({}), ['L1']);
// P1: brand on the hostname of a non-official domain.
assert.deepEqual(matched({ official_domain_match: false, brand_domain_mismatch: true }), ['P1']);
assert.equal(run({ brand_domain_mismatch: 'unknown', official_domain_match: 'unknown' }).P1, 'undetermined');
// P2: credentials posted to another domain while the brand's official domain differs.
const credentialElsewhere = { official_domain_match: false, has_password_field: true, form_cross_domain: true };
assert.deepEqual(matched(credentialElsewhere), ['P2']);
assert.equal(run({ ...credentialElsewhere, official_domain_match: 'unknown' }).P2, 'undetermined');
assert.equal(run({ ...credentialElsewhere, form_cross_domain: false }).P2, 'not_matched');
// P3: young domain + other brand + credentials.
assert.deepEqual(matched({ official_domain_match: false, has_sensitive_input: true, domain_age_days: 30 }), ['P3']);
assert.equal(run({ official_domain_match: false, has_sensitive_input: true, domain_age_days: 366 }).P3, 'not_matched');
assert.equal(run({ official_domain_match: false, has_sensitive_input: true, domain_age_days: null }).P3, 'undetermined');
assert.equal(run({ official_domain_match: false, has_sensitive_input: true, domain_age_days: 365 }).P3, 'matched');
// P4: young domain + other brand + executable from the page or the URL.
assert.deepEqual(matched({ official_domain_match: false, download_file_extensions: ['exe'], domain_age_days: 10 }), ['P4']);
assert.deepEqual(matched({ official_domain_match: false, url_file_extension: 'apk', domain_age_days: 10 }), ['P4']);
assert.equal(run({ official_domain_match: false, download_file_extensions: ['pdf'], domain_age_days: 10 }).P4, 'not_matched');
assert.equal(run({ official_domain_match: false, download_file_extensions: ['pdf', 'unknown'], domain_age_days: 10 }).P4, 'undetermined');
// L1: official + brand shown + no observed credentials + older than 365 days.
assert.equal(run({ has_password_field: 'unknown' }).L1, 'matched', 'unknown credentials are not observed');
assert.equal(run({ has_password_field: true }).L1, 'not_matched');
assert.equal(run({ brand_in_title: false }).L1, 'not_matched');
assert.equal(run({ brand_in_title: 'unknown' }).L1, 'undetermined');
assert.equal(run({ domain_age_days: 200 }).L1, 'not_matched');
assert.equal(run({ domain_age_days: null }).L1, 'undetermined');
assert.equal(run({ claimed_brand_status: 'unknown', official_domain_match: 'unknown' }).L1, 'not_matched');
// L2: official login whose form stays on the same domain.
assert.deepEqual(matched({ has_password_field: true }), ['L2']);
assert.equal(run({ has_password_field: true, form_cross_domain: 'unknown' }).L2, 'undetermined');
assert.equal(run({ has_password_field: true, form_cross_domain: true }).L2, 'not_matched');
// L1 and L2 never overlap: L1 needs no observed password, L2 needs one.
for (const pw of [true, false, 'unknown']) assert.ok(!(run({ has_password_field: pw }).L1 === 'matched' && run({ has_password_field: pw }).L2 === 'matched'));

// collectParameters exposes exactly the fixed parameters.
const collected = collectParameters({ brand: { claimed_brand: { name: 'X' }, extra_metadata: 1 },
  dom: { forms: [{}], download_file_extensions: ['exe'], download_unresolved_checks: ['download_scan_incomplete'] } });
assert.deepEqual(Object.keys(collected).sort(), [...ALLOWED].sort());
assert.deepEqual(collected.download_file_extensions, ['exe', 'unknown']);
assert.ok(Object.isFrozen(collected));
// A URL without a file extension (null) is definite evidence of no executable
// in the URL; only an unread value is unknown.
assert.equal(collected.url_file_extension, 'unknown');
assert.equal(collectParameters({ urlFileExtension: null }).url_file_extension, null);
const noFile = collectParameters({ brand: { claimed_brand_status: 'identified', official_domain_match: false },
  dom: { download_file_extensions: ['pdf'] }, domainAgeDays: 42, urlFileExtension: null });
assert.equal(evaluateRules(noFile).find(r => r.id === 'P4').status, 'not_matched');
assert.ok(RULES.every(rule => typeof rule.reason === 'string' && /^[PL]\d$/.test(rule.id)));
console.log('Heuristic rules: truth tables for P1-P4/L1-L2 and parameter-only access passed.');
