import assert from 'node:assert/strict';
import { analyzeDomEvidence } from '../src/analyzer/dom/dom-evidence.js';
import { analyzeBrandEvidence } from '../src/analyzer/brand/brand-evidence.js';
import { buildAnalysisExplanation } from '../src/shared/analysis-explanation.js';
import { judge } from './pipeline.js';

const lookup = async token => ({ lookup_success: true,
  candidates: token === 'bca' ? [{ name: 'BCA', domain: 'bca.co.id', verified: true }] : [] });
const exeLink = { url: 'https://files.example.net/bca-update.exe', text: 'Download', filename_hint: null };
const page = (origin, links = [exeLink], extra = {}) => ({ page_origin: origin, title: 'Login BCA',
  headings: [{ text: 'BCA Downloads' }], logos: [], password_fields: [], sensitive_fields: [], forms: [], controls: [],
  download_page: { links, truncated: false, unresolved_controls: 0 }, ...extra });

// DOM download parameters.
const hostPage = page('https://bca.bank.com');
const dom = analyzeDomEvidence([hostPage]);
assert.equal(dom.has_download_link, true);
assert.deepEqual(dom.download_file_extensions, ['exe']);
assert.equal(dom.download_target_cross_domain, true);
assert.ok(!('has_executable_download_link' in dom));
const old = analyzeDomEvidence([{ ...hostPage, download_page: undefined }]);
assert.equal(old.has_download_link, 'unknown');
assert.equal(old.download_file_extensions, null);
const noLinks = analyzeDomEvidence([page('https://bca.bank.com', [])]);
assert.equal(noLinks.has_download_link, false);
assert.deepEqual(noLinks.download_file_extensions, []);
assert.equal(analyzeDomEvidence([{ ...hostPage, download_page: { links: [], unresolved_controls: 1 } }]).has_download_link, 'unknown');
const blob = analyzeDomEvidence([page('https://bca.bank.com', [{ url: 'blob:https://bca.bank.com/id', filename_hint: 'setup.apk' }])]);
assert.deepEqual(blob.download_file_extensions, ['apk']);
assert.equal(blob.download_target_cross_domain, 'unknown');

// A: brand on the hostname of a non-official domain -> P1, whatever the file type.
const hostBrand = await analyzeBrandEvidence(hostPage, 'https://bca.bank.com/download', { lookup });
assert.equal(hostBrand.brand_domain_mismatch, true);
const impersonation = judge({ urlClass: 'SAFE', dom, brand: hostBrand, domainAgeDays: 4000 });
assert.equal(impersonation.verdict, 'DANGEROUS');
assert.deepEqual(impersonation.matched, ['P1']);

// B-D: the page shows BCA on an unrelated domain without a hostname claim.
const otherUrl = 'https://downloads.example.org/bca';
const otherPage = page('https://downloads.example.org');
const otherBrand = await analyzeBrandEvidence(otherPage, otherUrl, { lookup });
assert.equal(otherBrand.official_domain_match, false);
assert.equal(otherBrand.brand_domain_mismatch, false);
const otherDom = analyzeDomEvidence([otherPage]);
assert.equal(judge({ urlClass: 'SAFE', dom: otherDom, brand: otherBrand, domainAgeDays: 4000 }).verdict, 'SAFE',
  'An old download portal naming another brand is not phishing by itself');
const youngExe = judge({ urlClass: 'SAFE', dom: otherDom, brand: otherBrand, domainAgeDays: 30 });
assert.deepEqual(youngExe.matched, ['P4']);
assert.equal(youngExe.verdict, 'DANGEROUS');
const pdfDom = analyzeDomEvidence([page('https://downloads.example.org', [{ url: 'https://files.example.net/manual.pdf' }])]);
assert.equal(judge({ urlClass: 'SAFE', dom: pdfDom, brand: otherBrand, domainAgeDays: 30 }).verdict, 'SAFE');
// An executable URL path counts as an offered executable, even without page links.
const urlOffer = judge({ urlClass: 'SAFE', dom: analyzeDomEvidence([page('https://downloads.example.org', [])]),
  brand: otherBrand, domainAgeDays: 30, url: 'https://downloads.example.org/bca-setup.exe' });
assert.deepEqual(urlOffer.matched, ['P4']);
// Snapshot without download metadata: executable offer stays undetermined.
const unrecorded = judge({ urlClass: 'SAFE', dom: analyzeDomEvidence([{ ...otherPage, download_page: undefined }]),
  brand: otherBrand, domainAgeDays: 30 });
assert.equal(unrecorded.status.P4, 'undetermined');

// E-F: official brand domain or no brand identity -> no download phishing reason.
const officialBrand = await analyzeBrandEvidence(page('https://www.bca.co.id'), 'https://www.bca.co.id/download', { lookup });
assert.equal(officialBrand.official_domain_match, true);
assert.equal(judge({ urlClass: 'SAFE', dom: analyzeDomEvidence([page('https://www.bca.co.id')]), brand: officialBrand,
  domainAgeDays: 30 }).status.P4, 'not_matched');
assert.equal(judge({ urlClass: 'SAFE', dom, brand: { claimed_brand_status: 'unknown' }, domainAgeDays: 30 }).verdict, 'SAFE');

// Explanation shows the download finding without claiming malware or a paused download.
const summary = buildAnalysisExplanation({ url: otherUrl, verdict: 'DANGEROUS',
  model_result: { model_family: 'XGBoost', verdict: 'SAFE' }, decision_policy: youngExe.decision,
  matched_rules: youngExe.rules.filter(rule => rule.status === 'matched'), brand_features: otherBrand, dom_features: otherDom });
assert.ok(summary.reasons.some(reason => reason.startsWith('Unduhan berbahaya:') && reason.includes('.exe') && reason.endsWith('[P4]')));
assert.ok(!summary.reasons.some(reason => /dijeda|malware terbukti/i.test(reason)));
console.log('DOM download rules: parameters, P1 address conflict, P4 new-domain executable, PDF/old/official/unknown negatives, explanation passed.');
