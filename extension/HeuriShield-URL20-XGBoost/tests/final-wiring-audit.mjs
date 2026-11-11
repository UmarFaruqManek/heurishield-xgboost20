import assert from 'node:assert/strict';
import { analyzeBrandEvidence } from '../src/analyzer/brand/brand-evidence.js';
import { analyzeDomEvidence } from '../src/analyzer/dom/dom-evidence.js';
import { judge } from './pipeline.js';

// End-to-end wiring: live analyzer output -> parameters -> P/L rules -> policy.
const lookup = async token => ({ lookup_success: true,
  candidates: token === 'bca' ? [{ name: 'BCA', domain: 'bca.co.id', verified: true }] : [] });
const snapshot = { page_origin: 'https://bca.bank.com', title: 'Login BCA', headings: [{ text: 'Masuk BCA' }],
  logos: [], controls: [{ type: 'native_login' }], password_fields: [{ form_index: 0 }], sensitive_fields: [],
  forms: [{ relevant: true, action_known: true, action_origin: 'https://receiver.example.net', same_origin: false }],
  inaccessible_frames: 0, document_ready_state: 'complete' };
const brand = await analyzeBrandEvidence(snapshot, 'https://bca.bank.com/login', { lookup });
const dom = analyzeDomEvidence([snapshot]);
assert.equal(brand.brand_domain_mismatch, true);
assert.equal(dom.form_cross_domain, true);
const phishing = judge({ urlClass: 'SAFE', dom, brand, domainAgeDays: 4000 });
assert.deepEqual(phishing.matched, ['P1', 'P2']);
assert.equal(phishing.verdict, 'DANGEROUS');
assert.equal(phishing.decision.source, 'brand_dom_phishing');
assert.deepEqual(phishing.decision.reasons, ['P1', 'P2']);

// Domain age: P3 matched when young, undetermined when unknown, not matched when old.
assert.equal(judge({ urlClass: 'SAFE', dom, brand, domainAgeDays: 30 }).status.P3, 'matched');
assert.equal(judge({ urlClass: 'SAFE', dom, brand, domainAgeDays: null }).status.P3, 'undetermined');
assert.equal(judge({ urlClass: 'SAFE', dom, brand, domainAgeDays: 400 }).status.P3, 'not_matched');

// A cross-domain form without any brand identity is not a phishing reason on its own.
const noBrand = judge({ urlClass: 'SAFE', dom, brand: { claimed_brand_status: 'unknown' }, domainAgeDays: 4000 });
assert.deepEqual(noBrand.matched, []);
assert.equal(noBrand.status.P2, 'undetermined');

// Official domain and a mere mention produce no address conflict.
const official = await analyzeBrandEvidence({ ...snapshot, page_origin: 'https://bca.co.id' }, 'https://bca.co.id/login', { lookup });
assert.equal(official.brand_domain_mismatch, false);
const mention = await analyzeBrandEvidence({ ...snapshot, password_fields: [], controls: [], title: 'Panduan BCA',
  headings: [{ text: 'Informasi' }] }, 'https://community.example.net/help', { lookup });
assert.notEqual(mention.brand_domain_mismatch, true);
console.log('Final wiring: analyzer parameters, P1/P2/P3 statuses, policy source and negative controls passed.');
