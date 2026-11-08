import assert from 'node:assert/strict';
import { analyzeDomEvidence } from '../src/analyzer/dom/dom-evidence.js';
import { analyzeBrandEvidence } from '../src/analyzer/brand/brand-evidence.js';
import { evaluateCorrelation } from '../src/analyzer/correlation/evidence-rules.js';
import { decideWithEvidence } from '../src/analyzer/correlation/decision-policy.js';
import { buildAnalysisExplanation } from '../src/shared/analysis-explanation.js';

const snapshot={page_origin:'https://bca.bank.com',title:'Login BCA',headings:[{text:'BCA Downloads'}],
  logos:[],password_fields:[],sensitive_fields:[],forms:[],controls:[],
  download_page:{links:[{url:'https://files.example.net/bca-update.exe',text:'Download',filename_hint:null}],truncated:false,unresolved_controls:0}};
const lookup=async token=>({lookup_success:true,candidates:token==='bca'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]});
const brand=await analyzeBrandEvidence(snapshot,'https://bca.bank.com/download',{lookup});
const dom=analyzeDomEvidence([snapshot]);
assert.equal(brand.claimed_brand.name,'BCA');assert.equal(brand.official_domain_match,false);
assert.equal(brand.high_confidence_host_impersonation,false); // No password: old subdomain rule does not qualify.
assert.equal(dom.has_download_link,true);assert.deepEqual(dom.download_file_extensions,['exe']);
assert.ok(!('has_executable_download_link' in dom));assert.ok(!('download_link_count' in dom));
assert.equal(dom.download_target_cross_domain,true);
const correlation=evaluateCorrelation(dom,brand,{urlVerdict:'SAFE'});
assert.equal(correlation.rules.find(r=>r.id==='R13').status,'matched');
const final=decideWithEvidence('SAFE',dom,brand,correlation);
assert.equal(final.verdict,'DANGEROUS');assert.equal(final.source,'brand_executable_download_phishing');
const pdf=analyzeDomEvidence([{...snapshot,download_page:{links:[{url:'https://files.example.net/manual.pdf'}]}}]);
assert.equal(pdf.has_download_link,true);assert.deepEqual(pdf.download_file_extensions,['pdf']);
assert.equal(decideWithEvidence('SAFE',pdf,brand,evaluateCorrelation(pdf,brand,{urlVerdict:'SAFE'})).verdict,'SAFE');
const official={...brand,official_domain_match:true,high_confidence_host_impersonation:false,high_confidence_credential_impersonation:false};
assert.equal(decideWithEvidence('SAFE',dom,official,evaluateCorrelation(dom,official,{urlVerdict:'SAFE'})).verdict,'SAFE');
const unknownBrand={claimed_brand_status:'unknown',official_domain_match:'unknown',host_brand_claim:'unknown'};
assert.equal(decideWithEvidence('SAFE',dom,unknownBrand,evaluateCorrelation(dom,unknownBrand,{urlVerdict:'SAFE'})).verdict,'SAFE');
const strong={...brand,high_confidence_host_impersonation:true};
const confirmed=evaluateCorrelation(dom,strong,{urlVerdict:'DANGEROUS'});
assert.equal(confirmed.rules.find(r=>r.id==='R12').status,'matched');
assert.equal(decideWithEvidence('DANGEROUS',dom,strong,confirmed).source,'url_brand_download_phishing');
const old=analyzeDomEvidence([{...snapshot,download_page:undefined}]);
assert.equal(old.has_download_link,'unknown');assert.equal(old.download_file_extensions,null);
assert.ok(!('download_link_count' in old));assert.equal(old.unresolved_checks.length,0); // Do not disable existing first-party corrections.
assert.equal(evaluateCorrelation(old,brand,{urlVerdict:'SAFE'}).rules.find(r=>r.id==='R13').status,'undetermined');
const noLinks=analyzeDomEvidence([{...snapshot,download_page:{links:[]}}]);
assert.equal(noLinks.has_download_link,false);assert.deepEqual(noLinks.download_file_extensions,[]);
const dynamic=analyzeDomEvidence([{...snapshot,download_page:{links:[],unresolved_controls:1}}]);
assert.equal(dynamic.has_download_link,'unknown');
const blob=analyzeDomEvidence([{...snapshot,download_page:{links:[{url:'blob:https://bca.bank.com/id',filename_hint:'setup.apk'}]}}]);
assert.deepEqual(blob.download_file_extensions,['apk']);assert.equal(blob.download_target_cross_domain,'unknown');
const summary=buildAnalysisExplanation({url:'https://bca.bank.com/download',verdict:'DANGEROUS',model_result:{model_family:'XGBoost',verdict:'SAFE'},decision_policy:final,brand_features:brand,dom_features:dom});
assert.ok(summary.reasons.some(reason=>reason.startsWith('Unduhan:')));
assert.ok(!summary.reasons.some(reason=>/dijeda|malware terbukti/i.test(reason)));
console.log('DOM download rules: R12/R13, URL SAFE correction, official/CDN/PDF negatives, unknown history, JS-only controls and explanations passed.');

const urlOffer=evaluateCorrelation(noLinks,brand,{urlVerdict:'SAFE',urlFileExtension:'exe'});
assert.equal(urlOffer.rules.find(r=>r.id==='R13').status,'matched');
assert.equal(decideWithEvidence('SAFE',noLinks,brand,urlOffer).verdict,'DANGEROUS');
assert.equal(evaluateCorrelation(noLinks,unknownBrand,{urlVerdict:'SAFE',urlFileExtension:'exe'}).rules.find(r=>r.id==='R13').status,'not_matched');
