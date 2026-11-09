import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {classifyUrl, predictProbability} from '../src/model/xgboost-engine.js';
import {extractUrl20Features} from '../src/analyzer/url/url20-features.js';
import {decideWithEvidence} from './decision-fixture.js';
import {evaluateCorrectionRules} from '../src/analyzer/correlation/correction-rules.js';
import {classificationRecord} from '../src/shared/classification-record.js';
const model=JSON.parse(readFileSync(new URL('../src/model/xgboost-url20.json',import.meta.url)));
assert.equal(model.threshold,.5);
for(const url of ['https://obsproject.com/','https://bca.portal-lab.test/setup.exe']) {
 const features=extractUrl20Features(url);
 assert.equal(classifyUrl(model,features),predictProbability(model,features)>=.5?'phishing':'legitimate');
}
const dom={observed_frame_count:1,has_password_field:false,has_sensitive_input:false,form_cross_domain:false,forms:[]};
const brand={claimed_brand_status:'identified',official_domain_match:true,brand_domain_mismatch:false,
 brand_claim_relation:'own_domain',verified_reference_domain:'example.com',brand_in_title:true,
 claimed_brand:{name:'Example',official_domain:'example.com'},
 candidates:[{name:'Example',domain:'example.com',in_title:true,claim:true}]};
const correlation={rules:[]};
const context={pageUrl:'https://example.com/docs',pageRegistrableDomain:'example.com',sameSite:true,
 domainAgeDays:4000,mainSnapshot:{page_origin:'https://example.com'}};
Object.defineProperty(context,'probability',{get(){throw new Error('Probability crossed URL boundary');}});
assert.equal(decideWithEvidence('DANGEROUS',dom,brand,correlation,context).verdict,'SAFE');
const correction=evaluateCorrectionRules('DANGEROUS',dom,brand,correlation,context);
assert.equal(correction.rules.find(r=>r.id==='R17').status,'matched');
assert.equal(decideWithEvidence('SAFE',dom,brand,correlation,context).verdict,'SAFE');
assert.equal(decideWithEvidence('DANGEROUS',dom,{claimed_brand_status:'unknown'},correlation,context).verdict,'DANGEROUS');
const dirty={score:80,url_score:80,dom_score:2,model_result:{verdict:'DANGEROUS',probability_phishing:.8},
 history:[{score:10,status:'SAFE'}],feature_vector:{url_length:100}};
assert.deepEqual(classificationRecord(dirty),{model_result:{verdict:'DANGEROUS'},history:[{status:'SAFE'}],feature_vector:{url_length:100}});
console.log('Categorical URL boundary, explicit correction rules and score-free records passed.');

const incomplete=evaluateCorrectionRules('DANGEROUS',{},{claimed_brand_status:'unknown'}, {rules:[]}, {});
assert.ok(incomplete.rules.every(rule=>rule.status==='undetermined'));

assert.equal(classifyUrl({...model,trees:[],base_margin:0},{}),'phishing'); // inclusive TH0.50
