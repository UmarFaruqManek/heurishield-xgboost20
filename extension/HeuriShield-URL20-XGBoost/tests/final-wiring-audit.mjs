import assert from 'node:assert/strict';
import {analyzeBrandEvidence} from '../src/analyzer/brand/brand-evidence.js';
import {analyzeDomEvidence,verifyFormDestinations} from '../src/analyzer/dom/dom-evidence.js';
import {evaluateCorrelation} from '../src/analyzer/correlation/evidence-rules.js';
import {decideWithEvidence} from '../src/analyzer/correlation/decision-policy.js';
const snapshot={page_origin:'https://bca.bank.com',title:'Login BCA',headings:[{text:'Masuk BCA'}],
 logos:[],controls:[{type:'native_login'}],password_fields:[{form_index:0}],sensitive_fields:[],
 forms:[{relevant:true,action_known:true,action_origin:'https://receiver.example.net',same_origin:false}],
 inaccessible_frames:0,document_ready_state:'complete'};
const brand=await analyzeBrandEvidence(snapshot,'https://bca.bank.com/login',{
 lookup:async token=>({lookup_success:true,candidates:token==='bca'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]})});
assert.equal(brand.brand_domain_mismatch,true);
const dom=verifyFormDestinations(analyzeDomEvidence([snapshot]),brand);
assert.equal(dom.forms[0].destination_verification,false);
const correlation=evaluateCorrelation(dom,brand,{urlVerdict:'SAFE'});
for(const id of ['R01','R02','R03','R04','R09','R10'])
 assert.equal(correlation.rules.find(rule=>rule.id===id).status,'matched',id);
assert.equal(decideWithEvidence('SAFE',correlation.rules).verdict,'DANGEROUS');
const unresolved=verifyFormDestinations(analyzeDomEvidence([snapshot]),{claimed_brand_status:'unknown'});
assert.equal(unresolved.forms[0].destination_verification,'unknown');
assert.equal(evaluateCorrelation(unresolved,{claimed_brand_status:'unknown'}).rules.find(r=>r.id==='R04').status,'undetermined');
const official=await analyzeBrandEvidence({...snapshot,page_origin:'https://bca.co.id'},'https://bca.co.id/login',{
 lookup:async token=>({lookup_success:true,candidates:token==='bca'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]})});
assert.equal(official.brand_domain_mismatch,false);
const mention=await analyzeBrandEvidence({...snapshot,password_fields:[],controls:[],title:'Panduan BCA',headings:[{text:'Informasi'}]},
 'https://community.example.net/help',{
 lookup:async token=>({lookup_success:true,candidates:token==='bca'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]})});
assert.notEqual(mention.brand_domain_mismatch,true);
const provider=verifyFormDestinations({...dom,controls:[{type:'oauth_login',provider:'Google'}],forms:[{
 relevant:true,action_known:true,action_origin:'https://accounts.google.com',cross_domain:true}]},brand);
assert.equal(provider.forms[0].destination_verification,true);
console.log('Final wiring: confirmed vs potential identity conflict, R02/R03/R04/R10 activation, OAuth and unknown destination passed.');

const {classifyDomainAge,evaluateDomainAgeRule}=await import('../src/analyzer/domain/domain-age-policy.js');
const agePolicy=JSON.parse((await import('node:fs')).readFileSync(new URL('../src/model/domain-age-policy.json',import.meta.url),'utf8'));
assert.equal(evaluateDomainAgeRule(classifyDomainAge(30,agePolicy),dom,brand).status,'matched');
assert.equal(evaluateDomainAgeRule(classifyDomainAge(null,agePolicy),dom,brand).status,'undetermined');
assert.equal(evaluateDomainAgeRule(classifyDomainAge(400,agePolicy),dom,brand).status,'not_matched');
