import assert from 'node:assert/strict';
import {analyzeBrandEvidence} from '../src/analyzer/brand/brand-evidence.js';
import {analyzeDomEvidence,verifyFormDestinations} from '../src/analyzer/dom/dom-evidence.js';
import {evaluateCorrelation} from '../src/analyzer/correlation/evidence-rules.js';
import {decideWithEvidence} from './decision-fixture.js';

const candidate={name:'PayPal',domain:'paypal.com',verified:true};
const snapshot={page_origin:'https://paypal.login.com',title:'Login to your PayPal account',
 headings:[],logos:[],controls:[{type:'native_login'}],password_fields:[{form_index:0,visible:true}],
 sensitive_fields:[],forms:[{relevant:true,action_known:true,action_origin:'https://receiver.example.net',same_origin:false}],
 inaccessible_frames:0,document_ready_state:'complete'};
const deps={
 domainSearch:async()=>({lookup_success:true,found:true,candidates:[{name:'Login',domain:'login.com',verified:false}]}),
 lookup:async token=>({lookup_success:true,candidates:token==='paypal'?[candidate]:[]})
};
async function check(page=snapshot,url='https://paypal.login.com/',options=deps){
 const brand=await analyzeBrandEvidence(page,url,options);
 const dom=verifyFormDestinations(analyzeDomEvidence([page]),brand);
 const verdict=decideWithEvidence('SAFE',dom,brand,evaluateCorrelation(dom,brand,{urlVerdict:'SAFE'})).verdict;
 return {brand,dom,verdict};
}
const positive=await check();
assert.equal(positive.brand.claimed_brand.name,'PayPal');
assert.equal(positive.brand.verified_reference_domain,'paypal.com');
assert.equal(positive.brand.host_brand_claim,'subdomain_exact');
assert.equal(positive.brand.brand_domain_mismatch,true);
assert.equal(positive.brand.high_confidence_credential_impersonation,true);
assert.equal(positive.verdict,'DANGEROUS');
const same=await check({...snapshot,forms:[{relevant:true,action_known:true,action_origin:'https://paypal.login.com',same_origin:true}]});
assert.equal(same.verdict,'DANGEROUS','Same-site form is not a brand authorization');
for(const [name,changes] of [
 ['article',{title:'PayPal guide and review'}],
 ['OAuth mention',{title:'Login with PayPal',password_fields:[],controls:[{type:'oauth_login',provider:'PayPal'}]}],
 ['missing password',{password_fields:[]}],
 ['missing native login',{controls:[]}],
 ['no title',{title:''}]
]){
 const result=await check({...snapshot,...changes});
 assert.equal(result.verdict,'SAFE',name);
 assert.equal(result.brand.high_confidence_host_impersonation,false,name);
}
const missing=await check(snapshot,'https://paypal.login.com/',{...deps,lookup:async()=>({lookup_success:false,candidates:[]})});
assert.equal(missing.verdict,'SAFE');
const unverified=await check(snapshot,'https://paypal.login.com/',{...deps,lookup:async t=>({lookup_success:true,candidates:t==='paypal'?[{...candidate,verified:false}]:[]})});
assert.equal(unverified.verdict,'SAFE','Unknown reference must not be promoted to confirmed impersonation');
const official=await check({...snapshot,page_origin:'https://www.paypal.com'},'https://www.paypal.com/login',{
 ...deps,domainSearch:async()=>({lookup_success:true,found:true,candidates:[candidate]})});
assert.equal(official.brand.official_domain_match,true);
assert.equal(official.verdict,'SAFE');
const realSite=await check({...snapshot,title:'Merchant Portal - Login with PayPal',headings:[{text:'Merchant Portal'}]},'https://paypal.merchant.example/login',{
 ...deps,domainSearch:async()=>({lookup_success:true,found:true,candidates:[{name:'Merchant Portal',domain:'merchant.example',verified:true}]})});
assert.equal(realSite.brand.claimed_brand.name,'Merchant Portal');
assert.equal(realSite.verdict,'SAFE');
// The rule is not tied to PayPal or a fixed domain list.
const other=await check({...snapshot,title:'Sign in to your Acme account',page_origin:'https://acme.login.com'},'https://acme.login.com/',{
 ...deps,lookup:async token=>({lookup_success:true,candidates:token==='acme'?[{name:'Acme',domain:'acme.com',verified:true}]:[]})});
assert.equal(other.brand.claimed_brand.name,'Acme');
assert.equal(other.verdict,'DANGEROUS');
console.log('Credential owner identity: subdomain + explicit title + native password form; official, OAuth, article, missing evidence, provider failure and unrelated brand controls passed.');
