import assert from 'node:assert/strict';
import { analyzeBrandEvidence } from '../src/analyzer/brand/brand-evidence.js';
import { analyzeDomEvidence } from '../src/analyzer/dom/dom-evidence.js';
import { evaluateCorrelation } from '../src/analyzer/correlation/evidence-rules.js';
import { decideWithEvidence } from './decision-fixture.js';

const url='https://www.roblox.com.ml/users/390783638810/profile';
const page={page_origin:'https://www.roblox.com.ml',title:'Player - Roblox',
  headings:[{text:'Roblox profile'}],logos:[],password_fields:[],sensitive_fields:[],forms:[],controls:[]};
const domainSearch=async()=>({found:true,lookup_success:true,candidates:[
  {name:'Roblox',domain:'roblox.com.ml',verified:false,source:'domain_fixture'}]});
const lookup=async token=>({lookup_success:true,candidates:token==='roblox'?
  [{name:'Roblox',domain:'roblox.com',verified:true,source:'token_fixture'}]:[]});
const brand=await analyzeBrandEvidence(page,url,{domainSearch,lookup});
assert.equal(brand.canonical_reference_check_used,true);
assert.equal(brand.api_domain_reference_conflict,true);
assert.equal(brand.claimed_brand.name,'Roblox');
assert.equal(brand.verified_reference_domain,'roblox.com');
assert.equal(brand.official_domain_match,false);
assert.equal(brand.high_confidence_host_impersonation,true);
const dom=analyzeDomEvidence([page]);
assert.equal(decideWithEvidence('SAFE',dom,brand,evaluateCorrelation(dom,brand)).verdict,'DANGEROUS');

const absent=await analyzeBrandEvidence(null,url,{domainSearch,lookup});
assert.equal(absent.api_domain_reference_conflict,false);
assert.equal(absent.high_confidence_host_impersonation,false);
const article=await analyzeBrandEvidence({...page,title:'Roblox guide and review'},url,{domainSearch,lookup});
assert.equal(article.high_confidence_host_impersonation,false);
const noHeading=await analyzeBrandEvidence({...page,headings:[]},url,{domainSearch,lookup});
assert.equal(noHeading.api_domain_reference_conflict,false);
const unavailable=await analyzeBrandEvidence(page,url,{domainSearch,lookup:async()=>({lookup_success:false,candidates:[]})});
assert.equal(unavailable.api_domain_reference_conflict,false);
assert.equal(unavailable.official_domain_match,true);
const regional=await analyzeBrandEvidence({...page,page_origin:'https://google.com.au',title:'Google',headings:[{text:'Google'}]},'https://google.com.au',{
  domainSearch:async()=>({found:true,lookup_success:true,candidates:[{name:'Google',domain:'google.com.au',verified:true}]}),
  lookup:async()=>({lookup_success:true,candidates:[{name:'Google',domain:'google.com',verified:true}]})});
assert.equal(regional.official_domain_match,true);
assert.equal(regional.high_confidence_host_impersonation,false);
const own=await analyzeBrandEvidence({...page,page_origin:'https://www.roblox.com'},'https://www.roblox.com/users/1/profile',{
  domainSearch:async()=>({found:true,lookup_success:true,candidates:[{name:'Roblox',domain:'roblox.com',verified:false,claimed:false}]}),lookup});
assert.equal(own.official_domain_match,true);
assert.equal(own.high_confidence_host_impersonation,false);
console.log('Canonical-reference conflict: corroborated imitation, absent DOM, article, missing heading, API failure, regional and official domains passed.');
