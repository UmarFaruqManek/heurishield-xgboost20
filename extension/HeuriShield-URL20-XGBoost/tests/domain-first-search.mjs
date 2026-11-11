import assert from "node:assert/strict";
import { searchDomainBrand } from "../src/analyzer/brand/domain-brand-search.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { buildAnalysisExplanation } from "../src/shared/analysis-explanation.js";
const response = (name,domain) => ({lookup_success:true,candidates:[{name,domain,source:"fixture",verified:false}]});
const calls=[];
const domain = await searchDomainBrand("dicoding.com", {
  clearbit: async q => {calls.push(`clearbit:${q}`);return response("Dicoding","dicoding.com");},
  brandfetch: async () => {throw Error("unneeded fallback");},
  domainLookup: async () => {throw Error("unneeded fallback");}
});
assert.equal(domain.found,true);
assert.deepEqual(calls,["clearbit:dicoding.com"]);
let tokenCalls=0;
const page={title:"Dicoding",headings:[{text:"Dicoding Academy"}],logos:[],password_fields:[],controls:[]};
const own=await analyzeBrandEvidence(page,"https://portal.dicoding.com",{
  domainSearch:async root=>{assert.equal(root,"dicoding.com");return domain;},
  lookup:async()=>{tokenCalls++;return {lookup_success:true,candidates:[]};}
});
assert.equal(tokenCalls,1); // Audit the unverified directory entry with its hostname token.
assert.equal(own.claimed_brand.name,"Dicoding");
assert.equal(own.candidate_domain_match,true);
assert.equal(own.official_domain_match,true);
assert.equal(own.verification_basis,"api_domain_match");
assert.equal(own.token_fallback_used,false);
assert.equal(own.canonical_reference_check_used,true);
const liquipedia = await analyzeBrandEvidence(null, "https://liquipedia.net/valorant/VCT/2027/Pacific/Kickoff", {
  domainSearch: async () => ({lookup_success:true,found:true,candidates:[{
    name:"Liquipedia",domain:"liquipedia.net",verified:false,claimed:false,source:"fixture"}]}),
  lookup: async () => ({lookup_success:true,candidates:[]})
});
assert.equal(liquipedia.claimed_brand.name,"Liquipedia");
assert.equal(liquipedia.official_domain_match,true);
assert.equal(liquipedia.verified_reference_domain,"liquipedia.net");
assert.equal(liquipedia.domain_matched_candidate.verified,true);
assert.equal(liquipedia.domain_matched_candidate.provider_verified,false);
assert.equal(liquipedia.unresolved_checks.includes("official_domain_unverified"),false);
const explanation = buildAnalysisExplanation({url:"https://liquipedia.net/valorant/VCT/2027/Pacific/Kickoff",
  verdict:"DANGEROUS",model_result:{model_family:"XGBoost",verdict:"DANGEROUS"},
  brand_features:liquipedia});
assert.ok(explanation.reasons.some(reason=>reason.includes("domain cocok dengan brand Liquipedia")));
const failedApi = await analyzeBrandEvidence(null,"https://example.test",{
  domainSearch:async()=>({lookup_success:false,found:true,candidates:[{name:"Example",domain:"example.test"}]}),
  lookup:async()=>({lookup_success:false,candidates:[]})
});
assert.equal(failedApi.official_domain_match,"unknown");
assert.equal(failedApi.claimed_brand,null);
const order=[];
const fallback=await searchDomainBrand("example.test",{
  clearbit:async()=>{order.push("clearbit");return response("Wrong","wrong.test");},
  brandfetch:async()=>{order.push("brandfetch");return {lookup_success:false,status:"rate_limited",candidates:[]};},
  domainLookup:async()=>{order.push("heurishield");return {lookup_success:true,found:true,registrable_domain:"example.test",brand_name:"Example",brand_verified:false};}
});
assert.deepEqual(order,["clearbit","brandfetch","heurishield"]);
assert.equal(fallback.candidates[0].domain,"example.test");
const conflict=await analyzeBrandEvidence({title:"Login BCA",headings:[{text:"Masuk ke BCA"}],
  logos:[],password_fields:[{}],controls:[{type:"native_login"}]},"https://bca.bank.com/login",{
  domainSearch:async()=>({queried_domain:"bank.com",lookup_success:true,found:true,candidates:[{name:"Bank",domain:"bank.com",verified:false}]}),
  lookup:async q=>q==="bca"?{lookup_success:true,candidates:[{name:"BCA",domain:"bca.co.id",verified:true}]}:{lookup_success:true,candidates:[]}
});
assert.equal(conflict.token_fallback_used,true);
assert.equal(conflict.claimed_brand.name,"BCA");
assert.equal(conflict.brand_domain_mismatch,true);
const hostingLogin = await analyzeBrandEvidence({title:"Microsoft | Login",headings:[],logos:[],
  password_fields:[{}],controls:[{type:"native_login"}]},"https://f005.backblazeb2.com/file/auth00/Hotmailfile.html",{
  domainSearch:async()=>({lookup_success:true,found:true,candidates:[{name:"Backblaze",domain:"backblazeb2.com",verified:false}]}),
  lookup:async token=>({lookup_success:true,candidates:token==="microsoft"?[{name:"Microsoft",domain:"microsoft.com",verified:false}]:[]})
});
assert.equal(hostingLogin.candidate_domain_match,true);
assert.equal(hostingLogin.claimed_brand.name,"Microsoft");
assert.equal(hostingLogin.official_domain_match,false);
assert.equal(hostingLogin.brand_domain_mismatch,false);
console.log("Domain-first search: exact domain, lazy fallback, provider failure, and conflicting identity passed");
