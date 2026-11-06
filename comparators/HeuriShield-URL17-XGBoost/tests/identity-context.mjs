import assert from "node:assert/strict";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";

const snapshot = {page_origin:"https://agency.example",title:"Non-major Source - Example Agency",
  headings:[{text:"Non-major Source"}],logos:[],forms:[],controls:[],
  password_fields:[],sensitive_fields:[],inaccessible_frames:0};
const brand = await analyzeBrandEvidence(snapshot,"https://agency.example/resources",{
  domainSearch:async()=>({found:false,lookup_success:true,candidates:[]}),
  lookup:async token=>({lookup_success:true,candidates:token==="major"?[{name:"Major",domain:"major.bot",verified:true}]:
    token==="agency"?[{name:"Example Agency",domain:"agency.example",verified:false}]:[]})
});
assert.equal(brand.candidates.find(candidate=>candidate.name==="Major").role,"mention");
const dom = analyzeDomEvidence([snapshot]);
assert.equal(decideWithEvidence("DANGEROUS",dom,brand,evaluateCorrelation(dom,brand),{
  pageUrl:"https://agency.example/resources",mainSnapshot:snapshot,pageRegistrableDomain:"agency.example",
  sameSite:true,domainAgeDays:4000,probability:.70}).verdict,"SAFE");

const wp = {page_origin:"https://town.example",title:"Log In ‹ Town of Example — WordPress",
  headings:[{text:"Log In"}],logos:[],controls:[{type:"native_login"}],
  password_fields:[{form_index:0}],sensitive_fields:[],
  forms:[{relevant:true,action_known:true,action_origin:"https://town.example",same_origin:true}]};
const software = await analyzeBrandEvidence(wp,"https://town.example/wp-login.php",{
  lookup:async token=>({lookup_success:true,candidates:token==="wordpress"?[{name:"WordPress",domain:"wordpress.org",verified:true}]:[]})
});
assert.equal(software.claimed_brand,null);
assert.deepEqual(software.software_brands,["WordPress"]);
assert.equal(software.high_confidence_credential_impersonation,false);
assert.equal(software.candidates.find(candidate=>candidate.name==="WordPress").role,"software");

const compact = await analyzeBrandEvidence({...snapshot,title:"Medication Management",headings:[]},
  "https://medication.example",{
    domainSearch:async()=>({lookup_success:true,found:true,candidates:[{name:"MedicationManagement",domain:"medication.example"}]}),
    lookup:async()=>({lookup_success:true,candidates:[]})
  });
assert.equal(compact.candidates.find(candidate=>candidate.name==="MedicationManagement").in_title,true);

const loginSnapshot = {...snapshot,title:"Example Agency",headings:[],
  forms:[{relevant:true,action_known:true,action_origin:snapshot.page_origin,same_origin:true}],
  password_fields:[{form_index:0}]};
const loginBrand = await analyzeBrandEvidence(loginSnapshot,"https://agency.example/login",{
  domainSearch:async()=>({lookup_success:true,found:true,candidates:[{name:"Example Agency",domain:"agency.example"}]}),
  lookup:async()=>({lookup_success:true,candidates:[]})
});
const loginDom = analyzeDomEvidence([loginSnapshot]);
const loginContext = {pageUrl:"https://agency.example/login",mainSnapshot:loginSnapshot,
  pageRegistrableDomain:"agency.example",sameSite:true,domainAgeDays:4000,probability:.82};
const decideLogin = (d=loginDom,b=loginBrand,c=loginContext) =>
  decideWithEvidence("DANGEROUS",d,b,evaluateCorrelation(d,b),c).verdict;
assert.equal(decideLogin(),"SAFE");
assert.equal(decideLogin({...loginDom,form_cross_domain:true,
  forms:[{relevant:true,cross_domain:true,same_origin:false}]}),"DANGEROUS");
assert.equal(decideLogin({...loginDom,unresolved_checks:["inaccessible_iframe"]}),"DANGEROUS");
assert.equal(decideLogin(loginDom,{...loginBrand,official_domain_match:null}),"DANGEROUS");
assert.equal(decideLogin(loginDom,loginBrand,{...loginContext,probability:.95}),"DANGEROUS");
assert.equal(decideLogin(loginDom,loginBrand,{...loginContext,domainAgeDays:null}),"DANGEROUS");
assert.equal(decideLogin(loginDom,loginBrand,{...loginContext,
  mainSnapshot:{...loginSnapshot,page_origin:"https://other.example"}}),"DANGEROUS");
console.log("Identity context passed: page topics, software attribution and spaced organization names.");
