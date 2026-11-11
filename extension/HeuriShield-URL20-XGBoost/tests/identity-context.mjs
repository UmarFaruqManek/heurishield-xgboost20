import assert from "node:assert/strict";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { judge } from "./pipeline.js";

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
// A topic word on the page ("Major") is a mention; the agency's own domain is shown (L1).
const resources = judge({ urlClass: "DANGEROUS", dom, brand, domainAgeDays: 4000 });
assert.deepEqual(resources.matched, ["L1"]);
assert.equal(resources.verdict, "SAFE");

const wp = {page_origin:"https://town.example",title:"Log In ‹ Town of Example — WordPress",
  headings:[{text:"Log In"}],logos:[],controls:[{type:"native_login"}],
  password_fields:[{form_index:0}],sensitive_fields:[],
  forms:[{relevant:true,action_known:true,action_origin:"https://town.example",same_origin:true}]};
const software = await analyzeBrandEvidence(wp,"https://town.example/wp-login.php",{
  lookup:async token=>({lookup_success:true,candidates:token==="wordpress"?[{name:"WordPress",domain:"wordpress.org",verified:true}]:[]})
});
assert.equal(software.claimed_brand,null);
assert.deepEqual(software.software_brands,["WordPress"]);
assert.notEqual(software.brand_domain_mismatch,true);
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
const decideLogin = ({ d = loginDom, b = loginBrand, age = 4000 } = {}) =>
  judge({ urlClass: "DANGEROUS", dom: d, brand: b, domainAgeDays: age }).verdict;
assert.equal(decideLogin(), "SAFE");
assert.equal(decideLogin({ d: analyzeDomEvidence([{ ...loginSnapshot,
  forms: [{ relevant: true, action_known: true, action_origin: "https://collector.example.net" }] }]) }), "DANGEROUS");
// An unreadable iframe leaves the form destination unknown, so L2 is undetermined.
assert.equal(decideLogin({ d: analyzeDomEvidence([{ ...loginSnapshot, inaccessible_frames: 1 }]) }), "DANGEROUS");
assert.equal(decideLogin({ b: { ...loginBrand, official_domain_match: null } }), "DANGEROUS");
assert.equal(decideLogin({ age: null }), "DANGEROUS");
assert.equal(decideLogin({ age: 200 }), "DANGEROUS");
// A snapshot from another origin is discarded by the worker: no page evidence.
const noPage = await analyzeBrandEvidence(null, "https://agency.example/login", {
  domainSearch: async () => ({ lookup_success: true, found: true, candidates: [{ name: "Example Agency", domain: "agency.example" }] }),
  lookup: async () => ({ lookup_success: true, candidates: [] }) });
assert.equal(decideLogin({ d: analyzeDomEvidence([]), b: noPage }), "DANGEROUS");
console.log("Identity context passed: page topics, software attribution and spaced organization names.");
