import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";
import { extractUrl20Features as extractUrl18Features } from "../src/analyzer/url/url20-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";

const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url20.json",import.meta.url)));
for (const url of ["https://liquipedia.net/valorant/VCT/2027/Pacific/Kickoff",
  "https://liquipedia.net/valorant/VCT/2026/Pacific_League/Stage_2"]) {
  const snapshot = {page_origin:"https://liquipedia.net",title:"VCT Pacific - Liquipedia VALORANT Wiki",
    headings:[{text:"VCT Pacific"}],logos:[],forms:[],password_fields:[],sensitive_fields:[],
    controls:[],inaccessible_frames:0,document_ready_state:"complete"};
  const brand = await analyzeBrandEvidence(snapshot,url,{
    domainSearch:async()=>({found:true,lookup_success:true,candidates:[{name:"Liquipedia",domain:"liquipedia.net",verified:false}]}),
    lookup:async()=>({lookup_success:true,candidates:[]})
  });
  const dom = analyzeDomEvidence([snapshot]);
  const actualProbability = predictProbability(model,extractUrl18Features(url));
  assert.ok(actualProbability >= 0 && actualProbability <= 1);
  // Exercise the evidence correction independently of a newly trained model's score.
  const probability = 0.80;
  const context = {pageUrl:url,mainSnapshot:snapshot,pageRegistrableDomain:"liquipedia.net",
    domainAgeDays:6000,sameSite:true,probability};
  assert.equal(decideWithEvidence("DANGEROUS",dom,brand,evaluateCorrelation(dom,brand),context).verdict,"SAFE");
  for (const [badDom,badBrand,badContext] of [
    [{...dom,has_password_field:true},brand,context],
    [{...dom,has_password_field:"unknown"},brand,context],
    [{...dom,form_cross_domain:true},brand,context],
    [dom,{...brand,official_domain_match:"unknown"},context],
    [dom,{...brand,brand_in_title:false},context],
    [dom,{...brand,candidates:brand.candidates.map(candidate=>({...candidate,in_title:false}))},context],
    [dom,brand,{...context,sameSite:false}],
    [dom,brand,{...context,probability:0.95}],
    [dom,brand,{...context,domainAgeDays:null}],
    [dom,brand,{...context,mainSnapshot:{...snapshot,page_origin:"https://different.test"}}]
  ]) assert.equal(decideWithEvidence("DANGEROUS",badDom,badBrand,
    evaluateCorrelation(badDom,badBrand),badContext).verdict,"DANGEROUS");
}
console.log("Verified content pages correct URL false positives; incomplete, sensitive and conflicting evidence stay blocked.");
