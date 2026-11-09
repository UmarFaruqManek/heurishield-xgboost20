import assert from 'node:assert/strict';
import {decideWithEvidence} from '../src/analyzer/correlation/decision-policy.js';
// Independent decision table from the thesis: strong phishing evidence wins;
// legitimate corrections require no conflict; otherwise keep the URL class.
const strong=['R03','R07','R09','R10','R13'];
const corrections=['R14','R15','R16','R17','R18','R19'];
const conflicts=['R04','R05','R12'];
const ids=[...strong,...corrections,...conflicts];
let cases=0;
for(let mask=0;mask<2**ids.length;mask++) {
 const active=new Set(ids.filter((id,index)=>(mask & (1<<index))!==0));
 const rows=ids.map(id=>({id,status:active.has(id)?'matched':'not_matched'}));
 for(const url of ['SAFE','DANGEROUS']) {
   const strongMatch=strong.some(id=>active.has(id));
   const correctionMatch=corrections.some(id=>active.has(id));
   const conflictMatch=conflicts.some(id=>active.has(id));
   const expected=strongMatch?'DANGEROUS':url==='SAFE'?'SAFE':
     correctionMatch&&!conflictMatch?'SAFE':'DANGEROUS';
   assert.equal(decideWithEvidence(url,rows).verdict,expected,`${mask}:${url}`);
   cases++;
 }
}
for(const id of ['R01','R02','R06','R08','R11']) {
 for(const url of ['SAFE','DANGEROUS']) assert.equal(decideWithEvidence(url,[{id,status:'matched'}]).verdict,url);
}
console.log(`Final decision table: ${cases} combinations passed; contextual/supporting rules do not independently override.`);
