import assert from 'node:assert/strict';
import {decideWithEvidence} from '../src/analyzer/correlation/decision-policy.js';
const rule=(id,status='matched')=>({id,status});
for(const id of ['R03','R07','R09','R10','R13']) {
  assert.equal(decideWithEvidence('SAFE',[rule(id)]).verdict,'DANGEROUS',id);
  assert.equal(decideWithEvidence('SAFE',[rule(id,'undetermined')]).verdict,'SAFE',id);
}
for(const id of ['R14','R15','R16','R17','R18','R19']) {
  assert.equal(decideWithEvidence('DANGEROUS',[rule(id)]).verdict,'SAFE',id);
  assert.equal(decideWithEvidence('DANGEROUS',[rule(id,'not_matched')]).verdict,'DANGEROUS',id);
  assert.equal(decideWithEvidence('DANGEROUS',[rule(id,'undetermined')]).verdict,'DANGEROUS',id);
  for(const conflict of ['R03','R04','R05','R07','R09','R10','R12','R13'])
    assert.equal(decideWithEvidence('DANGEROUS',[rule(id),rule(conflict)]).verdict,'DANGEROUS');
}
assert.equal(decideWithEvidence('SAFE',[rule('R11')]).verdict,'SAFE');
assert.equal(decideWithEvidence('DANGEROUS',[]).verdict,'DANGEROUS');
assert.equal(decideWithEvidence('LIMITED',[rule('R14')]).verdict,'LIMITED');
const opaque={};Object.defineProperty(opaque,'probability',{get(){throw Error('Score must not be read');}});
assert.equal(decideWithEvidence('DANGEROUS',[rule('R17')],opaque).verdict,'SAFE');
console.log('Policy uses only R IDs/statuses: both correction directions, conflicts, unknown and fallback passed.');
