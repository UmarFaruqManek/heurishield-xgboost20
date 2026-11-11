import assert from 'node:assert/strict';
import { decide } from '../src/analyzer/rules/decision-policy.js';
import { RULES } from '../src/analyzer/rules/heuristic-rules.js';

// Exhaustive check against the policy table, written independently:
//   URL class unavailable          -> LIMITED
//   any phishing rule matched      -> DANGEROUS
//   any legitimate rule matched    -> SAFE
//   otherwise                      -> URL class
const STATUSES = ['matched', 'not_matched', 'undetermined'];
const ids = RULES.map(rule => rule.id);
assert.deepEqual(ids, ['P1', 'P2', 'P3', 'P4', 'L1', 'L2']);
let cases = 0;
for (let combo = 0; combo < STATUSES.length ** RULES.length; combo++) {
  let rest = combo;
  const results = RULES.map(rule => {
    const status = STATUSES[rest % 3];
    rest = Math.floor(rest / 3);
    // Opaque rule rows: the policy may read only id, decision and status.
    return new Proxy({ id: rule.id, decision: rule.decision, status }, {
      get(target, key) {
        if (!['id', 'decision', 'status'].includes(key)) throw new Error(`Policy read ${String(key)}`);
        return target[key];
      }
    });
  });
  const matched = decision => results.filter(r => r.decision === decision && r.status === 'matched').map(r => r.id);
  for (const urlClass of ['SAFE', 'DANGEROUS', 'LIMITED']) {
    const expected = urlClass === 'LIMITED' ? 'LIMITED'
      : matched('phishing').length ? 'DANGEROUS'
        : matched('legitimate').length ? 'SAFE' : urlClass;
    const decision = decide(urlClass, results);
    assert.equal(decision.verdict, expected, `${combo}:${urlClass}`);
    if (expected === 'DANGEROUS' && urlClass !== 'LIMITED' && matched('phishing').length)
      assert.deepEqual(decision.reasons, matched('phishing'));
    cases++;
  }
}
assert.equal(cases, 3 ** RULES.length * 3); // 6 rules x 3 statuses x 3 URL classes = 2,187

// Sources name where the decision came from.
const row = (id, decision, status = 'matched') => ({ id, decision, status });
assert.equal(decide('SAFE', [row('P1', 'phishing')]).source, 'brand_dom_phishing');
assert.equal(decide('DANGEROUS', [row('L1', 'legitimate')]).source, 'brand_dom_legitimate');
assert.equal(decide('DANGEROUS', [row('P1', 'phishing', 'undetermined')]).source, 'url_model');
assert.equal(decide(undefined, [row('P1', 'phishing')]).source, 'url_unavailable');
// Phishing evidence wins over a simultaneous legitimate reason.
assert.equal(decide('SAFE', [row('L2', 'legitimate'), row('P2', 'phishing')]).verdict, 'DANGEROUS');
console.log(`Decision policy: ${cases} combinations of URL class and rule status match the policy table.`);
