import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyUrl, predictProbability } from '../src/model/xgboost-engine.js';
import { extractUrl20Features } from '../src/analyzer/url/url20-features.js';
import { classificationRecord } from '../src/shared/classification-record.js';

// The URL model forwards only a class; the threshold 0.50 is inclusive.
const model = JSON.parse(readFileSync(new URL('../src/model/xgboost-url20.json', import.meta.url)));
assert.equal(model.threshold, .5);
for (const url of ['https://obsproject.com/', 'https://bca.portal-lab.test/setup.exe']) {
  const features = extractUrl20Features(url);
  assert.equal(classifyUrl(model, features), predictProbability(model, features) >= .5 ? 'phishing' : 'legitimate');
}
assert.equal(classifyUrl({ ...model, trees: [], base_margin: 0 }, {}), 'phishing'); // p = 0.50 exactly

// Stored records keep measured features but no classification score or probability.
const dirty = { score: 80, url_score: 80, dom_score: 2, model_result: { verdict: 'DANGEROUS', probability_phishing: .8 },
  history: [{ score: 10, status: 'SAFE' }], feature_vector: { url_length: 100 } };
assert.deepEqual(classificationRecord(dirty), { model_result: { verdict: 'DANGEROUS' },
  history: [{ status: 'SAFE' }], feature_vector: { url_length: 100 } });
console.log('Categorical URL boundary (inclusive TH 0.50) and score-free records passed.');
