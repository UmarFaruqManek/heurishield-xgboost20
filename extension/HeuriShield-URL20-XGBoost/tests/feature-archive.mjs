import assert from 'node:assert/strict';
import { saveFeatureJsonArchive } from '../src/storage/feature-archive.js';
import { STORAGE_KEYS } from '../src/utils/constants.js';

const key = STORAGE_KEYS.FEATURE_ARCHIVE;
const oldRecords = Array.from({ length: 500 }, (_, id) => ({ id: `old-${id}` }));
let archives = oldRecords;
let reads = 0;
let writes = 0;
let failWrites = false;
globalThis.chrome = { storage: { local: {
  async get() { reads++; return { [key]: archives }; },
  async set(value) {
    writes++;
    if (failWrites) throw new Error('storage quota exceeded');
    archives = value[key];
  }
} } };

await saveFeatureJsonArchive(null);
await saveFeatureJsonArchive({ feature_vector: {} });
assert.equal(reads, 0, 'Incomplete analyses must not overwrite archives');
const analysis = {
  hostname: 'Accounts.Example.com', document_id: 'test/id', verdict: 'SAFE',
  feature_vector: { vector: { url_length: 28 }, values: [28] },
  dom_features: { unresolved_checks: ['frame'] },
  brand_features: { unresolved_checks: ['lookup'] },
  model_result: { predicted_label: 'legitimate', threshold: 0.5,
    probability: 0.1, fired_rules: Array.from({ length: 8 }, (_, id) => ({ id })) }
};
await saveFeatureJsonArchive(analysis);
assert.equal(archives.length, 500, 'Keep the newest 500 records');
assert.equal(archives[1].id, 'old-0');
assert.equal(archives.at(-1).id, 'old-498');
const saved = archives[0];
assert.equal(saved.verdict, 'SAFE');
assert.deepEqual(saved.feature_vector_20, { url_length: 28 });
assert.deepEqual(saved.feature_vector_values, [28]);
assert.deepEqual(saved.unresolved_checks, ['frame', 'lookup']);
assert.equal(saved.model_result.top_fired_rules.length, 6);
assert.equal(saved.model_result.threshold, 0.5);
assert.ok(!('probability' in saved.model_result));
assert.ok(saved.id.endsWith('_accounts.example.com_test_id'));
assert.equal(saved.path_hint, `riwayat/json/${saved.id}.json`);

archives = 'invalid stored data';
await saveFeatureJsonArchive(analysis);
assert.equal(archives.length, 1, 'Recover from invalid archive storage');
assert.equal(writes, 2);
failWrites = true;
const warnings = [];
const originalWarn = console.warn;
try {
  console.warn = (...args) => warnings.push(args);
  await saveFeatureJsonArchive(analysis);
} finally { console.warn = originalWarn; }
assert.equal(warnings.length, 1);
assert.equal(warnings[0][1], 'storage quota exceeded');
console.log('Feature archive retention, missing input, sanitization and storage failure OK');
