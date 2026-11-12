import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractUrl20Features, normalizeUrlForFeatures } from "../src/analyzer/url/url20-features.js";
import { predictProbability } from "../src/model/xgboost-engine.js";

// Model v3 is trained on browser-normalized (WHATWG) URLs. Spellings of the same
// address must give identical features, otherwise offline tests would score a
// form the browser never reports (e.g. homepages without a trailing "/").
const model = JSON.parse(readFileSync(new URL("../src/model/xgboost-url20.json", import.meta.url)));
const contract = JSON.parse(readFileSync(new URL("../src/model/feature-contract-20.json", import.meta.url)));
assert.deepEqual(model.feature_names, contract.features);
assert.equal(model.feature_set, contract.feature_set);
assert.equal(model.source_model_sha256, contract.source_model_sha256);
assert.equal(model.threshold, 0.5);

for (const [a, b] of [
  ["https://www.levelup.com", "https://www.levelup.com/"],
  ["HTTPS://WWW.Example.COM:443", "https://www.example.com/"],
  ["http://example.com:80/a", "http://example.com/a"]
]) {
  assert.equal(normalizeUrlForFeatures(a), b);
  assert.deepEqual(extractUrl20Features(a), extractUrl20Features(b), a);
  assert.equal(predictProbability(model, extractUrl20Features(a)), predictProbability(model, extractUrl20Features(b)));
}
// Unparseable input is left unchanged instead of throwing in the normalizer.
assert.equal(normalizeUrlForFeatures("not a url"), "not a url");
console.log("URL normalization: equivalent spellings give identical URL20 features");
