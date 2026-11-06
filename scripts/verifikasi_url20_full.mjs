import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { extractUrl20Features } from "../extension/HeuriShield-URL20-XGBoost/src/analyzer/url/url20-features.js";
import { predictProbability } from "../extension/HeuriShield-URL20-XGBoost/src/model/xgboost-engine.js";

const root = path.resolve(import.meta.dirname, "..");
const reports = {};
const model = JSON.parse(fs.readFileSync(path.join(root, "extension/HeuriShield-URL20-XGBoost/src/model/xgboost-url20.json")));

// URL inputs have no internal whitespace/newlines. Handle quoted commas and quotes.
function csvFields(line) {
  const fields = [];
  let value = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const character = line[i];
    if (character === '"') {
      if (quoted && line[i + 1] === '"') { value += '"'; i++; }
      else quoted = !quoted;
    } else if (character === "," && !quoted) { fields.push(value); value = ""; }
    else value += character;
  }
  fields.push(value);
  return fields;
}

for (const [name, file] of [
  ["development", "experiments/v2/data/url20_augmented_splits.csv"],
  ["archive", "data/evaluation/live_url20.csv"]
]) {
  let header;
  let checked = 0;
  let bad = 0;
  const examples = [];
  const fieldsWithDifferences = new Map();
  for await (const line of readline.createInterface({ input: fs.createReadStream(path.join(root, file)), crlfDelay: Infinity })) {
    if (!header) { header = csvFields(line); continue; }
    if (!line) continue;
    const fields = csvFields(line);
    const url = fields[header.indexOf("url")];
    checked++;
    try {
      const features = extractUrl20Features(url);
      const differences = [];
      for (const feature of model.feature_names) {
        const expected = Math.fround(Number(fields[header.indexOf(feature)]));
        if (Math.fround(features[feature]) !== expected) {
          differences.push({ feature, python: expected, javascript: features[feature] });
          fieldsWithDifferences.set(feature, (fieldsWithDifferences.get(feature) || 0) + 1);
        }
      }
      if (differences.length) { bad++; if (examples.length < 15) examples.push({ url, differences }); }
    } catch (error) { bad++; if (examples.length < 15) examples.push({ url, error: String(error) }); }
  }
  reports[name] = { checked, mismatched_rows: bad, feature_differences: Object.fromEntries(fieldsWithDifferences), examples };
  console.log(name, checked, "checked;", bad, "mismatched");
}

const parityInput = path.join(root, "experiments/v2/reports/extension_inference_cases.json");
if (fs.existsSync(parityInput)) {
  const cases = JSON.parse(fs.readFileSync(parityInput));
  let maximumError = 0;
  let mismatchedDecisions = 0;
  const examples = [];
  for (const item of cases) {
    const features = extractUrl20Features(item.url);
    const probability = predictProbability(model, features);
    const error = Math.abs(probability - item.probability);
    maximumError = Math.max(maximumError, error);
    if ((probability >= .5) !== (item.probability >= .5) || error > 1e-5) {
      mismatchedDecisions++;
      if (examples.length < 10) examples.push({ url: item.url, python: item.probability, javascript: probability });
    }
  }
  reports.inference = { checked: cases.length, maximum_probability_error: maximumError, mismatched_decisions: mismatchedDecisions, examples };
}
const passed = Object.values(reports).every(row => (row.mismatched_rows || row.mismatched_decisions || 0) === 0);
const report = { feature_count: 20, comparison: "Exact float32 model-input values", reports, passed };
fs.writeFileSync(path.join(root, "experiments/v2/reports/extension_parity.json"), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
if (!passed) process.exitCode = 1;
