// stdin: {models:{name:path}, urls:[...]} -> {name:[verdict,...]}
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const E = "D:/heurishield-xgboost20/extension/HeuriShield-URL20-XGBoost/src";
const { extractUrl20Features } = await import(pathToFileURL(E + "/analyzer/url/url20-features.js"));
const { classifyUrl } = await import(pathToFileURL(E + "/model/xgboost-engine.js"));
const input = JSON.parse(readFileSync(0, "utf8"));
const out = {};
for (const [name, path] of Object.entries(input.models)) {
  const model = JSON.parse(readFileSync(path, "utf8"));
  out[name] = input.urls.map(u => { try { return classifyUrl(model, extractUrl20Features(u)) === "phishing" ? "DANGEROUS" : "SAFE"; } catch { return null; } });
}
process.stdout.write(JSON.stringify(out));
