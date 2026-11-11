// Replay the current DOM, brand, rule and decision code over saved evidence.
// No browser navigation or API requests occur here. The frozen URL-model class
// comes from the original live run; URL feature/model changes require a new test.
// stdin: {records:[{index,url,expected_label,analysis_status,old_verdict,analysis}], include_evidence?}
import { readFileSync } from "node:fs";
import { analyzeDomEvidence } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { urlFileExtension } from "../src/analyzer/url/download-file-extension.js";
import { ageLookupDomain } from "../src/analyzer/url/url18-features.js";
import { collectParameters } from "../src/analyzer/rules/parameters.js";
import { evaluateRules } from "../src/analyzer/rules/heuristic-rules.js";
import { decide } from "../src/analyzer/rules/decision-policy.js";

const input = JSON.parse(readFileSync(0, "utf8"));
const output = [];

for (const item of input.records || []) {
  const analysis = item.analysis;
  const base = { index: item.index, url: item.url, expected_label: item.expected_label,
    analysis_status: item.analysis_status, old_verdict: item.old_verdict,
    url_model_verdict: analysis?.model_result?.verdict || null };
  if (item.analysis_status !== "completed" || !analysis?.model_result?.ready ||
      !["SAFE", "DANGEROUS"].includes(base.url_model_verdict)) {
    output.push({ ...base, replay_level: "not_replayable", new_verdict: null,
      reason: "No completed URL model analysis" });
    continue;
  }

  const { dom, brand, level, missing } = await replayEvidence(analysis, item.url);
  if (missing.length) base.missing_saved_lookups = missing;
  const parameters = collectParameters({ brand, dom,
    domainAgeDays: pageDomainAge(analysis, item.url),
    urlFileExtension: urlFileExtension(analysis.original_url || analysis.url || item.url) });
  const rules = evaluateRules(parameters);
  const decision = decide(base.url_model_verdict, rules);
  output.push({ ...base, replay_level: level, new_verdict: decision.verdict,
    old_source: analysis.decision_policy?.source || null,
    new_source: decision.source,
    changed: decision.verdict !== item.old_verdict,
    matched_rules: rules.filter(rule => rule.status === "matched").map(rule => rule.id),
    parameters,
    ...(input.include_evidence ? { replayed_brand: brand, replayed_dom: dom } : {}) });
}

process.stdout.write(JSON.stringify({ records: output }));

// Saved runs looked up the age of the initial URL's domain. It describes the
// analyzed page only when both URLs share one registrable domain.
function pageDomainAge(analysis, url) {
  if ("page_domain_age_days" in (analysis.rdap_features || {})) return analysis.rdap_features.page_domain_age_days;
  const lookedUp = analysis.rdap_features?.lookup_domain || ageLookupDomain(analysis.original_url || url);
  const page = ageLookupDomain(analysis.final_url || url);
  return lookedUp && lookedUp === page ? analysis.rdap_features?.source_domain_age_days ?? null : null;
}

// Rebuild DOM/brand evidence from the saved snapshot and saved API responses.
// Lookups that were never recorded return "failed" and are listed as missing.
async function replayEvidence(analysis, url) {
  const saved = analysis.replay_evidence;
  const lookup = analysis.brand_features?.lookup_replay;
  if (!saved?.main_snapshot || !Array.isArray(saved.snapshots) || !lookup) {
    return { dom: analysis.dom_features || null, brand: analysis.brand_features || null,
      level: "decision_only", missing: [] };
  }
  const missing = [];
  const searches = new Map((lookup.searches || []).map(result => [result.token, result]));
  const recorded = (key, found, fallback) => {
    if (found) return found;
    missing.push(key);
    return fallback;
  };
  const brand = await analyzeBrandEvidence(saved.main_snapshot, analysis.final_url || url, {
    lookup: token => recorded(`brand:${token}`, searches.get(token), { lookup_success: false, candidates: [] }),
    domainLookup: root => recorded(`domain:${root}`,
      lookup.domain?.registrable_domain === root ? lookup.domain : null, { lookup_success: false, found: false }),
    verifyLookup: token => recorded(`verification:${token}`,
      lookup.verification?.token === token ? lookup.verification : null, { lookup_success: false, candidates: [] }),
    domainSearch: root => recorded(`domain_search:${root}`,
      lookup.domain_search?.queried_domain === root ? lookup.domain_search : null,
      { lookup_success: false, found: false, candidates: [], status: "not_recorded" })
  });
  return { dom: analyzeDomEvidence(saved.snapshots, saved.navigation), brand,
    level: missing.length ? "partial_api_snapshot" : "full_snapshot", missing: [...new Set(missing)] };
}
