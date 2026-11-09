// Replay the current DOM, brand, correlation, and decision code over saved evidence.
// No browser navigation or API requests occur here. The frozen URL-model verdict
// comes from the original live run; URL feature/model changes require a new test.
import { readFileSync } from "node:fs";
import { analyzeDomEvidence, verifyFormDestinations } from "../src/analyzer/dom/dom-evidence.js";
import { analyzeBrandEvidence } from "../src/analyzer/brand/brand-evidence.js";
import { evaluateCorrelation } from "../src/analyzer/correlation/evidence-rules.js";
import { evaluateCorrectionRules } from "../src/analyzer/correlation/correction-rules.js";
import { decideWithEvidence } from "../src/analyzer/correlation/decision-policy.js";
import { ageLookupDomain } from "../src/analyzer/url/url18-features.js";
import { urlFileExtension } from '../src/analyzer/url/download-file-extension.js';

import {classifyDomainAge,evaluateDomainAgeRule} from "../src/analyzer/domain/domain-age-policy.js";
const agePolicy=JSON.parse(readFileSync(new URL("../src/model/domain-age-policy.json",import.meta.url),"utf8"));

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

  let dom = analysis.dom_features || null;
  let brand = analysis.brand_features || null;
  let level = "decision_only";
  const saved = analysis.replay_evidence;
  if (saved?.main_snapshot && Array.isArray(saved.snapshots) && brand?.lookup_replay) {
    const lookup = brand.lookup_replay;
    const searches = new Map((lookup.searches || []).map(result => [result.token, result]));
    const missing = [];
    const readLookup = token => {
      if (searches.has(token)) return searches.get(token);
      missing.push(`brand:${token}`);
      return { lookup_success: false, candidates: [] };
    };
    const readDomain = root => {
      if (lookup.domain && lookup.domain.registrable_domain === root) return lookup.domain;
      missing.push(`domain:${root}`);
      return { lookup_success: false, found: false };
    };
    const readVerification = token => {
      if (lookup.verification?.token === token) return lookup.verification;
      missing.push(`verification:${token}`);
      return { lookup_success: false, candidates: [] };
    };
    const readDomainSearch = root => {
      if (lookup.domain_search?.queried_domain === root) return lookup.domain_search;
      missing.push(`domain_search:${root}`);
      return { lookup_success: false, found: false, candidates: [], status: "not_recorded" };
    };
    dom = analyzeDomEvidence(saved.snapshots, saved.navigation);
    brand = await analyzeBrandEvidence(saved.main_snapshot, analysis.final_url || item.url,
      { lookup: readLookup, domainLookup: readDomain, verifyLookup: readVerification, domainSearch: readDomainSearch });
    level = missing.length ? "partial_api_snapshot" : "full_snapshot";
    if (missing.length) base.missing_saved_lookups = [...new Set(missing)];
  }

  dom = verifyFormDestinations(dom, brand);
  const correlation = evaluateCorrelation(dom, brand, { urlVerdict: base.url_model_verdict,
    urlFileExtension: urlFileExtension(analysis.original_url || analysis.url || item.url) });
  correlation.rules.push(evaluateDomainAgeRule(classifyDomainAge(analysis.rdap_features?.source_domain_age_days ?? null,agePolicy),dom,brand));
  const context = {
    domainAgeDays: analysis.rdap_features?.source_domain_age_days ?? null,
    sameSite: ageLookupDomain(item.url) === ageLookupDomain(analysis.final_url || item.url),
    parentSiteLink: analysis.parent_site_link_observed === true,
    pageRegistrableDomain: analysis.registrable_domain,
    pageUrl: analysis.final_url || item.url,
    mainSnapshot: saved?.main_snapshot || null
  };
  const corrections = evaluateCorrectionRules(base.url_model_verdict, dom, brand, correlation, context);
  correlation.rules.push(...corrections.rules);
  const decision = decideWithEvidence(base.url_model_verdict, correlation.rules, corrections);
  output.push({ ...base, replay_level: level, new_verdict: decision.verdict,
    old_source: analysis.decision_policy?.source || null,
    new_source: decision.source,
    changed: decision.verdict !== item.old_verdict,
    review_candidate: decision.review_candidate === true,
    matched_rules: correlation.rules.filter(rule => rule.status === "matched").map(rule => rule.id),
    brand_status: brand?.claimed_brand_status || null,
    official_domain_match: brand?.official_domain_match ?? null,
    dom_sensitive: dom?.has_sensitive_input === true || dom?.has_password_field === true,
    ...(input.include_evidence ? { replayed_brand: brand, replayed_dom: dom } : {}) });
}

process.stdout.write(JSON.stringify({ records: output }));
