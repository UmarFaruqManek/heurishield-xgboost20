// Test helper: the same parameters -> rules -> policy path as the service worker.
import { collectParameters } from "../src/analyzer/rules/parameters.js";
import { evaluateRules } from "../src/analyzer/rules/heuristic-rules.js";
import { decide } from "../src/analyzer/rules/decision-policy.js";
import { urlFileExtension } from "../src/analyzer/url/download-file-extension.js";

export function judge({ urlClass, dom = null, brand = null, domainAgeDays = null, url = null }) {
  const parameters = collectParameters({ brand, dom, domainAgeDays,
    urlFileExtension: url ? urlFileExtension(url) : null });
  const rules = evaluateRules(parameters);
  const decision = decide(urlClass, rules);
  const status = Object.fromEntries(rules.map(rule => [rule.id, rule.status]));
  return { parameters, rules, status, decision, verdict: decision.verdict,
    matched: rules.filter(rule => rule.status === "matched").map(rule => rule.id) };
}
