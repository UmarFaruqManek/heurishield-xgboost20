// Integration helper: mirror the worker's explicit rules -> policy boundary.
import {evaluateCorrectionRules} from '../src/analyzer/correlation/correction-rules.js';
import {decideWithEvidence as applyPolicy} from '../src/analyzer/correlation/decision-policy.js';
export function decideWithEvidence(urlVerdict, dom, brand, correlation, context = {}) {
  const corrections=evaluateCorrectionRules(urlVerdict,dom,brand,correlation,context);
  return applyPolicy(urlVerdict,[...(correlation?.rules || []),...corrections.rules],corrections);
}
