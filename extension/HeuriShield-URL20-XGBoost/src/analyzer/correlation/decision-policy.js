/* Policy consumes only the URL class and evaluated rule IDs/statuses.
 * DOM/brand conditions belong to the rule engine, never to this module. */
const LEGITIMATE_RULES = [
  ['R14', 'verified_oauth_provider_page'],
  ['R15', 'corroborated_own_domain_review'],
  ['R16', 'verified_own_domain_login'],
  ['R17', 'verified_own_domain_documentation_page'],
  ['R18', 'verified_own_domain_search_page'],
  ['R19', 'verified_own_domain_non_sensitive_page']
];
const CONFLICT_RULES = ['R03','R04','R05','R07','R09','R10','R12','R13'];

export function decideWithEvidence(urlVerdict, rules = [], review = {}) {
  const matched = new Set(rules.filter(rule => rule.status === 'matched').map(rule => rule.id));
  const decision = (verdict, source) => ({verdict,source,review_candidate:false,review_reason:null});
  if (!['SAFE','DANGEROUS'].includes(urlVerdict)) return decision('LIMITED','url_unavailable');
  if (urlVerdict === 'DANGEROUS' && matched.has('R12')) return decision('DANGEROUS','url_brand_download_phishing');
  if (matched.has('R13')) return decision('DANGEROUS','brand_executable_download_phishing');
  if (['R03','R07','R10'].some(id => matched.has(id))) return decision('DANGEROUS','confirmed_credential_impersonation');
  if (matched.has('R09')) return decision('DANGEROUS','corroborated_brand_impersonation');
  if (urlVerdict === 'DANGEROUS' && !CONFLICT_RULES.some(id => matched.has(id))) {
    const correction = LEGITIMATE_RULES.find(([id]) => matched.has(id));
    if (correction) return {...decision('SAFE',correction[1]),
      ...(correction[0] === 'R15' ? {corroboration:'parent_site_link'} : {})};
  }
  // Review metadata is descriptive only; it never changes the verdict.
  return {verdict:urlVerdict,source:'url_model',
    review_candidate:review.review_candidate === true,
    review_reason:review.review_candidate === true ? review.review_reason || null : null};
}
