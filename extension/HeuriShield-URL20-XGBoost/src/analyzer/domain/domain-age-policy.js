/** Pure policy evaluation. Caller supplies the saved, observed age and config. */
export function evaluateDomainAgeRule(age, dom, brand) {
  const sensitive = dom?.has_password_field === true || dom?.has_sensitive_input === true ? true :
    dom?.has_password_field === false && dom?.has_sensitive_input === false ? false : 'unknown';
  const conditions = [age.supporting_risk_signal,sensitive,brand?.brand_domain_mismatch ?? 'unknown'];
  return {id:'R11',status:age.category === 'unknown' ? 'undetermined' :
    conditions.includes(false) ? 'not_matched' : conditions.every(value => value === true) ? 'matched' : 'undetermined',
    evidence_ids:['domain_age_days','B07','D01','D02'],
    supporting_only:true,age_category:age.category};
}
export function classifyDomainAge(value, policy) {
  const numeric = typeof value === "number" && Number.isFinite(value) && value >= 0;
  if (!numeric) {
    return { policy_version: policy.version, domain_age_days: null,
      category: policy.unknown.id, label: policy.unknown.label,
      supporting_risk_signal: "unknown", standalone_verdict_change: false };
  }
  const days = Math.floor(value);
  const category = policy.categories.find(item => days >= item.min_days &&
    (item.max_days === null || days <= item.max_days));
  if (!category) throw new Error("Domain age category missing from policy");
  return { policy_version: policy.version, domain_age_days: value,
    category: category.id, label: category.label,
    supporting_risk_signal: days <= policy.supporting_signal_max_days,
    standalone_verdict_change: false };
}
