/* Kategori umur domain untuk tampilan/pencatatan; rule membaca domain_age_days secara langsung. */
export function classifyDomainAge(value, policy) {
  const numeric = typeof value === "number" && Number.isFinite(value) && value >= 0;
  if (!numeric) return { policy_version: policy.version, category: policy.unknown.id, label: policy.unknown.label };
  const days = Math.floor(value);
  const category = policy.categories.find(item => days >= item.min_days &&
    (item.max_days === null || days <= item.max_days));
  if (!category) throw new Error("Domain age category missing from policy");
  return { policy_version: policy.version, category: category.id, label: category.label };
}
