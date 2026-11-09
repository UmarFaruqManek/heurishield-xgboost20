// Strip obsolete decision scores without removing measured URL/DOM features.
const OMIT = new Set(['score','url_score','dom_score','risk_score',
  'probability','probability_phishing','raw_probability_phishing',
  'raw_score','compatibilityScore']);
export function classificationRecord(value) {
  if (Array.isArray(value)) return value.map(classificationRecord);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !OMIT.has(key))
    .map(([key, item]) => [key, classificationRecord(item)]));
}
