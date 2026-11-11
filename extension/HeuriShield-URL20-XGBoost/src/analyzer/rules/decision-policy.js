/*
 * Decision policy: brand/DOM diperiksa lebih dahulu; kelas URL dipakai hanya
 * jika brand/DOM tidak memberikan alasan.
 *   1. Kelas URL tidak tersedia            -> LIMITED (status teknis)
 *   2. Ada rule phishing yang matched       -> DANGEROUS
 *   3. Ada rule legitimate yang matched     -> SAFE
 *   4. Selain itu                           -> kelas URL
 * Policy hanya membaca kelas URL dan status rule; tidak membaca parameter.
 */
export function decide(urlClass, ruleResults = []) {
  if (!["SAFE", "DANGEROUS"].includes(urlClass)) return { verdict: "LIMITED", source: "url_unavailable", reasons: [] };
  const matched = decision => ruleResults
    .filter(rule => rule.decision === decision && rule.status === "matched").map(rule => rule.id);
  const phishing = matched("phishing");
  if (phishing.length) return { verdict: "DANGEROUS", source: "brand_dom_phishing", reasons: phishing };
  const legitimate = matched("legitimate");
  if (legitimate.length) return { verdict: "SAFE", source: "brand_dom_legitimate", reasons: legitimate };
  return { verdict: urlClass, source: "url_model", reasons: [] };
}
