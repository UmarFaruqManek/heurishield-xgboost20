import { STORAGE_KEYS } from "../utils/constants.js";

export async function saveFeatureJsonArchive(analysis) {
  // Arsip mentah untuk audit/debug berbeda dari tiga alasan ringkas yang terlihat di UI.
  if (!analysis?.feature_vector?.vector) return;

  const observedAt = new Date().toISOString();
  const archive = {
    archive_version: "heurishield-v5-feature-json-v1",
    observed_at: observedAt,
    analyzer_version: analysis.analyzer_version,
    document_id: analysis.document_id,
    tab_id: analysis.tab_id,
    url: analysis.url,
    original_url: analysis.original_url,
    final_url: analysis.final_url,
    normalized_url: analysis.normalized_url,
    hostname: analysis.hostname,
    registrable_domain: analysis.registrable_domain,
    verdict: analysis.verdict,
    model_result: compactModelResult(analysis.model_result),
    brand_identity: analysis.brand_identity || null,
    correlation_rules: analysis.correlation_rules || [],
    oauth_context: analysis.oauth_context === true,
    decision_policy: analysis.decision_policy || null,
    unresolved_checks: [...(analysis.dom_features?.unresolved_checks || []), ...(analysis.brand_features?.unresolved_checks || [])],
    feature_vector_coverage: analysis.feature_vector_coverage,
    feature_vector_20: analysis.feature_vector.vector,
    feature_vector_values: analysis.feature_vector.values,
    feature_sources: {
      url: analysis.url_features || null,
      dom: analysis.dom_features || null,
      rdap: analysis.rdap_features || null,
      brand: analysis.brand_features || null,
      status: analysis.page_status_features || null
    }
  };

  try {
    const result = await chrome.storage.local.get({ [STORAGE_KEYS.FEATURE_ARCHIVE]: [] });
    const archives = Array.isArray(result[STORAGE_KEYS.FEATURE_ARCHIVE])
      ? result[STORAGE_KEYS.FEATURE_ARCHIVE]
      : [];
    archives.unshift({
      id: `${fileTimestamp(observedAt)}_${safeFilePart(analysis.hostname || "unknown")}_${safeFilePart(analysis.document_id || "analysis")}`,
      path_hint: `riwayat/json/${fileTimestamp(observedAt)}_${safeFilePart(analysis.hostname || "unknown")}_${safeFilePart(analysis.document_id || "analysis")}.json`,
      ...archive
    });
    await chrome.storage.local.set({ [STORAGE_KEYS.FEATURE_ARCHIVE]: archives.slice(0, 500) });
  } catch (error) {
    console.warn("HeuriShield feature archive storage failed:", error?.message || error);
  }
}

function compactModelResult(model) {
  if (!model || typeof model !== "object") return null;
  return {
    model_family: model.model_family || null,
    model_name: model.model_name || null,
    threshold: model.threshold ?? null,
    source_model_sha256: model.source_model_sha256 || null,
    feature_set: model.feature_set || null,
    predicted_label: model.predicted_label || model.targetLabel || null,
    verdict: model.verdict || null,
    raw_verdict: model.raw_verdict || model.verdict || null,
    post_model_guard: model.post_model_guard || null,
    fired_rule_count: model.fired_rule_count ?? null,
    top_fired_rules: Array.isArray(model.fired_rules)
      ? model.fired_rules.slice(0, 6).map((rule) => ({
          id: rule.id,
          coefficient: rule.coefficient,
          direction: rule.direction,
          expression: rule.expression
        }))
      : [],
    feature_coverage: model.feature_coverage || model.features || null
  };
}


function fileTimestamp(value) {
  return String(value || new Date().toISOString()).replace(/[:.]/g, "-");
}

function safeFilePart(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "unknown";
}
