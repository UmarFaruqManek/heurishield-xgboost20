/*
 * Klien API pencarian brand: Clearbit lebih dahulu, Brandfetch pelengkap/verifikasi.
 * Hasil direktori adalah kandidat identitas, bukan bukti keamanan atau kepemilikan.
 */
import { parse as parseDomain } from "../../shared/tldts.js";

const DEFAULT_BRANDFETCH_API = "https://api.brandfetch.io/v2/search/{query}";
const DEFAULT_CLEARBIT_API = "https://autocomplete.clearbit.com/v1/companies/suggest?query={token}";
const DEFAULT_TIMEOUT_MS = 7000;

export async function searchBrand(query, options = {}) {
  // Clearbit is tried first; an empty or failed result never suppresses
  // Brandfetch. Brandfetch also verifies matching domains returned by Clearbit.
  const primary = await searchClearbit(query, options.clearbit || {});
  const secondary = await searchBrandfetch(query, options.brandfetch || {});
  const provider_attempts = [
    { provider: "clearbit", lookup_success: primary.lookup_success,
      candidate_count: primary.candidates.length, status: primary.status,
      http_status: primary.http_status ?? null, retry_after_ms: primary.retry_after_ms ?? null },
    { provider: "brandfetch", lookup_success: secondary.lookup_success,
      candidate_count: secondary.candidates.length, status: secondary.status,
      http_status: secondary.http_status ?? null, retry_after_ms: secondary.retry_after_ms ?? null }
  ];
  if (!primary.candidates.length) {
    return { ...secondary, lookup_success: primary.lookup_success || secondary.lookup_success,
      provider_attempts };
  }
  const scoresByDomain = new Map(secondary.candidates.map((candidate) => [candidate.domain, candidate]));
  return {
    ...primary,
    lookup_success: primary.lookup_success || secondary.lookup_success,
    provider_attempts,
    candidates: [...primary.candidates.map((candidate) => {
      const scores = scoresByDomain.get(candidate.domain);
      return {
        ...candidate,
        _score: scores?._score ?? null,
        qualityScore: scores?.qualityScore ?? null,
        score_source: scores ? "brandfetch" : null,
        verified: scores?.verified === true,
        brandId: scores?.brandId || null
      };
    }), ...secondary.candidates.filter((candidate) => !primary.candidates.some((item) => item.domain === candidate.domain))]
  };
}

export async function searchClearbit(query, options = {}) {
  const cleanQuery = String(query || "").trim();
  if (!cleanQuery) return lookupResult(cleanQuery, [], false);
  const apiUrl = options.apiUrl || DEFAULT_CLEARBIT_API;
  const url = new URL(apiUrl.replace("{token}", encodeURIComponent(cleanQuery)));
  if (!apiUrl.includes("{token}")) url.searchParams.set("query", cleanQuery);
  return fetchBrandCandidates(cleanQuery, url.toString(), normalizeClearbitItem, options);
}

export async function searchBrandfetch(query, options = {}) {
  const cleanQuery = String(query || "").trim();
  if (!cleanQuery) return lookupResult(cleanQuery, [], false);

  const apiUrl = options.apiUrl || DEFAULT_BRANDFETCH_API;
  const url = apiUrl.includes("{query}")
    ? apiUrl.replace("{query}", encodeURIComponent(cleanQuery))
    : `${apiUrl.replace(/\/$/, "")}/${encodeURIComponent(cleanQuery)}`;

  return fetchBrandCandidates(cleanQuery, url, normalizeBrandfetchItem, options);
}

const providerCooldowns = new Map();
let runningLookups = 0;
const lookupQueue = [];
async function acquireLookup() {
  if (runningLookups >= 4) await new Promise(resolve => lookupQueue.push(resolve));
  else runningLookups++;
}
function releaseLookup() {
  const next = lookupQueue.shift();
  if (next) next();
  else runningLookups--;
}
async function fetchBrandCandidates(query, url, normalizeItem, options) {
  await acquireLookup();
  const provider = new URL(url).origin;
  if ((providerCooldowns.get(provider) || 0) > Date.now()) {
    releaseLookup();
    return { ...lookupResult(query, [], false), status: "provider_cooldown",
      retry_after_ms: providerCooldowns.get(provider) - Date.now() };
  }
  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeout = controller ? setTimeout(() => controller.abort(), Number(options.timeoutMs || DEFAULT_TIMEOUT_MS)) : null;
  try {
    const response = await fetch(url, {
      headers: { accept: "application/json" },
      signal: controller?.signal
    });
    if (!response.ok) {
      let retry = null;
      if (response.status === 429 || response.status === 503) {
        const value = response.headers?.get?.("retry-after");
        retry = Math.max(1000, Number.isFinite(Number(value)) && value !== null
          ? Number(value) * 1000 : Number.isFinite(Date.parse(value)) ? Date.parse(value) - Date.now() : 60000);
        providerCooldowns.set(provider, Date.now() + retry);
      }
      return { ...lookupResult(query, [], false), status: response.status === 429 ? "rate_limited" : "http_error",
        http_status: response.status, retry_after_ms: retry };
    }
    const data = await response.json();
    if (!Array.isArray(data)) return { ...lookupResult(query, [], false), status: "invalid_response" };
    const results = data.slice(0, 8).map(normalizeItem).filter(Boolean);
    return { ...lookupResult(query, results, true), status: results.length ? "matched" : "no_match", http_status: response.status };
  } catch (error) {
    return { ...lookupResult(query, [], false), status: error?.name === "AbortError" ? "timeout" :
      error instanceof SyntaxError ? "invalid_json" : "network_error" };
  } finally {
    if (timeout) clearTimeout(timeout);
    releaseLookup();
  }
}

function lookupResult(query, candidates, lookupSuccess) {
  return { query, candidates, lookup_success: Boolean(lookupSuccess) };
}

function normalizeClearbitItem(item) {
  if (!item || typeof item !== "object") return null;
  const domain = registrableBrandDomain(item.domain);
  if (!domain) return null;
  return { name: item.name || null, domain, source: "clearbit", _score: null, qualityScore: null };
}

function normalizeBrandfetchItem(item) {
  if (!item || typeof item !== "object") return null;
  const domain = registrableBrandDomain(item.domain);
  if (!domain) return null;
  return {
    name: item.name || null,
    domain,
    source: "brandfetch",
    _score: numberOrNull(item._score ?? item.score),
    qualityScore: numberOrNull(item.qualityScore),
    verified: item.verified === true,
    brandId: item.brandId || null
  };
}

function registrableBrandDomain(value) {
  const host = String(value || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .toLowerCase();
  if (!host || !host.includes(".")) return null;

  const domain = parseDomain(host, { allowPrivateDomains: false });
  if (domain.isIp || !domain.domain || !domain.publicSuffix) return null;
  return domain.domain;
}

function numberOrNull(value) {
  if (value == null || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}
