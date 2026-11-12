/* URL20 adds the same three numerical definitions used by the Python training extractor. */
import { parse as parseDomain } from "../../shared/tldts.js";
import { extractUrl18Features, ageLookupDomain, hostnameForFeatures } from "./url18-features.js";

const sensitiveTokens = new Set([
  "account", "admin", "auth", "confirm", "login", "logon", "otp",
  "password", "reset", "secure", "signin", "update", "verification", "verify"
]);

export { ageLookupDomain };

// Model v3 is trained on WHATWG-normalized URLs, the same form the browser
// reports for a tab (e.g. "https://a.com" becomes "https://a.com/"). Offline
// inputs are normalized here so they match what the model sees live.
export function normalizeUrlForFeatures(input) {
  try { return new URL(input).href; } catch { return input; }
}

export function extractUrl20Features(rawInput) {
  const input = normalizeUrlForFeatures(rawInput);
  const features = extractUrl18Features(input);
  const host = hostnameForFeatures(input);
  const parserHost = host.split(".").map(label => label.replace(/^[-_]+|[-_]+$/g, "") || "x").join(".");
  const parsed = parseDomain(parserHost, { allowPrivateDomains: true });
  // Recover original label spelling after using sanitized labels solely for PSL lookup.
  const suffixLabels = (parsed.isIcann || parsed.isPrivate) && parsed.publicSuffix
    ? parsed.publicSuffix.split(".").length : 0;
  const labels = host.split(".");
  const domainLabel = features.has_ip_host ? host.split(":")[0] : labels[labels.length - suffixLabels - 1] || "";
  const digitRuns = host.match(/[0-9]+/g) || [];
  const tokens = host.match(/[a-z0-9]+/g) || [];
  return {
    ...features,
    domain_label_length: Array.from(domainLabel).length,
    hostname_longest_digit_run: Math.max(0, ...digitRuns.map(value => value.length)),
    hostname_sensitive_token_count: tokens.filter(token => sensitiveTokens.has(token)).length
  };
}
