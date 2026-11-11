/*
 * Konstanta penyimpanan, pengaturan default, label verdict dan daftar provider OAuth.
 * Daftar provider adalah konfigurasi manual, bukan hasil pelatihan.
 */
export const STORAGE_KEYS = {
  ENABLED: "heurishieldEnabled",
  ANALYSIS_BY_TAB: "analysisByTab",
  URL_HISTORY: "urlHistory",
  FEATURE_ARCHIVE: "featureArchive",
  DOMAIN_METADATA_CACHE: "domainMetadataCache",
  WARNING_CONTEXTS: "warningContexts",
  RUNTIME_STATE_VERSION: "heurishieldRuntimeStateVersion",
  ALLOWLIST: "heurishieldAllowlist",
  BLACKLIST: "heurishieldBlacklist"
};

export const DEFAULT_SETTINGS = {
  heurishieldEnabled: true
};

export const TRUSTED_OAUTH_PROVIDER_DOMAINS = new Set([
  "google.com",
  "github.com",
  "x.com",
  "twitter.com",
  "facebook.com",
  "microsoft.com",
  "microsoftonline.com",
  "live.com",
  "apple.com",
  "linkedin.com",
  "gitlab.com",
  "bitbucket.org"
]);

export const VERDICT_LABELS_ID = {
  SAFE: "Aman",
  DANGEROUS: "Berbahaya",
  LIMITED: "Analisis Terbatas"
};
