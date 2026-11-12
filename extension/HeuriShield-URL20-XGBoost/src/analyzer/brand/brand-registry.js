/*
 * Registri brand lokal: brand yang sering ditiru beserta SELURUH domain resminya.
 * Dipakai sebagai acuan terverifikasi bila API brand gagal atau tidak mengenali
 * brand. Konfigurasi manual (bukan hasil pelatihan), sama seperti daftar
 * shared hosting. Hanya brand yang domain resminya dapat didaftar lengkap;
 * brand dengan banyak domain negara (Amazon, Google, DHL) sengaja tidak dimasukkan
 * agar domain negara yang sah tidak dianggap peniru.
 * Kunci: token nama brand (huruf kecil, tanpa spasi).
 */
export const BRAND_REGISTRY = new Map([
  // Indonesia
  ["bca", { name: "BCA", domains: ["bca.co.id", "klikbca.com"] }],
  ["bni", { name: "BNI", domains: ["bni.co.id"] }],
  ["bri", { name: "BRI", domains: ["bri.co.id"] }],
  ["brimo", { name: "BRImo", domains: ["bri.co.id"] }],
  ["livin", { name: "Livin' by Mandiri", domains: ["bankmandiri.co.id"] }],
  ["bankmandiri", { name: "Bank Mandiri", domains: ["bankmandiri.co.id"] }],
  ["ovo", { name: "OVO", domains: ["ovo.id"] }],
  ["gopay", { name: "GoPay", domains: ["gopay.co.id", "gojek.com"] }],
  ["gojek", { name: "Gojek", domains: ["gojek.com", "gopay.co.id"] }],
  ["shopee", { name: "Shopee", domains: ["shopee.co.id", "shopee.com"] }],
  ["tokopedia", { name: "Tokopedia", domains: ["tokopedia.com"] }],
  ["bukalapak", { name: "Bukalapak", domains: ["bukalapak.com"] }],
  ["lazada", { name: "Lazada", domains: ["lazada.co.id", "lazada.com"] }],
  ["blibli", { name: "Blibli", domains: ["blibli.com"] }],
  ["traveloka", { name: "Traveloka", domains: ["traveloka.com"] }],
  ["telkomsel", { name: "Telkomsel", domains: ["telkomsel.com"] }],
  // Global
  ["paypal", { name: "PayPal", domains: ["paypal.com", "paypal.me"] }],
  ["instagram", { name: "Instagram", domains: ["instagram.com"] }],
  ["facebook", { name: "Facebook", domains: ["facebook.com", "fb.com"] }],
  ["whatsapp", { name: "WhatsApp", domains: ["whatsapp.com"] }],
  ["netflix", { name: "Netflix", domains: ["netflix.com"] }],
  ["binance", { name: "Binance", domains: ["binance.com"] }],
  ["coinbase", { name: "Coinbase", domains: ["coinbase.com"] }],
  ["metamask", { name: "MetaMask", domains: ["metamask.io"] }],
  ["roblox", { name: "Roblox", domains: ["roblox.com"] }],
  ["dropbox", { name: "Dropbox", domains: ["dropbox.com"] }],
  ["docusign", { name: "DocuSign", domains: ["docusign.com", "docusign.net"] }],
  ["linkedin", { name: "LinkedIn", domains: ["linkedin.com"] }],
  ["adobe", { name: "Adobe", domains: ["adobe.com"] }],
  ["steamcommunity", { name: "Steam", domains: ["steamcommunity.com", "steampowered.com"] }],
  ["steampowered", { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"] }]
]);

const compact = value => String(value || "").normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "");

/** Registry entry for an exact brand token, or null. */
export function registryEntry(token) {
  return BRAND_REGISTRY.get(compact(token)) || null;
}

/** Registry entry whose display name matches a brand name, or null. */
export function registryEntryByName(name) {
  const target = compact(name);
  for (const entry of BRAND_REGISTRY.values()) if (compact(entry.name) === target) return entry;
  return null;
}

/** All registry keys, for approximate (lookalike) host matching. */
export function registryKeys() {
  return [...BRAND_REGISTRY.keys()];
}
