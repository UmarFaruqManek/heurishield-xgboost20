/*
 * Penjelasan untuk pengguna. Urutan alasan mengikuti alur keputusan:
 * kelas URL, rule brand/DOM yang menentukan, lalu temuan brand, formulir dan unduhan.
 * Setiap baris diawali label (Alamat/Aturan/Identitas situs/Formulir/Login/Unduhan).
 */
import { EXECUTABLE_FILE_EXTENSIONS, executableExtensionEvidence } from "../analyzer/url/download-file-extension.js";

const SUMMARY = {
  brand_dom_phishing: "Pemeriksaan brand dan halaman menemukan indikasi phishing.",
  brand_dom_legitimate_corrected: "Pemeriksaan brand dan halaman mengoreksi penilaian alamat menjadi legitimate.",
  brand_dom_legitimate: "Pemeriksaan brand dan halaman mendukung bahwa situs ini resmi.",
  url_model: "Brand dan halaman tidak memberikan alasan khusus; keputusan mengikuti penilaian alamat.",
  url_unavailable: "Pemeriksaan belum lengkap."
};

export function buildAnalysisExplanation(analysis = {}) {
  const source = analysis.decision_policy?.source;
  if (source === "manual_allowlist" || source === "manual_blocklist") return manualExplanation(analysis, source);
  if (analysis.model_result?.model_family !== "XGBoost") return incompleteExplanation(analysis);

  const verdict = analysis.verdict;
  const urlClass = analysis.model_result.verdict;
  const pageUrl = analysis.final_url || analysis.url;
  const summaryKey = source === "brand_dom_legitimate" && urlClass === "DANGEROUS"
    ? "brand_dom_legitimate_corrected" : source;
  const ruleReasons = (analysis.matched_rules || [])
    .filter(rule => rule.reason).map(rule => `Aturan ${rule.id}: ${rule.reason}`);
  const reasons = [
    urlClass === "DANGEROUS" ? "Alamat: dinilai phishing oleh model."
      : urlClass === "SAFE" ? "Alamat: dinilai legitimate oleh model." : "Alamat: penilaian belum tersedia.",
    ...ruleReasons,
    brandExplanation(analysis.brand_features),
    domExplanation(analysis.dom_features, pageUrl),
    downloadExplanation(analysis)
  ].filter(Boolean);
  const offersDownload = analysis.dom_features?.has_download_link === true ||
    EXECUTABLE_FILE_EXTENSIONS.has(analysis.url_features?.url_file_extension);
  return {
    title: verdict === "DANGEROUS" ? "Terindikasi phishing"
      : verdict === "SAFE" ? "Tidak ditemukan indikasi phishing kuat" : "Pemeriksaan belum lengkap",
    summary: verdict === "LIMITED" ? SUMMARY.url_unavailable : SUMMARY[summaryKey] || SUMMARY.url_model,
    domain: hostname(pageUrl),
    reasons,
    action: verdict === "DANGEROUS"
      ? offersDownload ? "Jangan masukkan data akun atau unduh file sebelum memastikan alamat situs."
        : "Jangan masukkan kata sandi atau kode verifikasi sebelum memastikan alamat situs."
      : "Periksa alamat situs sebelum memasukkan kata sandi atau data pribadi.",
    limitation: analysis.dom_features?.unresolved_checks?.includes("inaccessible_iframe")
      ? "Sebagian isi halaman tidak dapat diperiksa." : ""
  };
}

function manualExplanation(analysis, source) {
  const allowed = source === "manual_allowlist";
  return {
    title: allowed ? "Diizinkan oleh daftar Anda" : "Diblokir oleh daftar Anda",
    summary: allowed ? "Domain ini ada di Allow list Anda." : "Domain ini ada di Block list Anda.",
    domain: hostname(analysis.final_url || analysis.url),
    reasons: [allowed ? "Anda mengizinkan domain ini secara manual; hasil model tidak digunakan untuk keputusan ini."
      : "Anda memblokir domain ini secara manual; hasil model tidak digunakan untuk keputusan ini."],
    action: allowed ? "Tetap periksa alamat situs sebelum memasukkan data pribadi."
      : "Hapus domain dari Block list jika Anda ingin membuka situs ini.",
    limitation: ""
  };
}

function incompleteExplanation(analysis) {
  return {
    title: "Pemeriksaan belum lengkap",
    summary: "Keamanan halaman belum dapat dipastikan.",
    domain: hostname(analysis.final_url || analysis.url),
    reasons: ["Data pemeriksaan belum cukup untuk menyimpulkan keamanan halaman."],
    action: "Tetap periksa alamat situs sebelum memasukkan data pribadi.",
    limitation: analysis.dom_error ? "Struktur halaman belum berhasil dibaca lengkap." : ""
  };
}

function brandExplanation(brand) {
  if (!brand || brand.claimed_brand_status === "ambiguous") return null;
  const name = brand.claimed_brand?.name;
  if (!name) return null;
  if (brand.official_domain_match === true)
    return `Identitas situs: domain cocok dengan brand ${name}.`;
  if (brand.unresolved_checks?.includes("dom_unavailable")) return null;
  if (brand.official_domain_match === false && brand.verified_reference_domain)
    return `Identitas situs: halaman menampilkan ${name}, tetapi domain yang dibuka berbeda dari domain resminya (${brand.verified_reference_domain}).`;
  return `Identitas situs: nama brand ${name} ditemukan.`;
}

function domExplanation(dom, pageUrl) {
  if (!dom || dom.unresolved_checks?.includes("dom_unavailable") || !dom.observed_frame_count) return null;
  const navigation = dom.navigation;
  if (navigation?.observed === true && navigation.destination_type === "official_provider")
    return "Login: pengalihan ke penyedia identitas resmi teramati; ini tidak membuktikan situs asal aman.";
  const fields = [...(dom.password_fields || []), ...(dom.sensitive_fields || [])];
  // Hidden controls are kept for diagnosis; they do not mean the page asks for credentials now.
  if (fields.length && fields.every(field => field.visible === false)) return null;
  const relevant = (dom.forms || []).filter(form => form.relevant === true && form.visible !== false);
  const cross = relevant.find(form => form.cross_domain === true);
  if (cross) return crossDomainFormExplanation(cross, pageUrl);
  if (relevant.some(form => form.cross_domain === "unknown"))
    return "Formulir: ditemukan formulir; tujuan pengirimannya belum teramati.";
  if (relevant.length && dom.form_cross_domain === false)
    return `Formulir: ditemukan formulir yang mengarah ke domain halaman ini (${hostname(pageUrl)}).`;
  if (dom.has_password_field === true || dom.has_sensitive_input === true)
    return "Formulir: ditemukan kolom data akun; tujuan pengirimannya belum teramati.";
  return null;
}

function crossDomainFormExplanation(form, pageUrl) {
  let target = form.destination_registrable_domain;
  try { target = new URL(form.action_origin).hostname || target; } catch { /* Keep the recorded domain. */ }
  if (!target) return "Formulir: tujuan lintas domain terdeteksi, tetapi nama domain tujuannya belum tersedia.";
  const source = form.frame_index === 0 ? hostname(pageUrl) : form.source_registrable_domain || hostname(pageUrl);
  return `Formulir: ditemukan formulir yang mengarah ke ${target}, berbeda dari domain halaman (${source}).`;
}

function downloadExplanation(analysis) {
  const dom = analysis.dom_features;
  if (dom?.has_download_link === true) {
    return executableExtensionEvidence(dom.download_file_extensions) === true
      ? "Unduhan: halaman menawarkan tautan installer atau skrip yang dapat dijalankan."
      : "Unduhan: halaman menyediakan tautan download.";
  }
  const extension = analysis.url_features?.url_file_extension;
  return EXECUTABLE_FILE_EXTENSIONS.has(extension) ? `Unduhan: alamat URL memiliki akhiran file .${extension}.` : null;
}

function hostname(value) {
  try { return new URL(value).hostname; } catch { return "domain halaman"; }
}
