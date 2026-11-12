/*
 * Penjelasan untuk pengguna awam, untuk keputusan phishing MAUPUN legitimate.
 *
 * Setiap alasan berbentuk "Label: kalimat. [P1]". Label menjelaskan jenis temuan,
 * kalimat memakai fakta nyata dari pemeriksaan (nama brand, domain resmi, umur
 * domain, tujuan pengiriman data, jenis file), dan kode aturan di akhir (opsional)
 * ditampilkan kecil sebagai jejak teknis.
 *
 * Urutan: (1) alasan yang menentukan keputusan, (2) penilaian pola alamat,
 * (3) temuan pendukung yang belum disebut. Tampilan memakai 3 alasan pertama.
 */
import { EXECUTABLE_FILE_EXTENSIONS } from "../analyzer/url/download-file-extension.js";

const EXFIL_SERVICES = [
  [/telegram/, "Telegram"], [/discord/, "Discord"], [/slack/, "Slack"], [/formspree/, "Formspree"],
  [/getform/, "Getform"], [/formsubmit/, "FormSubmit"], [/submit-form/, "Submit-Form"],
  [/formcarry/, "Formcarry"], [/script\.google/, "Google Apps Script"], [/webhook\.site/, "Webhook.site"],
  [/pipedream/, "Pipedream"]
];
const PLATFORM_NAMES = [
  [/google\.com$/, "Google"], [/sharemyhtml\.com$/, "ShareMyHTML"], [/office\.com$|forms\.gle$|live\.com$|1drv\.ms$/, "Microsoft"],
  [/dropbox\.com$/, "Dropbox"], [/ipfs|dweb\.link$/, "IPFS"], [/telegra\.ph$/, "Telegraph"], [/notion\.so$/, "Notion"],
  [/linktr\.ee$/, "Linktree"], [/googleapis\.com$/, "Google Cloud"]
];

export function buildAnalysisExplanation(analysis = {}) {
  const source = analysis.decision_policy?.source;
  if (source === "manual_allowlist" || source === "manual_blocklist") return manualExplanation(analysis, source);
  if (analysis.model_result?.model_family !== "XGBoost") return incompleteExplanation(analysis);

  const facts = gatherFacts(analysis);
  const verdict = analysis.verdict;
  const urlClass = analysis.model_result.verdict;
  const matched = (analysis.matched_rules || []).filter(rule => rule.id);
  const deciding = matched.filter(rule => verdict === "DANGEROUS" ? rule.id.startsWith("P") : rule.id.startsWith("L"));
  const covered = new Set();
  const reasons = [];

  // 1. The reasons that decided the result, in plain language with real facts.
  for (const rule of deciding) {
    const sentence = ruleSentence(rule.id, facts, covered);
    if (sentence) reasons.push(sentence);
  }
  // 2. What the address pattern (URL model) said, phrased against the final result.
  const urlLine = urlSentence(verdict, urlClass, deciding.length > 0);
  if (urlLine) reasons.push(urlLine);
  // 3. Supporting findings not already stated by a rule sentence.
  reasons.push(...supportingSentences(facts, covered, verdict));

  return {
    title: verdict === "DANGEROUS" ? "Terindikasi phishing"
      : verdict === "SAFE" ? "Tidak ditemukan indikasi phishing" : "Pemeriksaan belum lengkap",
    summary: summaryFor(verdict, source, facts, deciding),
    domain: facts.host,
    reasons,
    action: actionFor(verdict, facts),
    limitation: limitationFor(analysis, facts)
  };
}

// ---------------------------------------------------------------------------
// Facts read from the analysis (never from the URL model's internals).

function gatherFacts(analysis) {
  const brand = analysis.brand_features || {};
  const dom = analysis.dom_features || {};
  const pageUrl = analysis.final_url || analysis.url;
  const host = hostname(pageUrl);
  const age = Number.isFinite(analysis.rdap_features?.page_domain_age_days) ? analysis.rdap_features.page_domain_age_days
    : Number.isFinite(analysis.parameters?.domain_age_days) ? analysis.parameters.domain_age_days : null;
  const domReadable = Boolean(dom.observed_frame_count) && !dom.unresolved_checks?.includes("dom_unavailable");
  const fields = [...(dom.password_fields || []), ...(dom.sensitive_fields || [])];
  const visibleCredentials = domReadable && fields.length > 0 && !fields.every(field => field.visible === false);
  const relevantForms = (dom.forms || []).filter(form => form.relevant === true && form.visible !== false);
  const crossForm = relevantForms.find(form => form.cross_domain === true);
  const exfil = (dom.credential_exfil_endpoints || [])[0] || null;
  const extensions = [
    ...(Array.isArray(dom.download_file_extensions) ? dom.download_file_extensions : []),
    analysis.url_features?.url_file_extension
  ].filter(ext => EXECUTABLE_FILE_EXTENSIONS.has(ext));
  return {
    host,
    brand: brand.claimed_brand_status === "ambiguous" ? null : brand.claimed_brand?.name || null,
    official: brand.verified_reference_domain || null,
    officialMatch: brand.official_domain_match,
    hostClaim: brand.host_brand_claim,
    pathHosted: brand.self_reference_conflict === "path_hosted_user_content",
    age,
    credentials: visibleCredentials ? credentialText(dom) : null,
    credentialTarget: exfil ? exfilName(exfil)
      : crossForm ? formTarget(crossForm) : null,
    credentialTargetKnownSame: visibleCredentials && relevantForms.length > 0 && dom.form_cross_domain === false,
    oauthRedirect: dom.navigation?.observed === true && dom.navigation.destination_type === "official_provider",
    download: extensions[0] || null,
    otherDownload: dom.has_download_link === true && !extensions.length,
    pageUrl
  };
}

function credentialText(dom) {
  const kinds = [];
  if ((dom.password_fields || []).some(field => field.visible !== false)) kinds.push("kata sandi");
  const types = new Set((dom.sensitive_fields || []).filter(field => field.visible !== false).map(field => field.type));
  if (types.has("otp")) kinds.push("kode OTP");
  if (types.has("pin")) kinds.push("PIN");
  if (types.has("card") || types.has("cvv")) kinds.push("data kartu");
  if (types.has("recovery")) kinds.push("kode pemulihan");
  return kinds.length ? joinList(kinds) : "data akun";
}

// ---------------------------------------------------------------------------
// Sentences.

function ruleSentence(id, f, covered) {
  const brand = f.brand || "brand lain";
  switch (id) {
    case "P1":
      covered.add("brand");
      return f.hostClaim === "lookalike" || f.hostClaim === "subdomain_lookalike"
        ? `Peniruan alamat: alamat ${f.host} dibuat mirip dengan ${f.official || brand}, situs resmi ${brand}. [P1]`
        : `Peniruan alamat: alamat ${f.host} memakai nama ${brand}, padahal situs resmi ${brand} adalah ${f.official || "domain lain"}. [P1]`;
    case "P2":
      covered.add("credentials");
      return `Pengiriman data: ${f.credentials || "data akun"} yang Anda ketik akan dikirim ke ${f.credentialTarget || "situs lain"}, bukan ke situs resmi ${brand}. [P2]`;
    case "P3":
      covered.add("credentials"); covered.add("brand");
      return `Situs baru: situs ini baru dibuat ${ageText(f.age)} lalu, tetapi sudah meminta ${f.credentials || "data akun"} atas nama ${brand}. [P3]`;
    case "P4":
      covered.add("download"); covered.add("brand");
      return `Unduhan berbahaya: situs yang baru dibuat ${ageText(f.age)} lalu ini menawarkan file .${f.download || "program"} atas nama ${brand}; file seperti ini dapat menjalankan program di perangkat Anda. [P4]`;
    case "L1":
      covered.add("brand"); covered.add("credentials");
      return `Situs resmi: ${f.host} adalah situs resmi ${f.brand || "brand ini"}, sudah ada sejak ${ageText(f.age)} lalu, dan tidak meminta data akun. [L1]`;
    case "L2":
      covered.add("brand"); covered.add("credentials");
      return `Login resmi: ini halaman login resmi ${f.brand || "situs ini"}; data akun dikirim ke situs ${f.brand || "ini"} sendiri, dan situsnya sudah ada sejak ${ageText(f.age)} lalu. [L2]`;
    default: return null;
  }
}

function urlSentence(verdict, urlClass, ruleDecided) {
  if (urlClass !== "DANGEROUS" && urlClass !== "SAFE") return "Pola alamat: penilaian pola alamat belum tersedia.";
  if (!ruleDecided) return urlClass === "DANGEROUS"
    ? "Pola alamat: susunan alamat situs ini mirip dengan alamat phishing yang dikenali sistem."
    : "Pola alamat: susunan alamat situs ini tidak menunjukkan ciri phishing.";
  if (verdict === "DANGEROUS") return urlClass === "DANGEROUS"
    ? "Pola alamat: susunan alamatnya juga mirip dengan alamat phishing."
    : "Pola alamat: sekilas alamatnya terlihat biasa, tetapi isi halaman menunjukkan penipuan.";
  return urlClass === "SAFE"
    ? "Pola alamat: susunan alamatnya juga tidak menunjukkan ciri phishing."
    : "Pola alamat: susunan alamatnya sempat terlihat mencurigakan, tetapi pemeriksaan halaman memastikan ini situs resmi.";
}

function supportingSentences(f, covered, verdict) {
  const lines = [];
  if (f.pathHosted && !covered.has("brand")) {
    lines.push(`Platform: halaman ini dibuat oleh pengguna di layanan ${platformName(f.host)}, bukan oleh ${platformName(f.host)} sendiri.`);
    covered.add("brand");
  }
  if (!covered.has("brand") && f.brand) {
    if (f.officialMatch === true) lines.push(`Identitas: alamat ini cocok dengan situs resmi ${f.brand}.`);
    else if (f.officialMatch === false && f.official)
      lines.push(`Identitas: halaman menampilkan ${f.brand}, tetapi situs resmi ${f.brand} adalah ${f.official}.`);
  }
  if (!covered.has("credentials")) {
    if (f.oauthRedirect) lines.push("Login: login diarahkan ke penyedia akun resmi; hal ini belum membuktikan situs asalnya aman.");
    else if (f.credentials && f.credentialTarget)
      lines.push(`Data akun: halaman meminta ${f.credentials} dan mengirimkannya ke ${f.credentialTarget}, bukan ke ${f.host}.`);
    else if (f.credentials && f.credentialTargetKnownSame)
      lines.push(`Data akun: halaman meminta ${f.credentials}; formulirnya mengarah ke ${f.host} sendiri.`);
    else if (f.credentials)
      lines.push(`Data akun: halaman meminta ${f.credentials}; tujuan pengirimannya belum dapat dipastikan.`);
  }
  if (!covered.has("download")) {
    if (f.download) lines.push(`Unduhan: halaman menawarkan file .${f.download} yang dapat menjalankan program.`);
    else if (f.otherDownload && verdict === "DANGEROUS") lines.push("Unduhan: halaman menyediakan tautan unduhan.");
  }
  return lines;
}

function summaryFor(verdict, source, f, deciding) {
  if (verdict === "LIMITED") return "Pemeriksaan belum lengkap, sehingga keamanan halaman belum dapat dipastikan.";
  if (verdict === "DANGEROUS") {
    if (source === "brand_dom_phishing") {
      if (deciding.some(r => r.id === "P4")) return `Situs ini menawarkan file berbahaya${f.brand ? ` atas nama ${f.brand}` : ""}.`;
      if (f.brand) return `Situs ini meniru ${f.brand} dan bukan situs resminya.`;
      return "Halaman ini menunjukkan tanda-tanda penipuan.";
    }
    return "Alamat situs ini memiliki pola yang mirip dengan alamat phishing.";
  }
  if (source === "brand_dom_legitimate") return `Ini situs resmi ${f.brand || "yang terverifikasi"}.`;
  return "Tidak ditemukan tanda phishing yang kuat pada alamat maupun isi halaman.";
}

function actionFor(verdict, f) {
  if (verdict !== "DANGEROUS") return "Tetap periksa alamat di browser sebelum memasukkan kata sandi atau data pribadi.";
  const visit = f.official ? ` Jika perlu, buka langsung ${f.official} dengan mengetik alamatnya sendiri.` : "";
  if (f.download) return `Jangan unduh atau membuka file dari halaman ini.${visit}`;
  return `Jangan masukkan kata sandi, kode OTP, atau data kartu di halaman ini.${visit}`;
}

function limitationFor(analysis, f) {
  const notes = [];
  if (analysis.dom_features?.unresolved_checks?.includes("inaccessible_iframe")) notes.push("Sebagian isi halaman tidak dapat diperiksa.");
  const ageMatters = (analysis.rule_results || []).some(rule => rule.status === "undetermined") && f.age === null;
  if (ageMatters) notes.push("Umur situs tidak dapat diperiksa, sehingga sebagian pemeriksaan tidak dapat dilakukan.");
  return notes.join(" ");
}

// ---------------------------------------------------------------------------
// Other result types.

function manualExplanation(analysis, source) {
  const allowed = source === "manual_allowlist";
  const listed = analysis.manual_domain || hostname(analysis.final_url || analysis.url);
  return {
    title: allowed ? "Diizinkan oleh daftar Anda" : "Diblokir oleh daftar Anda",
    summary: allowed ? `Domain ${listed} ada di Allow list Anda.` : `Domain ${listed} ada di Block list Anda.`,
    domain: hostname(analysis.final_url || analysis.url),
    reasons: [allowed
      ? `Daftar: Anda mengizinkan ${listed} beserta semua subdomainnya; pemeriksaan otomatis tidak dijalankan.`
      : `Daftar: Anda memblokir ${listed} beserta semua subdomainnya; pemeriksaan otomatis tidak dijalankan.`],
    action: allowed ? "Tetap periksa alamat situs sebelum memasukkan data pribadi."
      : `Hapus ${listed} dari Block list jika Anda ingin membuka situs ini.`,
    limitation: ""
  };
}

function incompleteExplanation(analysis) {
  return {
    title: "Pemeriksaan belum lengkap",
    summary: "Keamanan halaman belum dapat dipastikan.",
    domain: hostname(analysis.final_url || analysis.url),
    reasons: ["Pemeriksaan: data pemeriksaan belum cukup untuk menyimpulkan keamanan halaman."],
    action: "Tetap periksa alamat situs sebelum memasukkan data pribadi.",
    limitation: analysis.dom_error ? "Struktur halaman belum berhasil dibaca lengkap." : ""
  };
}

// ---------------------------------------------------------------------------
// Helpers.

function ageText(days) {
  if (!Number.isFinite(days)) return "waktu yang tidak diketahui";
  if (days < 1) return "kurang dari sehari";
  if (days < 60) return `${days} hari`;
  if (days < 365) return `${Math.round(days / 30)} bulan`;
  return `${Math.floor(days / 365)} tahun`;
}

function exfilName(endpoint) {
  const found = EXFIL_SERVICES.find(([pattern]) => pattern.test(endpoint));
  return found ? `${found[1]} (${endpoint})` : endpoint;
}

function formTarget(form) {
  try { return new URL(form.action_origin).hostname; } catch { return form.destination_registrable_domain || "situs lain"; }
}

function platformName(host) {
  const found = PLATFORM_NAMES.find(([pattern]) => pattern.test(host));
  return found ? found[1] : host;
}

function joinList(items) {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} dan ${items.at(-1)}`;
}

function hostname(value) {
  try { return new URL(value).hostname; } catch { return "domain halaman"; }
}
