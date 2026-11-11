/*
 * Membaca konteks hasil sebelum redirect dan menampilkan alasan ringkas halaman blokir.
 * Tombol izin menyimpan domain ke Allow list sebelum membuka kembali URL tujuan.
 */
import { getWarningContext, getAnalysisByTab, addToAllowlist } from "../storage/settings.js";
import { buildAnalysisExplanation } from "../shared/analysis-explanation.js";

const params = new URLSearchParams(location.search);
const contextId = params.get("id");
const elements = {
  domain: document.querySelector("#domain"),
  reasonList: document.querySelector("#reasonList"),
  redirectSourceSection: document.querySelector("#redirectSourceSection"),
  redirectSourceText: document.querySelector("#redirectSourceText"),
  backButton: document.querySelector("#backButton"),
  continueButton: document.querySelector("#continueButton"),
  actionError: document.querySelector("#actionError")
};

let originalUrl = null;
let currentTabId = null;

document.addEventListener("DOMContentLoaded", init);

async function init() {
  currentTabId = await getCurrentTabId();
  let context = contextId ? await getWarningContext(contextId) : null;
  if (context && !context.analysis && currentTabId !== null) {
    const previous = await getAnalysisByTab(currentTabId);
    if (previous && (previous.final_url || previous.url) === context.originalUrl) context.analysis = previous;
  }
  // Cadangan per tab mempertahankan identitas saat daftar konteks lokal dipangkas.
  const cacheKey = `heurishield-warning:${contextId}`;
  if (context) { try { sessionStorage.setItem(cacheKey, JSON.stringify(context)); } catch { /* Storage utama tetap menjadi sumber. */ } }
  else if (contextId) {
    try { context = JSON.parse(sessionStorage.getItem(cacheKey) || "null"); } catch { /* Cache invalid tidak dipakai. */ }
  }

  if (!context) {
    renderFallback();
  } else {
    try {
      const parsed = new URL(context.originalUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Bukan situs web.");
      originalUrl = parsed.href;
      elements.continueButton.disabled = false;
      elements.domain.textContent = parsed.hostname;
      document.title = `HeuriShield - ${parsed.hostname} diblokir`;
    } catch { renderFallback(); return; }
    const explanation = context.analysis ? buildAnalysisExplanation(context.analysis) : context.explanation || buildAnalysisExplanation(context);
    document.querySelector("h1").textContent = explanation.title;
    document.querySelector(".lead").textContent = context.analysis?.decision_policy?.source === "url_model"
      ? "Pemeriksaan alamat menandai situs ini berisiko phishing. Akses dihentikan agar Anda dapat meninjau hasil pemeriksaannya."
      : explanation.summary;
    document.querySelector("#reasonAdvice").textContent = explanation.action;
    document.querySelector("#reasonNote").textContent = explanation.limitation || "";
    document.querySelector("#reasonNote").hidden = !explanation.limitation;
    renderReasons(explanation.reasons);
    renderRedirectSource(context.redirect_source_warning);
  }

  elements.backButton.addEventListener("click", () => history.back());
  elements.continueButton.addEventListener("click", allowDomainAndOpen);
}

function renderFallback() {
  elements.domain.textContent = "Tidak tersedia";
  document.querySelector(".lead").textContent = "Rincian pemeriksaan tersimpan tidak tersedia. Kembali ke halaman sebelumnya untuk melanjutkan penelusuran.";
  renderReasons(["Detail analisis tidak tersedia, tetapi halaman ini dibuka dari proteksi HeuriShield."]);
  renderRedirectSource(null);
}

function renderReasons(reasons) {
  const items = Array.isArray(reasons) && reasons.length ? reasons.slice(0, 3) : ["Detail pemeriksaan belum tersedia."];
  elements.reasonList.replaceChildren(
    ...items.map((reason) => {
      const item = document.createElement("li");
      const text = String(reason);
      const prefix = /^(Alamat|Aturan [A-Z]\d+|Identitas situs|Formulir|Login|Unduhan):\s*/.exec(text);
      const labels = { Alamat: "Analisis alamat URL", "Identitas situs": "Identitas situs", Formulir: "Formulir",
        Login: "Alur login", Unduhan: "Unduhan" };
      const label = document.createElement("strong");
      label.className = "reason-label";
      label.textContent = !prefix ? "Temuan pemeriksaan" : labels[prefix[1]] || prefix[1];
      const detail = document.createElement("span");
      detail.className = "reason-detail";
      const description = prefix ? text.slice(prefix[0].length) : text;
      detail.textContent = description === "dinilai phishing oleh model."
        ? "Model URL menilai alamat ini sebagai phishing."
        : description === "tujuan yang tertera berada pada domain halaman ini; pengiriman aktual belum diamati."
          ? "Formulir mencantumkan tujuan pada domain yang sama dengan halaman ini. Tujuan pengiriman saat formulir digunakan belum diamati."
          : description;
      item.append(label, document.createTextNode(" "), detail);
      return item;
    })
  );
}

function renderRedirectSource(warning) {
  if (!warning) {
    elements.redirectSourceSection.hidden = true;
    elements.redirectSourceText.textContent = "";
    return;
  }

  elements.redirectSourceSection.hidden = false;
  if (warning.trigger === "final_risk_after_redirect") {
    elements.redirectSourceText.textContent =
      `${warning.source_domain || "Domain awal"} mengarah ke ${warning.final_domain || "domain akhir"}; halaman akhir berstatus ${getDecisionClassLabel(warning.final_verdict)}.`;
    return;
  }

  elements.redirectSourceText.textContent =
    `${warning.source_domain || "Domain awal"} berstatus ${getDecisionClassLabel(warning.source_verdict)} sebelum mengarah ke ${warning.final_domain || "domain akhir"}.`;
}

function getDecisionClassLabel(verdict) {
  return {
    SAFE: "Legitimate",
    WARNING: "Warning",
    DANGEROUS: "Phishing",
    LIMITED: "Analisis terbatas"
  }[verdict] || verdict || "Phishing";
}
async function allowDomainAndOpen() {
  if (!originalUrl || elements.continueButton.disabled) return;
  elements.continueButton.disabled = true;
  elements.continueButton.textContent = "Menyimpan izin…";
  elements.continueButton.setAttribute("aria-busy", "true");
  elements.actionError.hidden = true;
  try {
    await addToAllowlist(new URL(originalUrl).hostname);
    location.replace(originalUrl);
  } catch {
    elements.actionError.textContent = "Domain gagal disimpan ke Allow list. Silakan coba kembali.";
    elements.actionError.hidden = false;
    elements.continueButton.disabled = false;
    elements.continueButton.textContent = "Izinkan domain";
  } finally {
    elements.continueButton.removeAttribute("aria-busy");
  }
}

async function getCurrentTabId() {
  try {
    const tab = await chrome.tabs.getCurrent();
    return Number.isInteger(tab?.id) ? tab.id : null;
  } catch {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return Number.isInteger(tab?.id) ? tab.id : null;
    } catch {
      return null;
    }
  }
}
