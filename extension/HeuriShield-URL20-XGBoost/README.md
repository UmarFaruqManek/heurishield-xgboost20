# HeuriShield URL20 XGBoost v2

Extension Chromium (Manifest V3) untuk mendeteksi dan memblokir situs phishing dengan analisis heuristik. Versi pengembangan **0.7.0**; rancangan penelitian yang dibekukan tetap berada pada tag `skripsi-v0.6.2`.

## Memuat extension

Buka `chrome://extensions` atau `edge://extensions`, aktifkan Developer mode, pilih **Load unpacked**, lalu pilih folder ini.

## Alur analisis

1. **URL Analyzer** — `src/analyzer/url/url20-features.js` mengekstraksi 20 fitur dari URL awal. `src/model/xgboost-engine.js` mengevaluasi 500 pohon XGBoost (`src/model/xgboost-url20.json`) dengan threshold 0,50. Probabilitas hanya dipakai di dalam engine; keluarannya kelas legitimate/phishing.
2. **Informasi pendukung** (bukan input model) — umur domain (`src/analyzer/domain/url18-age.js`, kategori di `src/model/domain-age-policy.json`) dan akhiran file pada URL (`src/analyzer/url/download-file-extension.js`).
3. **DOM Analyzer** — content script `src/content/dom-brand-observer.js` membaca metadata halaman (tanpa membaca isi field), lalu `src/analyzer/dom/dom-evidence.js` menyusun parameter DOM.
4. **Brand Analyzer** — `src/analyzer/brand/brand-evidence.js` mencari identitas brand berdasarkan domain terlebih dahulu, lalu token hostname/halaman, melalui `brand-search-api.js` (Clearbit, Brandfetch) dan `brand-domain-api.js`.
5. **Rule dan decision policy** — `src/analyzer/correlation/` mengevaluasi rule secara logis (tanpa bobot) dan menetapkan keputusan akhir.
6. **Tindakan** — `src/background/service-worker.js` menerapkan allowlist/blocklist, lalu block page (`src/warning/`) atau popup overlay (`src/content/score-overlay.js`).
7. **Pencatatan** — riwayat, arsip fitur dan dataset lokal di `src/storage/`. Skor/probabilitas klasifikasi tidak disimpan (`src/shared/classification-record.js`).

## Pengujian

- Seluruh fixture: `python ../../scripts/uji_extension_url20.py`.
- Replay keputusan pada rekaman live tersimpan: `python ../../scripts/replay_audit.py snapshot OUT.json`, lalu `compare BASELINE.json OUT.json`.
- Uji live: `../../scripts/Uji_Live_URL20.ps1`.
- `tools/predict-saved-features.mjs` menghitung ulang probabilitas model dari fitur tersimpan untuk audit offline.
