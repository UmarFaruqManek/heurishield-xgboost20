# Penguatan v0.7 (12 Nov 2026)

Perubahan hanya pada cara parameter dihitung dan pada daftar konfigurasi.
Daftar 19 parameter, enam rule P1–P4/L1–L2, decision policy, dan model URL v3 tidak berubah.

| Kode | Kelemahan | Perbaikan | File |
|---|---|---|---|
| A | Domain dianggap resmi hanya karena direktori brand punya entri untuk domain itu sendiri (`roblox.com.ml`) | Pengaman *self-reference*: entri direktori yang tidak teratestasi tidak cukup bila nama brand menunjuk ke domain lain. Jika label meniru nama (`robiox`), nilainya `false`; jika label sama dengan akhiran berbeda, nilainya `unknown` | `src/analyzer/brand/brand-evidence.js` |
| A | Konten pengguna pada path platform (`docs.google.com/forms`, `sharemyhtml.com/p`) dianggap milik platform | Daftar `PATH_HOSTED_USER_CONTENT`; `official_domain_match` menjadi `unknown` | `src/analyzer/brand/shared-hosting.js` |
| C | Brand tidak dikenali bila API gagal atau ejaan meniru | Registri brand lokal (31 entri, seluruh domain resmi tiap brand); host yang selisih satu huruf (`shoopee`, `t0kopedia`) dicocokkan | `src/analyzer/brand/brand-registry.js` |
| D | Kredensial dikirim lewat JavaScript, tujuan tidak terlihat | Endpoint pengumpul data yang dikenal (Telegram Bot API, webhook Discord/Slack, Formspree, Getform, Google Apps Script, dan lainnya) pada skrip inline membuat `form_cross_domain = true` bila halaman meminta kredensial. Hanya nama layanan yang disimpan | `src/content/dom-brand-observer.js`, `src/analyzer/dom/dom-evidence.js` |
| G | Malware dalam arsip tidak dihitung | Ditambahkan: zip, rar, 7z, iso, img, vhd, vhdx, cab (wadah), serta js, hta, lnk, msc, xll | `src/analyzer/url/download-file-extension.js` |
| — | URL tanpa akhiran file tercatat `unknown`, sehingga P4 tidak pernah `not_matched` | `null` dipertahankan sebagai "tidak ada file" | `src/analyzer/rules/parameters.js` |
| E | Login yang muncul setelah halaman dimuat | Sudah ada sebelumnya (MutationObserver lalu analisis ulang), tidak diubah | — |

## Hasil

Replay 3.636 rekaman (bukti DOM/brand tersimpan, tanpa jaringan): `replay_before.json`, `replay_after.json`, `compare.json`.

| | Sebelum | Sesudah |
|---|---:|---:|
| Legitimate benar | 94,58% | 94,58% |
| Phishing benar | 81,06% | **85,56%** |
| Keputusan berubah | — | 33, semuanya phishing yang menjadi benar (0 regresi) |

Pipeline lengkap pada rekaman live 11 Nov dengan model URL v3 (`replay_live11nov_v2_v3_after.json`): akurasi 85,44% → **86,56%**, phishing terdeteksi 73,68% → **78,95%**, legitimate benar 88,62% (tetap).

Lab lokal (`D:\testing-local`):
- clone: 13/13 diblokir (Shopee kini oleh P1);
- unduhan: 9/9;
- penguatan: 8/8 (`lab-penguatan-v070`).

Tes unit: 28/28 lulus, termasuk `tests/hardening-v070.mjs`.

## Catatan untuk skripsi
- Selama pengembangan ditemukan dua regresi pada replay, dan keduanya diperbaiki sebelum hasil di atas:
  - nama berdiakritik ("Fundación Renal" pada `fundacionrenal.org.ar`);
  - akronim yang dipakai banyak organisasi (NVPC).
  Aturan pembandingnya kini hanya memakai jawaban utama direktori untuk nama brand.
- Replay ini memakai data yang juga dipakai untuk mengembangkan perbaikan, jadi bukan uji independen. Angka akhir harus berasal dari uji live baru.
- Formulir pada `docs.google.com/forms` tidak lagi dapat dinilai "resmi Google". Keputusannya kembali ke model URL, yang bisa saja menilainya SAFE. Perbaikan ini mencegah L1 meloloskan halaman tersebut, tetapi tidak dengan sendirinya memblokir.
- Phishing di domain lama yang dibobol (usulan P5) dan umur domain .de/.jp belum ditangani.
