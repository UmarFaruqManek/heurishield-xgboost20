# Keputusan kategoris — versi lokal 0.6.0

## Alur aktif

1. XGBoost menghitung probabilitas secara internal dan membandingkannya dengan threshold 0,50. `classifyUrl` mengembalikan hanya `legitimate` atau `phishing`. Model, 20 fitur dan berkas pohon tidak berubah.
2. DOM dan Brand Analyzer menghasilkan temuan. Correlation rules R01–R13 dan correction rules C01–C06 menggabungkan temuan logis.
3. Decision policy mempertahankan kelas URL, menaikkannya menjadi phishing bila aturan peniruan terkonfirmasi aktif, atau mengoreksinya menjadi legitimate bila syarat koreksi terpenuhi. Bukti phishing terkonfirmasi didahulukan atas koreksi legitimate.
4. Hasil analisis, riwayat, konteks block page, feature archive, dan kolom laporan live baru tidak menyimpan probabilitas/skor klasifikasi. Migrasi chrome.storage menghapus kunci skor lama sambil mempertahankan temuan dan label. Arsip penelitian di disk tetap dipertahankan sebagai baseline historis.

Tidak ada batas probabilitas tambahan 0,45, 0,60, atau 0,90 dalam aturan koreksi. Batas umur domain dan pemeriksaan teknis asal halaman tetap merupakan kondisi fitur, bukan skor risiko atau penjumlahan bobot. Tidak ada perubahan pada API, model terlatih, atau pencarian token brand.

## Koreksi legitimate yang dicatat secara eksplisit

| ID | Ringkasan kondisi selain hasil URL phishing |
|---|---|
| C01 | Halaman OAuth pada domain penyedia login yang cocok dengan referensi brand, struktur permintaan OAuth sesuai, dan tidak ada konflik teramati. |
| C02 | Identitas halaman sesuai domain sendiri, halaman login didukung tautan dari situs induk, umur memenuhi kondisi yang sudah ada, dan tidak ada konflik. |
| C03 | Domain brand cocok, klaim halaman didukung judul/heading/logo sesuai kondisi, formulir password seasal, HTTPS, umur memenuhi kondisi, dan tidak ada konflik. |
| C04 | Dokumentasi HTTPS pada domain brand yang cocok, judul mendukung identitas, tanpa input sensitif/form lintas domain, dan tidak ada konflik. |
| C05 | Halaman pencarian HTTPS pada domain brand yang cocok, tanpa bukti kredensial atau formulir lintas domain yang teramati. |
| C06 | Domain brand cocok dengan halaman HTTPS yang teramati, kandidat yang sama didukung judul, tanpa input sensitif/form lintas domain, umur memenuhi kondisi, dan tidak ada konflik identitas. |

Untuk C06, cabang lama berbasis skor rendah telah diganti dengan gabungan bukti identitas yang lebih kuat. Jadi perubahan ini bukan sekadar mengizinkan semua hasil yang dahulu gagal pada batas probabilitas. Nama brand saja, unknown, atau formulir seasal saja tidak otomatis mengizinkan halaman. R12/R13 unduhan tetap berlaku.

Implementasi: `src/model/xgboost-engine.js`, `src/analyzer/correlation/correction-rules.js`, `src/analyzer/correlation/decision-policy.js`, dan `src/background/service-worker.js` di folder extension aktif.

## Pengujian

- 28/28 pengujian fungsi/integrasi lulus. Termasuk pengujian bahwa akses `context.probability` akan melempar error, sementara koreksi tetap berhasil; penghapusan kunci skor; migrasi riwayat lama; dan penyimpanan browser nyata tanpa skor klasifikasi.
- Enam fixture laboratorium unduhan tetap sesuai kondisi R13. Halaman dan API merupakan simulasi lokal, model dan aturan asli.
- Launcher live lolos dry-run: v0.6.0, 20 fitur, TH0,50 dan hash berkas sesuai. Tidak menjalankan uji live publik.

Replay 1.087 rekaman dengan kelas URL asli:

| Label | Sebelum | Sesudah |
|---|---|---|
| Legitimate | 808/842 (95,96%) | 809/842 (96,08%) |
| Phishing | 199/245 (81,22%) | 200/245 (81,63%) |

Empat keputusan berubah: dua legitimate yang salah menjadi benar, satu legitimate yang benar menjadi salah, dan satu phishing yang lolos menjadi terdeteksi. Kasus legitimate yang mengalami regresi adalah `https://darbhangamedicalcollege.in/sitemap/`; koreksi sebelumnya bergantung pada cabang skor rendah, sementara bukti judul/kandidat tidak memenuhi syarat koreksi baru. Ini belum diatasi dengan pengecualian domain.

323 rekaman memiliki snapshot/API lengkap relatif terhadap replay, 763 parsial, dan satu hanya tingkat keputusan. Pemeriksaan situs induk yang baru menjadi layak setelah batas skor dilepas tidak dapat dilakukan ulang dari arsip bila responsnya belum disimpan. Tidak ada API atau situs publik dibuka dalam replay. Angka di atas adalah bukti pengembangan/regresi, bukan pengujian independen baru atau jaminan tidak ada regresi pada situs lain.

Rincian: `replay_rows.csv`, `replay_summary.json`, `before_replay.json`, `after_replay.json`, `extension_tests.json`, `browser_test.json`. Model SHA256 tetap `d623eefd35e9bb4cc028d40172acdd28b75a6ddc99d91a82a1c6dabfbf2f452b`.

Perubahan belum dipush. Checkpoint GitHub tetap v0.5.2 / cae5e8c.
