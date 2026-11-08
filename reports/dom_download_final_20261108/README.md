# Pemeriksaan unduhan terintegrasi — versi lokal 0.5.2

Paket aktif: `extension/HeuriShield-URL20-XGBoost`. Model XGBoost tetap memakai 20 fitur, 500 pohon, dan ambang 0,50. Pemeriksaan akhiran file merupakan metadata tambahan untuk aturan, bukan tambahan masukan model. Tidak ada perubahan API, monitor Chrome Downloads, atau halaman peringatan unduhan terpisah.

## Parameter final

- `url_features.url_file_extension`: akhiran nama file pada path URL sumber, huruf kecil. Query/fragment dan akhiran hostname tidak dipakai. `null` berarti URL valid tanpa akhiran file; `unknown` berarti tidak dapat dibaca.
- `dom_features.has_download_link`: tautan unduhan teramati; `false` jika pemindaian lengkap tanpa temuan; `unknown` jika tidak tersedia atau belum lengkap.
- `dom_features.download_file_extensions`: daftar unik akhiran dari tautan DOM atau nama pada atribut download. Contoh `["exe", "pdf"]`; `[]` jika tidak ada; `null` jika belum diamati. Tautan tanpa nama file terbaca dicatat `unknown`.
- `dom_features.download_target_cross_domain`: informasi domain tujuan unduhan berbeda. Parameter ini tidak memblokir layanan CDN secara mandiri.

`download_links` mencatat rincian tautan, domain sumber/tujuan dan akhiran file. URL rincian tautan dibersihkan dari query, fragment dan userinfo. Metadata disimpan bersama hasil ekstraksi dan aturan dalam riwayat analisis. `has_executable_download_link` dan `download_link_count` sudah dilepas.

## Aturan dan keputusan

- **R12:** model URL phishing + brand teridentifikasi + bukti kuat peniruan hostname/kredensial + tawaran unduhan. Tawaran berasal dari tautan DOM atau akhiran installer/skrip URL. Keputusan phishing dipertahankan dengan alasan gabungan.
- **R13:** brand teridentifikasi + domain rujukan brand berbeda + klaim brand pada domain/subdomain + judul mendukung kandidat brand yang sama + tawaran installer/skrip. Keputusan menjadi phishing, termasuk jika hasil model URL legitimate.
- Daftar akhiran installer/skrip: `exe`, `msi`, `msix`, `appx`, `apk`, `scr`, `com`, `bat`, `cmd`, `ps1`, `vbs`, `vbe`, `jse`, `wsf`, `jar`, `dmg`, `pkg`, `deb`, `rpm`.
- Tautan unduhan, ekstensi file, domain tujuan berbeda, dan umur domain tidak menjadi keputusan phishing mandiri. PDF/arsip tidak memenuhi syarat installer/skrip R13.
- Keputusan memakai kondisi logis tanpa bobot angka tambahan. R12/R13 diperiksa sebelum koreksi legitimate. Allow list / block list pengguna dan pilihan block page / popup tetap berlaku.

Pemeriksaan membaca metadata halaman/URL; ini bukan pemeriksaan isi file atau intersepsi transfer.

## Hasil pengujian

27/27 pengujian fungsi dan integrasi lulus. Chromium fixture lokal menguji tautan EXE, PDF, penghapusan tautan, kemunculan APK dinamis, path URL EXE tanpa tautan DOM, penggabungan R13, serta vektor model yang tetap 20 fitur. Tidak membuka situs publik atau memulai unduhan dalam pengujian ini. Lihat `browser_test.json` dan `extension_tests.json`.

Pemutaran ulang 1.087 rekaman dengan skor URL dibekukan:

| Label | Jumlah | Benar sebelum | Benar sesudah | Persentase sebelum/sesudah |
|---|---:|---:|---:|---:|
| Legitimate | 842 | 808 | 808 | 95,96% |
| Phishing | 245 | 199 | 199 | 81,22% |

Tidak ada keputusan berubah. Hanya 323 rekaman memiliki snapshot/API lengkap; 763 parsial dan satu hanya tingkat keputusan. Seluruh rekaman lama belum menyimpan tautan unduhan DOM, sehingga nilai tersebut tetap unknown. Hasil ini merupakan pemeriksaan regresi atas bukti tersedia, bukan bukti akurasi aturan unduhan pada situs baru. Sumber: `reports/brand_reference_fix_20261108/replay_input.json`. Perbandingan rinci: `replay_rows.csv`, `before_replay.json`, `after_replay.json`, `replay_summary.json`.

Model SHA256 tidak berubah: `d623eefd35e9bb4cc028d40172acdd28b75a6ddc99d91a82a1c6dabfbf2f452b`.

Paket pembaruan versi 0.5.2. Reload extension sebelum pengujian berikutnya.
