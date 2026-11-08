# Tautan download sebagai parameter DOM — versi lokal 0.5.1

Desain ini menggantikan modul unduhan terpisah versi 0.5.0 sesuai arahan pengguna. Monitor `chrome.downloads`, izin `downloads`, kontrol jeda/batal/lanjut dan halaman peringatan unduhan telah dilepas dari extension aktif. Isi file tidak diunduh/dibaca/dipindai oleh analyzer. Tautan dibaca dari DOM, lalu hasilnya digabungkan dengan URL Analyzer dan Brand Analyzer untuk keputusan phishing yang sama.

## Empat parameter DOM tambahan

| Parameter | Arti |
|---|---|
| `has_download_link` | Ada tautan yang ditandai atribut download, nama file installer/arsip pada path, atau teks Download/Unduh/Installer. |
| `has_executable_download_link` | Tautan menunjukkan installer/skrip melalui path URL atau nama pada atribut download; misalnya exe, msi, apk, ps1. Ini indikasi dari metadata, bukan pemeriksaan isi. |
| `download_target_cross_domain` | Ada tujuan download dengan domain situs berbeda, memakai parser public/private suffix. Dicatat sebagai informasi, tidak memblokir CDN sendirian. |
| `download_link_count` | Jumlah tautan yang teramati pada snapshot. Pencatatan dibatasi 30 per frame; rincian gabungan dibatasi 60. |

`download_links` menyimpan rincian URL tanpa query/fragment/username/password, teks, petunjuk nama file, ekstensi dan perbandingan domain. `download_scope=dom_links_only` menegaskan bahwa ini bukan rekaman kejadian unduhan aktual. Tidak ada klik yang dicegah dan tidak ada file yang dijeda/dibatalkan oleh analyzer DOM.

Snapshot lama yang tidak mencatat tautan menghasilkan `unknown` dan count null, bukan false/0. Tombol JavaScript yang bertuliskan Download tetapi tidak mempunyai URL yang dapat dibaca juga dicatat sebagai pemeriksaan belum lengkap. Perubahan atribut href/download serta penambahan/penghapusan tautan pada halaman dinamis ikut dipantau. Informasi unduhan yang tidak lengkap dicatat pada `download_unresolved_checks`, terpisah dari unresolved checks autentikasi agar koreksi legitimate/OAuth lama tidak terhambat hanya karena parameter baru belum terekam.

## Aturan dan decision policy

| Aturan | Kondisi | Keputusan |
|---|---|---|
| R12 | Model URL phishing AND identitas brand terdeteksi AND peniruan brand kuat AND ada tautan download | Phishing, source `url_brand_download_phishing` |
| R13 | Identitas brand terdeteksi AND referensi domain terverifikasi berbeda dari domain halaman AND klaim brand pada hostname AND kandidat brand terpilih tampil pada judul AND ada tautan installer/skrip | Phishing, source `brand_executable_download_phishing`, termasuk ketika model URL semula legitimate |

R12 terutama memperjelas alasan kasus yang sebelumnya sudah bisa diputus phishing dari peniruan kuat. R13 menambah kombinasi pendukung untuk halaman tanpa kolom password, misalnya klaim brand pada subdomain, judul yang sama, dan tawaran installer. Bukan aturan bahwa setiap brand berbeda atau setiap download merupakan phishing.

Kedua aturan diperiksa sebelum koreksi otomatis menjadi legitimate. Jika tidak cocok, aturan lama diteruskan. Tidak ada risk score/bobot baru, threshold tidak diubah, model tetap 20 fitur. Keputusan akhir tetap hanya memakai jalur phishing yang sudah ada. Pengaturan block page atau popup phishing tetap berlaku; tidak ada peringatan unduhan terpisah dan tidak ada keputusan file malware.

Tautan executable saja, tujuan berbeda/CDN saja, tautan PDF tanpa bukti lain, atau brand unknown tidak menaikkan keputusan menjadi phishing melalui aturan ini. Situs resmi dengan identitas domain cocok tidak memenuhi R13.

## File implementasi

- `src/content/dom-brand-observer.js`: membaca metadata tautan dari DOM.
- `src/analyzer/dom/dom-download-features.js`: menormalkan empat parameter dan rincian link.
- `src/analyzer/dom/dom-evidence.js`: menggabungkannya dengan parameter DOM sebelumnya.
- `src/analyzer/correlation/evidence-rules.js`: R12/R13 dan status matched/not_matched/undetermined.
- `src/analyzer/correlation/decision-policy.js`: prioritas keputusan gabungan.
- `src/shared/analysis-explanation.js`: menampilkan alasan unduhan pada panel/halaman blokir yang sama, hanya bila tautan benar-benar ditemukan.

## Pengujian dan batas bukti

- `tests/dom-download-rules.mjs`: R12/R13, koreksi URL SAFE, negatif situs resmi/CDN/PDF, metadata unknown, tombol JS dan penjelasan.
- `tests/dom-download-browser.py`: runtime Chromium dengan halaman dan API fixture lokal; tautan exe/PDF/APK dinamis terbaca, R13 aktif, perubahan/penghapusan tautan terbaca, izin/API warning terpisah tidak ada. Tidak memulai unduhan atau membuka target publik.
- `replay_summary.json` dan `replay_rows.csv`: perbandingan arsip per URL. Arsip yang tidak mempunyai metadata unduhan tidak dapat digunakan untuk mengklaim keberhasilan R12/R13; hasil tersebut hanya menguji kestabilan keputusan lama.

Indikasi peniruan brand yang menawarkan file bukan bukti isi file mengandung malware. Evaluasi Bab V perlu membedakan pengujian pembacaan parameter, pengujian aturan gabungan, dan pengujian malware nyata.
