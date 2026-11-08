# HeuriShield XGBoost20

> **Versi aktif lokal 0.5.2:** akhiran file URL dan tautan unduhan DOM menjadi bukti tambahan dalam aturan R12/R13. Tidak ada monitor atau peringatan unduhan terpisah. Model tetap 20 fitur dan TH0,50. 27 pengujian lulus; replay 1.087 rekaman tidak mengubah keputusan. [Laporan final](reports/dom_download_final_20261108/README.md). Paket pembaruan versi 0.5.2.

> Desain lokal v0.5.0 dengan monitor/peringatan unduhan terpisah sudah dibatalkan dan dilepas dari extension aktif. Riwayat pengujiannya disimpan lokal sebagai arsip.

> Pembaruan lokal 8 November 2026: extension versi **0.4.1** menambahkan audit token untuk hasil pencarian domain yang belum memiliki penguatan provider, serta penanganan konflik referensi brand. Model URL20 dan threshold 0,50 tidak berubah. Sebanyak 24 pengujian fungsi/integrasi lulus. Replay sebelum/sesudah pada 323 rekaman dengan respons lengkap tidak mengubah keputusan; 763 rekaman memerlukan respons API tambahan yang belum tersimpan, dan satu rekaman hanya dapat diputar pada tingkat keputusan. Kasus Roblox diuji dalam browser dengan halaman/API fixture lokal; halaman publik target tidak berhasil dibaca. Laporan berada di `reports/brand_reference_fix_20261108`. Pembaruan lokal ini belum dipush; angka dan versi v0.4.0 di bagian historis berikut merujuk paket publikasi awal.

HeuriShield adalah extension browser Chromium untuk memeriksa indikasi phishing melalui model URL, bukti identitas brand, dan struktur formulir halaman. Repository ini menyimpan extension XGBoost20 versi **0.4.0**, data, proses ekstraksi fitur, pelatihan lima model, EDA, evaluasi, dan rekaman pengujian yang mendasari versi tersebut.

Paket aktif memakai **20 fitur URL, 500 pohon XGBoost, dan threshold 0,50**. Model berasal dari eksperimen `experiments/v2`. Threshold yang terpilih dalam cross-validation pelatihan adalah 0,41. Paket extension memakai 0,50 sesuai konfigurasi perbandingan yang dicatat dalam laporan.

## Struktur repository

```text
extension/
  HeuriShield-URL20-XGBoost/      Extension aktif untuk Load unpacked
experiments/
  v2/
    data/                       Tambahan data, train/test, dan bobot tiap URL
    models/                     XGBoost dan empat model pembanding
    reports/                    CV, prediksi per URL, SHAP, dan verifikasi
    HASIL_PERBAIKAN.md           Laporan eksperimen v2
data/
  raw/                          Workbook URL/label, normalisasi, sumber tambahan
  processed/                    Dataset bersih, 20 fitur, dan pembagian baseline
  evaluation/                   Daftar uji serta arsip fitur URL
reports/
  baseline/                     EDA dan hasil sebelum perbaikan v2
  data_preparation/             Sumber, pemeriksaan HTTP, dan audit daftar legitimate
testing/
  live/                         Hasil live CSV/JSON, snapshot model, manifest run
  history/                      SQLite hasil impor ulang bukti yang disamarkan
comparators/
  HeuriShield-URL17-XGBoost/     Extension pembanding yang dipakai dalam uji
scripts/                        Ekstraksi, pelatihan, evaluasi, dan launcher PowerShell
publication_manifest.json       SHA-256 dan asal file publikasi
requirements.txt                Versi dependensi Python lingkungan eksperimen
```

CSV/SQLite besar disimpan sebagai `.gz` agar setiap berkas sesuai batas unggah GitHub. Semua berkas terkompresi memiliki checksum sebelum dan sesudah kompresi. Folder model hanya menyertakan model v2. Hasil baseline disimpan sebagai riwayat pembanding.

## Memuat extension

1. Clone repository ini.
2. Buka `chrome://extensions` atau `edge://extensions` dan aktifkan Developer mode.
3. Pilih **Load unpacked** lalu folder `extension/HeuriShield-URL20-XGBoost`.
4. Pastikan nama **HeuriShield URL20 XGBoost v2**, versi **0.4.0**.

Source dan bundle content script sudah disertakan. Browser memerlukan akses jaringan untuk pencarian brand serta informasi registrasi domain. API yang tersedia dalam proyek tetap digunakan melalui modul `src/analyzer/brand` dan `src/analyzer/domain`.

## Cara kerja

1. URL awal diekstraksi menjadi 20 fitur numerik oleh JavaScript.
2. Engine menjumlahkan keluaran 500 pohon XGBoost dan memetakannya ke probabilitas phishing. Nilai minimal 0,50 menghasilkan keputusan awal phishing.
3. DOM Analyzer mengamati field sensitif, formulir, tujuan pengiriman, frame, perubahan halaman, serta konteks login.
4. Brand Analyzer mencari identitas menggunakan domain terlebih dahulu, kemudian token hostname dan bukti halaman. Kandidat domain dibandingkan dengan domain yang dibuka.
5. Correlation rules dan kebijakan keputusan menggabungkan bukti URL, DOM, brand, serta konteks OAuth. Umur domain menjadi bukti pendukung bersama temuan lain.
6. Keputusan ditampilkan melalui block page atau popup sesuai pengaturan. Allow list dan block list menyediakan keputusan domain manual.
7. Hasil analisis dan fitur disimpan untuk penelusuran kesalahan dan evaluasi ulang.

Kontrak model aktif berada di `extension/HeuriShield-URL20-XGBoost/src/model/feature-contract-20.json`. Engine ada di `src/model/xgboost-engine.js`, correlation rules di `src/analyzer/correlation/evidence-rules.js`, dan kebijakan akhir di `src/analyzer/correlation/decision-policy.js`.

## Dua puluh fitur URL

| Parameter | Definisi ringkas |
|---|---|
| `url_length` | Panjang teks URL awal setelah trim |
| `hostname_length` | Panjang hostname ASCII/IDNA |
| `path_length` | Panjang path, dengan path root `/` jika kosong |
| `query_length` | Panjang query tanpa `?` |
| `subdomain_count` | Jumlah label subdomain berdasarkan PSL termasuk private suffix |
| `path_depth` | Jumlah segmen path yang tidak kosong |
| `dot_count` | Jumlah titik pada hostname |
| `hyphen_count` | Jumlah tanda hubung pada hostname |
| `digit_ratio` | Proporsi angka pada hostname |
| `special_char_count` | Jumlah karakter selain alfanumerik ASCII pada path dan query |
| `has_at_symbol` | Keberadaan `@` pada URL awal |
| `has_ip_host` | Host berupa alamat IP |
| `has_https_scheme` | Scheme URL adalah HTTPS |
| `hostname_entropy` | Entropi Shannon karakter hostname |
| `sensitive_token_count` | Token akun/autentikasi pada path dan query setelah decoding |
| `url_entropy` | Entropi Shannon karakter teks URL |
| `path_hyphen_count` | Jumlah tanda hubung pada path |
| `domain_label_length` | Panjang label domain utama menurut parser pelatihan |
| `hostname_longest_digit_run` | Rangkaian angka berurutan terpanjang pada hostname |
| `hostname_sensitive_token_count` | Jumlah token akun/autentikasi pada hostname |

Ekstraksi numerik tersebut menggunakan teks URL. Umur domain berada pada pemeriksaan bukti tambahan extension. Definisi lengkap dan perlakuan input khusus tersedia dalam extractor Python dan JavaScript.

## Data dan eksperimen

Dataset awal diberikan sebagai workbook dua kolom URL dan label dari **PhreshPhish**. File berisi 666.315 baris. Sebanyak 18 baris bermasalah dikeluarkan, dan 5.741 URL legitimate tanpa scheme ditambahkan HTTPS atas permintaan pengguna. Normalisasi tersebut adalah asumsi format, bukan hasil verifikasi koneksi.

Setelah deduplikasi dan karantina kedua rekaman satu URL dengan label bertentangan, tersedia **666.228 baris**, terdiri atas **367.909 legitimate** dan **298.319 phishing**. Sebanyak **54.984 baris** dipisahkan karena domainnya terdapat dalam arsip evaluasi. Baseline memiliki 551.958 train dan 59.286 test dengan kelompok domain terpisah.

Eksperimen v2 menambahkan **66.871 URL berlabel sumber**, terdiri atas 21.871 legitimate berquery dan 45.000 phishing. Sumber tambahan berasal dari `URL dataset.csv` dan `url_features_extracted1.csv` yang disertakan di `data/raw/supplementary_sources`. Data sumber lama ini mempertahankan label asal. Tanggal pengumpulan dan label seluruh halaman belum diverifikasi ulang.

Data akhir eksperimen v2 memiliki **612.713 train**, **59.286 test PhreshPhish awal**, dan **6.116 test sumber tambahan**. Domain train terpisah dari test dan 6.460 URL arsip. Penambahan URL dari domain yang telah masuk train mengikuti pembagian domain awal.

Bobot train mengurangi dominasi domain serta keluarga endpoint. Bobot kelas dihitung dari bagian train. Tiga fold berdasarkan domain dijalankan pada sampel deterministik **100.016 baris dari 43.891 domain**. Dua konfigurasi setiap model dibandingkan dengan probabilitas out-of-fold. Model akhir dilatih pada seluruh train.

Workbook yang diterima hanya menyertakan URL dan label. Tanggal serta pembagian train/test resmi PhreshPhish tidak tersedia pada workbook. Pembagian dalam repository ini dibuat ulang berdasarkan domain. Hasil eksperimen ini menggunakan protokol tersebut.

## Hasil evaluasi URL Analyzer

Berikut hasil pada 6.460 URL arsip, dengan threshold tetap 0,50 untuk perbandingan sebelum/sesudah.

| Model | Legitimate sebelum | Legitimate v2 | Phishing sebelum | Phishing v2 |
|---|---:|---:|---:|---:|
| XGBoost | 78,25% | **83,00%** | 82,80% | **85,63%** |
| Random Forest | 80,42% | 88,03% | 83,11% | 84,41% |
| Extra Trees | 76,22% | 83,94% | 83,60% | 84,72% |
| HistGradientBoosting | 78,00% | 83,97% | 83,01% | 85,80% |
| Logistic Regression | 65,28% | 71,08% | 85,56% | 82,45% |

XGBoost v2 pada test PhreshPhish awal dan threshold 0,50 memperoleh accuracy **92,64%**, specificity legitimate **95,57%**, dan recall phishing **88,52%**. Hasil threshold 0,41 pilihan CV juga disimpan dalam `experiments/v2/reports/results.json`.

SHAP mengukur kontribusi terhadap keluaran model. Proporsi mean absolute SHAP seluruh fitur tersedia pada `experiments/v2/reports/xgboost_feature_influence_20.csv`. Nilai tersebut bergantung pada model dan sampel evaluasi, sehingga tidak ditafsirkan sebagai pengaruh sebab-akibat parameter terhadap label.

## Rekaman pengujian browser yang disertakan

| Extension | Label | Input | Selesai dianalisis | Benar | Salah | Benar pada yang dianalisis |
|---|---|---:|---:|---:|---:|---:|
| URL20 v0.4.0 | Legitimate | 500 | 495 | 471 | 24 | 95,15% |
| URL20 v0.4.0 | Phishing | 300 | 124 | 104 | 20 | 83,87% |
| URL17 v0.3.7 | Legitimate | 500 | 495 | 406 | 89 | 82,02% |
| URL17 v0.3.7 | Phishing | 300 | 118 | 96 | 22 | 81,36% |

Jumlah yang berhasil dianalisis berbeda antarrun. Coverage dan penyebab tanpa analisis disimpan pada masing-masing `browser_live_summary.json`. Warning tanpa rekaman analisis lengkap dihitung terpisah. Persentase per daftar satu kelas merupakan tingkat benar pada kelas tersebut.

Arsip offline berlabel historis telah digunakan dalam pengembangan sistem. Data tersebut menjadi evaluasi pengembangan. Snapshot fitur memungkinkan peninjauan ulang keputusan tanpa membuka URL yang mungkin sudah berubah atau tidak aktif.

## Menyiapkan lingkungan Python

```powershell
git clone https://github.com/UmarFaruqManek/heurishield-xgboost20.git
cd heurishield-xgboost20
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python .\scripts\prepare_workspace.py
```

`prepare_workspace.py` memeriksa SHA-256 dan mengekstraksi file `.gz`. Ruang disk tambahan sekitar ukuran data tak terkompresi diperlukan. Extension dapat langsung dimuat tanpa mengekstraksi dataset.

Model joblib dibuat pada Python 3.13 dengan versi pustaka yang dicatat di `requirements.txt`. Gunakan dependensi tersebut saat memuat model tersimpan.

## Mengulang pelatihan dan evaluasi

```powershell
$env:OMP_NUM_THREADS='4'
$env:OPENBLAS_NUM_THREADS='4'
python .\scripts\perbaikan_v2.py
python .\scripts\laporan_perbaikan_v2.py
```

Perintah pelatihan menulis ulang hasil dalam `experiments/v2`. Baseline data dan prediksi yang diperlukan sudah disertakan. Penjelasan proses ekstraksi 17 fitur dasar beserta tiga tambahan tersedia pada `scripts/ekstrak_fitur_url17.py` dan `scripts/eksperimen_phreshphish.py`.

## Menjalankan testing live sendiri

Periksa paket terlebih dahulu.

```powershell
.\scripts\Uji_Live_URL20.ps1 -DryRun
```

Jalankan daftar URL baru dengan label aktual yang sesuai.

```powershell
.\scripts\Uji_Live_URL20.ps1 -InputFile "C:\lokasi\daftar_legitimate.txt" -Label legitimate
.\scripts\Uji_Live_URL20.ps1 -InputFile "C:\lokasi\daftar_phishing.txt" -Label phishing
```

Launcher memeriksa versi 0.4.0, 20 fitur, threshold 0,50, dan fingerprint berkas extension sebelum pengujian. Hasil baru ditulis di `testing/live`, sedangkan riwayat baru launcher berada di `data/evaluation/history_url20.sqlite`. Riwayat historis publik tersedia di `testing/history`.

## Pemeriksaan paket

- Kesetaraan input float32 extractor Python dan JavaScript diperiksa pada 678.115 baris eksperimen serta 6.460 URL arsip.
- Probabilitas/keputusan diperiksa pada 10.460 contoh, dengan selisih probabilitas maksimum sekitar 4,46 × 10⁻⁷ dan tanpa perbedaan keputusan.
- Pengujian fungsi lokal lulus 22/22. Chromium juga memeriksa runtime, DOM dan penyimpanan 20 fitur.
- Kasus fixture `portal.merdekasiber.com` masih menghasilkan false positive dengan probabilitas sekitar 0,830. Kasus ini dicatat terpisah dari kelulusan fungsi.
- Kandidat API dan sebagian bukti halaman dapat tidak tersedia. Status ketidaktersediaan disimpan pada rekaman analisis.

Laporan pemeriksaan lengkap berada di `experiments/v2/reports/extension_*.json`.

## Sumber, atribusi, dan penanganan publikasi

PhreshPhish dikembangkan oleh Thomas Dalton, Hemanth Gowda, Girish Rao, Sachin Pargi, Alireza Hadj Khodabakhshi, Joseph Rombs, Stephan Jou, dan Manish Marwah. Dataset card menyatakan lisensi **CC BY 4.0**. Salinan dalam repository ini mengubah cakupan menjadi URL/label, melakukan pembersihan dan normalisasi yang dijelaskan di atas, lalu menambahkan fitur serta pembagian eksperimen. [Dataset dan atribusi PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish), [makalah PhreshPhish](https://arxiv.org/abs/2507.10854).

Data tambahan menggunakan salinan dataset yang diberikan pengguna. Nama sumber, checksum dan pemetaan label dicatat di `experiments/v2/reports/data_preparation.json`. Keterangan lisensi sumber tambahan tidak tersedia pada file CSV yang diberikan. Ketentuan masing-masing sumber tetap berlaku.

Persiapan daftar legitimate memakai situs organisasi pada registri ROR dan daftar domain pemerintah CISA, dengan kuota sektor. Daftar tersebut merupakan sampel terarah dengan pemeriksaan HTTP saat persiapan. [ROR](https://ror.org/), [CISA dotgov-data](https://github.com/cisagov/dotgov-data).

Riwayat live publik menyamarkan email dan nilai query autentikasi yang terdeteksi. Nilai fitur numerik, skor dan keputusan tetap dipertahankan. Karena penyamaran URL, fitur tersimpan menjadi rujukan untuk replay keputusan historis. Dataset pelatihan mempertahankan string URL sumber untuk mereproduksi ekstraksi. File asli proyek tetap berada pada workspace lokal pengguna.

Hash sumber, hash salinan publikasi, daftar kompresi dan riwayat impor SQLite tersedia pada `publication_manifest.json`. Path absolut pada laporan historis menunjukkan lokasi saat eksperimen dijalankan. Script aktif menggunakan lokasi clone untuk data dan model utama.

Laboratorium enam skenario unduhan tersedia di `testing/local/lab-unduhan-heurishield`. Jalankan `Jalankan_Lab.ps1` dari folder tersebut. Halaman/API disimulasikan lokal; model dan aturan memakai extension asli.
