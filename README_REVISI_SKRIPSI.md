# Instruksi revisi skripsi — rancangan final HeuriShield v0.6.2

Dokumen ini merupakan petunjuk untuk penulis dan AI pendamping di perangkat lain. Acuan naskah yang diperiksa adalah **SKRIPSI UMAR FARUQ MANEK1.pdf**, terutama Bab IV. Versi implementasi penelitian dibekukan dengan tag **`skripsi-v0.6.2`**, commit **`2f43fe6`**. Jangan menggabungkan rancangan ini dengan RuleFit60, URL17, URL18, atau percobaan model lain.

**Pertahankan tulisan yang sudah sesuai. Perbarui hanya bagian yang tercantum di bawah.** Gunakan bahasa akademik bahasa Indonesia dan pertahankan gaya penulisan penulis. Jangan menambah metode, parameter, API, rule, bobot, klaim hasil, atau sitasi baru tanpa dasar. Dokumen ini tidak meminta penulisan ulang seluruh skripsi.

## 1. Rancangan yang menjadi acuan tetap

| Bagian | Ketentuan final |
|---|---|
| URL Analyzer | XGBoost, 20 fitur URL, 500 pohon, threshold 0,50. Probabilitas dihitung internal; hasil yang diteruskan hanya legitimate/phishing. |
| Informasi URL pendukung | `domain_age_days` dan `url_file_extension`, di luar 20 fitur masukan model. |
| Brand Analyzer | 9 parameter utama pada Tabel 4.2; pencarian domain-first, lalu token hostname/halaman apabila diperlukan. |
| DOM Analyzer | 8 parameter utama pada Tabel 4.3, termasuk informasi tautan unduhan. |
| Mesin aturan | R01–R19; keluaran berupa matched, not_matched, atau undetermined. Tidak menentukan verdict akhir. |
| Decision policy | Membaca kelas URL dan ID/status aturan untuk menetapkan keputusan akhir. Tidak diberi ID tersendiri. |
| Penggabungan | Kondisi logis, tanpa penjumlahan bobot risiko dan tanpa batas probabilitas tambahan setelah klasifikasi URL. |
| Hasil | Legitimate atau phishing. LIMITED/gagal analisis adalah status teknis, bukan kelas ketiga dataset. |
| Tindakan | Mengikuti pengaturan block page/popup serta allowlist/blocklist pengguna. |
| Pencatatan | Menyimpan hasil kelas, temuan, status rule dan keputusan akhir. Skor/probabilitas klasifikasi tidak disimpan pada catatan baru. |

Threshold 0,50 adalah konfigurasi versi penelitian. Jangan mengklaim bahwa audit ini membuktikan threshold tersebut optimal untuk semua data. Angka fitur URL dan batas umur domain tetap boleh digunakan; keduanya berbeda dari skor risiko tambahan DOM/brand.

Alur yang harus konsisten pada uraian dan diagram:

`URL -> ekstraksi 20 fitur -> XGBoost -> kelas URL -> pengumpulan evidence DOM/brand dan informasi pendukung -> evaluasi R01–R19 -> decision policy -> keputusan akhir -> tindakan/pencatatan`.

Alur tersebut menggambarkan ketergantungan logis; jangan menyatakan seluruh permintaan API/ekstraksi harus berjalan secara berurutan karena sebagian proses dapat dikoordinasikan bersamaan oleh service worker.

## 2. Bagian naskah yang perlu diperbarui

Gunakan nomor subbab dan judul tabel untuk mencari bagian, karena nomor halaman dapat bergeser setelah revisi.

| Lokasi pada naskah | Revisi yang diperlukan | Yang dipertahankan |
|---|---|---|
| Bab I/Bab IV yang menjelaskan keluaran URL dan penggabungannya | Tegaskan probabilitas hanya dipakai internal untuk threshold 0,50; lapisan rule/policy menerima kelas URL. | Pembahasan teori probabilitas XGBoost tetap boleh ada. |
| Tabel 4.1 Perancangan URL Analyzer | Tegaskan 20 fitur model + 2 informasi pendukung yang tidak masuk model. | Daftar dan definisi 20 fitur tidak diubah. |
| Tabel 4.2 Perancangan Brand Analyzer | Jelaskan logo berupa metadata; jelaskan makna konflik domain terkonfirmasi pada paragraf pendukung. | Tetap 9 parameter utama, domain-first dan token fallback. |
| Tabel 4.3 Perancangan DOM Analyzer | Hapus email biasa dari contoh has_sensitive_input; jelaskan tujuan form adalah action yang terbaca, bukan pengiriman aktual. | Tetap 8 parameter utama. |
| 4.2.5/Tabel 4.4 Perancangan Rule | Ubah rentang R01–R13 menjadi R01–R19. Tambahkan R14–R19. | Identitas R01–R13 tetap; tidak ada kategori C. |
| 4.2.6/Tabel 4.5 Perancangan Decision Policy | Ganti konjungsi panjang kondisi koreksi legitimate dengan rujukan ID R14–R19. Gunakan tabel policy pada bagian 5 dokumen ini. | Policy tidak diberi ID tersendiri dan tidak menghitung skor. |
| Diagram/alur yang terdampak | Selaraskan nama keluaran dan pemisahan evaluasi rule dari pengambilan keputusan. | Jangan menggambar ulang diagram yang sudah sesuai. |
| Rencana pengujian dan Bab V | Pisahkan pengujian fungsi, simulasi, uji live, replay, dan evaluasi model. | Jangan mengubah tujuan/metode penelitian karena penyelarasan implementasi ini. |

Kalimat penghubung yang dapat digunakan:

> URL Analyzer menggunakan model XGBoost untuk menghasilkan klasifikasi awal URL sebagai legitimate atau phishing berdasarkan 20 fitur URL. Probabilitas yang dihitung model digunakan secara internal dengan ambang keputusan 0,50. Hasil klasifikasi awal selanjutnya dikorelasikan dengan evidence dari DOM Analyzer, Brand Analyzer, serta informasi pendukung melalui R01 sampai R19. Setiap rule menghasilkan status evaluasi, sedangkan keputusan akhir ditetapkan oleh decision policy berdasarkan klasifikasi URL dan status rule yang aktif.

## 3. Definisi penting agar tulisan tidak melampaui implementasi

- **has_sensitive_input:** OTP, PIN, nomor kartu, CVV/CVC, recovery/backup code berdasarkan metadata input. Email biasa saja tidak mengaktifkannya. Password diperiksa terpisah.
- **brand_in_logo:** metadata alt, aria-label, title atau teks title SVG pada elemen logo. Tidak menggunakan OCR atau pengenalan citra/logo berbasis piksel.
- **brand_domain_mismatch:** domain rujukan berbeda disertai peniruan hostname terkonfirmasi atau klaim kredensial provider resmi terkonfirmasi. Perbedaan domain saja belum cukup untuk menghasilkannya sebagai true.
- **high_confidence_host_impersonation/high_confidence_credential_impersonation:** flag boolean berdasarkan kondisi yang dirancang, bukan skor atau persentase keyakinan.
- **verified_reference_domain:** referensi brand yang diterima melalui mekanisme pencarian/pencocokan sistem. Jangan diartikan sebagai pembuktian kepemilikan hukum perusahaan. Status claimed:false pada provider tidak otomatis membatalkan kecocokan domain.
- **form_cross_domain:** membandingkan domain tujuan action yang terbaca dengan domain halaman. Sistem tidak menyatakan telah mengamati pencurian atau pengiriman kredensial aktual.
- **destination_verification:** metadata detail form yang dipakai R04. Tujuan dapat dijelaskan oleh same-site, referensi brand, atau konteks provider OAuth. Pada konflik identitas terkonfirmasi, tujuan berbeda yang tidak memenuhi konteks tersebut dapat bernilai false. Informasi yang tidak memadai tetap unknown.
- **download_target_cross_domain:** metadata perbedaan registrable domain, bukan perbedaan hostname semata. `obsproject.com` dan `cdn-fastly.obsproject.com` tidak lintas domain. Metadata ini tidak menyebabkan pemblokiran mandiri.
- **Pemeriksaan unduhan:** membaca tautan dan akhiran file, bukan memeriksa isi file, membuktikan malware, atau menjeda/membatalkan transfer. Tautan yang baru dihasilkan JavaScript sesudah interaksi belum tentu terbaca pada snapshot awal.

`forms`, `candidates`, `same_origin`, konteks situs induk dan flag turunan lainnya merupakan metadata pemeriksaan. Jangan menambah jumlah fitur XGBoost atau jumlah parameter utama hanya karena metadata ini muncul dalam kondisi rule.

## 4. Tambahan untuk Tabel 4.4: R14–R19

Pertahankan R01–R13. Enam aturan berikut memeriksa syarat koreksi ketika hasil awal URL adalah phishing. Hasilnya hanya status rule; keputusan legitimate baru diberikan oleh policy.

| ID | Kondisi yang diperiksa | Fungsi |
|---|---|---|
| R14 | Halaman HTTPS pada domain provider OAuth yang cocok dengan referensi brand, identitas own_domain, snapshot asal sesuai halaman, struktur URL otorisasi dikenali (client_id, redirect_uri, serta response_type atau scope), same_site dan tanpa konflik. | Memeriksa halaman otorisasi resmi. Berbeda dari R06 yang memeriksa konteks kontrol/navigasi OAuth. |
| R15 | Identitas brand own_domain, judul serta heading/logo mendukung brand, official_domain_match tidak false, password ditemukan, form_cross_domain tidak true, parent_site_link=true, same_site=true, umur domain >=1095 hari dan tanpa konflik. | Memeriksa koreksi login yang didukung keterkaitan dengan situs induk. Unknown pada form tidak membuktikan form seasal; tautan situs induk menjadi bukti tambahan. |
| R16 | Brand/domain cocok, klaim kandidat didukung judul+heading/logo atau identitas pemilik yang didukung halaman teramati dan salah satu judul/heading/logo, password ditemukan, form same-origin, HTTPS, same_site, umur >=1095 hari dan tanpa konflik. | Memeriksa login pada domain brand yang sesuai. |
| R17 | Halaman HTTPS dengan path /docs, domain rujukan sesuai domain halaman, judul mendukung brand, snapshot sesuai, frame teramati, password=false, sensitive_input=false, form_cross_domain=false, same_site dan tanpa konflik. | Memeriksa halaman dokumentasi resmi. |
| R18 | Halaman HTTPS /search dengan parameter q, brand/domain cocok, same_site, snapshot asal sesuai bila tersedia, tidak ada bukti password/input sensitif/form lintas domain yang teramati dan tanpa konflik. | Memeriksa halaman pencarian pada domain brand yang sesuai. Sebagian DOM dapat belum terbaca; jangan menulis bahwa seluruh isi halaman selalu terverifikasi. |
| R19 | Halaman HTTPS teramati, kandidat/judul/domain brand konsisten, snapshot asal sesuai, password=false, sensitive_input=false, form_cross_domain=false, same_site, umur >=1095 hari dan tanpa konflik. | Memeriksa halaman resmi non-sensitif lainnya. |

“Tanpa konflik” mencakup tidak adanya brand_domain_mismatch=true, konflik klaim identitas yang terverifikasi, dan rule konflik matched. Detail teknis tetap mengikuti kode versi `skripsi-v0.6.2`; jangan menyederhanakan kondisi menjadi “brand cocok berarti selalu aman”.

R11 tetap menggunakan umur paling lama 365 hari bersama input sensitif dan konflik brand-domain sebagai bukti pendukung. Umur domain tidak menentukan verdict sendiri. Batas 1095 hari pada koreksi tertentu adalah konfigurasi heuristik implementasi, bukan hasil probabilitas model atau hukum universal usia situs legitimate. Jangan membuat sitasi untuk angka tersebut tanpa sumber yang benar-benar mendukungnya.

## 5. Tabel Decision Policy final — tanpa ID policy

Urutan baris penting. Temuan phishing terkonfirmasi diperiksa sebelum koreksi legitimate.

| Kondisi | Keputusan/tindakan analisis |
|---|---|
| Hasil URL tidak tersedia | Pemeriksaan belum lengkap; tidak dihitung sebagai klasifikasi terverifikasi. |
| URL phishing dan R12 matched | Phishing, dengan dukungan bukti unduhan. |
| R13 matched | Phishing. |
| Salah satu R03/R07/R10 matched | Phishing. |
| R09 matched | Phishing. |
| URL phishing, salah satu R14–R19 matched, dan tidak ada rule konflik matched | Legitimate. |
| Tidak memenuhi kondisi di atas | Pertahankan hasil klasifikasi URL. |

Rule konflik: **R03, R04, R05, R07, R09, R10, R12, R13**. R04/R05 menghalangi koreksi legitimate, tetapi tidak sendirian mengubah URL legitimate menjadi phishing. R01/R02/R06/R08/R11 juga tidak menentukan verdict mandiri. Unknown/undetermined tidak diperlakukan sebagai matched.

Apabila tabel dipisahkan berdasarkan kelas awal, tuliskan secara eksplisit `URL legitimate AND R13=matched -> phishing`. Jika beberapa R14–R19 aktif bersamaan, urutan alasan adalah R14, R15, R16, R17, R18, R19; verdict tetap legitimate. Allowlist/blocklist pengguna ditangani sebelum alur keputusan otomatis ini.

## 6. Dasar rencana pengujian yang dapat ditulis

Rencana berikut merupakan rancangan pengujian. Jangan menuliskannya sebagai hasil yang sudah tercapai sebelum dilaksanakan dan tersedia catatannya.

| Kelompok | Yang diuji | Kriteria dan bukti yang dicatat |
|---|---|---|
| Ekstraksi URL | Kesetaraan 20 fitur terhadap extractor pelatihan; threshold 0,50 termasuk batas tepat 0,50. | Nama/nilai fitur dan kelas model; tanpa menambah umur domain ke vektor model. |
| Ekstraksi DOM/brand | Login biasa, OTP/PIN/kartu, tanpa form, form action relatif/seasal/lintas domain, unknown, brand cocok/tiruan/tidak tersedia, metadata logo. | Temuan sesuai elemen fixture; input dummy rahasia tidak tersimpan. |
| Aturan R01–R19 | Kasus positif, kondisi tidak terpenuhi, serta informasi tidak mencukupi. | ID, evidence dan status rule sesuai kondisi. R05 yang belum terverifikasi tetap undetermined; R11 tetap pendukung. |
| Decision policy | URL legitimate dikoreksi phishing; URL phishing dikoreksi legitimate; beberapa rule aktif; konflik dan fallback. | Kelas awal, status rule, keputusan akhir dan sumber keputusan sesuai tabel pada bagian 5. |
| OAuth/SSO dan halaman dinamis | Provider resmi, provider tiruan, tombol Google pada situs lain, form muncul sesudah interaksi, SPA, iframe tidak dapat dibaca. | Identitas provider tidak keliru dianggap identitas situs asal; perubahan metadata teramati; unknown tidak dipakai sebagai bukti aman. |
| Unduhan | Brand tiruan+EXE, brand tiruan+PDF, domain cocok+EXE, tanpa brand+EXE, tanpa unduhan, URL berakhiran EXE; CDN se-domain dan domain berbeda. | Tautan/akhiran/domain terbaca; R12/R13 sesuai syarat; EXE/domain berbeda saja tidak otomatis memblokir. |
| Fitur pengguna | Allowlist, blocklist, pemilihan popup/block page, riwayat dan analisis ulang. | Pilihan tersimpan, diterapkan konsisten, domain izin dapat dibuka, domain blokir ditindak sesuai pengaturan. |
| Uji live | Legitimate dan phishing baru yang belum dipakai untuk pengembangan, diuji menggunakan versi beku. | Label/sumber/waktu, URL awal/akhir, versi/hash, status ketersediaan, kelas URL, temuan, aturan, keputusan akhir, waktu proses, dan tanpa analisis. |
| Replay regresi | Jalankan aturan versi yang diuji pada rekaman hasil ekstraksi lama. | Bandingkan per URL; catat perbaikan dan regresi. Bedakan rekaman lengkap, parsial dan tidak dapat diputar. |
| UAT bila dimasukkan dalam metodologi | Pengguna menafsirkan hasil/alasan, mengelola daftar dan pengaturan, serta menyelesaikan skenario penggunaan. | Responden, instrumen, prosedur dan kriteria penilaian dijelaskan dahulu; jangan mengarang responden atau hasil. |

Untuk uji live, gunakan confusion matrix, precision, recall phishing, specificity legitimate, F1, akurasi gabungan dan coverage. Tetapkan phishing sebagai kelas positif. Persentase benar pada daftar satu kelas bukan akurasi gabungan dua kelas. Halaman tidak tersedia/error/challenge, redirect dan kegagalan analisis dilaporkan terpisah; no analysis tidak otomatis dianggap benar atau salah model.

Simulasi lokal dapat memakai halaman/API fixture untuk memastikan kondisi rule. Untuk evaluasi API publik dan kondisi nyata, lakukan pengujian tersendiri. API fixture bukan bukti keberhasilan layanan publik. Data yang dipakai memperbaiki model/rule menjadi data pengembangan dan tidak lagi dihitung sebagai uji independen baru.

Arsip harus mencatat seluruh URL yang dicoba, termasuk yang gagal, supaya jumlah awal, coverage dan evaluasinya dapat ditelusuri. Perubahan desain tidak diperlukan hanya untuk menambahkan hasil pengujian terhadap versi yang sama.

## 7. Bukti yang sudah tersedia — laporkan sesuai jenisnya

- 31/31 pengujian fungsi/integrasi lulus.
- Di dalam pengujian policy, 32.768 kombinasi kelas URL dan rule sesuai tabel keputusan. Angka ini bukan jumlah situs live.
- 6/6 skenario laboratorium unduhan sesuai kondisi; halaman/API disimulasikan lokal dengan model/aturan asli.
- Replay 1.087 rekaman sesudah audit akhir: legitimate **809/842 (96,08%)**, phishing **200/245 (81,63%)**. Tidak ada keputusan berubah dibanding versi kategoris sebelum audit akhir.
- Rekaman replay terdiri atas 323 snapshot/API lengkap relatif terhadap replay, 763 parsial, dan satu replay tingkat keputusan. Jangan menyebut semua rekaman lengkap.
- Angka tersebut belum membuktikan minimal 85% untuk kedua kelas. Jangan mengubah 81,63% menjadi >=85% atau menyatakan penelitian telah mencapai target itu.
- Model terlatih, 20 fitur, 500 pohon dan threshold 0,50 tidak berubah dalam audit ini. Pengujian publik baru tidak dijalankan oleh audit.

## 8. Berkas sumber dan keluaran yang diminta dari AI penulis

Acuan teknis pada tag `skripsi-v0.6.2`:

- `extension/HeuriShield-URL20-XGBoost/src/analyzer/correlation/evidence-rules.js` — R01–R10/R12/R13.
- `extension/HeuriShield-URL20-XGBoost/src/analyzer/domain/domain-age-policy.js` — R11.
- `extension/HeuriShield-URL20-XGBoost/src/analyzer/correlation/correction-rules.js` — R14–R19.
- `extension/HeuriShield-URL20-XGBoost/src/analyzer/correlation/decision-policy.js` — pemetaan keputusan.
- `reports/final_audit_20261109/kontrak_final.json` — nama fitur/parameter dan hash runtime yang dibekukan.
- `reports/final_audit_20261109/extension_tests.json` dan `replay_summary.json` — bukti pengujian.

**Instruksi keluaran untuk AI penulis:**

1. Baca naskah yang saya berikan dan dokumen ini.
2. Sebutkan lokasi yang perlu diubah; pertahankan bagian yang sudah benar.
3. Berikan teks pengganti/tambahan dan tabel untuk bagian tersebut, siap ditempel.
4. Pisahkan revisi rancangan dari rencana pengujian dan hasil yang sudah tersedia.
5. Pertahankan format sitasi yang sudah digunakan. Jangan menambahkan sitasi palsu atau menyatakan sumber membahas angka/kondisi yang belum diperiksa.
6. Jangan menawarkan model, fitur, ID rule, skor, atau desain alternatif. Untuk ketidaksesuaian yang tidak dijelaskan acuan ini, tandai pertanyaannya secara spesifik; jangan mengisi dengan asumsi.

Sesudah paket revisi ini diterapkan, uraian versi penelitian mengacu pada v0.6.2. Pengembangan berikutnya harus dinyatakan sebagai versi berbeda, bukan otomatis mengganti rancangan yang sedang ditulis.
