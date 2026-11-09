# Acuan final penulisan HeuriShield — v0.6.2

**Gunakan dokumen ini sebagai acuan implementasi penelitian.** Laporan v0.5.x, v0.6.0 dan v0.6.1 merupakan riwayat pengembangan. Rancangan dibekukan pada penanda lokal `skripsi-v0.6.2`; perbaikan/eksperimen di kemudian hari tidak boleh dianggap otomatis mengubah versi penelitian ini.

Audit membaca PDF `SKRIPSI UMAR FARUQ MANEK1.pdf`, terutama Bab IV bagian analyzer, Tabel 4.4 dan Tabel 4.5; memeriksa kode aktif dari service worker; menguji fungsi/browser lokal; dan memutar ulang bukti lama. PDF asli belum diubah. Kesesuaian ini berlaku untuk arsitektur dan implementasi yang diperiksa, bukan pengesahan seluruh sitasi atau seluruh isi skripsi.

## 1. Rancangan yang ditetapkan

| Komponen | Ketentuan final |
|---|---|
| URL Analyzer | XGBoost; 20 fitur URL; 500 pohon; threshold 0,50. Probabilitas dihitung di dalam model; keluaran ke lapisan berikutnya hanya legitimate/phishing. |
| Informasi URL pendukung | `domain_age_days` dan `url_file_extension`; bukan fitur ke-21/22 dalam model. |
| Brand Analyzer | 9 parameter utama sesuai Tabel 4.2 PDF. Pencarian domain-first, kemudian token hostname/halaman bila perlu. |
| DOM Analyzer | 8 parameter utama sesuai Tabel 4.3 PDF. Membaca metadata, bukan isi kredensial. |
| Mesin aturan | R01–R19. Status matched/not_matched/undetermined. Tidak mengeluarkan keputusan akhir. Tidak ada kategori ID C. |
| Decision policy | Memakai kelas URL dan ID/status rule. Tidak mempunyai ID tersendiri, tidak membaca probabilitas, dan tidak mengulang pemeriksaan DOM/brand. |
| Tindakan | Mengikuti pilihan block page atau popup dan daftar izin/blokir pengguna. |
| Penyimpanan | Kelas URL, temuan, aturan/status dan keputusan akhir; tidak menyimpan skor/probabilitas klasifikasi pada hasil baru. |

Fitur dan nama parameter final ada di `kontrak_final.json`. Ukuran numerik fitur URL, batas umur domain, dan informasi teknis tetap dapat berupa angka. Yang tidak dipakai adalah skor risiko tambahan atau penjumlahan bobot DOM/brand. `high_confidence_*` adalah flag boolean hasil kondisi, bukan persentase kepercayaan.

## 2. Makna parameter dan metadata yang harus ditulis secara tepat

- Domain pembanding adalah registrable domain dengan public/private suffix parser. Subdomain CDN OBS masih memiliki domain pembanding `obsproject.com`; hostname berbeda belum tentu lintas domain.
- Brand cocok berarti referensi brand dari jalur API yang diterima sesuai domain yang dibuka. Ini bukan pemeriksaan kepemilikan perusahaan secara hukum atau kriptografis. `claimed:false` pada provider tidak otomatis menolak kecocokan domain.
- `brand_in_logo` membaca metadata logo: alt, aria-label, title atau teks title SVG pada elemen terkait. Tidak melakukan pengenalan citra/piksel, OCR, atau pembandingan visual logo.
- `has_sensitive_input` aktif untuk OTP, PIN, nomor kartu, CVV/CVC, dan recovery/backup code sesuai metadata input. Email biasa saja tidak dijadikan input sensitif oleh extractor aktif. Password dicatat terpisah.
- Form lintas domain berasal dari tujuan action yang dapat dibaca, bukan bukti bahwa pengiriman aktual telah terjadi. Form JavaScript yang tujuannya tidak terbaca dipertahankan unknown. Form seasal bukan bukti keamanan mandiri.
- `destination_verification` adalah metadata detail form yang sudah dipakai R04. Same-site, referensi brand, dan konteks provider OAuth yang dikenal dapat menjelaskan tujuan. Tujuan lain menjadi false hanya pada konteks konflik identitas terkonfirmasi; selain itu tetap unknown. Tidak dilakukan verifikasi hukum hubungan mitra.
- `brand_domain_mismatch=true` memerlukan domain referensi berbeda disertai peniruan hostname yang terkonfirmasi atau klaim kredensial provider resmi yang terkonfirmasi. Perbedaan domain saja tetap potential_mismatch/unknown. Domain cocok menghasilkan false.
- Nama seperti `forms`, `candidates`, `same_origin`, `observed_frame_count`, `brand_claim_relation`, `provider_credential_claim`, `high_confidence_*` dan konteks situs induk merupakan metadata/hasil turunan pemeriksaan, bukan tambahan fitur XGBoost atau perubahan jumlah parameter utama pada tabel.
- `download_target_cross_domain` hanya dicatat sebagai metadata. Saat ini ia tidak menjadi kondisi mandiri R12/R13. Ekstensi EXE/APK dan tautan unduhan bukan bukti isi file berbahaya.
- Halaman/URL tanpa hasil model yang dapat digunakan mendapat status teknis LIMITED atau gagal analisis. Itu bukan kelas ketiga pada label dataset; kelas klasifikasi tetap legitimate/phishing.

## 3. Daftar aturan final

| ID | Kondisi inti yang diperiksa |
|---|---|
| R01 | Brand identified dan official_domain_match=false. Perbedaan referensi belum menjadi keputusan phishing. |
| R02 | Brand identified dan brand_domain_mismatch=true, yaitu konflik identitas yang telah didukung bukti. |
| R03 | Rangkaian brand identified, konflik brand-domain terkonfirmasi, dan password/input sensitif. |
| R04 | Form relevan, lintas domain, dan destination_verification=false; bila verifikasi belum tersedia, status tetap undetermined. |
| R05 | Redirect login pada konteks brand yang tujuannya belum diketahui sebagai same_site/official_provider. Tujuan yang belum terverifikasi tetap undetermined, bukan otomatis phishing. |
| R06 | Kontrol OAuth, provider dikenali, dan navigasi ke official_provider teramati. Konteks resmi, bukan izin otomatis. |
| R07 | Peniruan identitas provider OAuth, konflik brand-domain, dan input sensitif. |
| R08 | Identitas ambiguous atau kecocokan domain/tujuan form unknown. Menandai keterbatasan, bukan tuduhan phishing. |
| R09 | high_confidence_host_impersonation=true. |
| R10 | high_confidence_credential_impersonation=true, input sensitif, serta bukti hostname/konflik domain/form lintas domain/klaim kredensial provider sesuai kondisi kode. |
| R11 | Umur paling lama 365 hari, input sensitif, serta konflik brand-domain. supporting_only=true; tidak mengubah verdict sendiri. |
| R12 | URL phishing, brand identified, indikasi kuat peniruan, dan tawaran unduhan dari DOM atau akhiran executable URL. |
| R13 | Brand identified, referensi berbeda dan tersedia, klaim pada hostname, judul mendukung kandidat brand yang sama, dan tawaran installer/skrip dari DOM atau URL. |
| R14 | Konteks koreksi halaman otorisasi OAuth resmi pada domain provider. |
| R15 | Konteks koreksi login dengan identitas own_domain, judul+heading/logo, tautan dari situs induk, same_site, umur >=1095 hari dan tanpa konflik. official_domain_match tidak false dan form_cross_domain tidak true. |
| R16 | Konteks koreksi login HTTPS pada domain brand yang cocok, kandidat halaman didukung bukti judul/heading/logo sesuai kondisi, form password same-origin, umur >=1095 hari dan tanpa konflik. |
| R17 | Konteks koreksi halaman /docs pada HTTPS, domain brand cocok, judul mendukung brand, tanpa input sensitif/form lintas domain, dan tanpa konflik. |
| R18 | Konteks koreksi halaman /search?q= pada HTTPS dan domain brand cocok, tanpa bukti input sensitif/form lintas domain yang teramati. |
| R19 | Konteks koreksi halaman non-sensitif HTTPS yang teramati, domain/kandidat/judul sesuai brand, umur >=1095 hari dan tanpa konflik. |

R14–R19 diperiksa ketika kelas URL phishing. Status matched menyatakan syarat rule terpenuhi, bukan verdict legitimate. Untuk R15, unknown pada pemeriksaan form tidak sama dengan bukti form seasal; koreksi membutuhkan bukti independen berupa tautan situs induk. R18 dapat mengoreksi halaman pencarian pada domain brand yang cocok ketika sebagian DOM belum terbaca, selama tidak ada bukti sensitif yang teramati. Jangan menulis bahwa semua koreksi selalu mensyaratkan seluruh DOM terverifikasi.

Definisi teknis lengkap dan konjungsi terdapat pada `src/analyzer/correlation/evidence-rules.js`, `correction-rules.js`, dan `src/analyzer/domain/domain-age-policy.js`. Metadata hilang tidak dianggap bukti pemenuhan kondisi; kondisi yang belum dapat ditentukan tidak mengaktifkan rule phishing/koreksi.

## 4. Decision policy final tanpa ID tersendiri

| Kondisi | Hasil |
|---|---|
| Kelas URL tidak tersedia | Status teknis pemeriksaan tidak lengkap |
| URL phishing dan R12 matched | Phishing dengan dukungan bukti unduhan |
| R13 matched | Phishing |
| Salah satu R03/R07/R10 matched | Phishing |
| R09 matched | Phishing |
| URL phishing, salah satu R14–R19 matched, dan tidak ada konflik matched | Legitimate |
| Selain kondisi tersebut | Pertahankan kelas URL |

Rule konflik yang menghalangi koreksi legitimate: R03, R04, R05, R07, R09, R10, R12, R13. R04/R05 tidak sendirian mengubah URL legitimate menjadi phishing. R01/R02/R06/R08/R11 juga tidak menentukan verdict mandiri. Jika beberapa koreksi legitimate aktif bersamaan, prioritas alasan R14, R15, R16, R17, R18, R19; verdict tetap legitimate. Indikasi phishing terkonfirmasi diperiksa lebih dahulu. Allowlist/blocklist manual ditangani sebelum alur ini.

## 5. Perbaikan konkret yang ditutup oleh audit

1. `brand_domain_mismatch` sebelumnya tidak dapat bernilai true dari analyzer live. Kini flag konflik terkonfirmasi dihasilkan dari bukti yang didefinisikan di atas. R02/R03/R07/R10/R11 tidak lagi bergantung pada flag buatan pengujian.
2. `destination_verification` sebelumnya hanya dibaca evaluator R04, belum dipasok pada jalur live. Kini metadata tersebut diisi dari bukti yang tersedia; unknown tetap unknown.
3. R14–R19 kini membedakan ketidaklengkapan dari kondisi yang jelas tidak cocok. Rule tetap tidak mengeluarkan verdict.
4. R11 memakai evaluator yang sama pada browser dan replay. Jejak seluruh R01–R19 ikut diperiksa di browser.

Tidak ada model baru, API baru, parameter utama baru, atau ID tambahan sesudah R19 pada audit ini.

## 6. Satu paket revisi pada PDF saat ini

Bagian yang sudah benar dipertahankan. Terapkan hanya penyelarasan berikut:

1. **4.2.5/Tabel 4.4:** ubah rentang R01–R13 menjadi R01–R19 dan tambahkan enam aturan koreksi yang sudah ditetapkan. Definisi R01–R13 dipertahankan; jelaskan makna konflik terkonfirmasi dan metadata tujuan form sesuai bagian 2.
2. **4.2.6/Tabel 4.5:** ganti konjungsi panjang koreksi legitimate dengan rujukan R14–R19 serta syarat tidak ada rule konflik matched. Tambahkan baris `URL legitimate AND R13=matched -> phishing`, yang belum ditulis tersendiri pada tabel PDF.
3. **Tabel 4.3:** hapus email biasa dari contoh `has_sensitive_input`; gunakan OTP, PIN, nomor kartu, CVV/CVC dan recovery code. Jelaskan form_cross_domain membaca tujuan yang tertera, bukan pengiriman aktual.
4. **Pembahasan logo:** sebut metadata elemen logo, bukan analisis gambar atau OCR.
5. **Kebutuhan/alur URL dan policy:** probabilitas boleh dibahas dalam teori XGBoost, tetapi tegaskan hanya dipakai secara internal untuk threshold 0,50. Policy menerima kelas URL, bukan probabilitas. Ubah kalimat “keputusan tidak hanya bergantung pada probabilitas” menjadi “keputusan menggunakan klasifikasi awal URL dan status aturan yang telah dievaluasi”.
6. **Pengujian/Bab V:** pisahkan hasil model, hasil akhir extension, coverage/kegagalan analisis, simulasi lokal, dan replay. Jangan menyebut simulasi dengan API fixture sebagai pengujian API publik atau uji live independen.

Tabel URL tetap 20 fitur model + 2 informasi pendukung; tabel brand tetap 9 parameter utama; tabel DOM tetap 8 parameter utama. Tidak perlu menulis ulang keseluruhan Bab II–IV atau mengubah metode hanya karena penyelarasan ini.

## 7. Bukti pengujian final

- **31/31 pengujian** fungsi/integrasi lulus.
- Di dalam pengujian policy, **32.768 kombinasi** aturan/kelas URL sesuai tabel keputusan.
- **6/6 skenario** laboratorium unduhan sesuai kondisi aturan; API/halaman fixture lokal, model dan aturan asli.
- Browser memverifikasi 19 ID aturan yang unik, status yang valid, flag konflik dan tujuan form, ketiadaan skor klasifikasi tersimpan, serta input dummy rahasia yang tidak ikut snapshot.
- Model native, kontrak fitur, extractor URL dan model sumber tidak berubah dari checkpoint GitHub. TH0,50 tetap digunakan; audit ini tidak membuktikan bahwa 0,50 merupakan threshold optimal universal.
- Launcher live lolos dry-run versi 0.6.2 dan verifikasi hash.

| Replay 1.087 rekaman | Sebelum audit | Sesudah audit |
|---|---|---|
| Legitimate | 809/842 (96,08%) | 809/842 (96,08%) |
| Phishing | 200/245 (81,63%) | 200/245 (81,63%) |

Tidak ada keputusan berubah. Jejak aturan berubah karena sambungan evidence yang diperbaiki. Terdapat 323 snapshot/API lengkap relatif terhadap replay, 763 parsial, dan satu replay keputusan saja. Replay bukan jaminan hasil identik pada situs baru atau bukti semua respons API lama dapat direkonstruksi. Target minimal 85% untuk kedua kelas belum dibuktikan oleh arsip ini; angka phishing 81,63% harus tetap dilaporkan.

## 8. Cara mempertahankan acuan penulisan

- Gunakan versi v0.6.2 dan `kontrak_final.json`, bukan cabang eksperimen lain.
- Jalankan `python .\scripts\cek_acuan_skripsi.py` untuk memastikan berkas runtime belum berubah dari kontrak.
- Perubahan konfigurasi/model/rule setelah pembekuan adalah versi lain dan tidak otomatis mengganti uraian versi penelitian ini.
- Eksperimen lanjutan dan hasil uji tambahan boleh dilaporkan sebagai evaluasi tanpa mengganti desain yang dibekukan.
- Laporan ini tidak menjanjikan perangkat lunak bebas bug selamanya. Temuan bug yang nyata tetap harus diungkapkan, bukan disembunyikan demi mempertahankan tulisan.

Extension aktif: `extension/HeuriShield-URL20-XGBoost`. Berkas acuan: `kontrak_final.json`, `audit_checks.json`, `extension_ready.json`, `extension_tests.json`, `replay_summary.json`, `replay_rows.csv`, dan `hasil_simulasi.json`. Audit tidak menjalankan uji live publik. Checkpoint GitHub belum diperbarui dari v0.5.2 pada saat acuan ini dibuat.
