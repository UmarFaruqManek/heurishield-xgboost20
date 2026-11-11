# Audit Rule dan Decision Policy HeuriShield — v0.7.0

Tanggal: 12 November 2026. Branch: `refactor/v0.7-audit-clean`. Objek audit: rule R01–R19 dan decision policy yang berasal dari `skripsi-v0.6.2`, setelah pembersihan kode warisan (keputusan identik dengan v0.6.2 + perubahan `credentialHostClaim`).

## 1. Prinsip penelitian yang dipakai sebagai tolok ukur

1. HeuriShield mendeteksi dan memblokir phishing dengan analisis heuristik, yaitu analisis karakteristik situs.
2. URL dianalisis oleh model XGBoost (20 fitur, threshold 0,50). Hasilnya kelas legitimate/phishing.
3. Umur domain dan akhiran file unduhan adalah informasi pendukung, bukan input model.
4. Brand dan DOM diproses dengan sistem berbasis aturan yang logis, **tanpa bobot atau skor**.
5. Kelas URL bukan satu-satunya alasan. Brand dan DOM diperiksa terlebih dahulu; **hanya jika brand dan DOM tidak memberikan alasan apa pun, keputusan akhir mengikuti kelas URL**.
6. Parameter dikunci: 20 fitur URL + 2 informasi pendukung, 9 parameter brand, 8 parameter DOM.

## 2. Data dan cara ukur

- Sumber: `replay_baseline.json` (3.636 rekaman dari arsip dan seluruh run live `testing/live/url20*`), diputar ulang dengan kode saat ini tanpa akses jaringan. Respons API brand diambil dari rekaman.
- Rekaman ganda (URL yang sama pada arsip dan run live) diambil satu, yaitu yang paling lengkap: **1.831 URL unik** (1.334 legitimate, 497 phishing). Sebanyak 819 snapshot lengkap, 1.007 parsial, dan 5 hanya tingkat keputusan.
- Seluruh data ini sudah pernah dipakai dalam pengembangan, sehingga statusnya **data pengembangan, bukan uji independen**. Angka di sini dipakai untuk audit dan perancangan. Evaluasi akhir harus memakai daftar baru yang belum dibuka.
- Skrip: `analyze_rules.py` (hasil lengkap di `rule_audit.json`).

## 3. Temuan utama

### 3.1 Brand dan DOM hampir tidak pernah memberi alasan

| | Legitimate benar | Phishing benar |
|---|---:|---:|
| Kelas URL saja | 1.195/1.334 (89,58%) | 371/497 (74,65%) |
| Keputusan akhir (dengan rule) | 1.236/1.334 (92,65%) | 378/497 (76,06%) |

- **1.762 dari 1.831 keputusan (96%) berasal langsung dari kelas URL** (`source = url_model`). Rule hanya mengubah 50 keputusan: 41 phishing→legitimate yang benar, 8 legitimate→phishing yang benar, dan 1 phishing→legitimate yang salah.
- Dalam praktik, sistem bekerja hampir sebagai pengklasifikasi URL murni. Ini berlawanan dengan prinsip nomor 5.

### 3.2 Rule yang informatif tidak diberi wewenang, sedangkan banyak rule tidak pernah aktif

| Rule | Matched (Legitimate / Phishing) | Menentukan verdict? | Catatan |
|---|---|---|---|
| R01 brand teridentifikasi, domain resmi berbeda | 4 / 78 | Tidak | Sinyal terkuat dalam data (95% phishing), tetapi hanya menjadi jejak |
| R02 konflik brand-domain terkonfirmasi | 0 / 25 | Tidak | 100% phishing, tetap hanya jejak |
| R03, R07, R10 peniruan kredensial | 0 / 6, 0 / 5, 0 / 6 | Ya | Benar semua, tetapi sangat jarang |
| R04 form lintas domain tak terverifikasi | 0 / 0 | Ya (penghalang koreksi) | Tidak pernah aktif |
| R05 redirect login tak terverifikasi | 0 / 0 | Penghalang koreksi | `login_redirect_detected` 100% unknown pada pengujian otomatis |
| R06 konteks OAuth resmi | 0 / 0 | Tidak | Tidak pernah aktif |
| R08 identitas ambigu / informasi unknown | 519 / 322 | Tidak | Aktif pada 46% rekaman; tidak membedakan kelas |
| R09 peniruan host | 0 / 22 | Ya | Benar semua |
| R11 umur ≤365 + input sensitif + konflik | 0 / 0 | Tidak (pendukung) | Tidak pernah aktif karena mensyaratkan konflik terkonfirmasi |
| R12 URL phishing + peniruan + unduhan | 0 / 3 | Ya | Benar |
| R13 brand + installer | 0 / 0 | Ya | Tidak pernah aktif |
| R14 halaman OAuth provider | 0 / 0 | Ya (koreksi) | Tidak pernah aktif |
| R15 login + tautan situs induk | 3 / 0 | Ya | Benar |
| R16 login resmi | 11 / 0 | Ya | Benar |
| R17 halaman `/docs` | 0 / 0 | Ya | Tidak pernah aktif; dibuat untuk satu kasus |
| R18 halaman `/search?q=` | 0 / 0 | Ya | Tidak pernah aktif; dibuat untuk satu kasus |
| R19 halaman resmi non-sensitif | 28 / 1 | Ya | Satu-satunya koreksi yang salah |

Delapan dari 19 rule tidak pernah aktif pada 1.831 URL. R08 aktif hampir pada separuh data tetapi tidak membawa informasi. R01 dan R02, yang paling bisa membedakan phishing, justru tidak boleh memengaruhi keputusan.

### 3.3 Parameter brand mengandung keputusan tersembunyi dan definisi melingkar

1. **`official_domain_match` bersifat melingkar.** Brand Analyzer lebih dahulu bertanya kepada direktori: "domain yang dibuka ini milik brand apa?" Jika direktori punya entri untuk domain itu, brand dianggap teridentifikasi dan domainnya otomatis dianggap resmi. Direktori seperti Clearbit juga memuat domain tiruan, sehingga:
   - `roblox.ly`, `roblox.com.ml`, `roblox.com.et`, `robiox.com.gr` teridentifikasi sebagai "Roblox" dengan `official_domain_match = true`. Ada **31 phishing yang lolos** dari pola ini (brand sama, akhiran domain berbeda dari domain kanonik `roblox.com`).
   - Penyewa hosting bersama (`*.wpengine.com`, `*.gitbook.io`, `sharemyhtml.com`) teridentifikasi sebagai brand platformnya. Ada **14 phishing lolos**.
   - Akibatnya, pada konteks kelas URL phishing, `official_domain_match = true` muncul pada 110 legitimate **dan** 62 phishing. Parameter ini tidak dapat dipakai sebagai alasan legitimate dalam definisinya sekarang.
2. **`brand_domain_mismatch`, `high_confidence_host_impersonation`, dan `high_confidence_credential_impersonation` adalah rule yang disembunyikan di dalam ekstraksi parameter.** Ketiganya dihitung dari belasan kondisi di `brand-evidence.js` (judul, heading, logo, password, kontrol login, rank kandidat, artikel, provider OAuth). Akibatnya R02, R03, R07, R09, R10, dan R12 hanya meneruskan flag yang sudah merupakan keputusan, dan logikanya tidak tampak pada tabel rule.
3. **Rule membaca metadata di luar parameter resmi**: daftar kandidat brand, detail per-form, `same_origin`, path `/docs`/`/search`, tautan situs induk, `sameSite`, `observed_frame_count`, dan snapshot mentah. R14–R19 hampir seluruhnya dibangun dari metadata ini, sehingga tidak dapat dijelaskan memakai 17 parameter pada naskah.

### 3.4 Kualitas observasi parameter DOM

| Parameter | Unknown pada legitimate | Unknown pada phishing |
|---|---:|---:|
| `login_redirect_detected` | 100% | 100% |
| `has_download_link` | 68% | 54% |
| `brand_in_logo` | 66% | 42% |
| `has_sensitive_input` | 23% | 9% |
| `form_cross_domain` | 24% | 15% |

`login_redirect_detected` hanya dapat diamati setelah pengguna mengklik tombol login. Pada pengujian otomatis nilainya selalu unknown, sehingga rule yang bergantung padanya (R05) tidak dapat diuji melalui uji live otomatis. Ini keterbatasan, bukan kesalahan, tetapi harus dinyatakan.

### 3.5 Pola kesalahan

**Phishing yang lolos (119):**

| Pola | Jumlah | Apakah brand/DOM bisa memberi alasan? |
|---|---:|---|
| Brand sama, akhiran domain berbeda (ccTLD squat Roblox) | 31 | Ya, jika `official_domain_match` tidak melingkar |
| Tanpa identitas brand | 31 | Hanya lewat DOM/umur domain |
| Brand ambigu | 25 | Terbatas |
| Penyewa hosting bersama | 14 | Ya, jika penyewa tidak disamakan dengan platform |
| Situs sah yang disusupi / terdaftar sendiri di direktori | 11 | Sulit; perlu kombinasi DOM |
| Konflik brand terlihat (R01) tetapi tidak menentukan | 7 | Ya. Contoh: `fedex.cqgty.cfd`, `www.facebook.gerardking.dev`, `homeloans-wellsfargo-com.sbx.pgsdemo.com` (brand di subdomain domain asing) |

Sebagian rekaman phishing `*.pages.dev` dialihkan oleh kit phishing ke `www.facebook.com` yang asli (*cloaking*). Halaman yang dianalisis adalah Facebook asli, sehingga verdict aman pada halaman itu bukan kesalahan logika. Pada evaluasi, kasus seperti ini perlu dilaporkan terpisah.

**Legitimate yang diblokir (98):** 68 di antaranya situs organisasi kecil (universitas, rumah sakit, pemerintah daerah) yang brand-nya cocok dengan domain sendiri. Rule koreksi R15/R16/R19 tidak aktif karena syaratnya sempit (judul harus memuat nama brand, umur harus diketahui ≥1095 hari, dan lain-lain). Melonggarkan syarat tanpa memperbaiki definisi `official_domain_match` akan ikut meloloskan phishing ccTLD squat dan penyewa hosting.

## 4. Kesimpulan audit

1. Masalah utama bukan pada jumlah rule, tetapi pada **definisi parameter brand** (melingkar dan menyimpan keputusan) dan **pembagian wewenang** (rule terkuat tidak boleh memutus).
2. Rule koreksi R14–R19 adalah tambalan kasus per kasus yang membaca metadata di luar parameter resmi. Dua di antaranya tidak pernah aktif.
3. Decision policy saat ini sudah berurutan dengan benar (bukti phishing lebih dahulu, lalu koreksi legitimate, lalu kelas URL), tetapi daftar rulenya perlu diganti.

## 5. Usulan rancangan baru (perlu persetujuan sebelum implementasi)

### 5.1 Pemisahan tanggung jawab

| Lapisan | Tanggung jawab | Tidak boleh |
|---|---|---|
| Analyzer URL | 20 fitur → kelas URL; `domain_age_days`, `url_file_extension` | Membaca DOM/brand |
| Analyzer brand/DOM | Mengisi 17 parameter sebagai **observasi** bernilai `true`/`false`/`unknown` (atau kategori) | Memutuskan phishing/legitimate; menghitung skor |
| Rule | Konjungsi logis atas kelas URL + 17 parameter + 2 informasi pendukung | Membaca metadata mentah; memakai bobot |
| Decision policy | Urutan: alasan phishing → alasan legitimate → kelas URL | Membaca parameter langsung |

Metadata (kandidat, form, snapshot) tetap disimpan untuk menjelaskan **mengapa** parameter bernilai tertentu, bukan sebagai input rule.

### 5.2 Perbaikan definisi parameter brand

- **`claimed_brand`**: brand yang diklaim **oleh halaman** (judul, heading, logo, label hostname), bukan brand pemilik domain menurut direktori.
- **`verified_reference_domain`**: domain kanonik brand tersebut, hasil pencarian **berdasarkan nama brand**. Pencarian berdasarkan domain yang sedang dibuka tidak boleh menjadi satu-satunya rujukan.
- **`official_domain_match`**: registrable domain halaman sama dengan (atau subdomain dari) domain rujukan, dan host bukan penyewa pada platform hosting bersama.
- **`host_brand_claim`**: tetap memakai `exact`/`lookalike`/`subdomain_exact`/`subdomain_lookalike`, ditambah nilai yang membedakan **label sama dengan akhiran berbeda** (pola `roblox.ly`).
- **`brand_domain_mismatch`**: didefinisikan sederhana dan terbuka, yaitu brand teridentifikasi, domain resmi tidak cocok, dan klaim brand muncul pada hostname. Syarat kredensial dipindahkan ke rule.
- Flag `high_confidence_*` dihapus dari analyzer; logikanya menjadi rule yang tertulis.

### 5.3 Kerangka rule baru (draf)

**Alasan phishing** (berlaku apa pun kelas URL):

| ID | Kondisi |
|---|---|
| P1 Peniruan kredensial | `brand_domain_mismatch = true` ∧ (`has_password_field` ∨ `has_sensitive_input`) |
| P2 Peniruan hostname | `brand_domain_mismatch = true` ∧ `host_brand_claim ∈ {lookalike, subdomain_exact, subdomain_lookalike, label sama akhiran berbeda}` |
| P3 Kredensial dikirim ke domain lain | (`has_password_field` ∨ `has_sensitive_input`) ∧ `form_cross_domain = true` ∧ `official_domain_match ≠ true` |
| P4 Unduhan atas nama brand lain | `brand_domain_mismatch = true` ∧ (`download_file_extensions` ∨ `url_file_extension`) berisi executable |
| P5 Domain baru meminta kredensial atas nama brand lain | `domain_age_days ≤ 365` ∧ `official_domain_match = false` ∧ (`has_password_field` ∨ `has_sensitive_input`) |

**Alasan legitimate** (hanya relevan ketika kelas URL phishing):

| ID | Kondisi |
|---|---|
| L1 Situs resmi brand | `claimed_brand_status = identified` ∧ `official_domain_match = true` (definisi baru) ∧ (`brand_in_title` ∨ `brand_in_heading` ∨ `brand_in_logo`) ∧ `form_cross_domain ≠ true` ∧ `domain_age_days > 365` |
| L2 Login resmi brand | L1 ∧ `has_password_field = true` ∧ `form_cross_domain = false` |

**Decision policy:** P1–P5 ada yang matched → phishing. Jika tidak, L1/L2 ada yang matched → legitimate. Jika tidak keduanya → kelas URL. Status `undetermined` tidak pernah dianggap matched.

Angka ambang umur (365) adalah konfigurasi heuristik yang harus dinyatakan apa adanya. Draf ini akan diukur dengan replay sebelum dikunci. Rule tanpa kontribusi tidak dipertahankan.

## 6. Langkah implementasi yang diusulkan

1. **Tahap 3a — perbaiki ekstraksi parameter brand** (definisi 5.2). Ukur perubahan nilai parameter pada replay, terutama pada kasus Roblox, hosting bersama, dan organisasi kecil.
2. **Tahap 3b — ganti rule dan policy** dengan kerangka 5.3. Lakukan dalam satu modul rule yang hanya menerima objek parameter.
3. **Tahap 3c — uji**: tes unit per rule, matriks seluruh kombinasi untuk policy, replay sebelum/sesudah per URL, smoke test browser, dan lab unduhan.
4. **Tahap 4 — evaluasi independen** dengan daftar legitimate/phishing baru yang belum pernah dipakai.

## 7. Keterbatasan audit

- Respons API pada 1.007 rekaman parsial tidak lengkap. Hasil definisi brand baru tidak dapat diputar ulang secara penuh untuk rekaman tersebut, sehingga sebagian pengukuran memerlukan uji live ulang.
- Data audit adalah data pengembangan; perbaikan yang diukur di sini tidak boleh dilaporkan sebagai hasil uji independen.
