# Penyelarasan rule dan decision policy dengan skripsi

Versi lokal 0.6.1. Acuan dibaca dari `C:\Users\USER\Downloads\SKRIPSI UMAR FARUQ MANEK1.pdf`: subbab 4.2.5/Tabel 4.4 pada halaman tercetak 78–86 dan subbab 4.2.6/Tabel 4.5 pada halaman 86–93. Berkas PDF asli tidak diubah.

## Perubahan kode

- R01–R13 dipertahankan dengan ID dan kondisi sebelumnya.
- Enam aturan koreksi legitimate yang sempat diberi nama C01–C06 diubah menjadi R14–R19. Tidak ada ID C dalam mesin aturan aktif.
- `correction-rules.js` memeriksa kondisi, menghasilkan ID/status/evidence_ids, dan tidak menghasilkan verdict atau tindakan. Pemeriksaan DOM/brand tetap di lapisan aturan.
- `decision-policy.js` hanya membaca kelas URL dan ID/status aturan yang sudah dievaluasi. Tidak mengimpor evaluator aturan, tidak mencari brand, tidak memeriksa field DOM, dan tidak membaca skor/probabilitas. Policy tidak mempunyai ID tersendiri.
- Worker mengevaluasi R01–R13, mengevaluasi R14–R19, menggabungkan hasilnya dalam `correlation_rules`, kemudian menjalankan policy. Data deskriptif review tidak menentukan verdict.
- Status `undetermined` tidak diperlakukan sebagai `matched`. R11 tetap pendukung dan tidak menghasilkan pemblokiran sendiri. Aturan konflik didahulukan atas koreksi legitimate.
- Model URL20 dan threshold 0,50 tetap. Skor klasifikasi tidak disimpan. Perubahan terhadap 0.6.0 berupa penyelarasan nama, batas tanggung jawab modul, dan representasi pemetaan policy.

## Pemetaan aturan koreksi

| ID akhir | ID sementara sebelumnya | Kondisi yang diperiksa |
|---|---|---|
| R14 | C01 | Halaman otorisasi OAuth pada domain penyedia resmi yang cocok dengan rujukan brand, struktur permintaan OAuth sesuai, dan tidak ada konflik. |
| R15 | C02 | Klaim identitas domain sendiri didukung judul serta heading/logo, halaman login didukung tautan situs induk, umur memenuhi syarat yang sudah digunakan, dan tidak ada konflik. |
| R16 | C03 | Identitas brand/domain cocok, bukti halaman sesuai kandidat, formulir password seasal pada HTTPS, umur memenuhi syarat, dan tidak ada konflik. |
| R17 | C04 | Dokumentasi HTTPS pada domain brand yang cocok, judul mendukung brand, tidak ada input sensitif/form lintas domain, dan tidak ada konflik. |
| R18 | C05 | Halaman pencarian HTTPS pada domain brand yang cocok dan tidak terdapat bukti kredensial/form lintas domain yang teramati. |
| R19 | C06 | Halaman non-sensitif HTTPS dengan judul/kandidat/domain brand yang konsisten, umur memenuhi syarat, dan tidak ada konflik. |

R14–R19 mengevaluasi konteks koreksi ketika hasil awal URL adalah phishing. Status matched menyatakan kondisi terpenuhi; pemberian verdict legitimate tetap dilakukan policy. Ringkasan di atas bukan pengganti seluruh konjungsi pada kode; kriteria teknis lengkap terdapat dalam `src/analyzer/correlation/correction-rules.js`. Batas umur merupakan syarat fitur yang sudah ada, bukan bobot/skor risiko baru.

## Teks pengantar untuk subbab 4.2.5

Setiap rule diberikan identitas R01 sampai R19 untuk memudahkan proses perancangan, implementasi, dan penggunaan hasil evaluasi pada decision policy. R01 sampai R13 mengevaluasi kondisi yang berkaitan dengan identitas brand, formulir, autentikasi, umur domain, dan tawaran unduhan. R14 sampai R19 mengevaluasi kondisi pendukung koreksi klasifikasi phishing menjadi legitimate, seperti autentikasi OAuth resmi, keterkaitan dengan situs induk, formulir login pada domain brand yang sesuai, serta halaman resmi yang tidak mengumpulkan informasi sensitif. Status matched menunjukkan bahwa kondisi yang dipersyaratkan oleh rule telah terpenuhi, bukan merupakan keputusan akhir sistem. Keputusan akhir ditentukan pada decision policy berdasarkan klasifikasi URL dan status rule yang telah dievaluasi.

Tabel 4.4 yang sudah ada cukup dilanjutkan dengan enam baris R14–R19. Jangan mengganti definisi R01–R13 hanya karena penamaan aturan koreksi diselaraskan.

## Pemetaan decision policy tanpa ID policy

| Kondisi | Keputusan akhir |
|---|---|
| URL legitimate dan salah satu R03/R07/R09/R10/R13 matched | Phishing |
| URL phishing dan R12 matched | Phishing; bukti unduhan memperkuat hasil awal |
| URL phishing dan salah satu R14–R19 matched, tanpa rule konflik yang matched | Legitimate |
| URL phishing dan tidak ada koreksi legitimate yang memenuhi syarat | Phishing |
| URL legitimate dan tidak ada rule peningkatan phishing yang matched | Legitimate |

Rule konflik untuk menolak koreksi legitimate adalah R03, R04, R05, R07, R09, R10, R12, dan R13. R04/R05 yang matched hanya menghalangi koreksi; keduanya tidak sendirian mengubah hasil URL legitimate menjadi phishing. R05 pada definisi sekarang tetap undetermined bila pengalihan belum terverifikasi. R06 sebagai konteks OAuth tidak identik dengan R14 sebagai syarat koreksi halaman otorisasi provider resmi. R08 dan R11 tidak memberi izin/pemblokiran mandiri.

Untuk Tabel 4.5, uraian panjang kondisi koreksi dapat dirujuk melalui R14–R19. Sertakan satu baris khusus `URL legitimate AND R13 = matched -> phishing`, karena tabel PDF saat ini sudah menyebut R13 pada kondisi fallback tetapi belum mencantumkan baris peningkatan tersebut secara tersendiri.

## Hasil pemeriksaan

- 29/29 pengujian lulus, termasuk pengujian policy langsung menggunakan ID/status saja, prioritas konflik, undetermined, dan fallback.
- Replay 1.087 rekaman dibanding versi kategoris sebelum penyelarasan: tidak ada keputusan berubah.
- Legitimate tetap 809/842 benar (96,08%); phishing tetap 200/245 terdeteksi (81,63%).
- 323 rekaman memiliki snapshot/API lengkap relatif terhadap replay, 763 parsial, dan satu hanya tingkat keputusan. Replay bukan pengujian live independen baru.
- Launcher live lolos dry-run versi 0.6.1 / 20 fitur / threshold 0,50 / hash runtime sesuai.

Rincian hasil: `replay_summary.json`, `before_replay.json`, `after_replay.json`, `extension_tests.json`, dan `extension_ready.json`. Versi ini belum dipush. Checkpoint GitHub tetap v0.5.2 / cae5e8c.
