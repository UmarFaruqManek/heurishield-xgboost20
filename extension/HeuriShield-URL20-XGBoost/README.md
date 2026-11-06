# HeuriShield URL20 XGBoost v2

Paket uji live versi 0.4.0 menggunakan XGBoost dari eksperimen PhreshPhish yang diperkaya data tambahan. URL Analyzer memakai 20 fitur dan 500 pohon dengan threshold 0,50.

Model pelatihan memilih threshold 0,41 melalui cross-validation. Paket ini memakai 0,50 sesuai konfigurasi perbandingan yang menghasilkan legitimate 83,00% dan phishing 85,63% pada 6.460 URL arsip. Skor tersebut berasal dari evaluasi URL Analyzer secara offline. Keputusan extension juga mempertimbangkan bukti DOM, brand, OAuth, dan umur domain melalui kebijakan yang disertakan.

## Memuat extension

Buka chrome://extensions atau edge://extensions, aktifkan Developer mode, lalu pilih Load unpacked dan folder ini. Nama yang ditampilkan adalah HeuriShield URL20 XGBoost v2 versi 0.4.0.

## Parameter tambahan

- `domain_label_length` mengukur panjang label domain utama menurut PSL yang digunakan pada pelatihan.
- `hostname_longest_digit_run` mengukur rangkaian angka berurutan terpanjang pada hostname.
- `hostname_sensitive_token_count` menghitung token akun/autentikasi pada hostname.

Kontrak lengkap tersedia pada `src/model/feature-contract-20.json`. Model aktif tersedia pada `src/model/xgboost-url20.json`. Identitas model dan threshold disimpan bersama hasil pemeriksaan.

## Pengujian dan rekaman

Launcher tersedia pada `../../scripts/Uji_Live_URL20.ps1`. Pengguna menjalankan daftar URL melalui terminal. Setiap URL memakai profil browser terpisah. Evaluator menyimpan CSV hasil, JSON analisis setiap URL, snapshot model, fingerprint extension, serta riwayat SQLite.

Pemeriksaan lokal mencakup kesetaraan input float32 Python dan JavaScript pada 678.115 baris eksperimen dan 6.460 URL arsip. Prediksi diperiksa pada 10.460 URL. Fixture Chromium memeriksa pemuatan, analisis 20 fitur, DOM, penyimpanan hasil, pengaturan blockpage/popup, allow list, dan block list.

Kasus fixture `portal.merdekasiber.com` masih menghasilkan false positive dari model URL sekitar 0,830. Kasus klasifikasi ini dicatat terpisah dalam laporan pengujian fungsi.

Laporan pemeriksaan tersimpan pada `../../perbaikan_v2/reports/extension_*.json`.
