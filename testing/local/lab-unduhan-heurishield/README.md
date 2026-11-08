# Laboratorium unduhan HeuriShield

Jalankan `Jalankan_Lab.ps1` dari PowerShell. Browser Chromium khusus akan terbuka dengan extension asli dari `D:\heurishield-xgboost20\extension\HeuriShield-URL20-XGBoost`. Pilih skenario 1–6 di terminal; ketik 0 untuk menutup. Tidak perlu Administrator, perubahan hosts, atau sertifikat lokal.

Alamat HTTPS, isi halaman, dan respons API dalam browser ini merupakan fixture lokal yang diintersep Playwright. Model XGBoost dan aturan keputusan tidak diganti. Pemblokiran otomatis dimatikan hanya di profil browser sementara agar halaman dan hasil dapat diperiksa. Hasil analisis asli ditampilkan di bagian bawah halaman, termasuk verdict model, verdict akhir, sumber keputusan, dan parameter unduhan. Ini menguji pembacaan parameter dan aturan, bukan ketersediaan API publik atau keberhasilan block page.

Tidak ada formulir kredensial. Klik tautan contoh hanya menampilkan pesan; tidak ada file executable yang dibuat atau dikirim. HTTPS fixture tidak memerlukan koneksi ke situs publik yang namanya digunakan. Jangan membuka alamat fixture di browser biasa karena intersepsi hanya berlaku di browser laboratorium.

Enam skenario menguji R13: peniruan+EXE, peniruan+PDF, brand cocok+EXE, tanpa brand+EXE, peniruan tanpa unduhan, dan suffix URL EXE tanpa tautan DOM. PDF/tanpa brand dapat tetap menghasilkan phishing dari model URL meskipun R13 tidak aktif. Periksa kolom `source`, bukan hanya verdict akhir.

Semua enam kondisi R13 telah diuji headless dan sesuai harapan. `hasil_simulasi.json` menyimpan hasil; file akan diperbarui setelah sesi interaktif selesai. Untuk mengulang pemeriksaan otomatis: `python .\lab.py --check`.
