# Laboratorium unduhan HeuriShield

Jalankan `Jalankan_Lab.ps1` dari PowerShell. Browser Chromium khusus akan terbuka dengan extension asli dari `D:\heurishield-xgboost20\extension\HeuriShield-URL20-XGBoost`. Pilih skenario 1–7 di terminal; ketik 0 untuk menutup. Tidak perlu Administrator, perubahan hosts, atau sertifikat lokal.

Alamat HTTPS, isi halaman, dan respons API dalam browser ini merupakan fixture lokal yang diintersep Playwright. Model XGBoost dan aturan keputusan tidak diganti. Pemblokiran otomatis dimatikan hanya di profil browser sementara agar halaman dan hasil dapat diperiksa. Hasil analisis asli ditampilkan di bagian bawah halaman, termasuk verdict model, verdict akhir, sumber keputusan, dan parameter unduhan. Ini menguji pembacaan parameter dan aturan, bukan ketersediaan API publik atau keberhasilan block page.

Tidak ada formulir kredensial. Klik tautan contoh hanya menampilkan pesan; tidak ada file executable yang dibuat atau dikirim. HTTPS fixture tidak memerlukan koneksi ke situs publik yang namanya digunakan. Jangan membuka alamat fixture di browser biasa karena intersepsi hanya berlaku di browser laboratorium.

Tujuh skenario menguji rule unduhan dan identitas versi 0.7.0: peniruan brand pada alamat + EXE/PDF (P1), domain resmi + EXE (L1), tanpa brand + EXE (mengikuti kelas URL), brand lain di domain baru + EXE (P4) atau PDF (tidak ada rule), dan akhiran EXE pada URL di domain baru (P4). Umur domain disimulasikan: `unduh-aplikasi.test` berumur 20 hari, domain lain terdaftar sejak 2000. Periksa kolom `matched_rules` dan `source`, bukan hanya verdict akhir.

Pemeriksaan otomatis: `python .\lab.py --check`. Hasil tersimpan di `hasil_simulasi.json`.
