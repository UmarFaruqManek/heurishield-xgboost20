# HeuriShield URL17 XGBoost — kandidat 0.3.7

Versi 0.3.7 menyederhanakan keterangan formulir: halaman tanpa form dibedakan dari form yang tidak meminta data akun, sementara pemeriksaan parsial tetap diberi keterangan belum lengkap. Kecocokan brand ditampilkan sebagai "Domain cocok dengan brand …". Perubahan hanya pada penjelasan dan versi cache analisis; model, threshold, dan aturan keputusan tetap.

Versi 0.3.6 membedakan identitas situs, penyedia login, perangkat lunak halaman, dan penyebutan biasa. Atribusi perangkat lunak pada judul login atau metadata tidak dipilih sebagai pemilik situs. Pencocokan nama tanpa spasi hanya diperluas pada kandidat yang domainnya cocok. Koreksi login mengharuskan identitas domain API cocok, identitas pada halaman, form pada origin yang sama, pemeriksaan lengkap, HTTPS, umur minimal tiga tahun, skor di bawah 0,90, serta tidak ada konflik. Bukti kredensial atau peniruan yang kuat tetap diprioritaskan. Replay 700 rekaman terbaru per URL dan label: legitimate 332/398 menjadi 338/398 (84,92%); phishing tetap 257/302 (85,10%). Tidak ada regresi pada arsip ini; 636 rekaman memiliki respons API parsial, sehingga hasil tersebut merupakan evaluasi pengembangan, bukan uji live independen.

Versi 0.3.5 memisahkan cache pencarian domain dan token. Refresh eksplisit diteruskan ke layanan pencarian. Penjelasan domain yang cocok menjadi "Domain cocok dengan brand …". Koreksi halaman tanpa input sensitif diperluas hingga skor di bawah 0,90 jika identitas brand terpilih muncul pada judul, referensi domain cocok, origin halaman teramati sesuai, umur domain setidaknya tiga tahun, dan pemeriksaan tidak menunjukkan konflik. Halaman dengan bukti belum lengkap tetap memerlukan pemeriksaan lanjut.

Versi 0.3.4 memakai kecocokan domain hasil API sebagai verifikasi brand. Respons API yang berhasil dengan nama brand dan domain yang cocok menghasilkan `official_domain_match: true`, termasuk ketika flag `verified` atau `claimed` penyedia bernilai false. Dasar verifikasi dicatat sebagai `api_domain_match`. Kecocokan nama saja dengan domain berbeda tetap memerlukan pemeriksaan referensi dan bukti halaman. Pengaturan menyediakan pilihan halaman blokir atau popup, dan tombol Izinkan domain pada halaman blokir menyimpan izin permanen ke Allow list.

Versi 0.3.2 mencari registrable domain terlebih dahulu melalui Clearbit, Brandfetch, lalu API domain HeuriShield. Kandidat harus cocok persis dengan domain yang ditanyakan. Pencarian token dipakai bila domain tidak ditemukan atau konteks hostname/halaman perlu pemeriksaan konflik. Hasil pencarian domain tetap dibedakan dari bukti verifikasi provider; keduanya disimpan dalam arsip replay. Respons domain-first baru belum tersedia pada arsip sebelum versi ini, sehingga replay lama melaporkannya sebagai bukti yang belum direkam.

Muat folder ini melalui **Load unpacked** pada browser Chromium. Aset, service worker, dan bundle content script sudah disertakan.

Model XGBoost memakai 17 fitur teks URL, threshold 0,45, dan 180 pohon hasil best iteration. Umur domain tetap diperiksa melalui layanan yang sudah digunakan sebelumnya, tetapi berada di luar input model. Kategori umur dikonfigurasi pada `src/model/domain-age-policy.json`.

DOM, brand, OAuth, pemblokiran, allow list/block list, dan rekaman bukti memakai integrasi extension URL18 sebelumnya. Korelasi R01–R10 serta koreksi keputusan sebelumnya dipertahankan. R11 mencatat umur sampai 365 hari bersama input sensitif dan ketidaksesuaian brand sebagai bukti pendukung; umur sendiri tidak mengubah keputusan. Delapan aturan konseptual yang dibahas belum menggantikan keseluruhan kebijakan lama pada kandidat ini.

Nama internal file `url18-features.js` dan `xgboost-url18.json` dipertahankan untuk kompatibilitas modul/evaluator; kontrak aktual model berisi tepat 17 fitur dan tidak memuat umur domain.

Uji offline mencakup kesetaraan Python/JavaScript pada 800 URL, allow list/block list, OAuth, brand API fallback, DOM, penjelasan, replay, dan pemuatan extension dalam Chromium dengan halaman fixture. Uji live situs publik dijalankan pengguna melalui `D:\experimen skripsi\scripts\Uji_Phishing_Perbandingan.ps1`.

Evaluator menyimpan ringkasan, baris hasil, JSON analisis/bukti, snapshot model/manifest dan database evaluasi. Replay dapat mengevaluasi konfigurasi menggunakan bukti yang sudah tersimpan; pemeriksaan baru yang membutuhkan bukti belum direkam memerlukan pengamatan tambahan.

Versi 0.3.1 mempertahankan kandidat domain tanpa menganggapnya terverifikasi. Aturan kandidat eksternal dibatasi pada penyisipan literal domain referensi di hostname dan klaim pada judul. Klaim kredensial juga diperiksa dari judul, password, dan kontrol login; registri penyedia OAuth yang sudah tersedia menjadi referensi untuk penyedia terkait. API membedakan hasil kosong, HTTP error/429, cooldown, timeout, JSON tidak valid dan kegagalan jaringan. Maksimum empat request provider berjalan bersamaan; hasil parsial memiliki TTL cache singkat.

Observer memantau perubahan teks, formulir dan atribut, serta perubahan hash/popstate. Snapshot kosong/loading ditandai belum lengkap, dan worker mengambil ulang snapshot maksimal dua kali dengan jeda 500 ms. Pengujian fixture memeriksa form dinamis tanpa mengirim kredensial.

Replay pada arsip phishing URL17: 106/132 menjadi 114/132 (86,36%). Pada dua arsip legitimate, 369/487 dan 304/491 tetap sama. Tidak ada regresi tambahan dalam rekaman tersebut. Sebagian replay hanya mempunyai snapshot API parsial; hasil ini bukan pengujian live baru. Empat label halaman akhir yang meragukan disimpan di laporan audit terpisah tanpa mengubah label feed atau hasil awal.
