# Hasil eksperimen PhreshPhish URL20

Model utama: XGBoost. Pembanding: Random Forest, Extra Trees, HistGradientBoosting, Logistic Regression.
Seluruh model menggunakan threshold tetap 0,50. Tidak ada validation split, early stopping, atau pemilihan threshold dari test/arsip.
Bobot kelas dihitung dari data train. Tidak dilakukan undersampling untuk menyamakan jumlah kelas.

## Data dan pembagian

- Sumber normalisasi HTTPS: 666.297 baris. Duplikat label sama dihapus: 67 baris. Kedua rekaman satu URL berlabel bertentangan dikarantina: 2 baris.
- Data bersih: 666,228; legitimate 367,909, phishing 298,319.
- Dipisahkan karena domain ada di arsip live: 54,984 baris, termasuk 4 URL persis.
- Train: 551,958; test: 59,286. Rasio aktual 90.30/9.70; pemisahan sekitar 90/10 mengikuti kelompok domain.
- Domain train/test tidak tumpang tindih; domain arsip tidak masuk data pengembangan.
- Train per label: {'legitimate': 331741, 'phishing': 220217}. Test per label: {'legitimate': 34596, 'phishing': 24690}.
- Arsip: 6,460 URL (legitimate 3.600, phishing 2.860); subset sebelumnya berstatus completed: 4.829.
- Seluruh fitur dihitung ulang dari URL menggunakan extractor Python 17 fitur lama ditambah tiga fitur. Tidak membuka website atau memanggil API.

## Evaluasi

| Model | Akurasi test | Legitimate test | Phishing test | Legitimate arsip | Phishing arsip |
|---|---:|---:|---:|---:|---:|
| XGBoost | 92.65% | 94.00% | 90.75% | 78.25% | 82.80% |
| RandomForest | 92.39% | 94.17% | 89.91% | 80.42% | 83.11% |
| ExtraTrees | 92.04% | 93.63% | 89.81% | 76.22% | 83.60% |
| HistGradientBoosting | 92.72% | 94.24% | 90.58% | 78.00% | 83.01% |
| LogisticRegression | 86.43% | 90.11% | 81.26% | 65.28% | 85.56% |

## Pengaruh fitur XGBoost

Persentase berikut adalah proporsi rata-rata nilai absolut kontribusi TreeSHAP terhadap log-odds pada sampel berstrata 10.000 baris test. Total seluruh fitur 100%. Ini bukan pengaruh sebab-akibat, korelasi langsung dengan label, atau persentase akurasi satu fitur.
Permutation importance juga disimpan: penurunan balanced accuracy setelah satu fitur diacak, pada 5.000 baris test dan dua pengulangan. Fitur berkorelasi dapat saling menggantikan.

| Fitur | Proporsi kontribusi SHAP | Penurunan balanced accuracy saat diacak (poin persentase) |
|---|---:|---:|
| `subdomain_count` | 14.4859% | 6.9750 |
| `path_length` | 12.5154% | 4.6045 |
| `hostname_length` | 12.2764% | 8.7962 |
| `url_entropy` | 7.4298% | 3.3923 |
| `path_depth` | 6.8041% | 1.0285 |
| `path_hyphen_count` | 6.3710% | 2.1599 |
| `domain_label_length` | 5.7046% | 2.9931 |
| `query_length` | 5.2289% | 2.6912 |
| `url_length` | 4.7727% | 2.6207 |
| `hostname_entropy` | 4.7252% | 1.5186 |
| `hyphen_count` | 4.2322% | 0.7989 |
| `has_https_scheme` | 3.6708% | 1.4965 |
| `dot_count` | 3.3455% | 1.4094 |
| `special_char_count` | 3.1910% | 2.7990 |
| `digit_ratio` | 2.8202% | 1.0336 |
| `sensitive_token_count` | 1.0063% | 0.2966 |
| `hostname_longest_digit_run` | 0.9385% | 0.1131 |
| `has_at_symbol` | 0.3579% | 0.1423 |
| `hostname_sensitive_token_count` | 0.1222% | 0.0703 |
| `has_ip_host` | 0.0014% | 0.0000 |

## EDA dan batas interpretasi

- Legitimate berquery pada data bersih hanya 68 URL. Phishing berquery jauh lebih banyak. HTTPS juga hampir selalu ada pada legitimate. Distribusi ini dapat menjadi jalan pintas model.
- Pada arsip XGBoost, 130 dari 130 URL legitimate berquery salah diprediksi. Legitimate tanpa query: 2.817/3.470 benar. Ini bukti kelemahan terhadap pola query pada arsip, bukan bukti semua query berbahaya.
- Label yang digunakan adalah label sumber/historis. Isi halaman tidak diverifikasi ulang. URL arsip dengan status HTTP/error terdahulu tetap dapat dinilai dari teks URL, tetapi tidak disebut keberhasilan analisis halaman live.
- Arsip telah digunakan dalam pengembangan sistem sebelumnya. Walaupun domain dikeluarkan dari train/test, hasilnya tetap bukti evaluasi pengembangan historis, bukan uji lapangan baru yang independen.
- Workbook hanya URL/label; tanggal dan pembagian train/test asli tidak tersedia. Hasil ini tidak identik dengan benchmark resmi PhreshPhish.
- Penambahan HTTPS pada 5.741 URL adalah asumsi format atas permintaan pengguna, bukan hasil pemeriksaan koneksi.
- Hasil ini hanya URL Analyzer dengan 20 fitur. DOM, brand, umur domain, dan aturan keputusan extension tidak ikut dijalankan.
- Pengaruh positif/negatif rata-rata per kelas ada pada CSV SHAP. Nilai sangat kecil tidak membuktikan fitur tidak berguna di semua keadaan.
- Extension lama tetap utuh. Model eksperimen belum dipasang ke extension. Tidak ada push GitHub.

## Berkas utama

- `data/raw/`: workbook asli, CSV normalisasi, catatan penambahan HTTPS.
- `data/processed/phreshphish_url20_all_clean.csv`: seluruh data bersih dan 20 fitur, termasuk penanda overlap arsip.
- `data/processed/url20_train_test.csv`: data pengembangan dengan kolom split train/test.
- `data/evaluation/live_url20.csv`: URL arsip beserta label, status historis, asal rekaman, dan 20 fitur.
- `models/`: kelima model beserta urutan fitur dan threshold. XGBoost juga disimpan sebagai JSON native.
- `reports/model_comparison.csv`, `training_results.json`: evaluasi seluruh model dan konfigurasi.
- `reports/*_test_predictions.csv`, `*_archive_predictions.csv`: skor dan benar/salah setiap URL.
- `reports/eda_feature_distribution.csv`, `eda_feature_correlations.csv`, `eda_distributions.png`: EDA.
- `reports/xgboost_feature_influence_20.csv`, `xgboost_feature_influence.png`: pengaruh semua fitur.
- `reports/verification.json`: pemeriksaan model tersimpan dan konsistensi hasil.

Sumber: https://huggingface.co/datasets/phreshphish/phreshphish (CC BY 4.0 menurut dataset card).
