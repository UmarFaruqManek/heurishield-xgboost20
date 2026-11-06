# Hasil perbaikan URL20 versi 2

Empat langkah dilaksanakan dengan lima model. Semua skor arsip berasal dari replay teks URL secara offline.

## Perubahan data dan bobot

- Audit seluruh 783 kesalahan legitimate dan 492 kesalahan phishing baseline tersimpan beserta pola URL, judul, tujuan akhir, dan tanda peninjauan label.
- Pada 492 kesalahan phishing, 350 rekaman berpindah situs akhir dan 191 berstatus analisis historis tidak lengkap. Kelompok tanda tersebut dapat saling beririsan.
- Tambahan 66.871 URL berlabel sumber terdiri atas 21.871 legitimate berquery dan 45.000 phishing berpola HTTPS, hostname pendek, atau path panjang.
- Sumber tambahan adalah URL dataset.csv dan url_features_extracted1.csv yang sudah dimiliki pengguna. Label asal dipertahankan setelah pemeriksaan konflik dan duplikasi. Isi halaman tidak diperiksa ulang.
- Semua URL asli dipertahankan. URL dengan penanda query buatan pengujian sebelumnya disaring.
- Data tambahan dibatasi maksimal 20 URL per domain dan lima per keluarga endpoint. Keluarga endpoint memakai domain, pola path dengan ID/angka dinormalisasi, dan nama parameter query.
- Bobot train memperkecil dominasi domain di atas 20 rekaman dan keluarga endpoint di atas lima rekaman. Bobot akhir diseimbangkan per kelas.
- Jumlah train 612,713, test PhreshPhish tetap 59,286, test sumber tambahan 6,116.
- Test asli dan 6.460 URL arsip memiliki domain terpisah dari train. Domain tambahan baru dibagi sekitar 90/10, sedangkan domain train yang sudah dikenal mengikuti pembagian awal.
- Legitimate berquery dalam train meningkat dari 55 menjadi 20.247. Sebanyak 99,97% tambahan legitimate berquery train menggunakan https://www. Variasi ini masih terbatas untuk OAuth/subdomain tanpa www.

## Cross-validation dan threshold

- Tiga fold berdasarkan domain dijalankan pada sampel deterministik 100.016 baris train dari 43.891 domain. Sampel mencakup 3.450 legitimate berquery.
- Dua konfigurasi per model dibandingkan. Semua kandidat dinilai dari probabilitas out-of-fold. Threshold dipilih untuk memaksimalkan nilai terendah antara specificity legitimate dan recall phishing pada train.
- Setelah pemilihan, lima model dilatih pada seluruh 612.713 baris train.
- Hasil threshold CV dan threshold tetap 0,50 dilaporkan terpisah. Threshold 0,50 telah ditentukan pada eksperimen baseline dan tidak dipilih dengan menyisir arsip.

## Perbandingan arsip pada threshold tetap 0,50

| Model | Legitimate awal | Legitimate baru | Phishing awal | Phishing baru | Akurasi baru |
|---|---:|---:|---:|---:|---:|
| XGBoost | 78.25% | 83.00% | 82.80% | 85.63% | 84.16% |
| RandomForest | 80.42% | 88.03% | 83.11% | 84.41% | 86.42% |
| ExtraTrees | 76.22% | 83.94% | 83.60% | 84.72% | 84.29% |
| HistGradientBoosting | 78.00% | 83.97% | 83.01% | 85.80% | 84.78% |
| LogisticRegression | 65.28% | 71.08% | 85.56% | 82.45% | 76.11% |

## Test PhreshPhish asli pada threshold 0,50

| Model | Accuracy awal | Accuracy baru | Legitimate baru | Phishing baru |
|---|---:|---:|---:|---:|
| XGBoost | 92.65% | 92.64% | 95.57% | 88.52% |
| RandomForest | 92.39% | 92.56% | 95.91% | 87.86% |
| ExtraTrees | 92.04% | 92.33% | 95.76% | 87.52% |
| HistGradientBoosting | 92.72% | 92.61% | 95.35% | 88.78% |
| LogisticRegression | 86.43% | 85.06% | 92.50% | 74.63% |

## Hasil memakai threshold pilihan cross-validation

| Model | Threshold | Test asli accuracy | Legitimate arsip | Phishing arsip |
|---|---:|---:|---:|---:|
| XGBoost | 0.41 | 92.14% | 77.78% | 87.69% |
| RandomForest | 0.41 | 92.33% | 82.36% | 86.54% |
| ExtraTrees | 0.40 | 91.88% | 76.61% | 87.76% |
| HistGradientBoosting | 0.41 | 92.23% | 77.14% | 88.46% |
| LogisticRegression | 0.39 | 85.32% | 61.11% | 85.59% |

## Koreksi dan regresi per URL pada threshold 0,50

| Model | Legitimate salah menjadi benar | Legitimate benar menjadi salah | Phishing salah menjadi benar | Phishing benar menjadi salah |
|---|---:|---:|---:|---:|
| XGBoost | 204 | 33 | 147 | 66 |
| RandomForest | 289 | 15 | 134 | 97 |
| ExtraTrees | 286 | 8 | 125 | 93 |
| HistGradientBoosting | 245 | 30 | 130 | 50 |
| LogisticRegression | 235 | 26 | 18 | 107 |

## Hasil XGBoost pada query legitimate

Baseline salah pada seluruh 130 legitimate berquery. Setelah perbaikan, hasil pada threshold 0,50 adalah berikut.

| Kelompok | URL | Benar | Persentase |
|---|---:|---:|---:|
| Tanpa query | 3470 | 2931 | 84.47% |
| Dengan query | 130 | 57 | 43.85% |

## Berkas hasil

- reports/results.json memuat seluruh metrik, konfigurasi terpilih, hasil threshold CV dan 0,50, serta pemeriksaan model tersimpan.
- reports/baseline_errors_with_evidence.csv mencatat semua kesalahan awal dan bukti rekaman yang tersedia.
- data/supplement_url20_with_provenance.csv mencatat URL tambahan, sumber label, split dan fitur.
- data/url20_augmented_splits.csv memuat seluruh data eksperimen beserta pembagian.
- data/training_weights.csv menyimpan bobot setiap URL train.
- reports/*_cv_selection.json menyimpan semua kandidat dan hasil pemilihan dari train.
- reports/*_per_url_changes.csv memuat perubahan benar/salah setiap URL, termasuk regresi.
- reports/xgboost_feature_influence_20.csv memuat proporsi kontribusi absolut SHAP pada 10.000 baris test asli.
- models/*.joblib menyimpan model dengan threshold pilihan CV. XGBoost juga disimpan dalam JSON native.

## Batas interpretasi

- Label sumber tambahan dan arsip bersifat historis. Pengumpulan baru, pemeriksaan halaman live, serta verifikasi independen semua label belum dilakukan.
- Arsip sebelumnya telah digunakan untuk pengembangan sehingga menjadi evaluasi pengembangan historis.
- Distribusi sumber tambahan sangat didominasi www dan data lama. Halaman OAuth panjang serta query autentikasi pada hostname tanpa www masih kurang terwakili.
- Keluarga endpoint adalah pendekatan pengelompokan kemiripan URL dalam satu domain. Pendekatan ini belum membuktikan seluruh kampanye lintas domain telah teridentifikasi.
- Cross-validation memakai sampel 100.016 baris untuk membatasi biaya, kemudian model akhir memakai seluruh train.
- Tidak ada ablation terpisah untuk mengukur kontribusi kausal setiap satu dari empat langkah. Perbandingan menunjukkan dampak perubahan secara gabungan.
- Akurasi ini hanya URL Analyzer. Hasil gabungan DOM/Brand memerlukan evaluasi terpisah.
