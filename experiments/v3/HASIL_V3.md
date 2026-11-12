# Hasil pelatihan XGBoost URL20 v3

V3 memakai baris dan split v2 yang sama. URL dinormalisasi dengan WHATWG URL pada Node.js sebelum dihitung oleh extractor JavaScript extension. Model dan extension aktif tidak ditimpa.

Seed: 20261106. Fitur: 20. Threshold keputusan: 0,50. Threshold CV 0.42 hanya dilaporkan dan tidak dipakai untuk keputusan.

**PhiUSIIL tidak dipakai untuk training, pemilihan kandidat, threshold, penyaringan, maupun pembobotan. Evaluasi eksternal belum dijalankan; disiapkan untuk pengguna.**

Pemilihan kandidat mengikuti kriteria v2 dari OOF train saja, dengan 3-fold StratifiedGroupKFold dan sampel 100.016 baris yang urutan URL, label, dan domainnya sama dengan arsip v2.

Bobot dihitung ulang menggunakan rumus v2 setelah normalisasi karena keluarga endpoint dapat berubah. Pemisahan domain dan seed tetap dipertahankan.

| Split | Model dan input | Akurasi | Precision | Recall phishing | Specificity legitimate | F1 | TP | FP | FN | TN |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| test | v2_raw | 92.636% | 93.450% | 88.522% | 95.572% | 90.919% | 21856 | 1532 | 2834 | 33064 |
| test | v2_normalized | 92.005% | 93.351% | 86.999% | 95.578% | 90.063% | 21480 | 1530 | 3210 | 33066 |
| test | v3_normalized | 91.971% | 92.100% | 88.295% | 94.595% | 90.157% | 21800 | 1870 | 2890 | 32726 |
| supplement_test | v2_raw | 98.627% | 99.703% | 98.400% | 99.226% | 99.047% | 4366 | 13 | 71 | 1666 |
| supplement_test | v2_normalized | 98.610% | 99.703% | 98.377% | 99.226% | 99.036% | 4365 | 13 | 72 | 1666 |
| supplement_test | v3_normalized | 98.627% | 99.658% | 98.445% | 99.107% | 99.048% | 4368 | 15 | 69 | 1664 |

## Kesetaraan ekspor
{
  "rows": 20000,
  "maximum_absolute_probability_error": 6.627035403217185e-07,
  "decision_mismatches": 0,
  "feature_mismatches": 0,
  "canonical_pipeline_mismatches": 0,
  "passed": true
}

## Hash model
- XGBoost.joblib: `8d87a5c05a6d478b0d62252d5bc180e9f67889059689c2f4c0bbf26ef476127e`
- xgboost-url20.json: `ff16dab32bfac02ea26d6c1c04688491c101c8b61fc4dc5320a4e65f93a265b0`
- XGBoost.json: `3e2fa7cbfd891fc3306b66270c9566527739ef9cdeac9727d1b0a8192fe95634`

## Keterbatasan
Hasil internal tidak membuktikan kinerja pada sumber eksternal. Angka peningkatan PhiUSIIL dari lampiran merupakan laporan sebelumnya, belum diverifikasi oleh eksperimen v3 ini. Identifikasi masalah telah melibatkan PhiUSIIL pada tahap diskusi, sehingga dataset tersebut bukan holdout yang sepenuhnya belum pernah dilihat dalam keseluruhan riwayat pengembangan. Tidak ada data PhiUSIIL yang dibaca oleh perintah --train.

Normalisasi merupakan bagian wajib pipeline v3, bukan perubahan pada nama 20 fitur. Pengujian tanpa normalisasi adalah diagnosis distribusi input berbeda dan tidak dijamin meningkat. Hasil pelatihan tidak boleh diklaim menghapus seluruh shortcut. Extension aktif tetap v2; ekspor JSON v3 saja belum mengganti alur extractor extension.

## Pengujian eksternal oleh pengguna
Jalankan `python .\scripts\perbaikan_v3.py --external` dari folder experiments/v3. Perintah ini menguji empat kombinasi v2/v3 dan mentah/normalisasi dalam satu lintasan setelah memverifikasi hash model beku. Tidak membuka browser atau API.

## Audit normalisasi
{
  "rows": 678115,
  "url_changed_rows": 46165,
  "feature_changed_rows": 46156,
  "failed_by_split_label": {},
  "site_key_changes": 3,
  "normalized_train_holdout_domain_overlap": 0,
  "endpoint_family_changes": 45778
}

Baris dan split dipertahankan persis. Tiga hostname berubah representasi karena aturan WHATWG (dua IP oktal dan satu hostname dengan backslash), semuanya train dan di luar sampel CV. Tidak ada overlap domain kanonis train dengan holdout. site_key asli dipertahankan sebagai provenance; normalized_site_key dipakai untuk keluarga endpoint, bobot, dan pengelompokan CV.

## Perubahan nilai fitur dibanding v2
| Fitur | Legitimate berubah | Phishing berubah |
|---|---:|---:|
| url_length | 92 | 45503 |
| hostname_length | 0 | 3 |
| path_length | 12 | 45 |
| query_length | 52 | 20 |
| subdomain_count | 0 | 0 |
| path_depth | 3 | 524 |
| dot_count | 0 | 0 |
| hyphen_count | 0 | 0 |
| digit_ratio | 0 | 2 |
| special_char_count | 25 | 15 |
| has_at_symbol | 0 | 0 |
| has_ip_host | 0 | 2 |
| has_https_scheme | 0 | 0 |
| hostname_entropy | 0 | 3 |
| sensitive_token_count | 0 | 0 |
| url_entropy | 92 | 46064 |
| path_hyphen_count | 0 | 0 |
| domain_label_length | 0 | 3 |
| hostname_longest_digit_run | 0 | 2 |
| hostname_sensitive_token_count | 0 | 0 |

## Feature importance gain
Gain merupakan ukuran kepentingan split model, bukan persentase pengaruh kausal terhadap label.
| Fitur | Gain v2 | Gain v3 |
|---|---:|---:|
| url_length | 54.586842 | 38.396450 |
| hostname_length | 73.214081 | 70.425873 |
| path_length | 250.523285 | 233.080383 |
| query_length | 112.970886 | 104.913307 |
| subdomain_count | 1345.602539 | 1268.886108 |
| path_depth | 43.905201 | 41.181892 |
| dot_count | 231.623367 | 220.706528 |
| hyphen_count | 289.579742 | 265.382294 |
| digit_ratio | 102.393524 | 94.562271 |
| special_char_count | 166.631744 | 155.128830 |
| has_at_symbol | 299.122986 | 281.361450 |
| has_ip_host | 0.000000 | 0.000000 |
| has_https_scheme | 1553.197754 | 2468.316895 |
| hostname_entropy | 55.768795 | 53.003235 |
| sensitive_token_count | 101.185326 | 98.472366 |
| url_entropy | 85.891182 | 83.190216 |
| path_hyphen_count | 352.825012 | 330.455658 |
| domain_label_length | 49.270859 | 48.238476 |
| hostname_longest_digit_run | 123.444031 | 107.793381 |
| hostname_sensitive_token_count | 27.987253 | 28.368118 |

## Parameter kandidat terpilih
{
  "n_estimators": 500,
  "max_depth": 7,
  "min_child_weight": 12,
  "reg_lambda": 5,
  "reg_alpha": 0.1
}

## Hasil eksternal setelah model dibekukan

| Subset | Mode | Akurasi | Recall phishing | Specificity legitimate |
|---|---|---:|---:|---:|
| all | v2_raw | 52.4311% | 92.589% | 22.37% |
| all | v2_normalized | 93.6746% | 92.0452% | 94.8943% |
| all | v3_raw | 93.4685% | 92.7782% | 93.9852% |
| all | v3_normalized | 92.6368% | 92.807% | 92.5095% |
| without_exact_development_overlap | v2_raw | 52.5599% | 92.5823% | 22.303% |
| without_exact_development_overlap | v2_normalized | 93.654% | 92.0386% | 94.8752% |
| without_exact_development_overlap | v3_raw | 93.4507% | 92.7737% | 93.9624% |
| without_exact_development_overlap | v3_normalized | 92.6264% | 92.8025% | 92.4932% |
| without_training_domain_overlap | v2_raw | 51.9706% | 93.0892% | 21.2218% |
| without_training_domain_overlap | v2_normalized | 93.8181% | 92.4899% | 94.8113% |
| without_training_domain_overlap | v3_raw | 93.6313% | 93.2616% | 93.9077% |
| without_training_domain_overlap | v3_normalized | 92.7841% | 93.2937% | 92.403% |
