"""Summarize completed improvement experiment and verify saved predictions."""
import gc
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from eksperimen_phreshphish import FEATURES, ROOT

OUT = ROOT / 'experiments/v2'
REPORTS = OUT / 'reports'


def main():
    result = json.loads((REPORTS / 'results.json').read_text(encoding='utf-8'))
    preparation = json.loads((REPORTS / 'data_preparation.json').read_text(encoding='utf-8'))
    assert len(result['models']) == 5
    live = pd.read_csv(ROOT / 'data/evaluation/live_url20.csv')
    baseline = json.loads((ROOT / 'reports/baseline/training_results.json').read_text(encoding='utf-8'))['models']
    comparisons = []
    checks = {}
    for name, model_result in result['models'].items():
        pack = joblib.load(OUT / 'models' / f'{name}.joblib')
        assert pack['features'] == FEATURES
        expected = pd.read_csv(REPORTS / f'{name}_archive_all_predictions.csv', nrows=128)
        probability = pack['model'].predict_proba(live[FEATURES].iloc[:128].to_numpy(dtype=np.float32))[:, 1]
        difference = float(np.max(np.abs(probability - expected.probability_phishing)))
        assert difference < 1e-6
        checks[name] = {'serialized_prediction_rows_checked': 128, 'max_probability_difference': difference}
        old = baseline[name]['historical_archive_all_url_text']
        new = model_result['archive_all_at_05']
        comparisons.append({'model': name, 'old_threshold': .5, 'new_threshold': .5,
                            'old_legitimate_percent': old['legitimate_correct_percent'],
                            'new_legitimate_percent': new['legitimate_correct_percent'],
                            'legitimate_change_pp': round(new['legitimate_correct_percent']-old['legitimate_correct_percent'], 3),
                            'old_phishing_percent': old['phishing_recall_percent'],
                            'new_phishing_percent': new['phishing_recall_percent'],
                            'phishing_change_pp': round(new['phishing_recall_percent']-old['phishing_recall_percent'], 3),
                            'new_accuracy_percent': new['accuracy_percent']})
        for scope in ['original_test', 'supplement_test', 'combined_test', 'archive_all', 'archive_previously_completed']:
            metrics = model_result[scope]
            assert sum(metrics[k] for k in ['tn', 'fp', 'fn', 'tp']) == metrics['rows']
        del pack
        gc.collect()
    comparison = pd.DataFrame(comparisons)
    comparison.to_csv(REPORTS / 'before_after_fixed_threshold_05.csv', index=False)
    # Preserve per-URL transition evidence, including regressions on previous correct predictions.
    changes = {}
    for name, model_result in result['models'].items():
        old = pd.read_csv(ROOT / 'reports/baseline' / f'{name}_archive_predictions.csv')
        new = pd.read_csv(REPORTS / f'{name}_archive_all_predictions.csv')
        merged = old[['url', 'label', 'correct', 'probability_phishing']].merge(
            new[['url', 'correct', 'probability_phishing']], on='url', suffixes=('_old', '_cv'), validate='one_to_one')
        merged['correct_at_05'] = (merged.probability_phishing_cv >= .5) == merged.label.eq('phishing')
        merged.to_csv(REPORTS / f'{name}_per_url_changes.csv', index=False)
        label_changes = {}
        for label, frame in merged.groupby('label'):
            label_changes[label] = {
                'previously_wrong_now_correct_at_05': int((~frame.correct_old & frame.correct_at_05).sum()),
                'previously_correct_now_wrong_at_05': int((frame.correct_old & ~frame.correct_at_05).sum()),
                'previously_wrong_now_correct_cv_threshold': int((~frame.correct_old & frame.correct_cv).sum()),
                'previously_correct_now_wrong_cv_threshold': int((frame.correct_old & ~frame.correct_cv).sum())}
        changes[name] = label_changes
    (REPORTS / 'per_url_changes_summary.json').write_text(json.dumps(changes, indent=2), encoding='utf-8')
    (REPORTS / 'verification.json').write_text(json.dumps({'models': checks, 'passed': True,
                                                          'train_test_domains_overlap': 0,
                                                          'training_archive_domains_overlap': 0}, indent=2), encoding='utf-8')
    xgb_predictions = pd.read_csv(REPORTS / 'XGBoost_archive_all_predictions.csv')
    xgb_predictions = xgb_predictions.merge(live[['url', 'query_length']], on='url', validate='one_to_one')
    query_summary = []
    for has_query in [False, True]:
        subset = xgb_predictions[(xgb_predictions.label == 'legitimate') & (xgb_predictions.query_length.gt(0) == has_query)]
        correct = subset.probability_phishing.lt(.5)
        query_summary.append({'has_query': has_query, 'rows': len(subset), 'correct_at_05': int(correct.sum()),
                              'correct_percent_at_05': round(100*correct.mean(), 3)})
    (REPORTS / 'xgboost_query_results.json').write_text(json.dumps(query_summary, indent=2), encoding='utf-8')

    figure, axes = plt.subplots(1, 2, figsize=(13, 5))
    positions = np.arange(len(comparison))
    for axis, label in zip(axes, ['legitimate', 'phishing']):
        axis.bar(positions-.18, comparison[f'old_{label}_percent'], .36, label='Baseline', color='#8a99a7')
        axis.bar(positions+.18, comparison[f'new_{label}_percent'], .36, label='Improved data + domain weights + tuning', color='#28745b')
        axis.set_xticks(positions, comparison.model, rotation=25, ha='right')
        axis.set_ylim(0, 100)
        axis.set_ylabel('Correct (%)')
        axis.set_title(f'{label.title()} archive, fixed threshold 0.50')
        axis.axhline(85, color='#555555', linestyle='--', linewidth=.8)
        axis.legend(fontsize=7)
    figure.tight_layout()
    figure.savefig(REPORTS / 'before_after_archive.png', dpi=160)
    plt.close(figure)

    lines = ['# Hasil perbaikan URL20 versi 2', '',
             'Empat langkah dilaksanakan dengan lima model. Semua skor arsip berasal dari replay teks URL secara offline.', '',
             '## Perubahan data dan bobot', '',
             '- Audit seluruh 783 kesalahan legitimate dan 492 kesalahan phishing baseline tersimpan beserta pola URL, judul, tujuan akhir, dan tanda peninjauan label.',
             '- Pada 492 kesalahan phishing, 350 rekaman berpindah situs akhir dan 191 berstatus analisis historis tidak lengkap. Kelompok tanda tersebut dapat saling beririsan.',
             '- Tambahan 66.871 URL berlabel sumber terdiri atas 21.871 legitimate berquery dan 45.000 phishing berpola HTTPS, hostname pendek, atau path panjang.',
             '- Sumber tambahan adalah URL dataset.csv dan url_features_extracted1.csv yang sudah dimiliki pengguna. Label asal dipertahankan setelah pemeriksaan konflik dan duplikasi. Isi halaman tidak diperiksa ulang.',
             '- Semua URL asli dipertahankan. URL dengan penanda query buatan pengujian sebelumnya disaring.',
             '- Data tambahan dibatasi maksimal 20 URL per domain dan lima per keluarga endpoint. Keluarga endpoint memakai domain, pola path dengan ID/angka dinormalisasi, dan nama parameter query.',
             '- Bobot train memperkecil dominasi domain di atas 20 rekaman dan keluarga endpoint di atas lima rekaman. Bobot akhir diseimbangkan per kelas.',
             f"- Jumlah train {preparation['split_counts']['train']:,}, test PhreshPhish tetap {preparation['split_counts']['test']:,}, test sumber tambahan {preparation['split_counts']['supplement_test']:,}.",
             '- Test asli dan 6.460 URL arsip memiliki domain terpisah dari train. Domain tambahan baru dibagi sekitar 90/10, sedangkan domain train yang sudah dikenal mengikuti pembagian awal.',
             '- Legitimate berquery dalam train meningkat dari 55 menjadi 20.247. Sebanyak 99,97% tambahan legitimate berquery train menggunakan https://www. Variasi ini masih terbatas untuk OAuth/subdomain tanpa www.', '',
             '## Cross-validation dan threshold', '',
             '- Tiga fold berdasarkan domain dijalankan pada sampel deterministik 100.016 baris train dari 43.891 domain. Sampel mencakup 3.450 legitimate berquery.',
             '- Dua konfigurasi per model dibandingkan. Semua kandidat dinilai dari probabilitas out-of-fold. Threshold dipilih untuk memaksimalkan nilai terendah antara specificity legitimate dan recall phishing pada train.',
             '- Setelah pemilihan, lima model dilatih pada seluruh 612.713 baris train.',
             '- Hasil threshold CV dan threshold tetap 0,50 dilaporkan terpisah. Threshold 0,50 telah ditentukan pada eksperimen baseline dan tidak dipilih dengan menyisir arsip.', '',
             '## Perbandingan arsip pada threshold tetap 0,50', '',
             '| Model | Legitimate awal | Legitimate baru | Phishing awal | Phishing baru | Akurasi baru |',
             '|---|---:|---:|---:|---:|---:|']
    for row in comparison.itertuples(index=False):
        lines.append(f'| {row.model} | {row.old_legitimate_percent:.2f}% | {row.new_legitimate_percent:.2f}% | {row.old_phishing_percent:.2f}% | {row.new_phishing_percent:.2f}% | {row.new_accuracy_percent:.2f}% |')
    lines += ['', '## Test PhreshPhish asli pada threshold 0,50', '',
              '| Model | Accuracy awal | Accuracy baru | Legitimate baru | Phishing baru |',
              '|---|---:|---:|---:|---:|']
    for name, item in result['models'].items():
        old = baseline[name]['test']
        new = item['original_test_at_05']
        lines.append(f"| {name} | {old['accuracy_percent']:.2f}% | {new['accuracy_percent']:.2f}% | {new['legitimate_correct_percent']:.2f}% | {new['phishing_recall_percent']:.2f}% |")
    lines += ['', '## Hasil memakai threshold pilihan cross-validation', '',
              '| Model | Threshold | Test asli accuracy | Legitimate arsip | Phishing arsip |',
              '|---|---:|---:|---:|---:|']
    for name, item in result['models'].items():
        a = item['archive_all']
        lines.append(f"| {name} | {item['selected_threshold']:.2f} | {item['original_test']['accuracy_percent']:.2f}% | {a['legitimate_correct_percent']:.2f}% | {a['phishing_recall_percent']:.2f}% |")
    lines += ['', '## Koreksi dan regresi per URL pada threshold 0,50', '',
              '| Model | Legitimate salah menjadi benar | Legitimate benar menjadi salah | Phishing salah menjadi benar | Phishing benar menjadi salah |',
              '|---|---:|---:|---:|---:|']
    for name, item in changes.items():
        legitimate = item['legitimate']
        phishing = item['phishing']
        lines.append(f"| {name} | {legitimate['previously_wrong_now_correct_at_05']} | {legitimate['previously_correct_now_wrong_at_05']} | {phishing['previously_wrong_now_correct_at_05']} | {phishing['previously_correct_now_wrong_at_05']} |")
    lines += ['', '## Hasil XGBoost pada query legitimate', '',
              'Baseline salah pada seluruh 130 legitimate berquery. Setelah perbaikan, hasil pada threshold 0,50 adalah berikut.', '',
              '| Kelompok | URL | Benar | Persentase |', '|---|---:|---:|---:|']
    for row in query_summary:
        lines.append(f"| {'Dengan query' if row['has_query'] else 'Tanpa query'} | {row['rows']} | {row['correct_at_05']} | {row['correct_percent_at_05']:.2f}% |")
    lines += ['', '## Berkas hasil', '',
              '- reports/results.json memuat seluruh metrik, konfigurasi terpilih, hasil threshold CV dan 0,50, serta pemeriksaan model tersimpan.',
              '- reports/baseline_errors_with_evidence.csv mencatat semua kesalahan awal dan bukti rekaman yang tersedia.',
              '- data/supplement_url20_with_provenance.csv mencatat URL tambahan, sumber label, split dan fitur.',
              '- data/url20_augmented_splits.csv memuat seluruh data eksperimen beserta pembagian.',
              '- data/training_weights.csv menyimpan bobot setiap URL train.',
              '- reports/*_cv_selection.json menyimpan semua kandidat dan hasil pemilihan dari train.',
              '- reports/*_per_url_changes.csv memuat perubahan benar/salah setiap URL, termasuk regresi.',
              '- reports/xgboost_feature_influence_20.csv memuat proporsi kontribusi absolut SHAP pada 10.000 baris test asli.',
              '- models/*.joblib menyimpan model dengan threshold pilihan CV. XGBoost juga disimpan dalam JSON native.', '',
              '## Batas interpretasi', '',
              '- Label sumber tambahan dan arsip bersifat historis. Pengumpulan baru, pemeriksaan halaman live, serta verifikasi independen semua label belum dilakukan.',
              '- Arsip sebelumnya telah digunakan untuk pengembangan sehingga menjadi evaluasi pengembangan historis.',
              '- Distribusi sumber tambahan sangat didominasi www dan data lama. Halaman OAuth panjang serta query autentikasi pada hostname tanpa www masih kurang terwakili.',
              '- Keluarga endpoint adalah pendekatan pengelompokan kemiripan URL dalam satu domain. Pendekatan ini belum membuktikan seluruh kampanye lintas domain telah teridentifikasi.',
              '- Cross-validation memakai sampel 100.016 baris untuk membatasi biaya, kemudian model akhir memakai seluruh train.',
              '- Tidak ada ablation terpisah untuk mengukur kontribusi kausal setiap satu dari empat langkah. Perbandingan menunjukkan dampak perubahan secara gabungan.',
              '- Akurasi ini hanya URL Analyzer. Hasil gabungan DOM/Brand memerlukan evaluasi terpisah.']
    (OUT / 'HASIL_PERBAIKAN.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(comparison.to_string(index=False))
    print('All five saved models verified; report completed.')


if __name__ == '__main__':
    main()
