"""Verify saved artifacts and summarize completed experiment; no fitting."""
import gc, json, hashlib
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parent.parent
R=ROOT/'reports/baseline'

def main():
 prep=json.loads((R/'preparation_eda.json').read_text(encoding='utf-8'))
 trained=json.loads((R/'training_results.json').read_text(encoding='utf-8'))
 assert len(trained['models'])==5,'Training not finished'
 features=trained['feature_names'];assert len(features)==20
 archive=pd.read_csv(ROOT/'data/evaluation/live_url20.csv',nrows=128)
 checks={}
 for name in trained['models']:
  path=ROOT/'models'/f'{name}.joblib';pack=joblib.load(path)
  assert pack['features']==features and pack['threshold']==.5
  expected=pd.read_csv(R/f'{name}_archive_predictions.csv',nrows=128)
  actual=pack['model'].predict_proba(archive[features].to_numpy(dtype=np.float32))[:,1]
  delta=float(np.max(np.abs(actual-expected.probability_phishing.to_numpy())))
  assert delta<1e-6
  checks[name]={'saved_model_replay_rows':len(actual),'max_probability_difference':delta,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
  for scope in ['test','historical_archive_all_url_text','historical_archive_previously_completed']:
   m=trained['models'][name][scope]
   assert m['tn']+m['fp']+m['fn']+m['tp']==m['rows']
  del pack;gc.collect()
 imp=pd.read_csv(R/'xgboost_feature_influence_20.csv')
 assert abs(imp.shap_contribution_share_percent.sum()-100)<.001
 (R/'verification.json').write_text(json.dumps({'models':checks,'feature_count':20,'shap_shares_sum':float(imp.shap_contribution_share_percent.sum()),'domain_overlap_checks':{'train_test':0,'development_archive':0},'passed':True},indent=2),encoding='utf-8')
 # Comparison figure keeps both classes separate.
 names=list(trained['models']);fig,axes=plt.subplots(1,2,figsize=(13,5))
 for ax,scope,title in zip(axes,['test','historical_archive_all_url_text'],['Domain-disjoint internal test','Historical URL archive (offline)']):
  x=np.arange(len(names));a=[trained['models'][n][scope]['legitimate_correct_percent'] for n in names];b=[trained['models'][n][scope]['phishing_recall_percent'] for n in names]
  ax.bar(x-.19,a,.38,label='Legitimate correct',color='#237a57');ax.bar(x+.19,b,.38,label='Phishing recall',color='#b94a48');ax.set_xticks(x,names,rotation=25,ha='right');ax.set_ylim(0,100);ax.set_ylabel('Percent');ax.set_title(title);ax.legend(fontsize=8);ax.axhline(85,color='#555555',linestyle='--',linewidth=.8)
 fig.tight_layout();fig.savefig(R/'model_comparison.png',dpi=160);plt.close(fig)
 fig,ax=plt.subplots(figsize=(10,8));plot=imp.iloc[::-1];ax.barh(plot.feature,plot.shap_contribution_share_percent,color='#386b87');ax.set_xlabel('Share of mean absolute TreeSHAP contribution (%)');ax.set_title('XGBoost: 20 URL features, 10,000 test rows');fig.tight_layout();fig.savefig(R/'xgboost_feature_influence.png',dpi=160);plt.close(fig)
 lines=['# Hasil eksperimen PhreshPhish URL20','',
 'Model utama: XGBoost. Pembanding: Random Forest, Extra Trees, HistGradientBoosting, Logistic Regression.',
 'Seluruh model menggunakan threshold tetap 0,50. Tidak ada validation split, early stopping, atau pemilihan threshold dari test/arsip.',
 'Bobot kelas dihitung dari data train. Tidak dilakukan undersampling untuk menyamakan jumlah kelas.','',
 '## Data dan pembagian','',
 f"- Sumber normalisasi HTTPS: 666.297 baris. Duplikat label sama dihapus: 67 baris. Kedua rekaman satu URL berlabel bertentangan dikarantina: 2 baris.",
 f"- Data bersih: {prep['all_clean_rows']:,}; legitimate {prep['all_clean_label_counts']['legitimate']:,}, phishing {prep['all_clean_label_counts']['phishing']:,}.",
 f"- Dipisahkan karena domain ada di arsip live: {prep['excluded_archive_domain_rows']:,} baris, termasuk {prep['excluded_archive_exact_url_rows']} URL persis.",
 f"- Train: {prep['train_rows']:,}; test: {prep['test_rows']:,}. Rasio aktual {prep['actual_train_percent']:.2f}/{100-prep['actual_train_percent']:.2f}; pemisahan sekitar 90/10 mengikuti kelompok domain.",
 '- Domain train/test tidak tumpang tindih; domain arsip tidak masuk data pengembangan.',
 f"- Train per label: {prep['train_labels']}. Test per label: {prep['test_labels']}.",
 f"- Arsip: {prep['archive_rows']:,} URL (legitimate 3.600, phishing 2.860); subset sebelumnya berstatus completed: 4.829.",
 '- Seluruh fitur dihitung ulang dari URL menggunakan extractor Python 17 fitur lama ditambah tiga fitur. Tidak membuka website atau memanggil API.','',
 '## Evaluasi','',
 '| Model | Akurasi test | Legitimate test | Phishing test | Legitimate arsip | Phishing arsip |',
 '|---|---:|---:|---:|---:|---:|']
 for n in names:
  a=trained['models'][n]['test'];b=trained['models'][n]['historical_archive_all_url_text']
  lines.append(f"| {n} | {a['accuracy_percent']:.2f}% | {a['legitimate_correct_percent']:.2f}% | {a['phishing_recall_percent']:.2f}% | {b['legitimate_correct_percent']:.2f}% | {b['phishing_recall_percent']:.2f}% |")
 lines += ['', '## Pengaruh fitur XGBoost','',
 'Persentase berikut adalah proporsi rata-rata nilai absolut kontribusi TreeSHAP terhadap log-odds pada sampel berstrata 10.000 baris test. Total seluruh fitur 100%. Ini bukan pengaruh sebab-akibat, korelasi langsung dengan label, atau persentase akurasi satu fitur.',
 'Permutation importance juga disimpan: penurunan balanced accuracy setelah satu fitur diacak, pada 5.000 baris test dan dua pengulangan. Fitur berkorelasi dapat saling menggantikan.','',
 '| Fitur | Proporsi kontribusi SHAP | Penurunan balanced accuracy saat diacak (poin persentase) |','|---|---:|---:|']
 for z in imp.itertuples(index=False):lines.append(f'| `{z.feature}` | {z.shap_contribution_share_percent:.4f}% | {z.permutation_balanced_accuracy_drop_percentage_points:.4f} |')
 lines += ['', '## EDA dan batas interpretasi','',
 '- Legitimate berquery pada data bersih hanya 68 URL. Phishing berquery jauh lebih banyak. HTTPS juga hampir selalu ada pada legitimate. Distribusi ini dapat menjadi jalan pintas model.',
 '- Pada arsip XGBoost, 130 dari 130 URL legitimate berquery salah diprediksi. Legitimate tanpa query: 2.817/3.470 benar. Ini bukti kelemahan terhadap pola query pada arsip, bukan bukti semua query berbahaya.',
 '- Label yang digunakan adalah label sumber/historis. Isi halaman tidak diverifikasi ulang. URL arsip dengan status HTTP/error terdahulu tetap dapat dinilai dari teks URL, tetapi tidak disebut keberhasilan analisis halaman live.',
 '- Arsip telah digunakan dalam pengembangan sistem sebelumnya. Walaupun domain dikeluarkan dari train/test, hasilnya tetap bukti evaluasi pengembangan historis, bukan uji lapangan baru yang independen.',
 '- Workbook hanya URL/label; tanggal dan pembagian train/test asli tidak tersedia. Hasil ini tidak identik dengan benchmark resmi PhreshPhish.',
 '- Penambahan HTTPS pada 5.741 URL adalah asumsi format atas permintaan pengguna, bukan hasil pemeriksaan koneksi.',
 '- Hasil ini hanya URL Analyzer dengan 20 fitur. DOM, brand, umur domain, dan aturan keputusan extension tidak ikut dijalankan.',
 '- Pengaruh positif/negatif rata-rata per kelas ada pada CSV SHAP. Nilai sangat kecil tidak membuktikan fitur tidak berguna di semua keadaan.',
 '- Extension lama tetap utuh. Model eksperimen belum dipasang ke extension. Tidak ada push GitHub.',
 '', '## Berkas utama','',
 '- `data/raw/`: workbook asli, CSV normalisasi, catatan penambahan HTTPS.',
 '- `data/processed/phreshphish_url20_all_clean.csv`: seluruh data bersih dan 20 fitur, termasuk penanda overlap arsip.',
 '- `data/processed/url20_train_test.csv`: data pengembangan dengan kolom split train/test.',
 '- `data/evaluation/live_url20.csv`: URL arsip beserta label, status historis, asal rekaman, dan 20 fitur.',
 '- `models/`: kelima model beserta urutan fitur dan threshold. XGBoost juga disimpan sebagai JSON native.',
 '- `reports/model_comparison.csv`, `training_results.json`: evaluasi seluruh model dan konfigurasi.',
 '- `reports/*_test_predictions.csv`, `*_archive_predictions.csv`: skor dan benar/salah setiap URL.',
 '- `reports/eda_feature_distribution.csv`, `eda_feature_correlations.csv`, `eda_distributions.png`: EDA.',
 '- `reports/xgboost_feature_influence_20.csv`, `xgboost_feature_influence.png`: pengaruh semua fitur.',
 '- `reports/verification.json`: pemeriksaan model tersimpan dan konsistensi hasil.',
 '', 'Sumber: https://huggingface.co/datasets/phreshphish/phreshphish (CC BY 4.0 menurut dataset card).']
 (ROOT/'HASIL_EKSPERIMEN.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
 print('Saved report and verified five models')

if __name__=='__main__':main()
