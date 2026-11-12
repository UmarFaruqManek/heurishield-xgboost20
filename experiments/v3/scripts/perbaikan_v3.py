"""V3: same v2 rows, WHATWG normalization, fixed .50, training-only grouped CV.
Run --train first. External PhiUSIIL evaluation is a separate user-run --external.
All generated files stay inside experiments/v3; v2 and extension are read-only.
"""
import argparse,csv,gc,hashlib,json,math,os,platform,shutil,subprocess,sys,time
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
from urllib.parse import urlsplit
import joblib,numpy as np,pandas as pd,sklearn,xgboost
from sklearn.model_selection import StratifiedGroupKFold

OUT=Path(__file__).resolve().parents[1];ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from perbaikan_v2 import training_weights,endpoint_family,select_threshold,evaluate
from eksperimen_phreshphish import SEED,domain,models
V2=ROOT/'experiments/v2';EXT=ROOT/'extension/HeuriShield-URL20-XGBoost'
DATA=OUT/'data';REPORTS=OUT/'reports';MODELS=OUT/'models'
FEATURES=json.loads((EXT/'src/model/feature-contract-20.json').read_text())['features']

def save(p,obj):
 p.write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=lambda x:x.item() if hasattr(x,'item') else str(x)),encoding='utf-8')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def node(mode,inp,out,model=None):
 exe=shutil.which('node')
 if not exe:raise RuntimeError('Node.js is required')
 args=[exe,str(Path(__file__).with_suffix('.mjs')),mode,str(EXT),str(inp),str(out)]
 if model:args.append(str(model))
 subprocess.run(args,check=True)
def protected_hashes():
 paths=[V2/'data/url20_augmented_splits.csv',V2/'data/training_weights.csv',V2/'data/cv_train_only_sample.csv',V2/'models/XGBoost.joblib',V2/'reports/results.json',V2/'reports/XGBoost_cv_selection.json',ROOT/'scripts/perbaikan_v2.py',ROOT/'scripts/eksperimen_phreshphish.py']
 paths+=list(p for p in EXT.rglob('*') if p.is_file() and 'node_modules' not in p.parts and '__pycache__' not in p.parts)
 return {str(p):sha(p) for p in paths}
def eval_frame(model,frame):
 return evaluate(frame.label.eq('phishing').to_numpy(dtype=np.int8),model.predict_proba(frame[FEATURES].to_numpy(np.float32))[:,1],.5)
def export(pack,path):
 raw=json.loads(pack['model'].get_booster().save_raw(raw_format='json'))['learner']
 base=raw['learner_model_param']['base_score'];p=float(json.loads(base)[0]) if base.startswith('[') else float(base)
 trees=[]
 for t in raw['gradient_booster']['model']['trees']:
  assert not any(t['split_type'])
  trees.append(dict(left=t['left_children'],right=t['right_children'],default_left=t['default_left'],feature=t['split_indices'],threshold_or_leaf=t['split_conditions']))
 obj=dict(model_family='XGBoost',objective='binary:logistic',feature_names=FEATURES,feature_set='url20-whatwg-v3',threshold=.5,training_cv_threshold=pack['training_cv_threshold'],source_model_sha256=sha(path),base_margin=math.log(p/(1-p)),trees=trees)
 (MODELS/'xgboost-url20.json').write_text(json.dumps(obj,separators=(',',':')),encoding='utf-8')

def train():
 started=time.time()
 if (MODELS/'FROZEN.json').exists():raise RuntimeError('V3 is frozen. Do not overwrite; use its external test command.')
 for p in [DATA,REPORTS,MODELS]:p.mkdir(parents=True,exist_ok=True)
 protected=protected_hashes();save(REPORTS/'protected_inputs_before.json',protected)
 full=pd.read_csv(V2/'data/url20_augmented_splits.csv',keep_default_na=False,low_memory=False)
 assert full.split.value_counts().to_dict()=={'train':612713,'test':59286,'supplement_test':6116}
 assert len(FEATURES)==20
 baseline_pack=joblib.load(V2/'models/XGBoost.joblib');assert baseline_pack['features']==FEATURES
 baseline=baseline_pack['model'];old_report=json.loads((V2/'reports/results.json').read_text())['models']['XGBoost']
 baseline_results={}
 for split,key in [('test','original_test_at_05'),('supplement_test','supplement_test_at_05')]:
  r=eval_frame(baseline,full[full.split==split]);baseline_results[split]=r
  assert all(r[k]==old_report[key][k] for k in ['tn','fp','fn','tp']),f'Baseline mismatch: {split}'
 print('Baseline internal reproduced:',json.dumps(baseline_results),flush=True)
 save(REPORTS/'baseline_internal.json',baseline_results)
 inp=DATA/'normalization_input.jsonl'
 with inp.open('w',encoding='utf-8') as f:
  cols=['url','label','split','source','site_key','endpoint_family']
  for i,r in enumerate(full[cols].to_dict('records')):f.write(json.dumps(dict(row_id=i,**r),ensure_ascii=True)+'\n')
 node('normalize',inp,DATA/'url20_normalized_splits.csv');inp.unlink()
 norm=pd.read_csv(DATA/'url20_normalized_splits.csv',keep_default_na=False)
 assert len(norm)==len(full) and np.array_equal(norm.row_id,np.arange(len(full)))
 assert np.array_equal(norm.original_url,full.url) and np.array_equal(norm.label,full.label) and np.array_equal(norm.split,full.split)
 failed=norm[norm.status!='ok'];failed.to_csv(REPORTS/'normalization_failures.csv',index=False)
 counts_failed=failed.groupby(['split','label']).size().to_dict()
 good=norm.status.eq('ok').to_numpy();old=full.loc[good].reset_index(drop=True);norm=norm.loc[good].reset_index(drop=True)
 changes=[]
 for label in ['legitimate','phishing']:
  mask=norm.label.eq(label)
  for feature in FEATURES:
   changes.append(dict(label=label,feature=feature,rows=int(mask.sum()),changed_rows=int(np.sum(old.loc[mask,feature].to_numpy(np.float32)!=norm.loc[mask,feature].to_numpy(np.float32)))))
 pd.DataFrame(changes).to_csv(REPORTS/'feature_changes.csv',index=False)
 old_values=old[FEATURES].to_numpy(np.float32);new_values=norm[FEATURES].to_numpy(np.float32)
 change_audit=dict(rows=len(full),url_changed_rows=int((norm.original_url!=norm.url).sum()),feature_changed_rows=int(np.any(old_values!=new_values,axis=1).sum()),failed_by_split_label={f'{s}|{l}':int(n) for (s,l),n in counts_failed.items()})
 normalized_sites=[domain(urlsplit(u).hostname or '') for u in norm.url]
 site_changes=sum(a!=b for a,b in zip(normalized_sites,norm.site_key))
 change_audit['site_key_changes']=site_changes
 norm['normalized_site_key']=normalized_sites
 changed=norm[norm.site_key!=norm.normalized_site_key]
 changed[['row_id','original_url','url','site_key','normalized_site_key','label','split']].to_csv(REPORTS/'domain_normalization_changes.csv',index=False)
 canonical_train=set(norm.loc[norm.split=='train','normalized_site_key'])
 canonical_holdout=set(norm.loc[norm.split!='train','normalized_site_key'])
 assert not canonical_train&canonical_holdout,'Canonical domain leakage requires review.'
 change_audit['normalized_train_holdout_domain_overlap']=0
 norm['endpoint_family']=[endpoint_family(u,d) for u,d in zip(norm.url,norm.normalized_site_key)]
 change_audit['endpoint_family_changes']=int((norm.endpoint_family!=norm.original_endpoint_family).sum())
 norm.to_csv(DATA/'url20_normalized_splits.csv',index=False)
 save(REPORTS/'normalization_audit.json',change_audit)
 trainframe=norm[norm.split=='train'].reset_index(drop=True)
 assert len(trainframe)==612713,'Training row exclusions require review before continuing.'
 for split in ['test','supplement_test']:
  assert not set(trainframe.site_key)&set(norm.loc[norm.split==split,'site_key'])
 # Recover the exact stored CV sample and its row order, not a new sample.
 original_cv=pd.read_csv(V2/'data/cv_train_only_sample.csv',keep_default_na=False)
 assert len(original_cv)==100016
 assert trainframe.original_url.is_unique
 indexed=trainframe.set_index('original_url',drop=False)
 cv=indexed.loc[original_cv.url].reset_index(drop=True)
 assert np.array_equal(cv.original_url,original_cv.url) and np.array_equal(cv.label,original_cv.label) and np.array_equal(cv.site_key,original_cv.site_key)
 cv[['original_url','url','label','site_key']].to_csv(DATA/'cv_train_only_sample.csv',index=False)
 # Retain original site_key for provenance and the fixed split. Weighting uses
 # the canonical hostname/domain after normalization, with the same v2 formula.
 def canonical_weights(frame,labels):
  weighted=frame.copy();weighted['site_key']=weighted.normalized_site_key
  return training_weights(weighted,labels)
 y=trainframe.label.eq('phishing').to_numpy(np.int8);weights=canonical_weights(trainframe,y)
 weight_frame=trainframe[['original_url','url','label','site_key','endpoint_family']].copy();weight_frame['sample_weight']=weights
 weight_frame.to_csv(DATA/'training_weights.csv',index=False)
 save(REPORTS/'weights.json',dict(method='Same v2 class-balanced soft domain cap 20 and endpoint family cap 5; recomputed after WHATWG normalization',endpoint_family_changes=change_audit['endpoint_family_changes'],sum=float(weights.sum()),minimum=float(weights.min()),maximum=float(weights.max())))
 Xcv=cv[FEATURES].to_numpy(np.float32);ycv=cv.label.eq('phishing').to_numpy(np.int8)
 folds=list(StratifiedGroupKFold(n_splits=3,shuffle=True,random_state=SEED).split(Xcv,ycv,cv.normalized_site_key))
 for tr,va in folds:assert not set(cv.iloc[tr].normalized_site_key)&set(cv.iloc[va].normalized_site_key)
 make=dict(models())['XGBoost'];trials=[]
 candidates=json.loads((V2/'reports/XGBoost_cv_selection.json').read_text())['trials']
 for j,trial in enumerate(candidates):
  params=trial['parameters'];oof=np.zeros(len(cv),np.float32)
  for k,(tr,va) in enumerate(folds):
   print(f'CV candidate {j+1}/2 fold {k+1}/3',flush=True)
   estimator=make().set_params(**params);estimator.fit(Xcv[tr],ycv[tr],sample_weight=canonical_weights(cv.iloc[tr],ycv[tr]))
   oof[va]=estimator.predict_proba(Xcv[va])[:,1];del estimator;gc.collect()
  trials.append(dict(parameters=params,cv=select_threshold(ycv,oof),cv_at_fixed_05=evaluate(ycv,oof,.5)))
  save(REPORTS/'XGBoost_cv_selection.json',dict(trials=trials))
 best=max(trials,key=lambda r:(r['cv']['min_class_correct_percent'],r['cv']['balanced_accuracy_percent']))
 save(REPORTS/'XGBoost_cv_selection.json',dict(trials=trials,selected=best,selection_method='Identical to v2: maximize minimum class correct at train-only OOF-selected threshold, then balanced accuracy; deployed threshold always 0.50'))
 print('Final train',len(trainframe),'rows, fixed threshold .50;',best['parameters'],flush=True)
 model=make().set_params(**best['parameters']);model.fit(trainframe[FEATURES].to_numpy(np.float32),y,sample_weight=weights)
 pack=dict(model=model,features=FEATURES,threshold=.5,training_cv_threshold=best['cv']['threshold'],label_mapping={'legitimate':0,'phishing':1},normalization='WHATWG new URL(input).href before JS feature extraction')
 joblib.dump(pack,MODELS/'XGBoost.joblib',compress=3);model.save_model(MODELS/'XGBoost.json');export(pack,MODELS/'XGBoost.joblib')
 internal={};table=[]
 for split in ['test','supplement_test']:
  frame=norm[norm.split==split]
  r3=eval_frame(model,frame);r2normalized=eval_frame(baseline,frame)
  internal[split]=dict(v2_raw=baseline_results[split],v2_normalized=r2normalized,v3_normalized=r3)
  for name,result in internal[split].items():table.append(dict(split=split,model_mode=name,**result))
 pd.DataFrame(table).to_csv(REPORTS/'internal_v2_vs_v3.csv',index=False)
 # Exact Python versus deployed JS tree evaluator, with independently re-extracted features.
 sample=norm.sample(n=20000,random_state=SEED)
 probs=model.predict_proba(sample[FEATURES].to_numpy(np.float32))[:,1]
 parity=DATA/'parity_cases.jsonl'
 with parity.open('w',encoding='utf-8') as f:
  for row,p in zip(sample.to_dict('records'),probs):
   u=urlsplit(row['url']);root_variant=row['url'][:-1] if u.path=='/' and not u.query and not u.fragment else None
   f.write(json.dumps(dict(url=row['url'],features=[row[k] for k in FEATURES],probability=float(p),root_without_slash=root_variant))+'\n')
 node('parity',parity,REPORTS/'export_parity.json',MODELS/'xgboost-url20.json')
 parity_result=json.loads((REPORTS/'export_parity.json').read_text());assert parity_result['passed']
 parity.unlink()
 gains=[]
 g2=baseline.get_booster().get_score(importance_type='gain');g3=model.get_booster().get_score(importance_type='gain')
 for i,f in enumerate(FEATURES):gains.append(dict(feature=f,v2_gain=float(g2.get('f'+str(i),g2.get(f,0))),v3_gain=float(g3.get('f'+str(i),g3.get(f,0)))))
 pd.DataFrame(gains).to_csv(REPORTS/'feature_importance_gain.csv',index=False)
 assert protected_hashes()==protected,'Protected inputs changed during experiment'
 hashes={p.name:sha(p) for p in [MODELS/'XGBoost.joblib',MODELS/'xgboost-url20.json',MODELS/'XGBoost.json']}
 result=dict(status='trained_frozen_external_pending',seed=SEED,threshold=.5,feature_names=FEATURES,
  source_sha256=protected[str(V2/'data/url20_augmented_splits.csv')],normalization=change_audit,
  split_counts=norm.split.value_counts().to_dict(),cv_sample_rows=len(cv),selected_parameters=best['parameters'],training_cv_threshold=best['cv']['threshold'],internal=internal,export_parity=parity_result,hashes=hashes,
  protected_inputs_unchanged=True,external_evaluation_executed=False,phiusiil_used_in_training_or_tuning=False,
  versions=dict(python=platform.python_version(),xgboost=xgboost.__version__,sklearn=sklearn.__version__,numpy=np.__version__,pandas=pd.__version__),elapsed_seconds=time.time()-started)
 save(REPORTS/'results.json',result)
 save(MODELS/'FROZEN.json',dict(frozen_at_utc=datetime.now(timezone.utc).isoformat(),hashes=hashes,threshold=.5,external_evaluation_executed=False))
 report(result)
 print('TRAINING COMPLETE',json.dumps(result['internal']),flush=True)

def report(result):
 lines=['# Hasil pelatihan XGBoost URL20 v3','',
 'V3 memakai baris dan split v2 yang sama. URL dinormalisasi dengan WHATWG URL pada Node.js sebelum dihitung oleh extractor JavaScript extension. Model dan extension aktif tidak ditimpa.',
 '',f"Seed: {SEED}. Fitur: 20. Threshold keputusan: 0,50. Threshold CV {result['training_cv_threshold']} hanya dilaporkan dan tidak dipakai untuk keputusan.",'',
 '**PhiUSIIL tidak dipakai untuk training, pemilihan kandidat, threshold, penyaringan, maupun pembobotan. Evaluasi eksternal belum dijalankan; disiapkan untuk pengguna.**','',
 'Pemilihan kandidat mengikuti kriteria v2 dari OOF train saja, dengan 3-fold StratifiedGroupKFold dan sampel 100.016 baris yang urutan URL, label, dan domainnya sama dengan arsip v2.',
 '', 'Bobot dihitung ulang menggunakan rumus v2 setelah normalisasi karena keluarga endpoint dapat berubah. Pemisahan domain dan seed tetap dipertahankan.','',
 '| Split | Model dan input | Akurasi | Precision | Recall phishing | Specificity legitimate | F1 | TP | FP | FN | TN |',
 '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
 for split,items in result['internal'].items():
  for name,r in items.items():lines.append(f"| {split} | {name} | {r['accuracy_percent']:.3f}% | {r['precision_percent']:.3f}% | {r['phishing_recall_percent']:.3f}% | {r['legitimate_correct_percent']:.3f}% | {r['f1_percent']:.3f}% | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} |")
 lines+=['','## Kesetaraan ekspor',json.dumps(result['export_parity'],indent=2),'','## Hash model']
 lines += [f'- {k}: `{v}`' for k,v in result['hashes'].items()]
 lines+=['','## Keterbatasan','Hasil internal tidak membuktikan kinerja pada sumber eksternal. Angka peningkatan PhiUSIIL dari lampiran merupakan laporan sebelumnya, belum diverifikasi oleh eksperimen v3 ini. Identifikasi masalah telah melibatkan PhiUSIIL pada tahap diskusi, sehingga dataset tersebut bukan holdout yang sepenuhnya belum pernah dilihat dalam keseluruhan riwayat pengembangan. Tidak ada data PhiUSIIL yang dibaca oleh perintah --train.',
 '','Normalisasi merupakan bagian wajib pipeline v3, bukan perubahan pada nama 20 fitur. Pengujian tanpa normalisasi adalah diagnosis distribusi input berbeda dan tidak dijamin meningkat. Hasil pelatihan tidak boleh diklaim menghapus seluruh shortcut. Extension aktif tetap v2; ekspor JSON v3 saja belum mengganti alur extractor extension.',
 '','## Pengujian eksternal oleh pengguna','Jalankan `python .\\scripts\\perbaikan_v3.py --external` dari folder experiments/v3. Perintah ini menguji empat kombinasi v2/v3 dan mentah/normalisasi dalam satu lintasan setelah memverifikasi hash model beku. Tidak membuka browser atau API.']
 lines+=['','## Audit normalisasi',json.dumps(result['normalization'],indent=2),
  '', 'Baris dan split dipertahankan persis. Tiga hostname berubah representasi karena aturan WHATWG (dua IP oktal dan satu hostname dengan backslash), semuanya train dan di luar sampel CV. Tidak ada overlap domain kanonis train dengan holdout. site_key asli dipertahankan sebagai provenance; normalized_site_key dipakai untuk keluarga endpoint, bobot, dan pengelompokan CV.',
  '', '## Perubahan nilai fitur dibanding v2',
  '| Fitur | Legitimate berubah | Phishing berubah |','|---|---:|---:|']
 changes=pd.read_csv(REPORTS/'feature_changes.csv').pivot(index='feature',columns='label',values='changed_rows')
 for feature in FEATURES:lines.append(f"| {feature} | {changes.loc[feature,'legitimate']} | {changes.loc[feature,'phishing']} |")
 lines+=['','## Feature importance gain','Gain merupakan ukuran kepentingan split model, bukan persentase pengaruh kausal terhadap label.',
  '| Fitur | Gain v2 | Gain v3 |','|---|---:|---:|']
 for r in pd.read_csv(REPORTS/'feature_importance_gain.csv').itertuples():lines.append(f'| {r.feature} | {r.v2_gain:.6f} | {r.v3_gain:.6f} |')
 lines+=['','## Parameter kandidat terpilih',json.dumps(result['selected_parameters'],indent=2)]
 (OUT/'HASIL_V3.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')

def external():
 frozen=json.loads((MODELS/'FROZEN.json').read_text())
 assert all(sha(MODELS/k)==v for k,v in frozen['hashes'].items())
 assert protected_hashes()==json.loads((REPORTS/'protected_inputs_before.json').read_text()),'V2/extension inputs changed since freeze; review before external test.'
 if (REPORTS/'external_started.json').exists():raise RuntimeError('External evaluation already started; do not repeat/tune using its results.')
 source=Path(r'C:\Users\USER\Downloads\PhiUSIIL_Phishing_URL_Dataset.csv')
 save(REPORTS/'external_started.json',dict(started_at_utc=datetime.now(timezone.utc).isoformat(),source_sha256=sha(source)))
 inp=DATA/'phiusiil_input.jsonl'
 with source.open(encoding='utf-8-sig',newline='') as f,inp.open('w',encoding='utf-8') as g:
  for i,r in enumerate(csv.DictReader(f)):
   label={'0':'phishing','1':'legitimate'}[r['label'].strip()]
   g.write(json.dumps(dict(row_id=i,url=r['URL'].strip(),label=label))+'\n')
 node('external',inp,REPORTS/'phiusiil_all_predictions.csv',MODELS/'xgboost-url20.json');inp.unlink()
 rows=pd.read_csv(REPORTS/'phiusiil_all_predictions.csv',keep_default_na=False)
 dev=pd.read_csv(V2/'data/url20_augmented_splits.csv',usecols=['url','site_key','split'],keep_default_na=False)
 rawknown=set(dev.url);normalized_known=set(pd.read_csv(DATA/'url20_normalized_splits.csv',usecols=['url']).url)
 train_domains=set(dev.loc[dev.split=='train','site_key'])
 rows['exact_development_overlap']=rows.original_url.isin(rawknown)|rows.normalized_url.isin(normalized_known)
 rows['train_domain_overlap']=rows.normalized_site.isin(train_domains)
 rows.to_csv(REPORTS/'phiusiil_all_predictions.csv',index=False)
 from uji_phiusiil_url20 import metrics as cm_metrics
 comparison=[]
 for subset,mask in [('all',np.ones(len(rows),bool)),('without_exact_development_overlap',~rows.exact_development_overlap),('without_training_domain_overlap',~rows.train_domain_overlap)]:
  frame=rows.loc[mask]
  for column in ['v2_raw','v2_normalized','v3_raw','v3_normalized']:
   m=cm_metrics(dict(status='evaluated' if r.status=='ok' else 'failed',actual_label=r.label,prediction=getattr(r,column)) for r in frame.itertuples())
   comparison.append(dict(subset=subset,model_mode=column,**m))
 pd.DataFrame(comparison).to_csv(REPORTS/'phiusiil_v2_vs_v3.csv',index=False)
 errors=rows[(rows.status=='ok')&(rows.v3_normalized!=rows.label)].copy()
 errors['error_type']=np.where(errors.label=='phishing','FN','FP')
 providers=['firebaseapp.com','web.app','repl.co','replit.app','godaddysites.com','vercel.app','pages.dev','workers.dev','blogspot.com','github.io','weebly.com','framer.app','ipfs']
 errors['hosting_family']=[next((p for p in providers if h==p or h.endswith('.'+p) or (p=='ipfs' and 'ipfs' in h)),'other') for h in errors.host]
 errors['length_bin']=pd.cut(errors.url_length.astype(int),[0,50,100,200,500,float('inf')],right=True).astype(str)
 errors.to_csv(REPORTS/'phiusiil_errors_v3.csv',index=False)
 grouped={}
 examples=[]
 for column in ['hosting_family','path_present','query_present','public_suffix','length_bin']:
  groups=errors.groupby(['error_type',column]).size().sort_values(ascending=False)
  grouped[column]={f'{a}|{b}':int(n) for (a,b),n in groups.items()}
  for (kind,value),n in groups.head(5).items():
   sample=errors[(errors.error_type==kind)&(errors[column]==value)].head(20).copy();sample['group_dimension']=column;sample['group_value']=str(value);examples.append(sample)
 if examples:pd.concat(examples,ignore_index=True).to_csv(REPORTS/'phiusiil_error_examples.csv',index=False)
 save(REPORTS/'phiusiil_error_groups.json',grouped)
 result=json.loads((REPORTS/'results.json').read_text());result.update(external_evaluation_executed=True,status='external_evaluated',external=comparison)
 save(REPORTS/'results.json',result)
 with (OUT/'HASIL_V3.md').open('a',encoding='utf-8') as f:
  f.write('\n## Hasil eksternal setelah model dibekukan\n\n| Subset | Mode | Akurasi | Recall phishing | Specificity legitimate |\n|---|---|---:|---:|---:|\n')
  for r in comparison:f.write(f"| {r['subset']} | {r['model_mode']} | {r['accuracy_percent']}% | {r['recall_phishing_percent']}% | {r['specificity_legitimate_percent']}% |\n")
 print(json.dumps(comparison,indent=2))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
 g.add_argument('--train',action='store_true');g.add_argument('--external',action='store_true')
 a=p.parse_args()
 if a.train:train()
 else:external()
