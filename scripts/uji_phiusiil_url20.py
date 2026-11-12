"""Evaluate frozen URL20 on raw PhiUSIIL URLs. No browser, API, training or scores saved.
PhiUSIIL source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
Official dataset labels: 1 legitimate, 0 phishing. Phishing is positive in metrics.
Python standard library + Node.js only. Imports the current extension's JS code.
"""
import argparse,csv,hashlib,json,shutil,subprocess,tempfile,sys
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter

ROOT=Path(__file__).resolve().parent.parent
DEFAULT_INPUT=Path(r'C:\Users\USER\Downloads\PhiUSIIL_Phishing_URL_Dataset.csv')
LABELS={'1':'legitimate','0':'phishing'}

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def node_path():
 node=shutil.which('node')
 if node:return node
 base=Path(r'C:\Program Files\WindowsApps')
 matches=sorted(base.glob('OpenAI.CodexPrimaryRuntime.*/dependencies/node/bin/node.exe'))
 if matches:return str(matches[-1])
 raise RuntimeError('Node.js tidak ditemukan. Instal Node.js LTS, lalu buka terminal kembali.')

def metrics(rows):
 counts=Counter();failed=0
 for row in rows:
  if row['status']!='evaluated':failed+=1;continue
  counts[(row['actual_label'],row['prediction'])]+=1
 tp=counts['phishing','phishing'];fn=counts['phishing','legitimate']
 tn=counts['legitimate','legitimate'];fp=counts['legitimate','phishing']
 n=tp+tn+fp+fn
 pct=lambda a,b:round(100*a/b,4) if b else None
 return dict(evaluated=n,failed=failed,tp=tp,fp=fp,fn=fn,tn=tn,
  accuracy_percent=pct(tp+tn,n),precision_phishing_percent=pct(tp,tp+fp),
  recall_phishing_percent=pct(tp,tp+fn),specificity_legitimate_percent=pct(tn,tn+fp),
  f1_phishing_percent=pct(2*tp,2*tp+fp+fn),coverage_percent=pct(n,n+failed),
  phishing_rows=tp+fn,legitimate_rows=tn+fp)

def prepare(source,dest=None,known=None,limit=0):
 labels=Counter();duplicates=0;seen=set();n=0
 with source.open(encoding='utf-8-sig',newline='') as f:
  reader=csv.DictReader(f)
  if not {'URL','label'}<=set(reader.fieldnames or []):raise ValueError('Kolom URL dan label wajib tersedia.')
  for number,row in enumerate(reader,2):
   if limit and n>=limit:break
   url=(row['URL'] or '').strip();raw=(row['label'] or '').strip()
   label=LABELS.get(raw,'unknown');labels[label]+=1;n+=1
   if url in seen:duplicates+=1
   seen.add(url)
   if dest:
    dest.write(json.dumps(dict(source_row=number,url=url,label=label,
      error='' if label!='unknown' else 'Unknown PhiUSIIL label: '+raw,
      overlap=('not_checked' if known is None else str(int(url in known)))),ensure_ascii=True)+'\n')
 return dict(rows=n,label_counts=dict(labels),unique_urls=len(seen),duplicate_url_rows=duplicates)

def self_test(extension):
 with tempfile.TemporaryDirectory(prefix='url20-self-test-') as temp:
  temp=Path(temp);inp=temp/'tiny.jsonl';out=temp/'tiny.csv'
  rows=[dict(source_row=2,url='https://example.com/login',label='legitimate',overlap='0'),
        dict(source_row=3,url='https://example.com/login',label='phishing',overlap='0'),
        dict(source_row=4,url='https://bad host.test/',label='legitimate',overlap='0')]
  inp.write_text(''.join(json.dumps(x)+'\n' for x in rows),encoding='utf-8')
  subprocess.run([node_path(),str(Path(__file__).with_suffix('.mjs')),str(extension),str(inp),str(out)],check=True)
  with out.open(encoding='utf-8',newline='') as f:result=list(csv.DictReader(f))
  assert result[0]['prediction']==result[1]['prediction']
  assert sum(x['correct']=='1' for x in result)==1
  assert result[2]['status']=='failed'
  m=metrics(result);assert m['evaluated']==2 and m['failed']==1 and m['accuracy_percent']==50
  assert len([x for x in result[0] if x not in ['source_row','url','actual_label','prediction','correct','status','error','exact_development_overlap']])==20
  assert LABELS=={'1':'legitimate','0':'phishing'}
  print('SELF-TEST PASSED: label mapping, 20 features, decisions, confusion matrix, invalid URL handling.')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--input',type=Path,default=DEFAULT_INPUT)
 p.add_argument('--extension-dir',type=Path,default=ROOT/'extension/HeuriShield-URL20-XGBoost')
 p.add_argument('--out-dir',type=Path)
 p.add_argument('--dry-run',action='store_true')
 p.add_argument('--self-test',action='store_true')
 p.add_argument('--limit',type=int,default=0,help='0=semua baris; nilai positif untuk uji kecil')
 p.add_argument('--skip-overlap',action='store_true')
 a=p.parse_args()
 if a.limit<0:p.error('--limit tidak boleh negatif')
 model_path=a.extension_dir/'src/model/xgboost-url20.json'
 model=json.loads(model_path.read_text(encoding='utf-8'))
 if model['threshold']!=.5 or len(model['feature_names'])!=20:raise ValueError('Konfigurasi bukan URL20 TH 0.50')
 if a.self_test:self_test(a.extension_dir);return
 if a.dry_run:
  print(json.dumps({**prepare(a.input,limit=a.limit),'dry_run':True,'mode':'offline_url_model_only',
    'features':20,'threshold':model['threshold'],'label_mapping':LABELS,'node':node_path(),
    'browser_opened':False,'api_calls':0,'predictions_executed':False},indent=2));return
 output=a.out_dir or ROOT/'outputs'/('phiusiil_url20_'+datetime.now().strftime('%Y%m%d_%H%M%S'))
 output.mkdir(parents=True,exist_ok=False)
 known=None;overlap_source=ROOT/'experiments/v2/data/url20_augmented_splits.csv'
 if not a.skip_overlap and overlap_source.exists():
  print('Membaca URL pengembangan untuk pemeriksaan tumpang tindih...',flush=True)
  with overlap_source.open(encoding='utf-8-sig',newline='') as f:known={(r['url'] or '').strip() for r in csv.DictReader(f)}
 with tempfile.TemporaryDirectory(prefix='phiusiil-url20-') as temp:
  inp=Path(temp)/'input.jsonl'
  with inp.open('w',encoding='utf-8',newline='\n') as f:info=prepare(a.input,f,known,a.limit)
  print(json.dumps(info,indent=2),flush=True)
  subprocess.run([node_path(),str(Path(__file__).with_suffix('.mjs')),str(a.extension_dir),str(inp),str(output/'prediksi_per_url.csv')],check=True)
 with (output/'prediksi_per_url.csv').open(encoding='utf-8',newline='') as f:rows=list(csv.DictReader(f))
 all_metrics=metrics(rows)
 nonoverlap=metrics(r for r in rows if r['exact_development_overlap']=='0') if known is not None else None
 summary=dict(generated_at_utc=datetime.now(timezone.utc).isoformat(),mode='offline_url_model_only',
  source=str(a.input.resolve()),source_sha256=sha(a.input),model=str(model_path.resolve()),
  model_sha256=sha(model_path),extractor_sha256=sha(a.extension_dir/'src/analyzer/url/url20-features.js'),
  feature_names=model['feature_names'],threshold=model['threshold'],label_mapping=LABELS,**info,
  all_rows_metrics=all_metrics,exact_overlap_checked=known is not None,
  exact_development_overlap_rows=sum(r['exact_development_overlap']=='1' for r in rows) if known is not None else None,
  without_exact_development_overlap=nonoverlap,
  notes=['Hanya kolom URL dan label yang digunakan; 20 fitur diekstraksi ulang dengan kode extension.',
   'Phishing adalah kelas positif; skor/probabilitas tidak disimpan.',
   'Duplikat dipertahankan dan jumlahnya dilaporkan; baris gagal tidak dimasukkan ke confusion matrix.',
   'Pemeriksaan overlap hanya URL persis terhadap arsip pengembangan v2, bukan jaminan pemisahan domain atau seluruh riwayat.',
   'Evaluasi model URL, bukan keputusan extension lengkap; tidak ada DOM, brand, umur domain, API atau browser.'])
 (output/'ringkasan.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
 fields=['subset',*all_metrics]
 with (output/'metrik.csv').open('w',encoding='utf-8-sig',newline='') as f:
  writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerow(dict(subset='all_rows',**all_metrics))
  if nonoverlap:writer.writerow(dict(subset='without_exact_development_overlap',**nonoverlap))
 print(json.dumps(all_metrics,indent=2));print('Hasil tersimpan:',output)

if __name__=='__main__':main()
