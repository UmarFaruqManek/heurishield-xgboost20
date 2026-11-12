import json, subprocess, copy, sys, collections
from pathlib import Path
ROOT = Path(r'D:/heurishield-xgboost20'); EXT = ROOT/'extension/HeuriShield-URL20-XGBoost'; S = Path(sys.argv[1])
runs = ['url20_v062_phishing_20261111_012825', 'url20_v062_legitimate_20261111_012427']
records = []
for run in runs:
    for x in json.loads((ROOT/'testing/live'/run/'browser_live_analysis.json').read_text(encoding='utf-8'))['records']:
        records.append(dict(index=x.get('index'), url=x.get('input_url'), expected_label=x.get('actual_label'),
                            analysis_status=x.get('analysis_status'), old_verdict=x.get('observed_verdict'), analysis=x.get('analysis')))
urls = [(r['analysis'] or {}).get('original_url') or r['url'] for r in records]
models = {'v2': str(S/'xgboost-url20-v2.json'), 'v3': str(EXT/'src/model/xgboost-url20.json')}
cls = json.loads(subprocess.run(['node', str(S/'url_class.mjs')], input=json.dumps({'models': models, 'urls': urls}).encode(), capture_output=True, check=True).stdout)
result = {}
for name in models:
    recs = copy.deepcopy(records)
    for r, v in zip(recs, cls[name]):
        if r['analysis'] and (r['analysis'].get('model_result') or {}).get('ready') and v:
            r['analysis']['model_result']['verdict'] = v
    p = subprocess.run(['node', str(EXT/'tools/replay-decisions.mjs')], input=json.dumps({'records': recs}).encode(), capture_output=True, check=True)
    result[name] = json.loads(p.stdout)['records']
def metrics(rows, key):
    c = collections.Counter()
    for r in rows:
        if r['new_verdict'] is None: continue
        lab = 'phishing' if r['expected_label'] in ('phishing', 'phish') else 'legitimate'
        c[(lab, r[key])] += 1
    tp, fn, tn, fp = c['phishing','DANGEROUS'], c['phishing','SAFE'], c['legitimate','SAFE'], c['legitimate','DANGEROUS']
    n = tp+fn+tn+fp
    return dict(n=n, TP=tp, FN=fn, TN=tn, FP=fp, accuracy=round(100*(tp+tn)/n,2), recall=round(100*tp/(tp+fn),2),
                specificity=round(100*tn/(tn+fp),2), precision=round(100*tp/(tp+fp),2), f1=round(100*2*tp/(2*tp+fp+fn),2))
summary = {}
for name, rows in result.items():
    summary[name] = {'url_only': metrics(rows, 'url_model_verdict'), 'pipeline': metrics(rows, 'new_verdict'),
                     'not_replayable': sum(r['new_verdict'] is None for r in rows),
                     'policy_source': dict(collections.Counter(r.get('new_source') for r in rows if r['new_verdict'])),
                     'matched_rules': dict(collections.Counter(x for r in rows for x in r.get('matched_rules', [])))}
# per-URL differences between v2 and v3 pipeline verdicts
diff = []
for a, b in zip(result['v2'], result['v3']):
    if a['new_verdict'] != b['new_verdict']:
        diff.append(dict(label=a['expected_label'], url=a['url'], url_v2=a['url_model_verdict'], url_v3=b['url_model_verdict'],
                         final_v2=a['new_verdict'], final_v3=b['new_verdict'], rules=b.get('matched_rules')))
summary['pipeline_verdict_changes_v2_to_v3'] = len(diff)
(S/'replay_v2_v3.json').write_text(json.dumps({'summary': summary, 'changes': diff, 'v2': result['v2'], 'v3': result['v3']}, ensure_ascii=False, indent=1), encoding='utf-8')
print(json.dumps(summary, indent=1))
for d in diff: print(d['label'][:5], d['final_v2'], '->', d['final_v3'], d['url'][:90])
