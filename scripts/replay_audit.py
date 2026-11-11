"""Replay saved live evidence through the current DOM/brand/rule/policy code.

Usage:
  python scripts/replay_audit.py snapshot OUT.json
  python scripts/replay_audit.py compare BASELINE.json CURRENT.json

No network access: brand/API responses come from the saved lookup_replay data.
The URL-model class is taken from the original live run.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / 'extension/HeuriShield-URL20-XGBoost'
ARCHIVE = ROOT / 'reports/brand_reference_fix_20261108/replay_input.json'


def sources():
    if ARCHIVE.exists():
        yield 'archive', json.loads(ARCHIVE.read_text(encoding='utf-8'))['records']
    for path in sorted((ROOT / 'testing/live').glob('url20*/browser_live_analysis.json')):
        raw = json.loads(path.read_text(encoding='utf-8'))
        yield path.parent.name, [dict(index=x.get('index'), url=x.get('input_url'),
                                      expected_label=x.get('actual_label'),
                                      analysis_status=x.get('analysis_status'),
                                      old_verdict=x.get('observed_verdict'),
                                      analysis=x.get('analysis')) for x in raw['records']]


def replay(records):
    result = subprocess.run(['node', str(EXTENSION / 'tools/replay-decisions.mjs')],
                            input=json.dumps({'records': records}).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return json.loads(result.stdout)['records']


def snapshot(out):
    rows = []
    for name, records in sources():
        for item in replay(records):
            rows.append({'source': name, 'index': item['index'], 'url': item['url'],
                         'label': item['expected_label'], 'replay_level': item['replay_level'],
                         'url_class': item.get('url_model_verdict'),
                         'verdict': item['new_verdict'], 'policy_source': item.get('new_source'),
                         'matched_rules': item.get('matched_rules', []),
                         'parameters': item.get('parameters')})
    Path(out).write_text(json.dumps({'records': rows}, indent=1, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(summary(rows), indent=2))


def summary(rows):
    counts = {}
    for row in rows:
        if row['verdict'] is None:
            continue
        label = 'phishing' if row['label'] in ('phishing', 'phish') else 'legitimate'
        expected = 'DANGEROUS' if label == 'phishing' else 'SAFE'
        c = counts.setdefault(label, {'evaluated': 0, 'correct': 0})
        c['evaluated'] += 1
        c['correct'] += row['verdict'] == expected
    for c in counts.values():
        c['percent'] = round(c['correct'] / c['evaluated'] * 100, 2)
    return {'records': len(rows), 'by_label': counts}


def compare(baseline, current):
    key = lambda r: (r['source'], r['index'], r['url'])
    before = {key(r): r for r in json.loads(Path(baseline).read_text(encoding='utf-8'))['records']}
    after = {key(r): r for r in json.loads(Path(current).read_text(encoding='utf-8'))['records']}
    verdicts = [k for k in before if k in after and before[k]['verdict'] != after[k]['verdict']]
    traces = [k for k in before if k in after and before[k]['matched_rules'] != after[k]['matched_rules']]
    report = {'baseline': summary(list(before.values())), 'current': summary(list(after.values())),
              'missing': len(set(before) ^ set(after)), 'verdict_changes': len(verdicts),
              'trace_changes': len(traces),
              'changed': [{'key': list(k), 'before': before[k]['verdict'], 'after': after[k]['verdict'],
                           'label': after[k]['label']} for k in verdicts]}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


if __name__ == '__main__':
    if sys.argv[1] == 'snapshot':
        snapshot(sys.argv[2])
    elif sys.argv[1] == 'compare':
        compare(sys.argv[2], sys.argv[3])
