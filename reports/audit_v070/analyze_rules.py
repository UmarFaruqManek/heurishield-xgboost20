"""Quantitative audit of the v0.6.2-era rules/policy over the replay baseline.

Usage: python reports/audit_v070/analyze_rules.py [replay.json]
Writes reports/audit_v070/rule_audit.json and prints a compact summary.
Records repeated across archive and live runs are de-duplicated by (url, label),
preferring the most complete replay level.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'replay_baseline.json'
LEVEL_RANK = {'full_snapshot': 3, 'partial_api_snapshot': 2, 'decision_only': 1, 'not_replayable': 0}
PARAMETERS = ['brand_in_title', 'brand_in_heading', 'brand_in_logo', 'claimed_brand_status',
              'host_brand_claim', 'official_domain_match', 'brand_domain_mismatch',
              'has_password_field', 'has_sensitive_input', 'form_cross_domain', 'login_button_detected',
              'login_redirect_detected', 'has_download_link', 'download_target_cross_domain',
              'high_confidence_host_impersonation', 'high_confidence_credential_impersonation',
              'brand_claim_relation']


def label_of(row):
    return 'phishing' if row['label'] in ('phishing', 'phish') else 'legitimate'


def expected(row):
    return 'DANGEROUS' if label_of(row) == 'phishing' else 'SAFE'


def unique_rows(rows):
    best = {}
    for row in rows:
        if row['verdict'] is None:
            continue
        key = (row['url'], label_of(row))
        if key not in best or LEVEL_RANK[row['replay_level']] > LEVEL_RANK[best[key]['replay_level']]:
            best[key] = row
    return list(best.values())


def accuracy(rows, field):
    out = {}
    for label in ('legitimate', 'phishing'):
        subset = [r for r in rows if label_of(r) == label]
        correct = sum(r[field] == expected(r) for r in subset)
        out[label] = {'n': len(subset), 'correct': correct,
                      'percent': round(100 * correct / len(subset), 2) if subset else None}
    return out


def bucket(value):
    if value is None or value == 'unknown':
        return 'unknown'
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def main():
    rows = unique_rows(json.loads(SOURCE.read_text(encoding='utf-8'))['records'])
    for row in rows:
        row['url_only'] = row['url_class']
    report = {'source': SOURCE.name, 'unique_records': len(rows),
              'replay_levels': Counter(r['replay_level'] for r in rows),
              'url_model_only': accuracy(rows, 'url_only'), 'final': accuracy(rows, 'verdict')}

    # Which policy branch produced each verdict, and was it right?
    sources = defaultdict(lambda: Counter())
    for r in rows:
        sources[r['policy_source']][('correct' if r['verdict'] == expected(r) else 'wrong') + '_' + label_of(r)] += 1
    report['policy_sources'] = {k: dict(v) for k, v in sources.items()}

    # Override effect: verdict differs from URL class.
    overrides = Counter()
    for r in rows:
        if r['verdict'] != r['url_class']:
            overrides[(r['url_class'], r['verdict'], 'fixed' if r['verdict'] == expected(r) else 'broke')] += 1
    report['overrides'] = {' -> '.join(k[:2]) + f' ({k[2]})': v for k, v in overrides.items()}

    # Per-rule matched counts by label and by URL class.
    per_rule = defaultdict(Counter)
    for r in rows:
        for rule in r['matched_rules']:
            per_rule[rule][f'{label_of(r)}|url={r["url_class"]}'] += 1
    report['rule_matches'] = {k: dict(sorted(v.items())) for k, v in sorted(per_rule.items())}

    # Parameter distributions per label (only records with a replayed snapshot).
    observed = [r for r in rows if r.get('parameters') and r['replay_level'] in ('full_snapshot', 'partial_api_snapshot')]
    dist = {}
    for name in PARAMETERS:
        table = defaultdict(Counter)
        for r in observed:
            table[label_of(r)][bucket(r['parameters'].get(name))] += 1
        dist[name] = {label: dict(c.most_common()) for label, c in table.items()}
    ages = defaultdict(Counter)
    for r in observed:
        days = r['parameters'].get('domain_age_days')
        cat = 'unknown' if days is None else '<=30' if days <= 30 else '<=365' if days <= 365 else '<=1095' if days <= 1095 else '>1095'
        ages[label_of(r)][cat] += 1
    dist['domain_age_category'] = {k: dict(v) for k, v in ages.items()}
    report['parameter_distribution'] = dist
    report['parameter_records'] = len(observed)

    # Errors that brand/DOM could plausibly explain.
    errors = defaultdict(list)
    for r in rows:
        if r['verdict'] != expected(r):
            kind = 'false_negative' if label_of(r) == 'phishing' else 'false_positive'
            errors[kind].append({'url': r['url'], 'url_class': r['url_class'], 'source': r['policy_source'],
                                 'rules': r['matched_rules'], 'parameters': r.get('parameters')})
    report['errors'] = {k: {'count': len(v), 'examples': v} for k, v in errors.items()}

    (HERE / 'rule_audit.json').write_text(json.dumps(report, indent=1, ensure_ascii=False, default=str), encoding='utf-8')
    compact = {k: v for k, v in report.items() if k not in ('errors', 'parameter_distribution')}
    compact['errors'] = {k: v['count'] for k, v in report['errors'].items()}
    print(json.dumps(compact, indent=1, default=str))


if __name__ == '__main__':
    main()
