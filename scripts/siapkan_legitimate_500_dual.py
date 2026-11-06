"""Prepare 500 source-backed, unseen-domain URLs without extension/model scoring."""
import asyncio
import csv
import importlib.util
import json
import random
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
AUDIT = ROOT / 'reports/data_preparation/legitimate500_dual_06nov2026'
OUTPUT = ROOT / 'data/evaluation/legitimate_fresh_500_dual_06nov2026.txt'
spec = importlib.util.spec_from_file_location('legitimate_source_helper', ROOT / 'scripts/legitimate_source_helper.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.AUDIT = AUDIT
helper.RNG = random.Random(20261106500)
helper.QUOTAS = {'government': 60, 'education': 100, 'company': 150, 'healthcare': 90, 'nonprofit': 100}


def exclusions():
    cached = ROOT / 'data/raw/legitimate_source_registry/excluded_domains.txt'
    seen = set(cached.read_text(encoding='utf-8').splitlines())
    sources = [{'path': str(cached), 'type': 'prior_domain_audit'}]
    csv_files = {ROOT / 'data/processed/phreshphish_url20_all_clean.csv',
                 ROOT / 'experiments/v2/data/url20_augmented_splits.csv',
                 ROOT / 'data/evaluation/live_url20.csv'}
    for directory in [ROOT / 'testing/live']:
        csv_files.update(directory.rglob('browser_live_rows*.csv'))
    for path in sorted(csv_files):
        if not path.is_file():
            continue
        count = 0
        with path.open(encoding='utf-8-sig', errors='replace', newline='') as stream:
            reader = csv.DictReader(stream)
            keys = [k for k in reader.fieldnames or [] if k.lower() in helper.CSV_KEYS or k == 'site_key']
            for row in reader:
                for key in keys:
                    if row.get(key):
                        site = helper.site(row[key])
                        if site:
                            seen.add(site)
                count += 1
        sources.append({'path': str(path), 'rows': count})
    text_files = set(Path(r'C:\Users\USER\Downloads').glob('*legitimate*.txt'))
    text_files.update(Path(r'D:\experimen skripsi\data\evaluation').glob('*legitimate*.txt'))
    for path in sorted(text_files):
        if path.name == OUTPUT.name:
            continue
        for match in re.finditer(r'https?://[^\s<>"\]]+', path.read_text(encoding='utf-8-sig', errors='replace')):
            site = helper.site(match.group())
            if site:
                seen.add(site)
        sources.append({'path': str(path), 'type': 'previous_prepared_list'})
    (AUDIT / 'exclusion_sources.json').write_text(json.dumps(sources, indent=2), encoding='utf-8')
    print(json.dumps({'excluded_domains': len(seen), 'source_files': len(sources)}), flush=True)
    return seen


def main():
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    AUDIT.mkdir(parents=True, exist_ok=True)
    seen = exclusions()
    original_seen = seen.copy()
    groups = asyncio.run(helper.pools(seen))
    selected, checked = asyncio.run(helper.collect(groups, seen))
    helper.RNG.shuffle(selected)
    assert len(selected) == 500
    assert len({row['site_key'] for row in selected}) == 500
    assert not {row['site_key'] for row in selected} & original_seen
    assert all(row['http_status'] == 200 for row in selected)
    OUTPUT.write_text('\n'.join(row['url'] for row in selected)+'\n', encoding='utf-8')
    (AUDIT / 'audit_500.json').write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding='utf-8')
    summary = {'prepared': 500, 'unique_domains': 500, 'domain_overlap_with_audited_sources': 0,
               'checked_candidates': checked, 'groups': dict(Counter(row['group'] for row in selected)),
               'page_types': dict(Counter(row['page_type'] for row in selected)),
               'countries': dict(Counter(row['country'] for row in selected)),
               'urls_with_query': sum(bool(urlsplit(row['url']).query) for row in selected),
               'urls_with_subdomain': sum(bool(helper.PARSER(urlsplit(row['url']).hostname).subdomain) for row in selected),
               'urls_with_path': sum(bool(urlsplit(row['url']).path.strip('/')) for row in selected),
               'public_suffixes': dict(Counter(helper.PARSER(urlsplit(row['url']).hostname).suffix for row in selected)),
               'output': str(OUTPUT), 'model_predictions_used_for_selection': False,
               'limitations': ['HTTP 200 HTML at collection time does not guarantee later extension coverage.',
                               'Sector quotas and CISA/ROR registries define a purposive organization sample, not a natural browsing population.',
                               'Label provenance is an official organization link; absence of compromise is not independently certified.',
                               'Novelty checked against available local dataset, prepared-list and live-report files.']}
    (AUDIT / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
