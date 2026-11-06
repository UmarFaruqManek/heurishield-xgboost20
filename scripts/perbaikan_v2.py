"""Enrich URL20 data, control domains/families, train-only grouped CV, five models."""

import csv
import gc
import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight

from eksperimen_phreshphish import FEATURES, ROOT, SEED, domain, extract, metrics, models

OUT = ROOT / 'experiments/v2'
REPORTS = OUT / 'reports'
DATA = OUT / 'data'


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding='utf-8')


def stable_number(text):
    return int.from_bytes(hashlib.sha256(f'{SEED}|{text}'.encode()).digest()[:8], 'big')


def endpoint_family(url, site):
    parsed = urlsplit(url)
    path = re.sub(r'[0-9a-f]{16,}', '{id}', parsed.path.lower())
    path = re.sub(r'[0-9]+', '{n}', path)
    keys = sorted(set(key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)))
    return f"{site}|{path}|{'&'.join(keys)}"


def archive_error_audit(live):
    baseline = pd.read_csv(ROOT / 'reports/baseline/XGBoost_archive_predictions.csv')
    rows = live.merge(baseline[['url', 'probability_phishing', 'prediction', 'correct']], on='url', validate='one_to_one')
    metadata = {}
    for path in rows.source_file.unique():
        file = Path(path)
        if not file.exists():
            continue
        try:
            records = json.loads(file.read_text(encoding='utf-8')).get('records', [])
        except (ValueError, OSError):
            continue
        for record in records:
            url = record.get('input_url')
            if url:
                metadata[(path, url)] = record
    details = []
    for row in rows[~rows.correct].to_dict('records'):
        record = metadata.get((row['source_file'], row['url']), {})
        final_url = record.get('browser_final_url') or ''
        final_site = ''
        try:
            final_site = domain(urlsplit(final_url).hostname or '')
        except ValueError:
            pass
        title = str(record.get('page_title') or '')
        review_flags = []
        if row['original_status'] != 'completed':
            review_flags.append('historical_analysis_incomplete')
        if final_site and final_site != row['site_key']:
            review_flags.append('final_site_changed')
        if re.search(r'not found|404|broken.link|captcha|access denied|just a moment|demo|example page', title, re.I):
            review_flags.append('title_requires_label_review')
        patterns = []
        if row['query_length'] > 0:
            patterns.append('query_present')
        if row['has_https_scheme']:
            patterns.append('https')
        if row['hostname_length'] <= 20:
            patterns.append('hostname_20_or_less')
        if row['path_depth'] == 0:
            patterns.append('root_path')
        if row['path_length'] >= 25:
            patterns.append('path_25_or_more')
        details.append({'url': row['url'], 'label': row['label'], 'site_key': row['site_key'],
                        'probability_phishing': row['probability_phishing'], 'patterns': '|'.join(patterns),
                        'review_flags': '|'.join(review_flags), 'page_title': title, 'final_url': final_url,
                        'historical_status': row['original_status']})
    frame = pd.DataFrame(details)
    frame.to_csv(REPORTS / 'baseline_errors_with_evidence.csv', index=False)
    summary = {}
    for label in ['legitimate', 'phishing']:
        subset = frame[frame.label == label]
        summary[label] = {'incorrect_rows': len(subset),
                          'pattern_counts_nonexclusive': dict(Counter(token for value in subset.patterns for token in value.split('|') if token)),
                          'review_flag_counts_nonexclusive': dict(Counter(token for value in subset.review_flags for token in value.split('|') if token))}
    write_json(REPORTS / 'baseline_error_audit.json', summary)


def prepare():
    base = pd.read_csv(ROOT / 'data/processed/url20_train_test.csv', dtype={f: 'float32' for f in FEATURES})
    live = pd.read_csv(ROOT / 'data/evaluation/live_url20.csv', dtype={f: 'float32' for f in FEATURES})
    archive_error_audit(live)
    existing = pd.read_csv(ROOT / 'data/processed/phreshphish_url20_all_clean.csv', usecols=['url', 'label'])
    known = dict(zip(existing.url, existing.label))
    baseline_test_domains = set(base.loc[base.split == 'test', 'site_key'])
    baseline_train_domains = set(base.loc[base.split == 'train', 'site_key'])
    reserved_domains = set(live.site_key) | baseline_test_domains
    live_urls = set(live.url)
    candidates = {}
    conflicts = set()
    counts = Counter()
    sources = [
        (ROOT / 'data/raw/supplementary_sources/URL dataset.csv', 'url', 'type', {'legitimate': 'legitimate', 'phishing': 'phishing'}),
        (ROOT / 'data/raw/supplementary_sources/url_features_extracted1.csv', 'URL', 'ClassLabel', {'1': 'legitimate', '0': 'phishing'}),
    ]
    source_info = []
    for source, url_column, label_column, mapping in sources:
        source_info.append({'path': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'label_mapping': mapping})
        with source.open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                counts['source_rows_read'] += 1
                url = str(row.get(url_column) or '').strip()
                label = mapping.get(str(row.get(label_column) or '').strip())
                if not label:
                    counts['unknown_label'] += 1
                    continue
                try:
                    parsed = urlsplit(url)
                    # Add naturally observed query-bearing legitimate and diverse source-labelled phishing.
                    if label == 'legitimate' and not parsed.query:
                        counts['legitimate_without_query_not_selected'] += 1
                        continue
                    feature_values, site = extract(url)
                except (ValueError, TypeError, UnicodeError):
                    counts['invalid_source_url'] += 1
                    continue
                if site in reserved_domains or url in live_urls:
                    counts['reserved_domain_or_archive_url'] += 1
                    continue
                if re.search(r'heurishield|heurisield|(?:[?&])sample=', url, re.I):
                    counts['prior_generated_test_marker'] += 1
                    continue
                if url in known:
                    counts['already_in_phreshphish'] += 1
                    if known[url] != label:
                        counts['label_conflict_with_phreshphish'] += 1
                    continue
                if url in candidates:
                    if candidates[url]['label'] != label:
                        conflicts.add(url)
                    counts['duplicate_supplement_url'] += 1
                    continue
                if label == 'phishing' and not (feature_values['has_https_scheme'] or feature_values['hostname_length'] <= 20 or feature_values['path_length'] >= 25):
                    counts['phishing_outside_requested_patterns'] += 1
                    continue
                split = 'train' if site in baseline_train_domains or stable_number(site) % 10 != 0 else 'supplement_test'
                candidates[url] = {'url': url, 'label': label, 'site_key': site, 'split': split,
                                   'source': source.name, **feature_values}
    selected = []
    domain_counts = Counter()
    family_counts = Counter()
    class_counts = Counter()
    for url in sorted(candidates, key=stable_number):
        if url in conflicts:
            counts['supplement_conflicting_url_removed'] += 1
            continue
        row = candidates[url]
        family = endpoint_family(url, row['site_key'])
        if domain_counts[row['site_key']] >= 20 or family_counts[family] >= 5:
            counts['supplement_domain_family_cap'] += 1
            continue
        if class_counts[row['label']] >= 45000:
            counts['supplement_class_cap'] += 1
            continue
        domain_counts[row['site_key']] += 1
        family_counts[family] += 1
        class_counts[row['label']] += 1
        selected.append(row)
    supplement = pd.DataFrame(selected)
    assert not set(supplement.site_key) & reserved_domains
    supplement.to_csv(DATA / 'supplement_url20_with_provenance.csv', index=False)
    # Keep the same original holdout and add a separately reported holdout for new sources.
    base['source'] = 'PhreshPhish'
    full = pd.concat([base, supplement], ignore_index=True)
    full['endpoint_family'] = [endpoint_family(u, d) for u, d in zip(full.url, full.site_key)]
    full.to_csv(DATA / 'url20_augmented_splits.csv', index=False)
    train_domains = set(full.loc[full.split == 'train', 'site_key'])
    test_domains = set(full.loc[full.split != 'train', 'site_key'])
    assert not train_domains & test_domains
    assert not set(full.site_key) & set(live.site_key)
    assert len(full.loc[full.split == 'test']) == 59286
    summary = {'source_files': source_info, 'source_filter_counts': dict(counts),
               'supplement_rows': len(supplement), 'supplement_label_counts': supplement.label.value_counts().to_dict(),
               'supplement_domains': supplement.site_key.nunique(),
               'supplement_by_split_label': supplement.groupby(['split', 'label']).size().to_dict(),
               'full_rows': len(full), 'split_counts': full.split.value_counts().to_dict(),
               'train_labels': full.loc[full.split == 'train', 'label'].value_counts().to_dict(),
               'train_query_counts': full.loc[(full.split == 'train') & full.query_length.gt(0), 'label'].value_counts().to_dict(),
               'train_test_domain_overlap': 0, 'training_archive_domain_overlap': 0,
               'notes': ['Supplement uses historical source labels. Page contents and collection times are not reverified.',
                         'PhreshPhish label conflicts are excluded from supplementary selection.',
                         'Supplements are naturally occurring URLs. No query/path is synthesized.',
                         'Original 59286-row test unchanged. New domains from supplementary sources receive approximately 90/10 allocation.',
                         'The historical archive has influenced earlier development and is reported as development replay.']}
    summary['supplement_by_split_label'] = {f'{s}|{l}': n for (s, l), n in summary['supplement_by_split_label'].items()}
    write_json(REPORTS / 'data_preparation.json', summary)
    print('DATA', json.dumps(summary, default=str), flush=True)
    del existing, candidates, selected, base
    gc.collect()
    return full, live


def training_weights(frame, y):
    domain_size = frame.groupby('site_key').url.transform('size').to_numpy(dtype=float)
    family_size = frame.groupby('endpoint_family').url.transform('size').to_numpy(dtype=float)
    # Soft caps: large domain/family collections contribute less per record.
    weight = 1 / np.sqrt(np.maximum(domain_size / 20, 1))
    weight *= 1 / np.sqrt(np.maximum(family_size / 5, 1))
    for label in [0, 1]:
        mask = y == label
        weight[mask] *= len(y) / (2 * weight[mask].sum())
    return weight


def select_threshold(y, probability):
    trials = []
    for threshold in np.arange(.15, .851, .01):
        tn, fp, fn, tp = confusion_matrix(y, probability >= threshold, labels=[0, 1]).ravel()
        specificity = tn / (tn + fp)
        recall = tp / (tp + fn)
        trials.append((min(specificity, recall), (specificity + recall) / 2,
                       -abs(threshold - .5), float(threshold), specificity, recall))
    chosen = max(trials)
    return {'threshold': round(chosen[3], 2), 'min_class_correct_percent': 100 * chosen[0],
            'balanced_accuracy_percent': 100 * chosen[1],
            'legitimate_correct_percent': 100 * chosen[4], 'phishing_recall_percent': 100 * chosen[5]}


def evaluate(y, probability, threshold):
    result = metrics(y, probability)
    tn, fp, fn, tp = confusion_matrix(y, probability >= threshold, labels=[0, 1]).ravel()
    result.update({'threshold': threshold, 'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
                   'accuracy_percent': round(100 * (tn + tp) / len(y), 3),
                   'legitimate_correct_percent': round(100 * tn / (tn + fp), 3),
                   'phishing_recall_percent': round(100 * tp / (tp + fn), 3)})
    # Precision/F1 must use the selected threshold as well.
    result['precision_percent'] = round(100 * tp / max(tp + fp, 1), 3)
    result['f1_percent'] = round(200 * tp / max(2 * tp + fp + fn, 1), 3)
    return result


def fit(model, name, features, labels, weights):
    if name == 'LogisticRegression':
        model.fit(features, labels, logisticregression__sample_weight=weights)
    else:
        model.fit(features, labels, sample_weight=weights)


def model_candidates(name, make):
    default = make()
    if name == 'XGBoost':
        changes = [dict(n_estimators=400, max_depth=5, min_child_weight=10, reg_lambda=3),
                   dict(n_estimators=500, max_depth=7, min_child_weight=12, reg_lambda=5, reg_alpha=.1)]
    elif name == 'RandomForest':
        changes = [dict(n_estimators=100, max_depth=18, min_samples_leaf=8),
                   dict(n_estimators=100, max_depth=24, min_samples_leaf=4)]
    elif name == 'ExtraTrees':
        changes = [dict(n_estimators=100, max_depth=20, min_samples_leaf=5),
                   dict(n_estimators=100, max_depth=26, min_samples_leaf=3)]
    elif name == 'HistGradientBoosting':
        changes = [dict(max_iter=220, max_leaf_nodes=31, l2_regularization=3),
                   dict(max_iter=280, max_leaf_nodes=63, l2_regularization=5)]
    else:
        changes = [dict(logisticregression__C=.1), dict(logisticregression__C=3)]
    del default
    return changes


def main():
    start = time.time()
    full, live = prepare()
    train = full.loc[full.split == 'train'].reset_index(drop=True)
    # Deterministic domain sample bounds CV cost; all final models use full train.
    selected_domains = sorted(train.site_key.unique(), key=stable_number)
    cv_indices = []
    by_domain = train.groupby('site_key', sort=False).indices
    for site in selected_domains:
        cv_indices.extend(by_domain[site])
        if len(cv_indices) >= 100000:
            break
    cv_frame = train.iloc[cv_indices].reset_index(drop=True)
    cv_frame[['url', 'label', 'site_key']].to_csv(DATA / 'cv_train_only_sample.csv', index=False)
    Xcv = cv_frame[FEATURES].to_numpy(dtype=np.float32)
    ycv = cv_frame.label.eq('phishing').to_numpy(dtype=np.int8)
    folds = list(StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED).split(Xcv, ycv, cv_frame.site_key))
    for tr, va in folds:
        assert not set(cv_frame.iloc[tr].site_key) & set(cv_frame.iloc[va].site_key)
    cv_audit = {'rows': len(cv_frame), 'domains': cv_frame.site_key.nunique(),
                'label_counts': cv_frame.label.value_counts().to_dict(),
                'query_by_label': cv_frame.loc[cv_frame.query_length.gt(0), 'label'].value_counts().to_dict(),
                'folds': 3, 'candidates_per_model': 2, 'only_original_training_and_supplement_training': True,
                'domain_overlap_with_test_or_archive': 0}
    write_json(REPORTS / 'cross_validation_design.json', cv_audit)
    print('CV DESIGN', json.dumps(cv_audit), flush=True)
    results = {}
    comparisons = []
    baseline_results = json.loads((ROOT / 'reports/baseline/training_results.json').read_text())['models']
    Xtrain = train[FEATURES].to_numpy(dtype=np.float32)
    ytrain = train.label.eq('phishing').to_numpy(dtype=np.int8)
    weights = training_weights(train, ytrain)
    weight_report = train[['url', 'label', 'site_key', 'endpoint_family']].copy()
    weight_report['sample_weight'] = weights
    weight_report.to_csv(DATA / 'training_weights.csv', index=False)
    for name, make in models():
        trials = []
        for candidate_index, parameters in enumerate(model_candidates(name, make)):
            out_of_fold = np.zeros(len(ycv), dtype=np.float32)
            for fold_index, (tr, va) in enumerate(folds):
                estimator = make().set_params(**parameters)
                fold_weights = training_weights(cv_frame.iloc[tr], ycv[tr])
                print(f'CV {name} candidate {candidate_index+1}/2 fold {fold_index+1}/3', flush=True)
                fit(estimator, name, Xcv[tr], ycv[tr], fold_weights)
                out_of_fold[va] = estimator.predict_proba(Xcv[va])[:, 1]
                del estimator
                gc.collect()
            trial = {'parameters': parameters, 'cv': select_threshold(ycv, out_of_fold)}
            trials.append(trial)
        best = max(trials, key=lambda item: (item['cv']['min_class_correct_percent'], item['cv']['balanced_accuracy_percent']))
        threshold = best['cv']['threshold']
        write_json(REPORTS / f'{name}_cv_selection.json', {'trials': trials, 'selected': best})
        print('FINAL TRAIN', name, len(train), 'threshold', threshold, flush=True)
        model = make().set_params(**best['parameters'])
        fit(model, name, Xtrain, ytrain, weights)
        pack = {'model': model, 'features': FEATURES, 'threshold': threshold, 'label_mapping': {'legitimate': 0, 'phishing': 1}}
        path = OUT / 'models' / f'{name}.joblib'
        joblib.dump(pack, path, compress=3)
        if name == 'XGBoost':
            model.save_model(OUT / 'models/XGBoost.json')
        scopes = {'original_test': full[full.split == 'test'],
                  'supplement_test': full[full.split == 'supplement_test'],
                  'combined_test': full[full.split != 'train'],
                  'archive_all': live,
                  'archive_previously_completed': live[live.original_status == 'completed']}
        model_result = {'selected_parameters': best['parameters'], 'selected_threshold': threshold, 'cv_selection': best['cv']}
        for scope, frame in scopes.items():
            features = frame[FEATURES].to_numpy(dtype=np.float32)
            labels = frame.label.eq('phishing').to_numpy(dtype=np.int8)
            probability = model.predict_proba(features)[:, 1]
            model_result[scope] = evaluate(labels, probability, threshold)
            model_result[f'{scope}_at_05'] = evaluate(labels, probability, .5)
            predictions = frame[['url', 'label', 'site_key']].copy()
            predictions['probability_phishing'] = probability
            predictions['threshold'] = threshold
            predictions['prediction'] = np.where(probability >= threshold, 'phishing', 'legitimate')
            predictions['correct'] = (probability >= threshold) == labels
            predictions.to_csv(REPORTS / f'{name}_{scope}_predictions.csv', index=False)
            comparisons.append({'model': name, 'scope': scope, **model_result[scope]})
        model_result['baseline_original_test'] = baseline_results[name]['test']
        model_result['baseline_archive_all'] = baseline_results[name]['historical_archive_all_url_text']
        # Verify a serialized model through its ordinary predict_proba entry point.
        saved = joblib.load(path)
        check = live[FEATURES].iloc[:64].to_numpy(dtype=np.float32)
        delta = float(np.max(np.abs(saved['model'].predict_proba(check) - model.predict_proba(check))))
        assert delta < 1e-7
        model_result['saved_model_verification_max_delta'] = delta
        del saved
        if name == 'XGBoost':
            import xgboost
            heldout = scopes['original_test']
            sample = heldout.sample(n=min(10000, len(heldout)), random_state=SEED)
            contributions = model.get_booster().predict(xgboost.DMatrix(sample[FEATURES].to_numpy(dtype=np.float32)), pred_contribs=True)
            absolute_mean = np.abs(contributions[:, :20]).mean(axis=0)
            table = pd.DataFrame({'feature': FEATURES, 'shap_share_percent': 100 * absolute_mean / absolute_mean.sum()})
            table.sort_values('shap_share_percent', ascending=False).to_csv(REPORTS / 'xgboost_feature_influence_20.csv', index=False)
        results[name] = model_result
        pd.DataFrame(comparisons).to_csv(REPORTS / 'model_comparison.csv', index=False)
        write_json(REPORTS / 'results.json', {'models': results, 'cv_design': cv_audit,
                                            'elapsed_seconds': time.time()-start,
                                            'threshold_selection': 'Training-only domain-grouped out-of-fold predictions',
                                            'weights': 'Class-balanced with soft domain cap 20 and endpoint-family cap 5'})
        print('RESULT', name, json.dumps({'test': model_result['original_test'], 'archive': model_result['archive_all']}), flush=True)
        del model, scopes, pack
        gc.collect()
    print('DONE', round(time.time()-start), 'seconds', flush=True)


if __name__ == '__main__':
    main()
