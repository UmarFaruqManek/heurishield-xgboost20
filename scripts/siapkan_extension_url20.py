"""Package the trained URL20 v2 XGBoost with an explicit live threshold of 0.50."""
import hashlib
import json
import math
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / 'extension/HeuriShield-URL20-XGBoost'
MODEL_SOURCE = ROOT / 'experiments/v2/models/XGBoost.joblib'


def main():
    pack = joblib.load(MODEL_SOURCE)
    raw = json.loads(pack['model'].get_booster().save_raw(raw_format='json'))['learner']
    names = pack['features']
    assert len(names) == 20
    base = raw['learner_model_param']['base_score']
    probability = float(json.loads(base)[0]) if base.startswith('[') else float(base)
    trees = []
    for tree in raw['gradient_booster']['model']['trees']:
        assert not any(tree['split_type']), 'Only numerical tree splits are supported'
        trees.append({'left': tree['left_children'], 'right': tree['right_children'],
                      'default_left': tree['default_left'], 'feature': tree['split_indices'],
                      'threshold_or_leaf': tree['split_conditions']})
    exported = {'model_family': 'XGBoost', 'objective': 'binary:logistic',
                'feature_names': names, 'feature_set': 'url20-phreshphish-v2',
                'threshold': .5, 'training_cv_threshold': pack['threshold'],
                'source_model_sha256': hashlib.sha256(MODEL_SOURCE.read_bytes()).hexdigest(),
                'base_margin': math.log(probability/(1-probability)), 'trees': trees}
    model_file = EXTENSION / 'src/model/xgboost-url20.json'
    model_file.write_text(json.dumps(exported, separators=(',', ':')), encoding='utf-8')
    contract = {'feature_set': exported['feature_set'], 'feature_count': 20, 'features': names,
                'threshold': .5, 'source_model_sha256': exported['source_model_sha256']}
    (EXTENSION / 'src/model/feature-contract-20.json').write_text(json.dumps(contract, indent=2), encoding='utf-8')
    worker = EXTENSION / 'src/background/service-worker.js'
    text = worker.read_text(encoding='utf-8')
    text = text.replace('extractUrl18Features', 'extractUrl20Features').replace('../analyzer/url/url18-features.js', '../analyzer/url/url20-features.js')
    text = text.replace('xgboost-url18.json', 'xgboost-url20.json').replace('feature-contract-18.json', 'feature-contract-20.json')
    text = text.replace('url17-explanation-v7', 'url20-phreshphish-v2-t050').replace('XGBoost URL17', 'XGBoost URL20 v2')
    text = text.replace('mode: "xgboost_url17"', 'mode: "xgboost_url20"')
    text = text.replace('provided_features: 17', 'provided_features: 20').replace('// URL17 reads', '// URL20 reads')
    if 'source_model_sha256: model.source_model_sha256' not in text:
        text = text.replace('threshold: model.threshold, probability_phishing: probability,',
                            'threshold: model.threshold, probability_phishing: probability,\n    source_model_sha256: model.source_model_sha256, feature_set: model.feature_set,')
    worker.write_text(text, encoding='utf-8')
    engine = EXTENSION / 'src/model/xgboost-engine.js'
    engine.write_text(engine.read_text(encoding='utf-8').replace('length !== 17', 'length !== 20'), encoding='utf-8')
    manifest_path = EXTENSION / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest.update(name='HeuriShield URL20 XGBoost v2', version='0.4.0',
                    description='20 URL features, PhreshPhish-enriched XGBoost v2, threshold 0.50, DOM and brand evidence.')
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    package_path = EXTENSION / 'package.json'
    package = json.loads(package_path.read_text(encoding='utf-8'))
    package.update(name='heurishield-url20-xgboost-v2', version='0.4.0')
    package_path.write_text(json.dumps(package, indent=2), encoding='utf-8')
    for path in (EXTENSION / 'tests').glob('*.mjs'):
        text = path.read_text(encoding='utf-8')
        text = text.replace('xgboost-url18.json', 'xgboost-url20.json')
        text = text.replace('import { extractUrl18Features, ageLookupDomain } from "../src/analyzer/url/url18-features.js";',
                            'import { extractUrl20Features as extractUrl18Features, ageLookupDomain } from "../src/analyzer/url/url20-features.js";')
        text = text.replace('import { extractUrl18Features } from "../src/analyzer/url/url18-features.js";',
                            'import { extractUrl20Features as extractUrl18Features } from "../src/analyzer/url/url20-features.js";')
        text = text.replace('"XGBoost URL17"', '"XGBoost URL20 v2"').replace('length !== 17', 'length !== 20')
        path.write_text(text, encoding='utf-8')
    # Old model names are removed from the new package to make its active model unambiguous.
    for name in ['xgboost-url18.json', 'feature-contract-18.json']:
        (EXTENSION / 'src/model' / name).unlink(missing_ok=True)
    (ROOT / 'experiments/v2/reports/extension_package.json').write_text(json.dumps({
        'extension': str(EXTENSION), 'manifest': manifest, 'feature_contract': contract,
        'trees': len(trees), 'export_sha256': hashlib.sha256(model_file.read_bytes()).hexdigest(),
        'threshold_choice': '0.50 fixed comparison threshold explicitly selected for this live package',
        'training_model_threshold': pack['threshold']}, indent=2), encoding='utf-8')
    print('Packaged', len(names), 'features,', len(trees), 'trees, threshold 0.50')


if __name__ == '__main__':
    main()
