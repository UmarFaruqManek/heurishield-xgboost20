"""Read-only verification of the frozen thesis runtime; never rewrites hashes."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]
EXTENSION=ROOT/'extension/HeuriShield-URL20-XGBoost'
CONTRACT=ROOT/'reports/final_audit_20261109/kontrak_final.json'

def main():
    contract=json.loads(CONTRACT.read_text(encoding='utf-8'))
    differences=[]
    for relative,expected in contract['runtime_file_hashes'].items():
        path=EXTENSION/relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            differences.append(relative)
    manifest=json.loads((EXTENSION/'manifest.json').read_text(encoding='utf-8'))
    model=json.loads((EXTENSION/'src/model/xgboost-url20.json').read_text(encoding='utf-8'))
    if manifest['version']!=contract['extension_version']:differences.append('extension_version')
    if model['feature_names']!=contract['features']:differences.append('model_feature_names')
    if model['threshold']!=contract['threshold']:differences.append('model_threshold')
    print(json.dumps({'baseline':contract['baseline'],'unchanged':not differences,
        'runtime_files_checked':len(contract['runtime_file_hashes']),
        'changed_files':differences},indent=2))
    if differences:raise SystemExit(1)

if __name__=='__main__':main()
