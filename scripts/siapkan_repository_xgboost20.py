"""Assemble a portable publication copy, retaining the active URL20 v2 package."""
import csv
import gzip
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SOURCE = Path(r'D:\experimen terakhir')
DESTINATION = Path(r'D:\heurishield-xgboost20')
SECRET_QUERY = re.compile(r'^(?:code|state|access_token|refresh_token|id_token|token|secret|nonce|api_key|apikey|password|pass|otp|session|ticket|credential|client_secret)$', re.I)
EMAIL = re.compile(r'(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])')
URL = re.compile(r'https?://[^\s<>"\\]+')
changes = []


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def sanitize_string(value):
    def sanitize_url(match):
        text = match.group()
        try:
            parsed = urlsplit(text)
            query = [(key, 'REDACTED' if SECRET_QUERY.fullmatch(key) else val)
                     for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
            if query == parse_qsl(parsed.query, keep_blank_values=True) and not parsed.username:
                return text
            host = parsed.hostname or ''
            authority = host + (f':{parsed.port}' if parsed.port else '')
            return urlunsplit((parsed.scheme, authority, parsed.path, urlencode(query), parsed.fragment))
        except ValueError:
            return text
    return EMAIL.sub('redacted@example.invalid', URL.sub(sanitize_url, value))


def sanitize(value):
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize(item) for key, item in value.items()}
    return value


def copy_file(source, destination, redact=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    before_hash = digest(source)
    if redact and source.suffix in ('.json', '.jsonl', '.csv'):
        if source.suffix == '.json':
            original = json.loads(source.read_text(encoding='utf-8-sig'))
            cleaned = sanitize(original)
            destination.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
        elif source.suffix == '.jsonl':
            with source.open(encoding='utf-8-sig') as source_stream, destination.open('w', encoding='utf-8') as target:
                for line in source_stream:
                    if line.strip():
                        target.write(json.dumps(sanitize(json.loads(line)), ensure_ascii=False)+'\n')
        else:
            with source.open(encoding='utf-8-sig', newline='') as source_stream, destination.open('w', encoding='utf-8', newline='') as target:
                reader = csv.DictReader(source_stream)
                writer = csv.DictWriter(target, fieldnames=reader.fieldnames)
                writer.writeheader()
                for row in reader:
                    writer.writerow({key: sanitize_string(value) if isinstance(value, str) else value for key, value in row.items()})
    else:
        shutil.copy2(source, destination)
    changes.append({'repository_path': destination.relative_to(DESTINATION).as_posix(),
                    'source_sha256': before_hash, 'published_sha256': digest(destination),
                    'redaction_applied': redact})


def copy_tree(source, destination, redact=False):
    for file in sorted(source.rglob('*')):
        if file.is_file() and not set(file.parts) & {'.git', '__pycache__', 'node_modules'} and file.suffix not in ('.pyc', '.sqlite', '.db', '.partial'):
            copy_file(file, destination/file.relative_to(source), redact)


def main():
    if DESTINATION.exists():
        raise FileExistsError(DESTINATION)
    DESTINATION.mkdir()
    copy_tree(SOURCE/'extension', DESTINATION/'extension')
    copy_tree(SOURCE/'data', DESTINATION/'data')
    copy_tree(SOURCE/'perbaikan_v2', DESTINATION/'experiments/v2')
    for file in (SOURCE/'reports').iterdir():
        if file.is_file():
            copy_file(file, DESTINATION/'reports/baseline'/file.name)
        elif file.is_dir():
            copy_tree(file, DESTINATION/'reports/data_preparation'/file.name)
    copy_tree(SOURCE/'hasil_live', DESTINATION/'testing/live', redact=True)
    copy_tree(SOURCE/'scripts', DESTINATION/'scripts')
    # Include the two original labelled supplementary sources used by v2.
    for name in ['URL dataset.csv', 'url_features_extracted1.csv']:
        copy_file(Path(r'C:\Users\USER\Downloads')/name, DESTINATION/'data/raw/supplementary_sources'/name)
    copy_file(SOURCE/'HASIL_EKSPERIMEN.md', DESTINATION/'reports/baseline/HASIL_EKSPERIMEN.md')
    # Preserve runnable path contracts for the organized clone.
    for file in (DESTINATION/'scripts').glob('*'):
        if file.suffix not in ('.py', '.ps1', '.mjs'):
            continue
        text = file.read_text(encoding='utf-8')
        text = text.replace('experiments/v2/', 'experiments/v2/').replace('experiments\v2\\', 'experiments\\v2\\')
        text = text.replace("ROOT / 'experiments/v2'", "ROOT / 'experiments/v2'")
        text = text.replace("R=ROOT/'reports/baseline'", "R=ROOT/'reports/baseline'")
        text = text.replace("R=ROOT/'reports/baseline'", "R=ROOT/'reports/baseline'")
        text = text.replace("ROOT / 'reports/baseline/training_results.json'", "ROOT / 'reports/baseline/training_results.json'")
        text = text.replace("ROOT / 'reports/baseline/XGBoost_archive_predictions.csv'", "ROOT / 'reports/baseline/XGBoost_archive_predictions.csv'")
        text = text.replace("ROOT / 'reports/baseline' /", "ROOT / 'reports/baseline' /")
        text = text.replace("ROOT / 'reports/data_preparation/legitimate500_dual_06nov2026'", "ROOT / 'reports/data_preparation/legitimate500_dual_06nov2026'")
        text = text.replace("ROOT / 'data/", "ROOT / 'data/")
        text = text.replace("out = ROOT/'reports/baseline'", "out = ROOT/'reports/baseline'")
        # Replace the old machine-specific extension location in the comparison launchers.
        text = text.replace("'D:\\experimen skripsi\\extension\\HeuriShield-URL17-XGBoost'", "(Join-Path $projectRoot 'comparators\\HeuriShield-URL17-XGBoost')") if file.suffix == '.ps1' else text
        text = text.replace("'hasil_live\\'", "'testing\\live\\'")
        file.write_text(text, encoding='utf-8')
    # Store only v2 models. The baseline is retained as reports and predictions.
    # Comparator package makes the saved comparison launchers portable.
    copy_tree(Path(r'D:\experimen skripsi\extension\HeuriShield-URL17-XGBoost'),
              DESTINATION/'comparators/HeuriShield-URL17-XGBoost')
    # Rebuild history from the redacted live evidence instead of uploading local SQLite files.
    sys.path.insert(0, str(DESTINATION/'scripts'))
    from analysis_history_db import import_report
    history_results = []
    for folder in sorted((DESTINATION/'testing/live').iterdir()):
        if (folder/'browser_live_analysis.json').exists():
            model_name = 'url20' if folder.name.startswith('url20') else 'url17'
            run_id, count = import_report(DESTINATION/f'testing/history/history_{model_name}.sqlite', folder)
            history_results.append({'run': folder.name, 'records': count})
    # Compress data rather than depending on Git LFS quotas. Original content hashes are retained.
    compressed = []
    for file in sorted(DESTINATION.rglob('*')):
        if not file.is_file() or file.suffix not in ('.csv', '.sqlite') or file.stat().st_size < 8*1024*1024:
            continue
        output = file.with_name(file.name+'.gz')
        with file.open('rb') as stream, output.open('wb') as target:
            with gzip.GzipFile(fileobj=target, mode='wb', mtime=0) as packed:
                shutil.copyfileobj(stream, packed)
        compressed.append({'path': output.relative_to(DESTINATION).as_posix(), 'unpacked_path': file.relative_to(DESTINATION).as_posix(),
                           'unpacked_sha256': digest(file), 'packed_sha256': digest(output),
                           'unpacked_bytes': file.stat().st_size, 'packed_bytes': output.stat().st_size})
        file.unlink()
    manifest = {'source_project': str(SOURCE), 'active_extension': 'extension/HeuriShield-URL20-XGBoost',
                'active_model_directory': 'experiments/v2/models', 'version': '0.4.0', 'live_threshold': .5,
                'training_cv_threshold': .41, 'history_rebuilt_from_redacted_evidence': history_results,
                'file_provenance': changes, 'compressed_files': compressed,
                'notes': ['Large CSV/SQLite files are stored as gzip. Use scripts/prepare_workspace.py before running analyses.',
                          'Live evidence has email addresses and sensitive query values redacted. Numeric feature vectors, scores and verdicts are preserved.',
                          'Training datasets retain original URL strings and features for reproducibility.',
                          'Original source paths in historic reports are provenance, not required runtime paths.']}
    (DESTINATION/'publication_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'repository': str(DESTINATION), 'compressed_files': len(compressed), 'history_runs': history_results,
                      'files': sum(p.is_file() for p in DESTINATION.rglob('*')),
                      'size_mb': round(sum(p.stat().st_size for p in DESTINATION.rglob('*') if p.is_file())/1024**2, 1)}, indent=2))


if __name__ == '__main__':
    main()
