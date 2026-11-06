"""Expand and verify gzip datasets needed for offline analyses and training."""
import gzip
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    manifest = json.loads((ROOT/'publication_manifest.json').read_text(encoding='utf-8'))
    for item in manifest['compressed_files']:
        source = ROOT/item['path']
        target = ROOT/item['unpacked_path']
        if target.exists():
            if sha256(target) != item['unpacked_sha256']:
                raise RuntimeError(f'Existing output has different content: {target}')
            print('Verified', item['unpacked_path'], flush=True)
            continue
        if sha256(source) != item['packed_sha256']:
            raise RuntimeError(f'Compressed input checksum mismatch: {source}')
        partial = target.with_suffix(target.suffix+'.partial')
        with gzip.open(source, 'rb') as incoming, partial.open('wb') as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        if sha256(partial) != item['unpacked_sha256']:
            raise RuntimeError(f'Extracted content checksum mismatch: {partial}')
        partial.replace(target)
        print('Extracted', item['unpacked_path'], flush=True)


if __name__ == '__main__':
    main()
