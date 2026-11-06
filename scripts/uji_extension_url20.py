"""Existing local fixture suite, no public live URL evaluation."""
import concurrent.futures
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / 'extension/HeuriShield-URL20-XGBoost'


def run(test):
    command = ['node', str(test)] if test.suffix == '.mjs' else ['python', str(test)]
    try:
        result = subprocess.run(command, cwd=EXTENSION, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=90)
        return {'test': test.name, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    except subprocess.TimeoutExpired:
        return {'test': test.name, 'exit_code': 124, 'stderr': 'Fixture exceeded 90 seconds'}


def main():
    tests = [file for file in sorted((EXTENSION / 'tests').glob('*.mjs')) if file.name != 'parity-runner.mjs']
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(run, tests))
    for name in ['extension-load-smoke.py', 'dynamic-dom-regression.py', 'warning-page-smoke.py']:
        results.append(run(EXTENSION / 'tests' / name))
    classification_cases = []
    for row in results:
        for line in row.get('stdout', '').splitlines():
            if line.startswith('{"classification_case"'):
                classification_cases.append(json.loads(line))
    report = {'checks': len(results), 'passed': sum(row['exit_code'] == 0 for row in results),
              'classification_cases': classification_cases, 'results': results}
    (ROOT / 'experiments/v2/reports/extension_tests.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'checks': report['checks'], 'passed': report['passed'],
                      'failed': [row for row in results if row['exit_code']]}, indent=2))
    if report['checks'] != report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
