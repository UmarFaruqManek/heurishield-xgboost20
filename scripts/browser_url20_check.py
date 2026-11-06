"""Check installed extension runtime and persistence using local synthetic content."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / 'extension/HeuriShield-URL20-XGBoost'


def main():
    cases = json.loads((ROOT / 'experiments/v2/reports/extension_inference_cases.json').read_text())[:128]
    with TemporaryDirectory(prefix='heurishield-url20-runtime-') as profile, sync_playwright() as browser:
        context = browser.chromium.launch_persistent_context(
            profile, channel='chromium', headless=True,
            args=[f'--disable-extensions-except={EXTENSION}', f'--load-extension={EXTENSION}'])
        worker = context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker', timeout=15000)
        worker.evaluate('''async () => {
          await chrome.storage.local.set({heurishieldEnabled:false});
          const originalFetch = globalThis.fetch.bind(globalThis);
          globalThis.fetch = async (input, options) => {
            const url = String(input);
            if (url.startsWith('chrome-extension://')) return originalFetch(input, options);
            return new Response('{}', {status:404,headers:{'Content-Type':'application/json'}});
          };
        }''')
        root_url = worker.url.removesuffix('src/background/service-worker.js')
        settings = context.new_page()
        settings.goto(root_url + 'src/options/options.html')
        actual = settings.evaluate('''async cases => {
          const {extractUrl20Features} = await import(chrome.runtime.getURL('src/analyzer/url/url20-features.js'));
          const {predictProbability} = await import(chrome.runtime.getURL('src/model/xgboost-engine.js'));
          const model = await (await fetch(chrome.runtime.getURL('src/model/xgboost-url20.json'))).json();
          return {threshold:model.threshold,count:model.feature_names.length,
            probabilities:cases.map(row=>predictProbability(model,extractUrl20Features(row.url)))};
        }''', cases)
        assert actual['threshold'] == .5 and actual['count'] == 20
        maximum_error = max(abs(row['probability']-score) for row, score in zip(cases, actual['probabilities']))
        assert maximum_error < 1e-5
        context.route('https://login123.fixture.test/**', lambda route: route.fulfill(
            status=200, content_type='text/html', body='''<html><head><title>Fixture account</title></head>
            <body><h1>Fixture</h1><form action="/session" method="post">
            <input type="password" name="password"><button>Login</button></form></body></html>'''))
        page = context.new_page()
        page.goto('https://login123.fixture.test/account?step=2')
        result = settings.evaluate('''async url => {
          const [tab] = await chrome.tabs.query({url:'https://login123.fixture.test/*'});
          return chrome.runtime.sendMessage({type:'ANALYZE_ACTIVE_TAB',tabId:tab.id,url});
        }''', page.url)
        assert result['ok'], result
        analysis = result['analysis']
        assert analysis['model_result']['ready']
        assert analysis['model_result']['threshold'] == .5
        assert analysis['model_result']['model_name'] == 'XGBoost URL20 v2'
        assert len(analysis['feature_vector']['vector']) == 20
        assert analysis['dom_features']['has_password_field'] is True
        assert analysis['dom_features']['form_cross_domain'] is False
        stored = worker.evaluate("async () => (await chrome.storage.local.get('featureArchive')).featureArchive")
        assert stored and len(stored[0]['feature_vector_20']) == 20
        assert stored[0]['model_result']['threshold'] == .5
        assert stored[0]['model_result']['source_model_sha256']
        assert stored[0]['feature_sources']['dom']['has_password_field']
        report = {'passed': True, 'manifest_version': worker.evaluate('()=>chrome.runtime.getManifest().version'),
                  'feature_count': 20, 'threshold': .5, 'actual_browser_prediction_cases': len(cases),
                  'maximum_probability_error': maximum_error, 'worker_analysis_ready': True,
                  'dom_password_observed': True, 'same_domain_form_observed': True,
                  'saved_feature_archive_count': len(stored), 'model_fingerprint_saved': True,
                  'public_pages_opened': 0}
        context.close()
    (ROOT / 'experiments/v2/reports/extension_browser_runtime.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
