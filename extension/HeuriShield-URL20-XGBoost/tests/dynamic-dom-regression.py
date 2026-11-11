"""Observe a controlled SPA fixture, without visiting public websites or APIs."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

extension = Path(__file__).resolve().parents[1]
with TemporaryDirectory(prefix='hs-spa-fixture-') as profile, sync_playwright() as p:
    context = p.chromium.launch_persistent_context(profile, headless=True, channel='chromium',
        args=[f'--disable-extensions-except={extension}', f'--load-extension={extension}'])
    worker = context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
    worker.evaluate('async () => chrome.storage.local.set({heurishieldEnabled:false})')
    context.route('https://spa.example.test/**', lambda route: route.fulfill(status=200,
        content_type='text/html', body='<html><head><title></title></head><body><main></main></body></html>'))
    page = context.new_page()
    page.goto('https://spa.example.test/')
    def snapshot():
        return worker.evaluate('''async () => {
          const [tab] = await chrome.tabs.query({url:'https://spa.example.test/*'});
          return (await chrome.tabs.sendMessage(tab.id, {type:'HEURISHIELD_COLLECT_EVIDENCE'}, {frameId:0})).snapshot;
        }''')
    before = snapshot()
    assert before['evidence_incomplete'] is True
    page.evaluate('''() => {
      document.title = 'Account login';
      document.querySelector('main').innerHTML = '<h1>Account</h1><form><input type="text" name="identity"><button>Login</button></form>';
      document.querySelector('input').type = 'password';
    }''')
    after = snapshot()
    assert after['evidence_incomplete'] is False
    assert after['password_fields'] and after['forms'][0]['relevant']
    assert after['title'] == 'Account login'
    page.locator('input').fill('HS_SECRET_MUST_NOT_BE_SAVED')
    assert 'HS_SECRET_MUST_NOT_BE_SAVED' not in json.dumps(snapshot())
    page.evaluate('''() => {
      const meta = document.createElement('meta');
      meta.name = 'generator'; meta.content = 'WordPress 6.8';
      document.head.append(meta);
    }''')
    assert 'WordPress 6.8' in snapshot()['software_attributions']
    page.evaluate("() => document.querySelector('input').setAttribute('autocomplete','one-time-code')")
    assert snapshot()['password_fields']
    page.evaluate('''() => {
      document.querySelector('main').innerHTML = '<section id="modal" style="display:none"><input type="password"><button>Masuk</button></section>';
    }''')
    hidden = snapshot()
    assert hidden['password_fields'] and all(f['visible'] is False for f in hidden['password_fields'])
    control = context.new_page()
    control.goto(worker.url.removesuffix('src/background/service-worker.js')+'src/options/options.html')
    def explanation_for(evidence):
        return control.evaluate('''async snapshot => {
          const {analyzeDomEvidence}=await import(chrome.runtime.getURL('src/analyzer/dom/dom-evidence.js'));
          const {buildAnalysisExplanation}=await import(chrome.runtime.getURL('src/shared/analysis-explanation.js'));
          return buildAnalysisExplanation({url:'https://spa.example.test/',verdict:'DANGEROUS',
            model_result:{model_family:'XGBoost',verdict:'DANGEROUS'},
            decision_policy:{source:'url_model'},
            brand_features:{claimed_brand_status:'ambiguous'},dom_features:analyzeDomEvidence([snapshot])});
        }''', evidence)
    assert explanation_for(hidden)['reasons'] == ['Alamat: dinilai phishing oleh model.']
    page.locator('#modal').evaluate("el=>el.style.display='block'")
    shown = snapshot()
    assert shown['password_fields'][0]['visible'] is True
    assert len(explanation_for(shown)['reasons']) == 2
    print('SPA fixture: empty initial document, text/title update, form insertion and password type change observed')
    print('Hidden modal: metadata retained, no fabricated form reason; opening modal adds the observed credential finding.')
    context.close()
