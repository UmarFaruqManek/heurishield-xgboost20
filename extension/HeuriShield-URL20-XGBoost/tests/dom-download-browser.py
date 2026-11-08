"""Read download-link DOM in the real extension. Never start a download."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

extension=Path(__file__).resolve().parents[1]
url='https://bca.bank.com/download'
html='<html><head><title>Login BCA</title></head><body><main><h1>BCA Downloads</h1><a id="payload" href="https://files.fixture.test/update.exe" download>Download BCA</a></main></body></html>'
with TemporaryDirectory(prefix='hs-dom-download-') as profile,sync_playwright() as p:
    context=p.chromium.launch_persistent_context(profile,channel='chromium',headless=True,
        args=[f'--disable-extensions-except={extension}',f'--load-extension={extension}'])
    worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
    worker.evaluate('''async()=>{
      await chrome.storage.local.set({heurishieldEnabled:false,heurishieldPhishingAction:'popup'});
      const original=globalThis.fetch.bind(globalThis);
      globalThis.fetch=async(input,options)=>{
        const u=String(input);if(u.startsWith('chrome-extension://'))return original(input,options);
        const reply=v=>new Response(JSON.stringify(v),{status:200,headers:{'Content-Type':'application/json'}});
        if(u.includes('data.iana.org'))return reply({services:[]});
        if(u.includes('whois')||u.includes('who-dat'))return reply({domain:'bank.com',registered_on:'2000-01-01'});
        if(u.includes('brnad-heuri'))return reply({found:false});
        if(u.includes('clearbit')||u.includes('brandfetch')){
          const q=new URL(u).searchParams.get('query')||decodeURIComponent(u.split('/').at(-1));
          return reply(q==='bca'||q==='bca.co.id'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]);
        }
        return reply({});
      };
    }''')
    context.route(url,lambda route:route.fulfill(status=200,content_type='text/html',body=html))
    settings=context.new_page();settings.goto(worker.url.removesuffix('src/background/service-worker.js')+'src/options/options.html')
    worker.evaluate("async()=>chrome.storage.local.set({heurishieldEnabled:false,heurishieldPhishingAction:'popup'})")
    page=context.new_page();page.goto(url)
    assert settings.locator('#downloadAction').count()==0
    assert worker.evaluate("()=>!chrome.runtime.getManifest().permissions.includes('downloads')")
    def analyze():
        result=settings.evaluate('''async url=>{const [tab]=await chrome.tabs.query({url});return chrome.runtime.sendMessage({type:'ANALYZE_ACTIVE_TAB',tabId:tab.id,url,forceRefresh:true});}''',url)
        assert result['ok'],result
        return result['analysis']
    a=analyze();dom=a['dom_features']
    assert a['url_features']['url_file_extension'] is None,a['url_features']
    assert 'has_executable_download_link' not in dom
    assert dom['has_download_link'] is True and dom['download_file_extensions']==['exe'],dom
    assert dom['download_target_cross_domain'] is True and 'download_link_count' not in dom,dom
    assert a['decision_policy']['source']=='brand_executable_download_phishing',a['decision_policy']
    assert a['verdict']=='DANGEROUS'
    assert any(reason.startswith('Unduhan:') for reason in a['explanation']['reasons'])
    page.locator('#payload').evaluate("el=>{el.href='https://files.fixture.test/manual.pdf';el.removeAttribute('download');el.textContent='Manual PDF';}")
    pdf=analyze();assert pdf['dom_features']['download_file_extensions']==['pdf']
    assert next(r for r in pdf['correlation_rules'] if r['id']=='R13')['status']=='not_matched'
    page.locator('#payload').evaluate('el=>el.remove()')
    absent=analyze();assert absent['dom_features']['has_download_link'] is False
    page.evaluate("()=>{const a=document.createElement('a');a.id='dynamic-download';a.href='https://files.fixture.test/setup.apk';a.textContent='Download';document.querySelector('main').append(a);}")
    dynamic=analyze();assert dynamic['dom_features']['download_file_extensions']==['apk']
    url='https://bca.bank.com/setup.exe'
    context.route(url,lambda route:route.fulfill(status=200,content_type='text/html',body='<html><head><title>Login BCA</title></head><body><h1>BCA Downloads</h1></body></html>'))
    page.goto(url)
    direct=analyze()
    assert direct['url_features']['url_file_extension']=='exe'
    assert len(direct['feature_vector']['vector'])==20
    assert direct['dom_features']['has_download_link'] is False
    assert direct['decision_policy']['source']=='brand_executable_download_phishing'
    report={'passed':True,'version':worker.evaluate('()=>chrome.runtime.getManifest().version'),
        'download_link_read':True,'executable_link_read':True,'cross_site_read':True,
        'R13_verdict':a['verdict'],'R13_source':a['decision_policy']['source'],
        'pdf_not_executable':True,'removed_link_detected':True,'dynamic_link_detected':True,
        'url_suffix_read':True,'model_vector_still_20':True,
        'separate_warning_removed':True,'downloads_permission_removed':True,
        'downloads_started':0,'public_sites_opened':0,'test':'local mocked page/API in Chromium'}
    out=extension.parents[1]/'reports/dom_download_final_20261108';out.mkdir(exist_ok=True,parents=True)
    (out/'browser_test.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
    context.close()
