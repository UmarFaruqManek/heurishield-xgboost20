"""Real extension runtime over a local mocked page/API, never the public target."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

extension=Path(__file__).resolve().parents[1]
url='https://www.roblox.com.ml/users/390783638810/profile'
with TemporaryDirectory(prefix='hs-brand-conflict-') as profile,sync_playwright() as p:
    context=p.chromium.launch_persistent_context(profile,channel='chromium',headless=True,
        args=[f'--disable-extensions-except={extension}',f'--load-extension={extension}'])
    worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
    worker.evaluate('''async () => {
      await chrome.storage.local.set({heurishieldEnabled:false});
      const original=globalThis.fetch.bind(globalThis);
      globalThis.fetch=async (input,options)=>{
        const url=String(input);if(url.startsWith('chrome-extension://'))return original(input,options);
        const response=value=>new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});
        if(url.includes('data.iana.org'))return response({services:[[['ml'],['https://rdap.fixture.test/']]]});
        if(url.includes('rdap.fixture.test'))return response({ldhName:'roblox.com.ml',events:[{eventAction:'registration',eventDate:'2026-01-01T00:00:00Z'}]});
        if(url.includes('autocomplete.clearbit.com'))return response([{name:'Roblox',domain:url.includes('roblox.com.ml')?'roblox.com.ml':'roblox.com'}]);
        if(url.includes('api.brandfetch.io'))return response([{name:'Roblox',domain:url.includes('roblox.com.ml')?'roblox.com.ml':'roblox.com',verified:!url.includes('roblox.com.ml')}]);
        if(url.includes('brnad-heuri'))return response({found:true,domain:'roblox.com.ml',registrable_domain:'roblox.com.ml',brand_name:'Roblox',brand_verified:false});
        return response({});
      };
    }''')
    context.route(url,lambda route:route.fulfill(status=200,content_type='text/html',body='<html><head><title>Player - Roblox</title></head><body><main><h1>Roblox profile</h1><p>Local fixture for domain/reference conflict testing.</p></main></body></html>'))
    page=context.new_page();page.goto(url)
    page.wait_for_function("window.__heurishieldEvidenceObserverInstalled || document.readyState==='complete'")
    page.wait_for_timeout(400)
    settings=context.new_page()
    settings.goto(worker.url.removesuffix('src/background/service-worker.js')+'src/options/options.html')
    analysis=settings.evaluate('''async url=>{
      const tabs=await chrome.tabs.query({});
      const tab=tabs.find(tab=>tab.url===url)||tabs.find(tab=>tab.url?.includes('/src/warning/'));
      if(!tab)throw new Error('Fixture tab missing: '+JSON.stringify(tabs));
      return new Promise(resolve=>chrome.runtime.sendMessage({type:'ANALYZE_ACTIVE_TAB',tabId:tab.id,url,forceRefresh:true},resolve));
    }''',url)
    assert analysis['ok'],analysis
    a=analysis['analysis'];b=a['brand_features']
    assert b['claimed_brand']['name']=='Roblox',b
    assert b['verified_reference_domain']=='roblox.com',b
    assert b['official_domain_match'] is False,b
    assert b['api_domain_reference_conflict'] is True,b
    assert b['high_confidence_host_impersonation'] is True,b
    assert a['verdict']=='DANGEROUS',a['decision_policy']
    report={'passed':True,'manifest_version':worker.evaluate('()=>chrome.runtime.getManifest().version'),
        'brand':b['claimed_brand']['name'],'reference_domain':b['verified_reference_domain'],
        'official_domain_match':False,'api_domain_reference_conflict':True,'verdict':a['verdict'],
        'decision_source':a['decision_policy']['source'],'test_type':'local_mock_page_and_API','public_target_opened':False}
    out=extension.parents[1]/'experiments/v2/reports';out.mkdir(exist_ok=True,parents=True)
    (out/'browser_conflict_test.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));context.close()
