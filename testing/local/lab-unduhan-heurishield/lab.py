"""Local intercepted fixtures; real extension/model, simulated page and API data."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parent
EXT=ROOT.parents[2]/'extension/HeuriShield-URL20-XGBoost'
# (scenario, url, brand shown on the page, linked file extension, expected matched rules)
CASES=[
 ('Peniruan brand pada alamat + installer','https://bca.portal-lab.test/download','BCA','exe',['P1']),
 ('Peniruan brand pada alamat + PDF','https://bca.portal-lab.test/manual','BCA','pdf',['P1']),
 ('Domain resmi brand + installer','https://bca.co.id/download','BCA','exe',['L1']),
 ('Tanpa brand + installer','https://portal-lab.test/download','Laboratorium','exe',[]),
 ('Brand lain di domain baru + installer','https://unduh-aplikasi.test/bca','BCA','exe',['P4']),
 ('Brand lain di domain baru + PDF','https://unduh-aplikasi.test/bca-manual','BCA','pdf',[]),
 ('Akhiran EXE pada URL di domain baru','https://unduh-aplikasi.test/bca-setup.exe','BCA',None,['P4']),
]

def document(case):
 name,url,brand,extension,expected=case
 link=f'<a class="button" href="/files/contoh.{extension}" download="contoh.{extension}">Unduh contoh .{extension}</a>' if extension else '<p>Tidak ada tautan unduhan pada skenario ini.</p>'
 return f'''<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{brand} — pusat unduhan simulasi</title>
 <style>body{{margin:0;background:#f4f5f7;color:#18212d;font:16px/1.6 system-ui}}main{{max-width:960px;margin:48px auto;padding:32px;background:white;border:1px solid #d9dee5;border-radius:12px}}.label{{color:#9a3d00;font-weight:700}}h1{{font-size:36px;margin:12px 0}}code{{overflow-wrap:anywhere}}.button{{display:inline-block;padding:12px 20px;background:#173d60;color:white;text-decoration:none;border-radius:6px}}section{{border-top:1px solid #dde2e8;margin-top:28px;padding-top:20px}}pre{{white-space:pre-wrap;font-size:13px}}small{{color:#586579}}</style>
 <main><div class="label">SIMULASI PENGUJIAN HEURISHIELD · LOKAL</div><h1>{brand}</h1><h2>{name}</h2><p>Alamat uji: <code>{url}</code></p>
 <p>Halaman ini bukan layanan bank. Tidak ada formulir akun atau pengumpulan kredensial.</p>{link}
 <section><h2>Yang diuji</h2><p>Rule yang diharapkan aktif: <strong>{', '.join(expected) or 'tidak ada (keputusan mengikuti kelas URL)'}</strong>.</p><small>Nama dan akhiran file hanya metadata. Klik unduhan ditahan dan tidak menghasilkan berkas.</small></section>
 <section id="result"><h2>Hasil extension asli</h2><p>Menunggu analisis…</p></section></main>
 <script>document.addEventListener('click',e=>{{if(e.target.closest('a[download]')){{e.preventDefault();alert('Simulasi: tidak ada berkas yang diunduh.');}}}});</script></html>'''

MOCK_FETCH='''async()=>{
 await chrome.storage.local.set({heurishieldEnabled:false,heurishieldPhishingAction:'popup'});
 const original=globalThis.fetch.bind(globalThis);
 globalThis.fetch=async(input,options)=>{
  const u=String(input);if(u.startsWith('chrome-extension://'))return original(input,options);
  const reply=v=>new Response(JSON.stringify(v),{status:200,headers:{'Content-Type':'application/json'}});
  if(u.includes('data.iana.org'))return reply({services:[]});
  // unduh-aplikasi.test is a newly registered domain (20 days); all others are old.
  if(u.includes('whois')||u.includes('who-dat'))return reply({registered_on:u.includes('unduh-aplikasi')?
    new Date(Date.now()-20*86400000).toISOString().slice(0,10):'2000-01-01'});
  if(u.includes('brnad-heuri'))return reply({found:false});
  if(u.includes('clearbit')||u.includes('brandfetch')){
   const q=new URL(u).searchParams.get('query')||decodeURIComponent(u.split('/').at(-1));
   return reply(q==='bca'||q==='bca.co.id'?[{name:'BCA',domain:'bca.co.id',verified:true}]:[]);
  }
  return reply({});
 };
}'''

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true',help='Run all fixtures headless');args=parser.parse_args()
 if not (EXT/'manifest.json').is_file():raise SystemExit(f'Extension tidak ditemukan: {EXT}')
 results=[]
 with TemporaryDirectory(prefix='hs-download-lab-') as profile,sync_playwright() as p:
  context=p.chromium.launch_persistent_context(profile,channel='chromium',headless=args.check,args=[f'--disable-extensions-except={EXT}',f'--load-extension={EXT}'])
  worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
  worker.evaluate(MOCK_FETCH)
  current={'case':CASES[0]}
  def route(request):
   # All web requests stay within fixtures; no public page or download is requested.
   if '/files/' in request.request.url:return request.fulfill(status=204,body='')
   return request.fulfill(status=200,content_type='text/html',body=document(current['case']))
  context.route('http://**/*',route);context.route('https://**/*',route)
  settings=context.new_page();settings.goto(worker.url.removesuffix('src/background/service-worker.js')+'src/options/options.html')
  worker.evaluate("async()=>chrome.storage.local.set({heurishieldEnabled:false,heurishieldPhishingAction:'popup'})")
  page=context.new_page()
  def run(index):
   case=CASES[index];current['case']=case;page.goto(case[1]);page.wait_for_load_state('domcontentloaded')
   response=settings.evaluate('''async url=>{const [tab]=await chrome.tabs.query({url});return chrome.runtime.sendMessage({type:'ANALYZE_ACTIVE_TAB',tabId:tab.id,url,forceRefresh:true});}''',case[1])
   if not response.get('ok'):raise RuntimeError(response)
   a=response['analysis'];matched=[r['id'] for r in a['rule_results'] if r['status']=='matched']
   row={'scenario':case[0],'url':case[1],'expected_rules':case[4],'matched_rules':matched,'passed':matched==case[4],
    'verdict':a['verdict'],'source':a['decision_policy']['source'],'url_model':a['model_result']['verdict'],
    'domain_age_days':a['parameters']['domain_age_days'],'url_file_extension':a['parameters']['url_file_extension'],
    'has_download_link':a['parameters']['has_download_link'],'download_file_extensions':a['parameters']['download_file_extensions'],
    'brand':a['parameters']['claimed_brand'],'official_domain_match':a['parameters']['official_domain_match'],
    'brand_domain_mismatch':a['parameters']['brand_domain_mismatch'],'feature_count':len(a['feature_vector']['vector'])}
   results.append(row)
   page.locator('#result').evaluate("(el,result)=>{el.replaceChildren();const h=document.createElement('h2');h.textContent='Hasil extension asli';const pre=document.createElement('pre');pre.textContent=JSON.stringify(result,null,2);el.append(h,pre);}",row)
   print(json.dumps(row,ensure_ascii=False,indent=2))
   return row
  if args.check:
   for i in range(len(CASES)):run(i)
  else:
   print('Laboratorium lokal. API disimulasikan; model dan keputusan memakai extension asli.\nPemblokiran otomatis dimatikan hanya pada profil sementara agar halaman bisa diperiksa.')
   run(0)
   while True:
    for i,c in enumerate(CASES,1):print(f'{i}. {c[0]}')
    try:choice=input(f'Pilih 1-{len(CASES)}; 0 untuk selesai: ').strip()
    except (EOFError,KeyboardInterrupt):break
    if choice=='0':break
    if choice.isdigit() and 1<=int(choice)<=len(CASES):run(int(choice)-1)
  (ROOT/'hasil_simulasi.json').write_text(json.dumps({'mode':'local_mocked_page_and_api_real_extension','results':results},ensure_ascii=False,indent=2),encoding='utf-8')
  context.close()
 if args.check and not all(r['passed'] for r in results):raise SystemExit(1)

if __name__=='__main__':main()
