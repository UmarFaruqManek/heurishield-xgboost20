"""Prepare source-backed, unseen-domain legitimate URLs; HTTP checks only, no model/API scoring."""
import asyncio
import csv
import functools
import io
import json
import random
import re
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
import tldextract
from bs4 import BeautifulSoup

ROOT=Path(__file__).resolve().parent.parent
AUDIT=ROOT/"reports/legitimate_500_preflight_05nov2026"
OUTPUT=Path(r"C:\Users\USER\Downloads\legitimate_fresh_500_05nov2026.txt")
ARCHIVE=ROOT/"data/evaluation"/OUTPUT.name
PARSER=tldextract.TLDExtract(suffix_list_urls=(),include_psl_private_domains=True)
QUOTAS={"government":100,"education":100,"company":100,"healthcare":100,"nonprofit":100}
CSV_KEYS={"url","input_url","original_url","final_url","browser_final_url","analysis_final_url","source_url","normalized_url","registrable_domain"}
AUTH=re.compile(r"login|log.?in|sign.?in|account|password|auth|portal|register|registration|reset|recover|verify|security|payment|billing|identity|masuk|pendaftaran|sso",re.I)
BAD=re.compile(r"404|not found|access denied|service unavailable|captcha|just a moment|checking your browser|site not found|domain for sale|domain is parked|under construction|coming soon",re.I)
ASSET=re.compile(r"\.(?:pdf|docx?|xlsx?|zip|png|jpe?g|gif|svg|webp|css|js|json|xml|mp4|ics)$",re.I)
HEADERS={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36","Accept":"text/html,application/xhtml+xml"}
RNG=random.Random(20261105500)


@functools.lru_cache(maxsize=1000000)
def domain(host):
    p=PARSER(host.lower().rstrip('.'))
    return p.top_domain_under_public_suffix or host.lower().rstrip('.')


def site(url):
    try:
        host=urlsplit(url if '://' in url else 'https://'+url).hostname
        return domain(host) if host else ''
    except ValueError:return ''


def exclusions():
    seen=set();sources=[];errors=[]
    csv.field_size_limit(50_000_000)
    csvs={ROOT/'data/raw/url_label_no_tranco_20261103.csv',
        Path(r'D:\Deployment Extension\data\dataset_60_fitur.csv'),
        Path(r'D:\experimen\dataset_000_003.csv'),
        Path(r'D:\experimen\persiapan_model_v5_age_observed_only\dataset_32_fitur_umur_observed_only.csv'),
        Path(r'D:\experimen\heurisield-skripsi\data\dataset\gabungan_url_label_umur.csv')}
    for base in [ROOT/'reports',Path(r'D:\Deployment Extension\data'),Path(r'D:\experimen')]:
        for pattern in ['browser_live_rows*.csv','*legitimate*.csv']:
            csvs.update(base.rglob(pattern))
    for path in sorted(csvs):
        if not path.is_file():continue
        rows=0
        try:
            with path.open(encoding='utf-8-sig',errors='replace',newline='') as f:
                reader=csv.DictReader(f)
                keys=[k for k in reader.fieldnames or [] if k.lower() in CSV_KEYS]
                if not keys:continue
                for row in reader:
                    rows+=1
                    for key in keys:
                        if row.get(key):
                            d=site(row[key])
                            if d:seen.add(d)
            sources.append({'path':str(path),'rows':rows,'columns':keys,'size':path.stat().st_size})
        except (OSError,csv.Error,ValueError) as e:errors.append({'path':str(path),'error':str(e)})
    txts=set(Path(r'C:\Users\USER\Downloads').glob('*legitimate*.txt'))
    for base in [ROOT/'data/evaluation',Path(r'D:\experimen'),Path(r'D:\Deployment Extension\data/evaluasi_live')]:
        txts.update(base.rglob('*legitimate*.txt'))
    for path in sorted(txts):
        if path in (OUTPUT,ARCHIVE):continue
        rows=0
        try:
            with path.open(encoding='utf-8-sig',errors='replace') as f:
                for line in f:
                    for match in re.finditer(r'https?://[^\s<>"\]]+',line):
                        d=site(match.group())
                        if d:seen.add(d);rows+=1
            sources.append({'path':str(path),'url_matches':rows,'size':path.stat().st_size})
        except OSError as e:errors.append({'path':str(path),'error':str(e)})
    if errors:raise RuntimeError(json.dumps(errors))
    AUDIT.mkdir(parents=True,exist_ok=True)
    (AUDIT/'exclusion_sources.json').write_text(json.dumps(sources,indent=2),encoding='utf-8')
    (AUDIT/'excluded_domains.txt').write_text('\n'.join(sorted(seen)),encoding='utf-8')
    print(json.dumps({'excluded_domains':len(seen),'files_scanned':len(sources)}),flush=True)
    return seen,sources


async def pools(seen):
    groups=defaultdict(dict)
    url='https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv'
    async with httpx.AsyncClient(timeout=35) as client:
        response=await client.get(url);response.raise_for_status()
    for row in csv.DictReader(io.StringIO(response.text)):
        d=(row.get('Domain name')or'').lower().strip()
        if not d.endswith('.gov') or d in seen:continue
        groups['government'][d]={'site_key':d,'seed_url':'https://'+d+'/',
            'source':'CISA .gov register','source_ref':url,'organization':row.get('Organization name',''),'country':'US'}
    archive=ROOT/'data/raw/legitimate_source_registry/ror-data.zip'
    with zipfile.ZipFile(archive) as z:
        name=next(n for n in z.namelist() if n.endswith('.csv'))
        with io.TextIOWrapper(z.open(name),encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                if row.get('status')!='active':continue
                url=(row.get('links.type.website')or'').split(';')[0].strip()
                if not url.startswith(('https://','http://')):continue
                d=site(url)
                if not d or d in seen:continue
                types=(row.get('types')or'').lower()
                group='company' if 'company' in types else 'healthcare' if 'healthcare' in types else 'nonprofit' if any(t in types for t in ['nonprofit','funder']) else 'education' if 'education' in types else None
                if not group:continue
                groups[group][d]={'site_key':d,'seed_url':url,'source':'ROR active organization',
                    'source_ref':row.get('id',''),'organization':row.get('names.types.ror_display',''),
                    'country':row.get('locations.geonames_details.country_code','')}
    result={}
    for group,items in groups.items():
        result[group]=list(items.values());RNG.shuffle(result[group])
    print(json.dumps({'pools':{k:len(v) for k,v in result.items()}}),flush=True)
    return result


def clean(url):
    try:
        p=urlsplit(url)
        if p.scheme not in ('https','http') or not p.hostname or p.username or p.password or ASSET.search(p.path):return ''
        if any(c.isspace() for c in url):return ''
        return urlunsplit((p.scheme,p.netloc.lower(),p.path or '/',p.query,''))
    except ValueError:return ''


def page(response,d):
    if response.status_code!=200 or 'html' not in response.headers.get('content-type','').lower():return None
    url=clean(str(response.url))
    if not url or urlsplit(url).scheme!='https' or site(url)!=d:return None
    soup=BeautifulSoup(response.content[:600000],'html.parser')
    title=soup.title.get_text(' ',strip=True) if soup.title else ''
    if not title or BAD.search(title):return None
    for tag in soup(['script','style','svg','noscript']):tag.decompose()
    text=soup.get_text(' ',strip=True)
    if len(text)<120 or BAD.search(text[:350]):return None
    return url,title[:200],soup


async def inspect(client,item):
    home=None
    p=urlsplit(item['seed_url'])
    seeds=[item['seed_url']]
    if p.hostname and not p.hostname.startswith('www.'):
        seeds.append(urlunsplit(('https','www.'+p.netloc,p.path or '/','','')))
    for seed in seeds:
        try:
            home=page(await client.get(seed),item['site_key'])
            if home:break
        except (httpx.HTTPError,ValueError,UnicodeError):pass
    if not home:return None
    url,title,soup=home;links={}
    for a in soup.select('a[href]'):
        target=clean(urljoin(url,a.get('href','')))
        if not target or site(target)!=item['site_key'] or not urlsplit(target).path.strip('/'):continue
        text=a.get_text(' ',strip=True)
        score=100 if AUTH.search(urlsplit(target).path+' '+text) else 20 if re.search('service|support|help|apply|admission|profile|contact|about',target+' '+text,re.I) else 5
        score+=min(len(urlsplit(target).path),60)/100
        links[target]=max(links.get(target,0),score)
    ordered=sorted(links,key=lambda u:-links[u])[:3]
    for target in ordered:
        try:
            checked=page(await client.get(target),item['site_key'])
            if not checked or not urlsplit(checked[0]).path.strip('/'):continue
            chosen,title,_=checked
            return {**item,'url':chosen,'label':'legitimate','title':title,'http_status':200,
                'source_homepage':url,'discovered_link':target,'page_type':'account_like' if links[target]>=100 else 'ordinary_deep_page',
                'checked_at_utc':datetime.now(timezone.utc).isoformat()}
        except (httpx.HTTPError,ValueError,UnicodeError):pass
    if urlsplit(url).path.strip('/'):
        return {**item,'url':url,'label':'legitimate','title':title,'http_status':200,'source_homepage':url,
            'discovered_link':url,'page_type':'organization_deep_page','checked_at_utc':datetime.now(timezone.utc).isoformat()}
    return None


async def collect(groups,seen):
    selected=[];counts=Counter();positions=Counter();checked=0;sem=asyncio.Semaphore(24)
    async with httpx.AsyncClient(headers=HEADERS,follow_redirects=True,timeout=httpx.Timeout(8,connect=4),limits=httpx.Limits(max_connections=24)) as client:
        async def bounded(group,item):
            async with sem:
                try:return group,await inspect(client,item)
                except Exception:return group,None
        while len(selected)<500:
            batch=[]
            for group,quota in QUOTAS.items():
                needed=quota-counts[group]
                if needed<=0:continue
                start=positions[group];items=groups.get(group,[])[start:start+min(60,max(12,needed*2))]
                positions[group]+=len(items);batch.extend((group,i) for i in items)
            if not batch:raise RuntimeError(f'Pools exhausted: {counts}')
            for task in asyncio.as_completed([bounded(g,i) for g,i in batch]):
                group,row=await task;checked+=1
                if row and counts[group]<QUOTAS[group] and row['site_key'] not in seen:
                    selected.append({**row,'group':group});counts[group]+=1;seen.add(row['site_key'])
                if checked%25==0:
                    (AUDIT/'checkpoint.json').write_text(json.dumps(selected,ensure_ascii=False,indent=2),encoding='utf-8')
                    print(json.dumps({'checked':checked,'selected':len(selected),'groups':dict(counts)}),flush=True)
    return selected,checked


def main():
    if OUTPUT.exists():raise FileExistsError(OUTPUT)
    seen,sources=exclusions();initial_seen=seen.copy()
    groups=asyncio.run(pools(seen));selected,checked=asyncio.run(collect(groups,seen))
    RNG.shuffle(selected)
    assert len(selected)==500 and len({r['site_key'] for r in selected})==500
    assert all(site(r['url']) not in initial_seen for r in selected)
    text='\n'.join(r['url'] for r in selected)+'\n';OUTPUT.write_text(text,encoding='utf-8');ARCHIVE.write_text(text,encoding='utf-8')
    (AUDIT/'audit_500.json').write_text(json.dumps(selected,ensure_ascii=False,indent=2),encoding='utf-8')
    summary={'prepared':500,'unique_registrable_domains':500,'overlap_excluded_domains':0,'excluded_domains':len(initial_seen),
        'files_scanned':len(sources),'checked_candidates':checked,'groups':dict(Counter(r['group'] for r in selected)),
        'page_types':dict(Counter(r['page_type'] for r in selected)),'public_suffixes':dict(Counter(PARSER(urlsplit(r['url']).hostname).suffix for r in selected)),
        'urls_with_path':sum(bool(urlsplit(r['url']).path.strip('/')) for r in selected),
        'urls_with_subdomain':sum(bool(PARSER(urlsplit(r['url']).hostname).subdomain) for r in selected),
        'countries':dict(Counter(r['country'] for r in selected)), 'output':str(OUTPUT),'archive':str(ARCHIVE),
        'created_at_utc':datetime.now(timezone.utc).isoformat(),'extension_tests_run':False,'model_predictions_used_to_select':False,
        'limitations':['Unseen against the local files listed in exclusion_sources.json, not unrecorded/deleted data.',
            'HTTP 200 HTML at preparation time does not guarantee future browser or extension analysis.',
            'Sector-balanced sample from CISA and ROR; not a natural browsing distribution or an unbiased population sample.',
            'Source-backed organization websites; cannot guarantee absence of compromise.']}
    (AUDIT/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2),flush=True)


if __name__=='__main__':main()
