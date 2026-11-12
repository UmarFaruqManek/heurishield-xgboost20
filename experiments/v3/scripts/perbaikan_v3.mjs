import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';
const [mode,extension,input,output,modelPath]=process.argv.slice(2);
const {extractUrl20Features}=await import(pathToFileURL(path.join(extension,'src/analyzer/url/url20-features.js')));
const {predictProbability}=await import(pathToFileURL(path.join(extension,'src/model/xgboost-engine.js')));
const contract=JSON.parse(fs.readFileSync(path.join(extension,'src/model/feature-contract-20.json'),'utf8'));
const names=contract.features;
const lines=()=>readline.createInterface({input:fs.createReadStream(input),crlfDelay:Infinity});
const quote=v=>'"'+String(v??'').replaceAll('"','""')+'"';
if(mode==='normalize') {
 const stream=fs.createWriteStream(output);
 const write=async a=>{if(!stream.write(a.map(quote).join(',')+'\n'))await once(stream,'drain');};
 await write(['row_id','original_url','url','label','split','source','site_key','original_endpoint_family','status','error',...names]);
 let n=0;
 for await(const line of lines()) {
  const r=JSON.parse(line);let url='',f={},error='';
  try {const u=new URL(r.url);if(!['http:','https:'].includes(u.protocol))throw Error('Non-HTTP(S) URL');url=u.href;f=extractUrl20Features(url);if(!names.every(k=>Number.isFinite(f[k])))throw Error('Nonfinite feature');}
  catch(e){error=String(e.message||e);}
  await write([r.row_id,r.url,url,r.label,r.split,r.source,r.site_key,r.endpoint_family,error?'failed':'ok',error,...names.map(k=>f[k]??'')]);
  if(++n%50000===0)console.log('Normalized',n);
 }
 stream.end();await once(stream,'finish');console.log('Normalization finished:',n);
} else if(mode==='parity') {
 const model=JSON.parse(fs.readFileSync(modelPath,'utf8'));
 let n=0,maxDelta=0,decisionMismatches=0,featureMismatches=0,canonicalMismatches=0;
 for await(const line of lines()) {
  const r=JSON.parse(line),f=extractUrl20Features(r.url),p=predictProbability(model,f);
  maxDelta=Math.max(maxDelta,Math.abs(p-r.probability));
  decisionMismatches+=Number((p>=.5)!==(r.probability>=.5));
  featureMismatches+=Number(names.some((k,i)=>Math.fround(f[k])!==Math.fround(r.features[i])));
  if(r.root_without_slash) {
   const normalized=new URL(r.root_without_slash).href;
   canonicalMismatches+=Number(predictProbability(model,extractUrl20Features(normalized))!==p);
  }
  n++;
 }
 const report={rows:n,maximum_absolute_probability_error:maxDelta,decision_mismatches:decisionMismatches,feature_mismatches:featureMismatches,canonical_pipeline_mismatches:canonicalMismatches,
  passed:n>=20000&&maxDelta<1e-5&&decisionMismatches===0&&featureMismatches===0&&canonicalMismatches===0};
 fs.writeFileSync(output,JSON.stringify(report,null,2));console.log(JSON.stringify(report));
} else if(mode==='external') {
 const model3=JSON.parse(fs.readFileSync(modelPath,'utf8'));
 const model2=JSON.parse(fs.readFileSync(path.join(extension,'src/model/xgboost-url20.json'),'utf8'));
 const stream=fs.createWriteStream(output);
 const write=async a=>{if(!stream.write(a.map(quote).join(',')+'\n'))await once(stream,'drain');};
 await write(['row_id','original_url','normalized_url','label','status','error','v2_raw','v2_normalized','v3_raw','v3_normalized','normalized_site','public_suffix','path_present','query_present','url_length','host']);
 const {parse}=await import(pathToFileURL(path.join(extension,'src/shared/tldts.js')));
 let n=0;
 for await(const line of lines()) {
  const r=JSON.parse(line);let u,fraw,fnorm,err='',pred=[],parsed={};
  try {
   u=new URL(r.url);if(!['http:','https:'].includes(u.protocol))throw Error('Non-HTTP(S) URL');
   fraw=extractUrl20Features(r.url);fnorm=extractUrl20Features(u.href);parsed=parse(u.hostname,{allowPrivateDomains:true});
   if(!names.every(k=>Number.isFinite(fraw[k])&&Number.isFinite(fnorm[k])))throw Error('Nonfinite feature');
   pred=[model2,model3].flatMap(m=>[fraw,fnorm].map(f=>predictProbability(m,f)>=.5?'phishing':'legitimate'));
  }catch(e){err=String(e.message||e);}
  await write([r.row_id,r.url,u?.href,r.label,err?'failed':'ok',err,...(pred.length?pred:['','','','']),parsed.domain||u?.hostname,parsed.publicSuffix,Number(Boolean(u&&u.pathname!=='/')),Number(Boolean(u?.search)),u?.href.length,u?.hostname]);
  if(++n%10000===0)console.log('External',n);
 }
 stream.end();await once(stream,'finish');
} else throw Error('Unknown mode: '+mode);
