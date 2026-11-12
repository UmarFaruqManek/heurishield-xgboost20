// Offline evaluation using the extension's actual extractor and tree evaluator.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {pathToFileURL} from 'node:url';
import {once} from 'node:events';

const [extension, input, output] = process.argv.slice(2);
if (!output) throw new Error('Expected extension, input JSONL, output CSV');
const {extractUrl20Features} = await import(pathToFileURL(path.join(extension,'src/analyzer/url/url20-features.js')));
const {classifyUrl} = await import(pathToFileURL(path.join(extension,'src/model/xgboost-engine.js')));
const model = JSON.parse(fs.readFileSync(path.join(extension,'src/model/xgboost-url20.json'),'utf8'));
const contract=JSON.parse(fs.readFileSync(path.join(extension,'src/model/feature-contract-20.json'),'utf8'));
if (model.threshold!==0.5 || JSON.stringify(model.feature_names)!==JSON.stringify(contract.features)) {
  throw new Error('Model must have threshold 0.50 and the matching URL20 contract.');
}
const csv=v=>'"'+String(v??'').replaceAll('"','""')+'"';
const stream=fs.createWriteStream(output,{encoding:'utf8'});
const write=async values=>{if(!stream.write(values.map(csv).join(',')+'\n')) await once(stream,'drain');};
await write(['source_row','url','actual_label','prediction','correct','status','error','exact_development_overlap',...model.feature_names]);
let count=0;
for await(const line of readline.createInterface({input:fs.createReadStream(input),crlfDelay:Infinity})) {
  const row=JSON.parse(line);
  let features={},prediction='',error=row.error||'';
  if(!error) {
    try {
      if(!/^https?:\/\//i.test(row.url) || /\s/.test(row.url)) throw new Error('URL must use HTTP(S) and contain no internal whitespace');
      const parsed=new URL(row.url);
      if(!parsed.hostname || parsed.hostname.includes('%')) throw new Error('Invalid hostname');
      features=extractUrl20Features(row.url);
      if(!model.feature_names.every(key=>Number.isFinite(features[key]))) throw new Error('Non-finite feature value');
      prediction=classifyUrl(model,features);
    } catch(e) { error=String(e.message||e); }
  }
  await write([row.source_row,row.url,row.label,prediction,error?'':Number(prediction===row.label),error?'failed':'evaluated',error,row.overlap,...model.feature_names.map(key=>features[key]??'')]);
  count++;
  if(count%10000===0) console.log(`[URL20] ${count.toLocaleString('en-US')} processed`);
}
stream.end();await once(stream,'finish');
console.log(`[URL20] Finished ${count.toLocaleString('en-US')} rows`);
