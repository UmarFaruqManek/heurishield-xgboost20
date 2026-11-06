"""URL20 experiment: descriptive EDA, domain-disjoint 90/10, five fixed models.
No browser, page fetches, APIs, validation split, threshold optimization or extension edits.
"""
import csv, gc, hashlib, json, platform, re, sys, time
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
import joblib
import numpy as np
import pandas as pd
import sklearn, xgboost
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score, average_precision_score, f1_score, precision_score
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.inspection import permutation_importance
from xgboost import XGBClassifier
from ekstrak_fitur_url17 import extract_url_features, URL_FEATURES, DOMAIN_PARSER, SENSITIVE_TOKENS

ROOT=Path(__file__).resolve().parent.parent
SEED=20261106
FEATURES=[*URL_FEATURES,'domain_label_length','hostname_longest_digit_run','hostname_sensitive_token_count']
R=ROOT/'reports/baseline'

def save(name,obj):
 (R/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False,default=lambda o:o.item() if hasattr(o,'item') else str(o)),encoding='utf-8')

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

@lru_cache(maxsize=300000)
def domain(host):
 p=DOMAIN_PARSER(host)
 return p.top_domain_under_public_suffix or host

def extract(url):
 u=str(url).strip()
 if any(c.isspace() for c in u):raise ValueError('internal_whitespace')
 f=extract_url_features(u);p=urlsplit(u);host=p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
 if '%' in host:raise ValueError('invalid_hostname_escape')
 _=p.port
 d=DOMAIN_PARSER(host)
 return {**f,'domain_label_length':len(d.domain),'hostname_longest_digit_run':max((len(x) for x in re.findall(r'[0-9]+',host)),default=0),'hostname_sensitive_token_count':sum(x in SENSITIVE_TOKENS for x in re.findall(r'[a-z0-9]+',host))},domain(host)

def metrics(y,p):
 pred=np.asarray(p)>=.5;tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel();n=len(y)
 return {'rows':n,'threshold':.5,'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),'accuracy_percent':round(100*(tn+tp)/n,3),'legitimate_correct_percent':round(100*tn/(tn+fp),3) if tn+fp else None,'phishing_recall_percent':round(100*tp/(tp+fn),3) if tp+fn else None,'precision_percent':round(100*precision_score(y,pred,zero_division=0),3),'f1_percent':round(100*f1_score(y,pred,zero_division=0),3),'roc_auc_percent':round(100*roc_auc_score(y,p),3) if len(np.unique(y))==2 else None,'average_precision_percent':round(100*average_precision_score(y,p),3) if len(np.unique(y))==2 else None}

def prepare():
 assert len(FEATURES)==20 and len(set(FEATURES))==20
 a,_=extract('https://login123.example.com/account')
 assert a['hostname_longest_digit_run']==3
 assert a['domain_label_length']==7
 b,_=extract('https://login.example.com/')
 assert b['hostname_sensitive_token_count']==1
 assert {k:b[k] for k in URL_FEATURES}==extract_url_features('https://login.example.com/')
 source=ROOT/'data/raw/phreshphish_url_label_https.csv'
 df=pd.read_csv(source,keep_default_na=False,dtype=str)
 df['url']=df.url.str.strip();df['label']=df.label.map({'benign':'legitimate','phish':'phishing'})
 assert df.label.notna().all()
 conflicts=set(df.groupby('url',sort=False).label.nunique().loc[lambda x:x>1].index)
 df[df.url.isin(conflicts)].to_csv(R/'quarantined_label_conflicts.csv',index=False)
 clean=df[~df.url.isin(conflicts)].drop_duplicates('url').copy()
 cleaned=len(clean);del df;gc.collect()
 archive=pd.read_csv(ROOT/'data/evaluation/live_archive_source.csv',usecols=['url','label','original_status','source_model','source_file'],keep_default_na=False)
 ac=set(archive.groupby('url').label.nunique().loc[lambda x:x>1].index)
 archive=archive[~archive.url.isin(ac)].drop_duplicates('url').copy()
 ars=[];bad=[]
 for row in archive.to_dict('records'):
  try:
   f,d=extract(row['url']);ars.append({**row,'site_key':d,**f})
  except (ValueError,UnicodeError,TypeError) as e:bad.append({'url':row['url'],'reason':str(e)})
 live=pd.DataFrame(ars);live.to_csv(ROOT/'data/evaluation/live_url20.csv',index=False)
 held=set(live.site_key);liveurls=set(live.url)
 out=ROOT/'data/processed/phreshphish_url20_all_clean.csv'
 rejected=[];rowcount=0
 with out.open('w',encoding='utf-8',newline='') as fo:
  w=csv.DictWriter(fo,fieldnames=['url','label','site_key','archive_overlap',*FEATURES]);w.writeheader()
  for row in clean.itertuples(index=False):
   try:
    f,d=extract(row.url);w.writerow({'url':row.url,'label':row.label,'site_key':d,'archive_overlap':int(d in held),**f});rowcount+=1
   except (ValueError,UnicodeError,TypeError) as e:rejected.append({'url':row.url,'label':row.label,'reason':str(e)})
   if (rowcount+len(rejected))%100000==0:print('Extracted',rowcount,'rejected',len(rejected),flush=True)
 del clean,ars,archive;gc.collect()
 data=pd.read_csv(out,dtype={k:'float32' for k in FEATURES})
 excluded=data[data.archive_overlap==1]
 excluded[['url','label','site_key']].to_csv(R/'excluded_live_archive_domains.csv',index=False)
 dev=data[data.archive_overlap==0].copy()
 groups=dev.site_key.to_numpy()
 tr,te=next(GroupShuffleSplit(n_splits=1,test_size=.1,random_state=SEED).split(dev,groups=groups))
 dev['split']='train';dev.iloc[te,dev.columns.get_loc('split')]='test'
 assert not set(dev.iloc[tr].site_key)&set(dev.iloc[te].site_key)
 assert not set(dev.site_key)&held
 dev.to_csv(ROOT/'data/processed/url20_train_test.csv',index=False)
 rows=[]
 for lab in ['legitimate','phishing']:
  z=data[data.label==lab]
  for f in FEATURES:
   vals=z[f];rows.append({'label':lab,'feature':f,'rows':len(z),'mean':float(vals.mean()),'median':float(vals.median()),'p10':float(vals.quantile(.1)),'p90':float(vals.quantile(.9)),'p99':float(vals.quantile(.99)),'nonzero_percent':100*float(vals.ne(0).mean())})
 pd.DataFrame(rows).to_csv(R/'eda_feature_distribution.csv',index=False)
 corr=data[FEATURES].corr();corr.to_csv(R/'eda_feature_correlations.csv')
 tops={lab:data.loc[data.label==lab,'site_key'].value_counts().head(15).to_dict() for lab in ['legitimate','phishing']}
 patterns={}
 for lab,z in data.groupby('label'):
  patterns[lab]={'rows':len(z),'domains':z.site_key.nunique(),'https_percent':100*float(z.has_https_scheme.mean()),'query_present_percent':100*float(z.query_length.gt(0).mean()),'root_path_depth_zero_percent':100*float(z.path_depth.eq(0).mean())}
 stats={'seed':SEED,'feature_names':FEATURES,'threshold_fixed':.5,'source_sha256':sha(source),'clean_rows_before_extractor':cleaned,'conflict_urls_quarantined':len(conflicts),'same_label_duplicates_removed':666297-cleaned-2*len(conflicts),'extraction_errors':rejected,'all_clean_rows':len(data),'all_clean_label_counts':data.label.value_counts().to_dict(),'archive_rows':len(live),'archive_label_counts':live.label.value_counts().to_dict(),'archive_original_status_counts':live.original_status.value_counts().to_dict(),'archive_extraction_errors':bad,'excluded_archive_domain_rows':len(excluded),'excluded_archive_exact_url_rows':int(excluded.url.isin(liveurls).sum()),'development_rows':len(dev),'train_rows':len(tr),'test_rows':len(te),'actual_train_percent':100*len(tr)/len(dev),'train_labels':dev.iloc[tr].label.value_counts().to_dict(),'test_labels':dev.iloc[te].label.value_counts().to_dict(),'train_domains':len(set(groups[tr])),'test_domains':len(set(groups[te])),'train_test_domain_overlap':0,'development_archive_domain_overlap':0,'patterns':patterns,'top_domains':tops,'limitations':['Raw XLSX has no date or official original split. A new domain split is used; this is not the original PhreshPhish benchmark.','5741 missing-scheme benign URLs had HTTPS assumed on user request, not network verified.','Historical archive labels are retained, not live reverified; archive has previously influenced system development.','Only URL20 model evaluated. DOM/brand rules not evaluated or modified.']}
 save('preparation_eda.json',stats)
 import matplotlib
 matplotlib.use('Agg')
 import matplotlib.pyplot as plt
 fig,axes=plt.subplots(2,3,figsize=(14,8))
 chosen=['url_length','hostname_length','path_length','domain_label_length','hostname_longest_digit_run','hostname_sensitive_token_count']
 for ax,f in zip(axes.flat,chosen):
  cap=float(data[f].quantile(.99));edges=np.linspace(0,max(cap,1),35)
  for lab,color in [('legitimate','#237a57'),('phishing','#b94a48')]:
   vals=data.loc[data.label==lab,f].clip(upper=cap);ax.hist(vals,bins=edges,density=True,alpha=.5,label=lab,color=color)
  ax.set_title(f);ax.set_ylabel('Density');ax.legend(fontsize=8)
 fig.suptitle('PhreshPhish URL features (values capped at overall p99 for display)');fig.tight_layout();fig.savefig(R/'eda_distributions.png',dpi=150);plt.close(fig)
 del data,excluded;gc.collect()
 print('PREPARATION',json.dumps(stats,default=str)[:1800],flush=True)
 return dev,live,stats

def models():
 return [
 ('XGBoost',lambda:XGBClassifier(n_estimators=650,max_depth=6,learning_rate=.05,min_child_weight=5,subsample=.85,colsample_bytree=.9,reg_lambda=1,reg_alpha=.02,tree_method='hist',objective='binary:logistic',eval_metric='logloss',n_jobs=4,random_state=SEED)),
 ('RandomForest',lambda:RandomForestClassifier(n_estimators=150,max_depth=18,max_leaf_nodes=4096,min_samples_leaf=8,max_features=.8,max_samples=.85,n_jobs=4,random_state=SEED)),
 ('ExtraTrees',lambda:ExtraTreesClassifier(n_estimators=150,max_depth=20,max_leaf_nodes=4096,min_samples_leaf=5,max_features=.85,n_jobs=4,random_state=SEED)),
 ('HistGradientBoosting',lambda:HistGradientBoostingClassifier(max_iter=350,learning_rate=.06,max_leaf_nodes=63,l2_regularization=1,early_stopping=False,random_state=SEED)),
 ('LogisticRegression',lambda:make_pipeline(StandardScaler(),LogisticRegression(max_iter=1000,C=1,random_state=SEED))) ]

def main():
 t=time.time();dev,live,prep=prepare()
 train=dev.split.eq('train').to_numpy();test=~train
 X=dev[FEATURES].to_numpy(dtype=np.float32);y=dev.label.eq('phishing').to_numpy(dtype=np.int8)
 Xtr,Xte=X[train],X[test];ytr,yte=y[train],y[test]
 XL=live[FEATURES].to_numpy(dtype=np.float32);yl=live.label.eq('phishing').to_numpy(dtype=np.int8)
 weights=compute_sample_weight('balanced',ytr)
 completed=live.original_status.eq('completed').to_numpy()
 # Fixed, reproducible class-stratified subset for contribution/permutation cost.
 sample_n=min(10000,len(yte));si,_=train_test_split(np.arange(len(yte)),train_size=sample_n,random_state=SEED,stratify=yte) if sample_n<len(yte) else (np.arange(len(yte)),None)
 results={};comparisons=[]
 for name,make in models():
  model=make();start=time.time();print('TRAINING',name,len(ytr),'rows',flush=True)
  if name=='LogisticRegression':model.fit(Xtr,ytr,logisticregression__sample_weight=weights)
  else:model.fit(Xtr,ytr,sample_weight=weights)
  prob=model.predict_proba(Xte)[:,1];lp=model.predict_proba(XL)[:,1]
  result={'test':metrics(yte,prob),'historical_archive_all_url_text':metrics(yl,lp),'historical_archive_previously_completed':metrics(yl[completed],lp[completed]),'fit_and_predict_seconds':round(time.time()-start,2),'parameters':model.get_params(deep=False)}
  joblib.dump({'model':model,'features':FEATURES,'threshold':.5,'label_mapping':{'legitimate':0,'phishing':1}},ROOT/'models'/f'{name}.joblib',compress=3)
  pd.DataFrame({'url':dev.loc[test,'url'],'label':dev.loc[test,'label'],'probability_phishing':prob,'prediction':np.where(prob>=.5,'phishing','legitimate'),'correct':(prob>=.5)==yte}).to_csv(R/f'{name}_test_predictions.csv',index=False)
  pred=live[['url','label','site_key','original_status','source_model','source_file']].copy();pred['probability_phishing']=lp;pred['prediction']=np.where(lp>=.5,'phishing','legitimate');pred['correct']=(lp>=.5)==yl;pred.to_csv(R/f'{name}_archive_predictions.csv',index=False)
  estimator=model[-1] if name=='LogisticRegression' else model
  imp=getattr(estimator,'feature_importances_',None)
  if imp is not None:pd.DataFrame({'feature':FEATURES,'importance_percent':100*imp/imp.sum()}).sort_values('importance_percent',ascending=False).to_csv(R/f'{name}_native_importance.csv',index=False)
  if name=='XGBoost':
   model.save_model(ROOT/'models/XGBoost.json')
   print('Computing XGBoost feature contributions and permutation checks',flush=True)
   contrib=model.get_booster().predict(xgboost.DMatrix(Xte[si],feature_names=None),pred_contribs=True)
   absmean=np.abs(contrib[:,:20]).mean(axis=0);share=100*absmean/absmean.sum()
   # Fixed 5000-row stratified subset, two repeats; no parameter selection.
   pi_idx,_=train_test_split(si,train_size=5000,random_state=SEED,stratify=yte[si]) if len(si)>5000 else (si,None)
   pi=permutation_importance(model,Xte[pi_idx],yte[pi_idx],scoring='balanced_accuracy',n_repeats=2,random_state=SEED,n_jobs=1)
   rows=[]
   for j,f in enumerate(FEATURES):
    rows.append({'feature':f,'mean_absolute_shap_log_odds':float(absmean[j]),'shap_contribution_share_percent':float(share[j]),'mean_shap_legitimate_log_odds':float(contrib[yte[si]==0,j].mean()),'mean_shap_phishing_log_odds':float(contrib[yte[si]==1,j].mean()),'gain_importance_percent':float(100*imp[j]/imp.sum()),'permutation_balanced_accuracy_drop_percentage_points':float(100*pi.importances_mean[j]),'permutation_std_percentage_points':float(100*pi.importances_std[j])})
   pd.DataFrame(rows).sort_values('shap_contribution_share_percent',ascending=False).to_csv(R/'xgboost_feature_influence_20.csv',index=False)
   result['explanation']={'tree_shap_rows':len(si),'permutation_rows':len(pi_idx),'permutation_repeats':2,'meaning':'Normalized mean absolute TreeSHAP contribution to model log-odds, not causal influence or single-feature accuracy. Shares sum to 100 across 20 features, excluding intercept. Permutation is test balanced-accuracy drop; correlated features may share effects.','sample_seed':SEED}
  results[name]=result
  for scope in ['test','historical_archive_all_url_text','historical_archive_previously_completed']:comparisons.append({'model':name,'scope':scope,**result[scope]})
  pd.DataFrame(comparisons).to_csv(R/'model_comparison.csv',index=False)
  save('training_results.json',{'models':results,'threshold':.5,'seed':SEED,'validation_split':False,'early_stopping':False,'class_weighting':'balanced weights computed from training only; no row undersampling','feature_names':FEATURES,'environment':{'python':platform.python_version(),'sklearn':sklearn.__version__,'xgboost':xgboost.__version__},'elapsed_seconds':time.time()-t})
  print('RESULT',name,json.dumps({k:result[k] for k in ['test','historical_archive_all_url_text','historical_archive_previously_completed']}),flush=True)
  del model,estimator,prob,lp,pred;gc.collect()
 print('DONE elapsed seconds',round(time.time()-t),flush=True)

if __name__=='__main__':main()
