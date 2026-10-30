"""Actual signed, multi-validator Studio acceptance with clearly authored fixtures."""
import json,os,re,hashlib,time,urllib.request,subprocess,sys
from pathlib import Path
from eth_account import Account
from network import client,operation,atomic,succeeded
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)
if Path('evidence/fixture-recovery-inputs.json').exists():
 raise SystemExit(subprocess.run([sys.executable, str(ROOT/'scripts/studio_resume.py')]).returncode)
d=json.loads(Path('deployments/studionet.json').read_text())
c=client();owner=Account.from_key(os.environ['DEPLOYER_PRIVATE_KEY']).address
registry=d['contracts']['source_registry']['address'];docket=d['contracts']['relation_docket']['address'];hub=d['contracts']['certificate_hub']['address']

def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(x):return hashlib.sha256(x.encode() if isinstance(x,str) else x).hexdigest()
def read(address,method,args):return c.read_contract(address=address,function_name=method,args=args)
def write(op,address,method,args,who=c,success=True):return operation(who,op,lambda:who.write_contract(address=address,function_name=method,args=args),expected_success=success)
def committed(name,url,revision=1):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=30) as response:raw=response.read(49153)
 assert 0<len(raw)<=49152
 Path('evidence/sources').mkdir(parents=True,exist_ok=True)
 (Path('evidence/sources')/(sha(raw)+'.txt')).write_bytes(raw)
 return {'record_id':name,'authority':name,'channel':'public','url':url,'capture_url':url,'byte_hash':sha(raw),'byte_length':len(raw),'revision':revision,'scope':'Original reporting or measurement and public editorial control','spans':[{'span_id':'complete','start':0,'end':len(raw),'quote_hash':sha(raw)}]}

def maximum(sources,pairs):
 best=[]
 for mask in range(1<<len(sources)):
  subset=[i for i in range(len(sources)) if mask&(1<<i)]
  if all(sources[a]['publisher_id']!=sources[b]['publisher_id'] and pairs[f'{a}:{b}']['relation']=='INDEPENDENT' and pairs[f'{a}:{b}']['witnesses'] for i,a in enumerate(subset) for b in subset[i+1:]) and len(subset)>len(best):best=subset
 return best

def children(parent_receipt,op):
 # Verify emitted finalized messages, not merely synchronous views.
 parent=parent_receipt if parent_receipt.get('triggered_transactions') else c.get_transaction(parent_receipt['hash'])
 hashes=parent.get('triggered_transactions',[])
 if not hashes:
  for _ in range(12):
   time.sleep(5);parent=c.get_transaction(parent_receipt['hash']);hashes=parent.get('triggered_transactions',[])
   if hashes:break
 for i,h in enumerate(hashes):
  if isinstance(h,dict):h=h.get('hash') or h.get('transaction_hash')
  path=Path('deployments/operations')/(op+'-child'+str(i)+'.json');atomic(path,{'transaction_hash':h,'operation_id':op+'-child'+str(i)})
  child_receipt=operation(c,op+'-child'+str(i),lambda:h)
  for j,ack_hash in enumerate(child_receipt.get('triggered_transactions',[])):
   ack_op=op+'-child'+str(i)+'-ack'+str(j)
   ack_path=Path('deployments/operations')/(ack_op+'.json');atomic(ack_path,{'transaction_hash':ack_hash,'operation_id':ack_op})
   operation(c,ack_op,lambda:ack_hash)
 return hashes

origin_file=Path('evidence/fixture-origin.json')
if origin_file.exists():origin=json.loads(origin_file.read_text())['origin']
else:
 origin=re.search(r'https://[a-z0-9-]+\.trycloudflare\.com',Path('.runtime/fixture-tunnel.log').read_text()).group(0)
 atomic(origin_file,{'origin':origin,'classification':'authored controlled validation fixtures','lifetime':'temporary validation tunnel; source unavailable when stopped'})
input_file=Path('evidence/scenario-inputs.json')
if input_file.exists():inputs=json.loads(input_file.read_text())
else:
 sources={}
 for family in ['wire','measurement']:
  for i in range(3):
   name=f'controlled_{family}{i}';pub=committed(name,origin+f'/{family}{i}.txt');aff=committed(name+'_owner',origin+f'/{family}-owner{i}.txt')
   sources[name]={'publisher_id':name,'publisher_revision':1,'publication':pub,'ownership':aff}
 inputs={'sources':sources,'requests':{}}
 for kind in ['incident','disclosure']:
  for family in ['wire','measurement']:
   key=f'controlled_{family}_{kind}';manifest=[sources[f'controlled_{family}{i}'] for i in range(3)]
   inputs['requests'][key]={'request_id':key,'owner':owner,'parties':[owner],'policy_id':'three_origins','policy_revision':1,'subject_id':f'Controlled {family} reporting for {kind}','subject_digest':sha('Controlled river level fixture, not real incident'),'manifest_digest':sha(canon(manifest)),'consumer':d['contracts'][kind+'_consumer']['address'],'consequence_digest':sha('Admit controlled validation request'),'generation':1,'deadline':'2026-11-06T00:00:00+00:00'}
 atomic(input_file,inputs)
for name,s in inputs['sources'].items():write('register-'+name,registry,'register_publisher',['register-'+name,name,owner,canon(s['ownership'])])
results=json.loads(Path("evidence/scenario-results.json").read_text()) if Path("evidence/scenario-results.json").exists() else {}
for key,request in inputs['requests'].items():
 if key in results:continue
 family='wire' if '_wire_'in key else 'measurement';kind='incident' if key.endswith('incident') else 'disclosure';manifest=[inputs['sources'][f'controlled_{family}{i}'] for i in range(3)]
 write('open-'+key,docket,'open_batch',[canon(request),canon(manifest)])
 batch=read(docket,'get_batch',[key])
 if key=='controlled_measurement_disclosure' and batch['generation']==1 and batch['pairs'].get('1:2',{}).get('rule_id')=='R_UNAVAILABLE':
  atomic('evidence/disclosure-unavailable-recovery.json',{'classification':'Preserved unavailable assessment before authorized prepublication appeal','batch':batch})
  write('appeal-disclosure-unavailable-g1',docket,'appeal_relation',['appeal-disclosure-unavailable-g1',key,1,1,2])
  batch=read(docket,'get_batch',[key])
 generation=batch['generation'];suffix='' if generation==1 else '-g'+str(generation)
 consumer=request['consumer'];who=client('INCIDENT_OWNER_PRIVATE_KEY' if kind=='incident' else 'DISCLOSURE_OWNER_PRIVATE_KEY');config={k:batch[k] for k in ['request_id','policy_id','policy_revision','subject_id','subject_digest','manifest_digest','consumer','consequence_digest','generation','deadline']}
 r=write('configure-'+key+suffix,consumer,'configure',['configure-'+key+suffix,canon(config)],who);children(r,'configure-'+key+suffix)
 for a in range(3):
  for b in range(a+1,3):write(f'assess-{key}{suffix}-{a}-{b}',docket,'assess_pair',[key,generation,a,b])
 batch=read(docket,'get_batch',[key]);selected=maximum(manifest,batch['pairs'])
 if family=='wire':assert len(selected)<3,('Copied domains inflated',batch)
 else:assert selected==[0,1,2],('Independent fixtures did not pass',batch)
 r=write('seal-'+key+suffix,docket,'seal_batch',[key,generation,canon(selected)]);children(r,'seal-'+key+suffix)
 cert=read(hub,'get_certificate',[key+':'+str(generation)]);assert cert['selected_subset']==selected
 r=write('deliver-'+key+suffix,hub,'deliver_certificate',['deliver-'+key+suffix,key+':'+str(generation),consumer]);children(r,'deliver-'+key+suffix)
 ack=read(hub,'get_delivery',['deliver-'+key+suffix]);assert ack['acknowledgement'] and ack['acknowledgement']['generation']==generation
 state=read(consumer,'get_state',[key]);assert state['receipt'] and state['last_generation']==generation
 r=write('admit-'+key+suffix,consumer,'admit_incident' if kind=='incident' else 'admit_disclosure',['admit-'+key+suffix,key,request['subject_digest'],request['consequence_digest']],who,success=family=='measurement')
 assert succeeded(r)==(family=='measurement')
 # Duplicate finalized callback delivery, including durable acknowledgement.
 r=write('duplicate-'+key+suffix,hub,'deliver_certificate',['deliver-'+key+suffix,key+':'+str(generation),consumer]);children(r,'duplicate-'+key+suffix)
 results[key]={'generation':generation,'subset':selected,'certificate':cert['status'],'admission':family=='measurement','delivery_acknowledged':True,'pair_vector':{k:v['relation'] for k,v in batch['pairs'].items()}}
 atomic('evidence/scenario-results.json',results)
# Mutated subset is refused even when JSON is syntactically valid.
key='controlled_measurement_incident';req=inputs['requests'][key]
r=write('mutated-seal',docket,'seal_batch',[key,results[key].get('generation',1),'[0,1]'],success=False);assert not succeeded(r)
# An outsider cannot correct a publisher or approve application configurations.
r=write('unauthorized-correction',registry,'correct_affiliation',['unauthorized','controlled_measurement2',canon(inputs['sources']['controlled_measurement2']['ownership']),False],client('DISCLOSURE_OWNER_PRIVATE_KEY'),False);assert not succeeded(r)
# A corrected relationship freezes both independently controlled consumers immediately.
corrected=committed('controlled_measurement2_owner_v2',origin+'/corrected-owner2.txt',2)
write('correct-real-affiliation',registry,'correct_affiliation',['correct-real-affiliation','controlled_measurement2',canon(corrected),False])
for kind in ['incident','disclosure']:
 if results.get(f'controlled_measurement_{kind}',{}).get('corrected_admission') is False:continue
 key=f'controlled_measurement_{kind}';req=inputs['requests'][key];who=client('INCIDENT_OWNER_PRIVATE_KEY' if kind=='incident' else 'DISCLOSURE_OWNER_PRIVATE_KEY')
 r=write('frozen-admission-'+kind,req['consumer'],'admit_'+('incident' if kind=='incident' else 'disclosure'),['fresh-after-correction-'+kind,key,req['subject_digest'],req['consequence_digest']],who,False);assert not succeeded(r)
 r=write('stale-delivery-'+kind,hub,'deliver_certificate',['stale-'+kind,key+':'+str(results[key].get('generation',1)),req['consumer']],success=False);assert not succeeded(r)
 manifest=[dict(inputs['sources'][f'controlled_measurement{i}']) for i in range(3)];manifest[2]['publisher_revision']=2;manifest[2]['ownership']=corrected
 write('successor-'+kind,docket,'acknowledge_revision',['successor-'+kind,key,canon(manifest),req['deadline']])
 successor=read(docket,'get_batch',[key]);generation=successor['generation']
 for a in range(3):
  for b in range(a+1,3):write(f'reassess-{kind}-g{generation}-{a}-{b}',docket,'assess_pair',[key,generation,a,b])
 batch=read(docket,'get_batch',[key]);selected=maximum(manifest,batch['pairs']);assert len(selected)<3
 r=write('reseal-'+kind+'-g'+str(generation),docket,'seal_batch',[key,generation,canon(selected)]);children(r,'reseal-'+kind+'-g'+str(generation))
 config={k:batch[k] for k in ['request_id','policy_id','policy_revision','subject_id','subject_digest','manifest_digest','consumer','consequence_digest','generation','deadline']}
 r=write('reconfigure-'+kind,req['consumer'],'configure',['reconfigure-'+kind,canon(config)],who);children(r,'reconfigure-'+kind)
 r=write('replacement-delivery-'+kind,hub,'deliver_certificate',['replacement-'+kind,key+':'+str(generation),req['consumer']]);children(r,'replacement-delivery-'+kind)
 r=write('reduced-admission-'+kind,req['consumer'],'admit_'+kind,['reduced-'+kind,key,req['subject_digest'],req['consequence_digest']],who,False);assert not succeeded(r)
 delivery=read(hub,'get_delivery',['replacement-'+kind]);assert delivery['acknowledgement'] and delivery['acknowledgement']['generation']==generation
 state=read(req['consumer'],'get_state',[key]);assert state['last_generation']==generation and state['receipt']['selected_subset']==selected
 results[key]['corrected_generation']=generation;results[key]['corrected_subset']=selected;results[key]['corrected_admission']=False;results[key]['replacement_acknowledged']=True
 atomic('evidence/scenario-results.json',results)
atomic('evidence/scenario-results.json',results)
print('Signed copied, independent and corrected scenarios verified for both consumers',flush=True)
