"""Network checks for deadlines, a complete six source matrix, appeals and source limits."""
import json,os,hashlib,time
from pathlib import Path
from datetime import datetime,timezone,timedelta
from network import client,operation,atomic,succeeded
from eth_account import Account
os.chdir(Path(__file__).resolve().parents[1]);c=client('PROBE_PRIVATE_KEY');owner=Account.from_key(os.environ['PROBE_PRIVATE_KEY']).address
d=json.loads(Path('deployments/studionet.json').read_text());docket=d['contracts']['relation_docket']['address'];registry=d['contracts']['source_registry']['address'];hub=d['contracts']['certificate_hub']['address'];inputs=json.loads(Path('evidence/scenario-inputs.json').read_text());sources=[]
for name,src in inputs['sources'].items():
 src=dict(src);pub=c.read_contract(address=registry,function_name='get_publisher',args=[name]);src['publisher_revision']=pub['revision'];src['ownership']=pub['evidence'];sources.append(src)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(x):return hashlib.sha256(x.encode()).hexdigest()
def write(op,method,args,success=True):return operation(c,op,lambda:c.write_contract(address=docket,function_name=method,args=args),expected_success=success)
def read():return c.read_contract(address=docket,function_name='get_batch',args=['controlled_six_source_matrix'])
request={'request_id':'controlled_six_source_matrix','owner':owner,'parties':[owner],'policy_id':'three_origins','policy_revision':1,'subject_id':'Controlled complete six source relation matrix','subject_digest':sha('Controlled matrix test'),'manifest_digest':sha(canon(sources)),'consumer':d['contracts']['incident_consumer']['address'],'consequence_digest':sha('Controlled inspection, no application admission'),'generation':1,'deadline':'2026-11-06T00:00:00Z'}
write('open-six-source','open_batch',[canon(request),canon(sources)])
for a in range(6):
 for b in range(a+1,6):
  if a==4 and b==5:
   r=write('refuse-fourteen-pair-seal','seal_batch',[request['request_id'],1,'[0,3,4,5]'],False);assert not succeeded(r)
  write(f'assess-six-{a}-{b}','assess_pair',[request['request_id'],1,a,b])
batch=read();assert len(batch['pairs'])==15
best=[]
for mask in range(64):
 subset=[i for i in range(6) if mask&(1<<i)]
 if all(batch['pairs'][f'{a}:{b}']['relation']=='INDEPENDENT' for i,a in enumerate(subset) for b in subset[i+1:]) and len(subset)>len(best):best=subset
write('seal-complete-six-source','seal_batch',[request['request_id'],1,canon(best)])
sealed=read();assert sealed['selected_subset']==best and len(sealed['pairs'])==15
# A different request exercises appeal before publication without discarding the sealed matrix.
appealed=dict(request,request_id='controlled_prepublication_appeal',manifest_digest=sha(canon(sources[:2])))
write('open-prepublication-appeal','open_batch',[canon(appealed),canon(sources[:2])])
write('assess-prepublication-appeal','assess_pair',[appealed['request_id'],1,0,1])
write('appeal-before-publication','appeal_relation',['appeal-before-publication',appealed['request_id'],1,0,1])
after=c.read_contract(address=docket,function_name='get_batch',args=[appealed['request_id']]);assert after['generation']==2 and after['pairs']=={}
r=write('appealed-matrix-cannot-publish','seal_batch',[appealed['request_id'],2,'[0]'],False);assert not succeeded(r)
# Validate explicit input ceiling without truncation.
large=json.dumps(dict(request,request_id='oversize',subject_id='x'*25000));r=write('oversized-request','open_batch',[large,canon(sources)],False);assert not succeeded(r)
# Deadlines use the supported transaction timestamp. The initial write locks a near future deadline.
timed=dict(request,request_id='controlled_deadline',manifest_digest=sha(canon(sources[:2])),deadline=(datetime.now(timezone.utc)+timedelta(seconds=65)).isoformat())
write('open-deadline','open_batch',[canon(timed),canon(sources[:2])]);
timed=c.read_contract(address=docket,function_name='get_batch',args=[timed['request_id']])
while datetime.now(timezone.utc)<=datetime.fromisoformat(timed['deadline']):time.sleep(5)
r=write('expired-assessment','assess_pair',[timed['request_id'],1,0,1],False);assert not succeeded(r)
write('expire-deadline','expire_batch',[timed['request_id']]);expired=c.read_contract(address=docket,function_name='get_batch',args=[timed['request_id']]);assert expired['status']=='TIMEOUT'
atomic('evidence/bounds-results.json',{'six_source_pairs':15,'subset_checks':64,'selected_before_appeal':best,'fourteen_pair_seal_refused':True,'appeal_before_publication_freezes_entire_matrix':True,'oversized_request_refused':True,'deadline_uses_transaction_time':True,'expired_status':expired['status'],'sources':[{'publisher_id':s['publisher_id'],'revision':s['publisher_revision']} for s in sources]})
print('Six source, appeal, deadline and limit network checks passed',flush=True)
