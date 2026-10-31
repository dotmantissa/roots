"""Exercise the corrected stack with authentic receipts and labelled public fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from network import client, operation, atomic, succeeded

ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prepare',action='store_true',help='Prepare and assess browser-owned incident batch; do not sign its approval')
args=parser.parse_args()
d=json.loads(Path('deployments/studionet.json').read_text())
assert d.get('schema_version')==2,'A verified v2 stack is required'
c=client();disclosure=client('DISCLOSURE_OWNER_PRIVATE_KEY')
registry=d['contracts']['source_registry']['address'];docket=d['contracts']['relation_docket']['address'];hub=d['contracts']['certificate_hub']['address']
prefix='review-'+d['release_id'][:12]
owner=d['owners']['registry']
origin=os.environ.get('PUBLIC_FIXTURE_ORIGIN','https://roots-mauve-delta.vercel.app')

def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(x):return hashlib.sha256(x.encode() if isinstance(x,str) else x).hexdigest()
def read(address,method,values):return c.read_contract(address=address,function_name=method,args=values)
def write(name,address,method,values,who=c,success=True):return operation(who,prefix+'-'+name,lambda:who.write_contract(address=address,function_name=method,args=values),expected_success=success)
def children(receipt,name,success=True):
    results=[]
    for i,tx in enumerate(receipt.get('triggered_transactions',[])):
        op=prefix+'-'+name+'-child'+str(i)
        p=Path('deployments/operations')/(op+'.json')
        if not p.exists():atomic(p,{'operation_id':op,'transaction_hash':tx,'network':'studionet','status':'BROADCAST'})
        child=operation(c,op,lambda:None,expected_success=success);results.append(child)
        for ai,ackhash in enumerate(child.get('triggered_transactions',[])):
            ackop=op+'-ack'+str(ai);p=Path('deployments/operations')/(ackop+'.json')
            if not p.exists():atomic(p,{'operation_id':ackop,'transaction_hash':ackhash,'network':'studionet','status':'BROADCAST'})
            operation(c,ackop,lambda:None,expected_success=success)
    return results

def record(record_id,filename,revision=1):
    body=Path('tests/fixtures/public',filename).read_bytes()
    # Full and shorter committed spans provide realistic citation alternatives.
    end=body.find(b'. ')+1
    spans=[{'span_id':'complete','start':0,'end':len(body),'quote_hash':sha(body)}]
    if end>0:spans.append({'span_id':'opening','start':0,'end':end,'quote_hash':sha(body[:end])})
    return {'record_id':record_id,'authority':'Authored controlled validation organization','channel':'public','url':origin+'/validation/'+filename,'capture_url':origin+'/validation/'+filename,'byte_hash':sha(body),'byte_length':len(body),'revision':revision,'scope':'Labelled controlled ancestry and public organizational authority test','spans':spans}

input_path=Path('evidence/review-v2-inputs.json')
if input_path.exists():
    inputs=json.loads(input_path.read_text());assert inputs['release_id']==d['release_id'],'Retained inputs belong to a different stack'
else:
    sources=[{'publisher_id':'controlled_v2_measurement'+str(i),'publisher_revision':1,'publication':record(['a','a:b','c'][i],'measurement'+str(i)+'.txt'),'ownership':record(['c:d','e','f'][i],'measurement-owner'+str(i)+'.txt')} for i in range(3)]
    wire=[{'publisher_id':'controlled_v2_wire'+str(i),'publisher_revision':1,'publication':record('wire:'+str(i),'injection.txt' if i==0 else 'wire'+str(i)+'.txt'),'ownership':record('wire-owner:'+str(i),'wire-owner'+str(i)+'.txt')} for i in range(2)]
    requests={}
    for kind,manifest in [('incident',sources),('disclosure',sources),('normal_injection',wire)]:
        consumer=d['contracts']['disclosure_consumer' if kind!='incident' else 'incident_consumer']['address']
        claim='Controlled fixture verification: authored independent river measurements.' if kind!='normal_injection' else 'Controlled normal-path injected copied dispatch; no forced leader mutation.'
        decision='Admit document ancestry only after application-owner relevance review.'
        requests[kind]={'request_id':'controlled_v2_'+kind,'owner':owner,'parties':[owner],'policy_id':'three_origins','policy_revision':1,'subject_id':'Controlled v2 '+kind,'subject_text':claim,'subject_digest':sha(claim),'manifest_digest':sha(canon(manifest)),'consumer':consumer,'consequence_text':decision,'consequence_digest':sha(decision),'admission_scope':'DOCUMENT_ANCESTRY','generation':1,'deadline':(datetime.now(timezone.utc)+timedelta(days=7)).isoformat()}
    inputs={'release_id':d['release_id'],'classification':'Authored controlled public fixtures, not real incidents or adoption','sources':sources,'wire':wire,'requests':requests}
    atomic(input_path,inputs)
for source in inputs['sources']+inputs['wire']:
    write('enroll-'+source['publisher_id'],registry,'register_publisher',[prefix+'-enroll-'+source['publisher_id'],source['publisher_id'],owner,canon(source['ownership'])])
# Self-enrollment and unreserved direct assessments must fail on the real VM.
r=write('reject-self-enrollment',registry,'register_publisher',[prefix+'-squat','recognizable_organization',d['owners']['disclosure'],canon(inputs['sources'][0]['ownership'])],disclosure,False)
assert not succeeded(r)
results={}
for kind,request in inputs['requests'].items():
    manifest=inputs['wire'] if kind=='normal_injection' else inputs['sources']
    write('open-'+kind,docket,'open_batch',[canon(request),canon(manifest)])
    if kind=='incident':
        r=write('reject-direct-assessment',docket,'assess_pair',[request['request_id'],1,0,1,prefix+'-fake'],success=False);assert not succeeded(r)
        r=write('reject-unchanged-reset',docket,'acknowledge_revision',[prefix+'-reset',request['request_id'],canon(manifest),request['deadline']],success=False);assert not succeeded(r)
    for left in range(len(manifest)):
        for right in range(left+1,len(manifest)):
            pair=str(left)+':'+str(right)
            for attempt in range(1,4):
                state=read(docket,'get_batch',[request['request_id']])
                if pair in state['pairs']:break
                name=f'assess-{kind}-{left}-{right}-{attempt}'
                reserve=write(name,docket,'reserve_assessment',[prefix+'-'+name,request['request_id'],1,left,right])
                outcomes=children(reserve,name,success=False)
                state=read(docket,'get_batch',[request['request_id']])
                if pair in state['pairs']:break
                assert state['attempts'][pair]>=attempt,'Failed child did not preserve its reserved attempt'
            assert pair in state['pairs'],'Three consumed attempts left this case unresolved; receipts are retained'
    batch=read(docket,'get_batch',[request['request_id']])
    expected=[0] if kind=='normal_injection' else [0,1,2]
    if kind=='normal_injection':assert batch['pairs']['0:1']['relation']=='SHARED_ORIGIN','Normal injection did not establish copied origin'
    else:assert all(p['relation']=='INDEPENDENT' for p in batch['pairs'].values()),'Independent fixture remained unresolved'
    receipt=write('seal-'+kind,docket,'seal_batch',[request['request_id'],1,canon(expected)]);children(receipt,'seal-'+kind)
    # An exact publication retry must re-emit in the same generation.
    retry=write('retry-publication-'+kind,docket,'seal_batch',[request['request_id'],1,canon(expected)]);assert retry.get('triggered_transactions');children(retry,'retry-publication-'+kind)
    cert=read(hub,'get_certificate',[request['request_id']+':1'])
    assert cert['selected_subset']==expected and cert['generation']==1
    assert read(docket,'publication_state',[request['request_id']])['published']
    assert cert['batch_digest']==sha(canon({'version':2,'request':request}))
    result={'generation':1,'selected_subset':expected,'pair_relations':{k:v['relation'] for k,v in cert['pairs'].items()},'certificate_id':cert['certificate_id'],'batch_commitment_verified':True,'publication_retry_same_generation':True,'normal_unmodified_execution':True,'accepted_witnesses':{k:v['witnesses'] for k,v in cert['pairs'].items()}}
    if kind=='disclosure':
        fields=['request_id','policy_id','policy_revision','subject_id','subject_digest','subject_text','manifest_digest','consumer','consequence_digest','consequence_text','admission_scope','generation','deadline']
        config={k:cert[k] for k in fields};consumer=request['consumer'];op=prefix+'-configure-disclosure'
        r=write('reject-unreviewed-configuration',consumer,'configure',[op,canon(config),False],disclosure,False);assert not succeeded(r)
        r=write('configure-disclosure',consumer,'configure',[op,canon(config),True],disclosure);children(r,'configure-disclosure')
        r=write('retry-subscription-disclosure',consumer,'configure',[op,canon(config),True],disclosure);assert r.get('triggered_transactions');children(r,'retry-subscription-disclosure')
        deliverop=prefix+'-deliver-disclosure';r=write('deliver-disclosure',hub,'deliver_certificate',[deliverop,cert['certificate_id'],consumer]);children(r,'deliver-disclosure')
        assert read(hub,'get_delivery',[deliverop])['acknowledgement']['certificate_id']==cert['certificate_id']
        r=write('admit-disclosure',consumer,'admit_disclosure',[prefix+'-admit-disclosure',request['request_id'],request['subject_digest'],request['consequence_digest']],disclosure)
        assert succeeded(r);result.update(owner_relevance_attestation_required=True,subscription_retry_same_generation=True,finalized_delivery_acknowledged=True,admitted=True)
    results[kind]=result
    atomic('evidence/consensus-v2.json',{'release_id':d['release_id'],'classification':inputs['classification'],'results':results,'limitations':['Public-fixture outcomes establish controlled execution, not universal semantic reliability. Historical public copied-source disagreement is retained without attributing its cause.']})
print('Corrected stack scenarios passed with authentic finalized receipts; incident certificate is ready for email-owner browser approval.',flush=True)
