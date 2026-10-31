"""Verify one authentic browser operation and its finalized callback chain."""
import argparse,json
from pathlib import Path
from network import client,operation,atomic,succeeded

p=argparse.ArgumentParser(description=__doc__);p.add_argument('step');args=p.parse_args()
path=Path('evidence/email-admission-v2.json');e=json.loads(path.read_text());d=json.loads(Path('deployments/studionet.json').read_text());assert e['release_id']==d['release_id']
s=e['steps'][args.step];name='email-v2-'+d['release_id'][:12]+'-'+args.step
c=client();journal=Path('deployments/operations')/(name+'.json')
if not journal.exists():atomic(journal,{'operation_id':name,'api_operation_id':s['operation_id'],'transaction_hash':s['transaction_hash'],'network':'studionet','status':'BROADCAST'})
r=operation(c,name,lambda:None);assert r['from_address'].lower()==e['wallet'].lower()
def callbacks(receipt,parent):
    for index,tx in enumerate(receipt.get('triggered_transactions',[])):
        childname=parent+'-child'+str(index);j=Path('deployments/operations')/(childname+'.json')
        if not j.exists():atomic(j,{'operation_id':childname,'transaction_hash':tx,'network':'studionet','status':'BROADCAST'})
        child=operation(c,childname,lambda:None,expected_success=s['method']!='reserve_assessment')
        callbacks(child,childname)
callbacks(r,name)
consumer=d['contracts']['incident_consumer']['address'];docket=d['contracts']['relation_docket']['address'];hub=d['contracts']['certificate_hub']['address']
def read(address,method,params):return c.read_contract(address=address,function_name=method,args=params)
if s['method']=='accept_owner':assert read(consumer,'get_authority',[])['owner'].lower()==e['wallet'].lower()
if s['method']=='open_batch':
    request=json.loads(s['args'][0]);e['request_id']=request['request_id'];assert request['owner'].lower()==e['wallet'].lower()
    batch=read(docket,'get_batch',[e['request_id']]);assert batch['subject_text']==e['claim'] and batch['consequence_text']==e['consequence']
    assert len(batch['manifest'])==3;e['batch']=batch
if s['method'] in ['reserve_assessment','seal_batch']:
    batch=read(docket,'get_batch',[e['request_id']]);e['batch']=batch
    if s['method']=='reserve_assessment':
        pair=str(s['args'][3])+':'+str(s['args'][4]);s['pair_applied']=pair in batch['pairs'];s['attempts_consumed']=batch['attempts'][pair]
        if s['pair_applied']:assert batch['pairs'][pair]['relation']=='INDEPENDENT'
    else:assert read(hub,'get_certificate',[e['request_id']+':1'])['selected_subset']==[0,1,2]
if s['method']=='configure':
    state=read(consumer,'get_state',[e['request_id']]);assert state['configuration']==json.loads(s['args'][1])
    assert state['subscription_digest'] and state['configuration_operation']==s['args'][0]
    assert s['args'][2] is True;s['owner_relevance_attestation']=True
if s['method']=='deliver_certificate':assert read(hub,'get_delivery',[s['args'][0]])['acknowledgement']['certificate_id']==e['request_id']+':1'
if s['method']=='admit_incident':
    action=read(consumer,'get_action',[s['args'][0]]);assert action['status']=='ADMITTED' and action['request_id']==e['request_id'];e['admission']=action;e['complete_email_to_admission']=True
s.update(finalized=True,verified=True,receipt_path='evidence/receipts/'+name+'.json');atomic(path,e)
print('Authentic email browser step verified:',args.step,flush=True)
