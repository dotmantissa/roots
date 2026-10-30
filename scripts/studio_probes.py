import json,os,hashlib,urllib.request,time
from pathlib import Path
from eth_account import Account
from network import client,operation,atomic,succeeded
from genlayer_py.types import TransactionStatus
os.chdir(Path(__file__).resolve().parents[1])
if not os.environ.get('PROBE_PRIVATE_KEY'):
 key='0x'+Account.create().key.hex()
 with Path('.env').open('a') as f:f.write('PROBE_PRIVATE_KEY='+key+'\n')
 os.environ['PROBE_PRIVATE_KEY']=key
if not os.environ.get('ATTACKS_PRIVATE_KEY'):
 key='0x'+Account.create().key.hex()
 with Path('.env').open('a') as f:f.write('ATTACKS_PRIVATE_KEY='+key+'\n')
 os.environ['ATTACKS_PRIVATE_KEY']=key
c=client('ATTACKS_PRIVATE_KEY')
code=Path('tests/integration/validator_probe.py').read_bytes();h=hashlib.sha256(code).hexdigest()
r=operation(c,'deploy-validator-probe-'+h[:12],lambda:c.deploy_contract(code=code,args=[]));address=r['data']['contract_address']
atomic('deployments/validator-probe.json',{'address':address,'source_hash':h,'network':'studionet','purpose':'adversarial validator validation, not production verdicts'})
inputs=json.loads(Path('evidence/scenario-inputs.json').read_text());s=inputs['sources']
wire=[s['controlled_wire0']['publication'],s['controlled_wire0']['ownership'],s['controlled_wire1']['publication'],s['controlled_wire1']['ownership']]

def public_record(name,url):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=30) as response:body=response.read(49153)
 assert len(body)<=49152
 digest=hashlib.sha256(body).hexdigest();Path('evidence/sources').mkdir(exist_ok=True);(Path('evidence/sources')/(digest+'.txt')).write_bytes(body)
 return {'record_id':name,'authority':name,'channel':'public','url':url,'capture_url':url,'byte_hash':digest,'byte_length':len(body),'revision':1,'scope':'Public scientific reporting process and organization','spans':[{'span_id':'complete','start':0,'end':len(body),'quote_hash':digest}]}

origin=json.loads(Path('evidence/fixture-origin.json').read_text())['origin']
# True public sources, no synthesized text. Whole source commitments are retained.
public=[public_record('NASA_Worldview','https://raw.githubusercontent.com/nasa-gibs/worldview/main/README.md'),public_record('NASA','https://api.github.com/orgs/nasa-gibs'),public_record('NOAA_workflow','https://raw.githubusercontent.com/NOAA-EMC/global-workflow/develop/README.md'),public_record('NOAA','https://api.github.com/orgs/NOAA-EMC')]
adverse=[public[0],public[1],public_record('NASA_mirrored_publication','https://raw.githubusercontent.com/nasa-gibs/worldview/master/README.md'),public_record('NASA_mirrored_authority','https://api.github.com/orgs/nasa-gibs')]
injected=[public_record('controlled_injection',origin+'/injection.txt'),wire[1],wire[2],wire[3]]
changed=[dict(x) for x in wire];changed[0]['byte_hash']='0'*64
cases=[('public-positive',public,'none',True),('public-copied',adverse,'none',False),('wrong-verdict',wire,'wrong_verdict',False),('omitted-exception',wire,'omitted_exception',False),('forged-span',wire,'forged_span',False),('injection',injected,'injection',False),('source-change',changed,'none',False)]
results=json.loads(Path('evidence/validator-probe-results.json').read_text()) if Path('evidence/validator-probe-results.json').exists() else {}
for name,records,mutation,expected in cases:
 if name in results:continue
 atomic('evidence/probe-input-'+name+'.json',records)
 started=time.monotonic()
 r=operation(c,'probe-'+name,lambda records=records,mutation=mutation,name=name:c.write_contract(address=address,function_name='probe',args=[name,json.dumps(records),mutation]),expected_success=expected)
 state=c.read_contract(address=address,function_name='get_probe',args=[name])
 assert state['accepted']==expected,(name,state,r['result_name'])
 if name=='public-positive':assert state['result']['relation']=='INDEPENDENT',state
 if name=='public-copied':assert r['result_name']=='MAJORITY_DISAGREE' and not state['accepted'],state
 votes=r.get('consensus_data',{}).get('votes',{})
 results[name]={'accepted':state['accepted'],'decision':state['result'],'transaction_hash':r['hash'],'network_result':r.get('result_name'),'validator_votes':votes,'elapsed_seconds':round(time.monotonic()-started,3),'packet_bytes':sum(x['byte_length'] for x in records),'max_records':4,'prompt_token_upper_bound':sum(x['byte_length'] for x in records)+8192}
 atomic('evidence/validator-probe-results.json',results)
print('Real public cases and all malicious leader probes verified',flush=True)
