from pathlib import Path
import os,json,hashlib
from eth_account import Account
from network import client,operation,atomic
ROOT=Path(__file__).resolve().parents[1]
os.chdir(ROOT)
# Different consumer owners. Private keys never go to deployments or evidence.
env=ROOT/'.env'
for name in ['INCIDENT_OWNER_PRIVATE_KEY','DISCLOSURE_OWNER_PRIVATE_KEY']:
    if not os.environ.get(name):
        account=Account.create()
        with env.open('a') as f:f.write(name+'=0x'+account.key.hex()+'\n')
        os.environ[name]='0x'+account.key.hex()
os.chmod(env,0o600)
c=client()
manifest_path=ROOT/'deployments/studionet.json'
manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {'network':'studionet','rpc':'https://studio.genlayer.com/api','chain_id':61999,'runner':'1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6','contracts':{},'owners':{}}
for key,name in [('INCIDENT_OWNER_PRIVATE_KEY','incident'),('DISCLOSURE_OWNER_PRIVATE_KEY','disclosure')]:manifest['owners'][name]=Account.from_key(os.environ[key]).address
manifest['owners']['registry']=Account.from_key(os.environ['DEPLOYER_PRIVATE_KEY']).address
for filename,args in [('source_registry',[]),('relation_docket',[manifest['contracts'].get('source_registry',{}).get('address')]),('certificate_hub',[manifest['contracts'].get('relation_docket',{}).get('address')]),('incident_consumer',[manifest['contracts'].get('certificate_hub',{}).get('address'),manifest['owners']['incident']]),('disclosure_consumer',[manifest['contracts'].get('certificate_hub',{}).get('address'),manifest['owners']['disclosure']])]:
    # Resolve dependencies after preceding deployment completes.
    if filename=='relation_docket':args=[manifest['contracts']['source_registry']['address']]
    if filename=='certificate_hub':args=[manifest['contracts']['relation_docket']['address']]
    if filename.endswith('_consumer'):args=[manifest['contracts']['certificate_hub']['address'],manifest['owners']['incident' if filename.startswith('incident') else 'disclosure']]
    code=(ROOT/f'contracts/{filename}.py').read_bytes();code_hash=hashlib.sha256(code).hexdigest()
    existing=manifest['contracts'].get(filename)
    if existing and existing['source_hash']==code_hash:continue
    r=operation(c,'deploy-'+filename+'-'+code_hash[:12],lambda code=code,args=args:c.deploy_contract(code=code,args=args))
    address=r['data']['contract_address']
    manifest['contracts'][filename]={'address':address,'source_hash':code_hash,'deployment_transaction':r['hash']}
    atomic(manifest_path,manifest)
operation(c,'bind-hub-'+manifest['contracts']['certificate_hub']['address'][2:10],lambda:c.write_contract(address=manifest['contracts']['relation_docket']['address'],function_name='bind_hub',args=[manifest['contracts']['certificate_hub']['address']]))
policy={'min_origins':3,'max_sources':6,'unresolved_consequence':'REFUSE_ADMISSION','name':'Three distinct roots'}
operation(c,'policy-three-origins-'+manifest['contracts']['source_registry']['address'][2:10],lambda:c.write_contract(address=manifest['contracts']['source_registry']['address'],function_name='register_source_policy',args=['policy-three-origins-v1','three_origins',1,json.dumps(policy)]))
print('All product deployments and bindings finalized',flush=True)
