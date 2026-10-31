"""Finalize a dependency-consistent replacement stack before publishing its manifest."""
from pathlib import Path
import os
import json
import hashlib
from eth_account import Account
try:
    from network import client, operation, atomic
except ModuleNotFoundError:
    from scripts.network import client, operation, atomic

ROOT = Path(__file__).resolve().parents[1]
NAMES = ['source_registry', 'relation_docket', 'certificate_hub', 'incident_consumer', 'disclosure_consumer']


def fingerprint(source_hash, args, deployer):
    payload = json.dumps({'source_hash': source_hash, 'constructor_args': args,
                          'deployer': deployer.lower()}, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()


def deployment_operation(name, identity, release_id):
    key = 'deploy-v2-' + name + '-' + identity[:20]
    # A docket's hub is bound after construction. Any coordinated release
    # needs a fresh docket even when its registry constructor is unchanged.
    return key + '-' + release_id[:12] if name == 'relation_docket' else key


def resolve_owners(previous, environment, generate, live_authorities=None):
    owners = {}
    for kind in ['incident', 'disclosure']:
        address = environment.get(kind.upper() + '_OWNER_ADDRESS')
        key = environment.get(kind.upper() + '_OWNER_PRIVATE_KEY')
        derived = Account.from_key(key).address if key else None
        if address and derived and address.lower() != derived.lower():
            raise ValueError(kind + ' owner key does not match the configured address')
        # Never silently invent a different owner for an existing deployment.
        owners[kind] = address or (live_authorities or {}).get(kind) or derived or previous.get('owners', {}).get(kind) or generate(kind)
    if owners['incident'].lower() == owners['disclosure'].lower():
        raise ValueError('The two consumer owners must be separate authorities')
    owners['registry'] = Account.from_key(environment['DEPLOYER_PRIVATE_KEY']).address
    return owners


def deployment_args(name, contracts, owners):
    if name == 'source_registry': return []
    if name == 'relation_docket': return [contracts['source_registry']['address']]
    if name == 'certificate_hub': return [contracts['relation_docket']['address']]
    return [contracts['certificate_hub']['address'], owners['incident' if name.startswith('incident') else 'disclosure']]


def verify_stack(c, manifest, initial_owners=True):
    contracts = manifest['contracts']
    registry = c.read_contract(address=contracts['source_registry']['address'], function_name='get_authority', args=[])
    docket = c.read_contract(address=contracts['relation_docket']['address'], function_name='get_dependencies', args=[])
    hub = c.read_contract(address=contracts['certificate_hub']['address'], function_name='get_dependencies', args=[])
    if initial_owners: assert registry['owner'].lower() == manifest['owners']['registry'].lower()
    assert docket['registry'].lower() == contracts['source_registry']['address'].lower()
    assert docket['hub'].lower() == contracts['certificate_hub']['address'].lower()
    assert hub['docket'].lower() == contracts['relation_docket']['address'].lower()
    for name, kind in [('incident_consumer','incident'),('disclosure_consumer','disclosure')]:
        authority = c.read_contract(address=contracts[name]['address'], function_name='get_authority', args=[])
        assert authority['hub'].lower() == contracts['certificate_hub']['address'].lower()
        if initial_owners: assert authority['owner'].lower() == manifest['owners'][kind].lower()


def main():
    os.chdir(ROOT)
    path = ROOT/'deployments/studionet.json'
    previous = json.loads(path.read_text()) if path.exists() else {}
    def generate(kind):
        account = Account.create()
        secure = ROOT/'.env'
        with secure.open('a') as f: f.write(kind.upper()+'_OWNER_PRIVATE_KEY=0x'+account.key.hex()+'\n')
        secure.chmod(0o600)
        os.environ[kind.upper()+'_OWNER_PRIVATE_KEY'] = '0x'+account.key.hex()
        return account.address
    owners = resolve_owners(previous, os.environ, generate)
    hashes = {name:hashlib.sha256((ROOT/f'contracts/{name}.py').read_bytes()).hexdigest() for name in NAMES}
    release_id = fingerprint(hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(), owners, owners['registry'])
    c = client()
    if previous.get('release_id') == release_id:
        for name in NAMES:
            entry = previous['contracts'][name]
            args = deployment_args(name, previous['contracts'], owners)
            if entry.get('deployment_fingerprint') != fingerprint(hashes[name], args, owners['registry']):
                raise RuntimeError('Recorded constructor identity is inconsistent for '+name)
        verify_stack(c, previous, initial_owners=False)
        print('Unchanged code, owners and constructor dependencies verified', flush=True)
        return
    if previous.get('schema_version') == 2:
        # Constructor owners describe deployment time. A subsequent nominated
        # wallet may now own a consumer; an old local key cannot reclaim it on
        # upgrade. Preserve the authoritative owner unless an address override
        # explicitly requests replacement under a different authority.
        live_authorities = {}
        for kind in ['incident', 'disclosure']:
            authority = c.read_contract(address=previous['contracts'][kind+'_consumer']['address'],
                                        function_name='get_authority', args=[])
            live_authorities[kind] = authority['owner']
        owners = resolve_owners(previous, os.environ, generate, live_authorities)
        release_id = fingerprint(hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(), owners, owners['registry'])
    # A hub cannot be replaced under an existing one-time docket binding.
    # Every incompatible release replaces the whole connected stack, preserving
    # the old public manifest until deployments, binding and reads all succeed.
    pending_path = ROOT/'.runtime'/('deployment-'+release_id+'.json')
    manifest = json.loads(pending_path.read_text()) if pending_path.exists() else {
        'network':'studionet','rpc':'https://studio.genlayer.com/api','chain_id':61999,
        'runner':'1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6',
        'schema_version':2,'release_id':release_id,'contracts':{},'owners':owners}
    for name in NAMES:
        args = deployment_args(name, manifest['contracts'], owners)
        identity = fingerprint(hashes[name], args, owners['registry'])
        existing = manifest['contracts'].get(name)
        if existing:
            if existing.get('deployment_fingerprint') != identity:
                raise RuntimeError('Pending deployment constructor identity changed')
            continue
        code = (ROOT/f'contracts/{name}.py').read_bytes()
        receipt = operation(c, deployment_operation(name,identity,release_id), lambda code=code,args=args:c.deploy_contract(code=code,args=args))
        manifest['contracts'][name] = {'address':receipt['data']['contract_address'], 'source_hash':hashes[name],
            'deployment_transaction':receipt['hash'], 'constructor_args':args,'deployment_fingerprint':identity}
        atomic(pending_path, manifest)
    docket = manifest['contracts']['relation_docket']['address']
    hub = manifest['contracts']['certificate_hub']['address']
    registry = manifest['contracts']['source_registry']['address']
    operation(c,'bind-v2-'+release_id[:20],lambda:c.write_contract(address=docket,function_name='bind_hub',args=[hub]))
    operation(c,'capacity-v2-'+release_id[:20],lambda:c.write_contract(address=docket,function_name='authorize_requester',args=[owners['registry'],128]))
    policy = {'min_origins':3,'max_sources':6,'unresolved_consequence':'REFUSE_ADMISSION','name':'Three distinct roots'}
    operation(c,'policy-v2-'+release_id[:20],lambda:c.write_contract(address=registry,function_name='register_source_policy',args=['policy-three-origins-v2','three_origins',1,json.dumps(policy)]))
    verify_stack(c, manifest)
    # Retain the historical stack/evidence, rather than rewriting its claims.
    if previous:
        atomic(ROOT/'deployments/archive'/('studionet-'+(previous.get('release_id') or 'v1')+'.json'), previous)
    atomic(path, manifest)
    atomic(ROOT/'evidence/deployment-v2.json',{'release_id':release_id,'dependency_reads_verified':True,'contracts':manifest['contracts'],'owners':owners})
    print('Replacement stack finalized, dependency reads verified, manifest published', flush=True)


if __name__ == '__main__': main()
