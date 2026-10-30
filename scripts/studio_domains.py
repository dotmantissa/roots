"""Verify authored copied reporting on three public hosts with real validators."""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import urllib.request

from eth_account import Account
from network import atomic, client, operation, succeeded

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
c = client()
owner = Account.from_key(os.environ['DEPLOYER_PRIVATE_KEY']).address
deployment = json.loads(Path('deployments/studionet.json').read_text())
recovery_path = Path('evidence/fixture-recovery-inputs.json')
inputs = json.loads((recovery_path if recovery_path.exists() else
                     Path('evidence/scenario-inputs.json')).read_text())


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def fixture_origin(name):
    explicit = os.environ.get('DOMAIN_' + name.upper() + '_ORIGIN')
    if explicit:
        return explicit.rstrip('/')
    for suffix in ['current-', 'restored-', '']:
        path = Path(f'.runtime/domain-{name}-{suffix}tunnel.log')
        if path.exists():
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', path.read_text())
            if match:
                return match.group()
    raise RuntimeError(f'Set DOMAIN_{name.upper()}_ORIGIN to an available public fixture host')


input_path = Path('evidence/three-domain-input.json')
if input_path.exists():
    saved = json.loads(input_path.read_text())
    manifest, request = saved['manifest'], saved['request']
else:
    first = inputs['origin'] if recovery_path.exists() else json.loads(
        Path('evidence/fixture-origin.json').read_text())['origin']
    origins = [first, fixture_origin('two'), fixture_origin('three')]
    assert len({urlparse(origin).hostname for origin in origins}) == 3
    manifest = []
    for i, origin in enumerate(origins):
        source = dict(inputs['sources'][f'controlled_wire{i}'])
        publication = dict(source['publication'])
        url = origin + f'/wire{i}.txt'
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(49153)
        assert sha(raw) == publication['byte_hash'] and len(raw) == publication['byte_length']
        publication.update(url=url, capture_url=url)
        source['publication'] = publication
        manifest.append(source)
    request = {
        'request_id': 'controlled_three_actual_domains', 'owner': owner, 'parties': [owner],
        'policy_id': 'three_origins', 'policy_revision': 1,
        'subject_id': 'Controlled copied reporting across three domains',
        'subject_digest': sha('Authored wire dispatch copies served on three distinct public hostnames'),
        'manifest_digest': sha(canon(manifest)),
        'consumer': deployment['contracts']['incident_consumer']['address'],
        'consequence_digest': sha('Controlled copied incident evidence admission'),
        'generation': 1,
        'deadline': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace('+00:00', 'Z'),
    }
    atomic(input_path, {
        'classification': 'Authored controlled source fixtures served on three actual public hostnames',
        'request': request, 'manifest': manifest,
    })
assert len({urlparse(source['publication']['url']).hostname for source in manifest}) == 3
assert request['manifest_digest'] == sha(canon(manifest))


def write(op, address, method, args, who=c, success=True):
    return operation(who, op, lambda: who.write_contract(
        address=address, function_name=method, args=args), expected_success=success)


def messages(receipt, name, acknowledgement=False):
    hashes = receipt.get('triggered_transactions') or c.get_transaction(
        receipt['hash']).get('triggered_transactions', [])
    assert hashes, 'Expected authenticated finalized message'
    for i, tx_hash in enumerate(hashes):
        op = name + '-child' + str(i)
        path = Path('deployments/operations') / (op + '.json')
        if not path.exists():
            atomic(path, {'operation_id': op, 'transaction_hash': tx_hash})
        assert json.loads(path.read_text())['transaction_hash'] == tx_hash
        child = operation(c, op, lambda: tx_hash)
        if acknowledgement:
            descendants = child.get('triggered_transactions') or c.get_transaction(
                tx_hash).get('triggered_transactions', [])
            assert descendants, 'Expected finalized consumer acknowledgement'
            for j, ack_hash in enumerate(descendants):
                ack_op = op + '-ack' + str(j)
                ack_path = Path('deployments/operations') / (ack_op + '.json')
                if not ack_path.exists():
                    atomic(ack_path, {'operation_id': ack_op, 'transaction_hash': ack_hash})
                assert json.loads(ack_path.read_text())['transaction_hash'] == ack_hash
                operation(c, ack_op, lambda: ack_hash)


docket = deployment['contracts']['relation_docket']['address']
hub = deployment['contracts']['certificate_hub']['address']
consumer = request['consumer']
who = client('INCIDENT_OWNER_PRIVATE_KEY')
key = request['request_id']
write('open-three-domains', docket, 'open_batch', [canon(request), canon(manifest)])
config = {k: request[k] for k in ['request_id', 'policy_id', 'policy_revision',
          'subject_id', 'subject_digest', 'manifest_digest', 'consumer',
          'consequence_digest', 'generation', 'deadline']}
receipt = write('configure-three-domains', consumer, 'configure',
                ['configure-three-domains', canon(config)], who)
messages(receipt, 'configure-three-domains')
for a, b in [(0, 1), (0, 2), (1, 2)]:
    write(f'assess-three-domains-{a}-{b}', docket, 'assess_pair', [key, 1, a, b])
batch = c.read_contract(address=docket, function_name='get_batch', args=[key])
assert set(batch['pairs']) == {'0:1', '0:2', '1:2'}
assert all(pair['relation'] == 'SHARED_ORIGIN' for pair in batch['pairs'].values())
receipt = write('seal-three-domains', docket, 'seal_batch', [key, 1, '[0]'])
messages(receipt, 'seal-three-domains')
receipt = write('deliver-three-domains', hub, 'deliver_certificate',
                ['deliver-three-domains', key + ':1', consumer])
messages(receipt, 'deliver-three-domains', acknowledgement=True)
delivery = c.read_contract(address=hub, function_name='get_delivery', args=['deliver-three-domains'])
assert delivery['acknowledgement']['certificate_id'] == key + ':1'
assert delivery['acknowledgement']['generation'] == 1
receipt = write('refuse-three-domains', consumer, 'admit_incident',
                ['refuse-three-domains', key, request['subject_digest'],
                 request['consequence_digest']], who, False)
assert not succeeded(receipt)
atomic('evidence/three-domain-results.json', {
    'classification': 'Authored copies on distinct authentic public URL hostnames',
    'domains': [urlparse(source['publication']['url']).hostname for source in manifest],
    'relations': {k: value['relation'] for k, value in batch['pairs'].items()},
    'selected_subset': [0], 'finalized_delivery_acknowledged': True, 'admission': False,
})
print('Three distinct copied domains certified as one origin and admission refused', flush=True)
