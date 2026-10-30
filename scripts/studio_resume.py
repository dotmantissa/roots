"""Resume the recorded Studio acceptance after temporary fixture hosts stopped.

Every changed URL is authorized as a source revision. Historical outages and
certificates are retained, and all consequential callbacks require receipts.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.request

from network import atomic, client, operation, succeeded

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
deployment = json.loads(Path('deployments/studionet.json').read_text())
original = json.loads(Path('evidence/scenario-inputs.json').read_text())
c = client()
registry = deployment['contracts']['source_registry']['address']
docket = deployment['contracts']['relation_docket']['address']
hub = deployment['contracts']['certificate_hub']['address']
origin = 'https://roots-mauve-delta.vercel.app/validation'


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def read(address, method, args):
    return c.read_contract(address=address, function_name=method, args=args)


def write(op, address, method, args, who=c, success=True):
    recovery = Path('evidence/consensus-recovery.json')
    retry = json.loads(recovery.read_text()).get(op) if recovery.exists() else None
    if retry:
        # Explicitly retained recovery only; a failed consensus receipt is never replaced.
        assert (address, method, args) == (retry['address'], retry['method'], retry['args'])
        original = json.loads((Path('evidence/receipts') / (op + '.json')).read_text())
        assert original['hash'] == retry['original_transaction_hash']
        assert original['status_name'] == 'FINALIZED' and original['result_name'] == 'MAJORITY_DISAGREE'
        op = retry['retry_operation_id']
        if not (Path('deployments/operations') / (op + '.json')).exists():
            batch = read(address, 'get_batch', [args[0]])
            assert batch['generation'] == args[1]
            assert f'{args[2]}:{args[3]}' not in batch['pairs'], 'Retry pair already applied'
    return operation(who, op, lambda: who.write_contract(
        address=address, function_name=method, args=args), expected_success=success)


def record(previous, filename, revision):
    url = origin + '/' + filename
    with urllib.request.urlopen(urllib.request.Request(
            url, headers={'Accept-Encoding': 'identity'}), timeout=30) as response:
        raw = response.read(49153)
    assert raw == (ROOT / 'tests/fixtures/public' / filename).read_bytes()
    assert 0 < len(raw) <= 49152
    digest = hashlib.sha256(raw).hexdigest()
    Path('evidence/sources').mkdir(parents=True, exist_ok=True)
    (Path('evidence/sources') / (digest + '.txt')).write_bytes(raw)
    return {**previous, 'url': url, 'capture_url': url, 'revision': revision,
            'byte_hash': digest, 'byte_length': len(raw), 'spans': [
                {'span_id': 'complete', 'start': 0, 'end': len(raw), 'quote_hash': digest}]}


def messages(parent, op):
    hashes = parent.get('triggered_transactions', [])
    for _ in range(12):
        if hashes:
            break
        hashes = c.get_transaction(parent['hash']).get('triggered_transactions', [])
        if not hashes:
            time.sleep(5)
    assert hashes, 'Missing authenticated finalized callback: ' + op
    for i, tx_hash in enumerate(hashes):
        child_op = op + '-child' + str(i)
        child_path = Path('deployments/operations') / (child_op + '.json')
        if not child_path.exists():
            atomic(child_path, {'operation_id': child_op, 'transaction_hash': tx_hash})
        assert json.loads(child_path.read_text())['transaction_hash'] == tx_hash
        child = operation(c, child_op, lambda: tx_hash)
        if op.startswith(('restored-delivery-', 'replacement-delivery-', 'restored-duplicate-',
                          'deliver-controlled_wire_')):
            acknowledgements = child.get('triggered_transactions', [])
            if not acknowledgements:
                acknowledgements = c.get_transaction(tx_hash).get('triggered_transactions', [])
            assert acknowledgements, 'Missing consumer acknowledgement: ' + op
            for j, ack_hash in enumerate(acknowledgements):
                ack_op = child_op + '-ack' + str(j)
                ack_path = Path('deployments/operations') / (ack_op + '.json')
                if not ack_path.exists():
                    atomic(ack_path, {'operation_id': ack_op, 'transaction_hash': ack_hash})
                assert json.loads(ack_path.read_text())['transaction_hash'] == ack_hash
                operation(c, ack_op, lambda: ack_hash)


def maximum(manifest, pairs):
    best = []
    for mask in range(1 << len(manifest)):
        subset = [i for i in range(len(manifest)) if mask & (1 << i)]
        if len(subset) > len(best) and all(
            manifest[a]['publisher_id'] != manifest[b]['publisher_id'] and
            pairs[f'{a}:{b}']['relation'] == 'INDEPENDENT' and pairs[f'{a}:{b}']['witnesses']
            for i, a in enumerate(subset) for b in subset[i + 1:]
        ):
            best = subset
    return best


def configured(batch):
    return {k: batch[k] for k in ['request_id', 'policy_id', 'policy_revision',
        'subject_id', 'subject_digest', 'manifest_digest', 'consumer',
        'consequence_digest', 'generation', 'deadline']}


path = Path('evidence/fixture-recovery-inputs.json')
if path.exists():
    inputs = json.loads(path.read_text())
else:
    sources = {}
    for family in ['wire', 'measurement']:
        for i in range(3):
            name = f'controlled_{family}{i}'
            source = original['sources'][name]
            publisher = read(registry, 'get_publisher', [name])
            revision = publisher['revision'] + 1
            sources[name] = {**source, 'publisher_revision': revision,
                'publication': record(source['publication'], f'{family}{i}.txt', 2),
                'ownership': record(source['ownership'], f'{family}-owner{i}.txt', revision)}
    before = {kind: read(docket, 'get_batch', ['controlled_measurement_' + kind])
              for kind in ['incident', 'disclosure']}
    correction_revision = sources['controlled_measurement2']['publisher_revision'] + 1
    corrected = record({**sources['controlled_measurement2']['ownership'],
                        'record_id': 'controlled_measurement2_owner_v' + str(correction_revision)},
                       'corrected-owner2.txt', correction_revision)
    inputs = {'classification': 'Authored controlled fixtures restored through explicit signed source revisions',
              'origin': origin, 'sources': sources, 'before': before, 'corrected': corrected,
              'original_results': json.loads(Path('evidence/scenario-results.json').read_text())}
    atomic(path, inputs)
    atomic('evidence/disclosure-unavailable-g2.json', {
        'classification': 'Preserved terminal unavailable retrieval before durable source replacement',
        'batch': before['disclosure']})

for name, source in inputs['sources'].items():
    write('restore-fixture-' + name, registry, 'correct_affiliation',
          ['restore-fixture-' + name, name, canon(source['ownership']), False])

results = json.loads(Path('evidence/scenario-results.json').read_text())
for kind in ['incident', 'disclosure']:
    key = 'controlled_measurement_' + kind
    if results.get(key, {}).get('durable_origin_baseline'):
        continue
    before = inputs['before'][kind]
    who = client('INCIDENT_OWNER_PRIVATE_KEY' if kind == 'incident' else 'DISCLOSURE_OWNER_PRIVATE_KEY')
    manifest = [inputs['sources'][f'controlled_measurement{i}'] for i in range(3)]
    write('restore-manifest-' + kind, docket, 'acknowledge_revision',
          ['restore-manifest-' + kind, key, canon(manifest), before['deadline']])
    batch = read(docket, 'get_batch', [key])
    generation = batch['generation']
    assert generation == before['generation'] + 1
    consumer = batch['consumer']
    op = f'restored-configure-{kind}-g{generation}'
    messages(write(op, consumer, 'configure', [op, canon(configured(batch))], who), op)
    for a, b in [(0, 1), (0, 2), (1, 2)]:
        write(f'restored-assess-{kind}-g{generation}-{a}-{b}', docket,
              'assess_pair', [key, generation, a, b])
    batch = read(docket, 'get_batch', [key])
    assert maximum(manifest, batch['pairs']) == [0, 1, 2], 'Restored measurements remain unresolved'
    op = f'restored-seal-{kind}-g{generation}'
    messages(write(op, docket, 'seal_batch', [key, generation, '[0,1,2]']), op)
    certificate_id = key + ':' + str(generation)
    op = f'restored-delivery-{kind}-g{generation}'
    messages(write(op, hub, 'deliver_certificate', [op, certificate_id, consumer]), op)
    delivery = read(hub, 'get_delivery', [op])
    assert delivery['acknowledgement']['generation'] == generation
    op = f'restored-admit-{kind}-g{generation}'
    write(op, consumer, 'admit_' + kind,
          [op, key, batch['subject_digest'], batch['consequence_digest']], who)
    duplicate = f'restored-duplicate-{kind}-g{generation}'
    messages(write(duplicate, hub, 'deliver_certificate',
                   [f'restored-delivery-{kind}-g{generation}', certificate_id, consumer]), duplicate)
    results[key] = {**results.get(key, {}), 'generation': generation,
        'subset': [0, 1, 2], 'certificate': 'FINALIZED', 'admission': True,
        'durable_origin_baseline': True, 'delivery_acknowledged': True,
        'restored_from_generation': before['generation'],
        'pair_vector': {k: v['relation'] for k, v in batch['pairs'].items()}}
    atomic('evidence/scenario-results.json', results)

key = 'controlled_measurement_incident'
receipt = write('mutated-restored-subset', docket, 'seal_batch',
                [key, results[key]['generation'], '[0,1]'], success=False)
assert not succeeded(receipt)
receipt = write('unauthorized-restored-correction', registry, 'correct_affiliation',
                ['unauthorized-restored-correction', 'controlled_measurement2',
                 canon(inputs['corrected']), False], client('DISCLOSURE_OWNER_PRIVATE_KEY'), False)
assert not succeeded(receipt)
write('correct-durable-affiliation', registry, 'correct_affiliation',
      ['correct-durable-affiliation', 'controlled_measurement2', canon(inputs['corrected']), False])

for kind in ['incident', 'disclosure']:
    key = 'controlled_measurement_' + kind
    if results[key].get('corrected_admission') is False:
        continue
    request = original['requests'][key]
    consumer = request['consumer']
    who = client('INCIDENT_OWNER_PRIVATE_KEY' if kind == 'incident' else 'DISCLOSURE_OWNER_PRIVATE_KEY')
    receipt = write('frozen-durable-' + kind, consumer, 'admit_' + kind,
                    ['fresh-after-durable-correction-' + kind, key,
                     request['subject_digest'], request['consequence_digest']], who, False)
    assert not succeeded(receipt)
    receipt = write('stale-durable-' + kind, hub, 'deliver_certificate',
                    ['stale-durable-' + kind, key + ':' + str(results[key]['generation']), consumer],
                    success=False)
    assert not succeeded(receipt)
    manifest = [dict(inputs['sources'][f'controlled_measurement{i}']) for i in range(3)]
    manifest[2] = {**manifest[2], 'publisher_revision': inputs['corrected']['revision'],
                   'ownership': inputs['corrected']}
    write('successor-durable-' + kind, docket, 'acknowledge_revision',
          ['successor-durable-' + kind, key, canon(manifest), request['deadline']])
    batch = read(docket, 'get_batch', [key])
    generation = batch['generation']
    assert generation == results[key]['generation'] + 1
    for a, b in [(0, 1), (0, 2), (1, 2)]:
        write(f'corrected-assess-{kind}-g{generation}-{a}-{b}', docket,
              'assess_pair', [key, generation, a, b])
    batch = read(docket, 'get_batch', [key])
    selected = maximum(manifest, batch['pairs'])
    assert len(selected) < 3, 'Shared affiliation failed to reduce independence'
    op = f'corrected-seal-{kind}-g{generation}'
    messages(write(op, docket, 'seal_batch', [key, generation, canon(selected)]), op)
    op = f'corrected-configure-{kind}-g{generation}'
    messages(write(op, consumer, 'configure', [op, canon(configured(batch))], who), op)
    op = f'replacement-delivery-{kind}-g{generation}'
    messages(write(op, hub, 'deliver_certificate', [op, key + ':' + str(generation), consumer]), op)
    delivery = read(hub, 'get_delivery', [op])
    assert delivery['acknowledgement']['generation'] == generation
    receipt = write('reduced-durable-' + kind, consumer, 'admit_' + kind,
                    ['reduced-durable-' + kind, key, request['subject_digest'],
                     request['consequence_digest']], who, False)
    assert not succeeded(receipt)
    state = read(consumer, 'get_state', [key])
    assert state['last_generation'] == generation and state['receipt']['selected_subset'] == selected
    results[key].update(corrected_generation=generation, corrected_subset=selected,
                        corrected_admission=False, replacement_acknowledged=True,
                        frozen_admission_refused=True, stale_delivery_refused=True)
    atomic('evidence/scenario-results.json', results)

for kind in ['incident', 'disclosure']:
    key = 'controlled_wire_' + kind
    op = 'deliver-' + key
    assert (Path('deployments/operations') / (op + '.json')).exists()
    messages(operation(c, op, lambda: None), op)
    ack = read(hub, 'get_delivery', ['deliver-' + key])
    assert ack['acknowledgement']['generation'] == 1
    results[key]['delivery_acknowledged'] = True
atomic('evidence/scenario-results.json', results)
print('Both consumers: finalized independent acceptance, shared affiliation freeze and reduced refusal verified', flush=True)
