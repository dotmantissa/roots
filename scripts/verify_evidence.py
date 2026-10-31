"""Audit retained public receipts and evidence without sending network requests."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from eth_utils import keccak
from genlayer_py.abi import calldata
from genlayer_py.utils.jsonifier import result_to_user_friendly_json
from network import succeeded

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def finalized(receipt):
    return receipt.get('status') in [7, 'FINALIZED'] or receipt.get('status_name') == 'FINALIZED'


def verify_operation(name, success=True):
    journal = read(f'deployments/operations/{name}.json')
    receipt = read(f'evidence/receipts/{name}.json')
    assert journal['transaction_hash'] == receipt['hash'], name
    assert finalized(receipt) and succeeded(receipt) == success, name
    return receipt


def verify_delivery(name):
    parent = verify_operation(name)
    child = verify_operation(name + '-child0')
    ack = verify_operation(name + '-child0-ack0')
    assert child['hash'] in parent['triggered_transactions'], name
    assert ack['hash'] in child['triggered_transactions'], name


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def calldata_value(value):
    if isinstance(value, dict):
        return json.loads(value['readable'])
    return calldata.decode(base64.b64decode(value, validate=True))


def verify_callbacks(name, acknowledgements=False, ack_suffix='-ack0'):
    parent = verify_operation(name)
    child = verify_operation(name + '-child0')
    assert child['hash'] in parent['triggered_transactions'], name
    assert child['triggered_on'] == 'finalized', name
    if acknowledgements:
        ack = verify_operation(name + '-child0' + ack_suffix)
        assert ack['hash'] in child['triggered_transactions'], name
        assert ack['triggered_on'] == 'finalized', name
    return child


def verify_assessment(receipt, records, relation, witnesses):
    assert not receipt['leader_only'], 'Full validator consensus required'
    leader = next(r for r in receipt['consensus_data']['leader_receipt']
                  if r['mode'] == 'leader' and r['execution_result'] == 'SUCCESS')
    output = leader['eq_outputs']['0']
    if isinstance(output, str):
        output = result_to_user_friendly_json(output)
    assert output['status'] == 'return'
    decision = calldata_value(output['payload'])
    assert decision['relation'] == relation and decision['witnesses'] == witnesses
    expected = {r['record_id']: r for r in records}
    assert decision['coverage'] and set(w['record_id'] for w in witnesses) == set(expected)
    for witness in witnesses:
        rec = expected[witness['record_id']]
        span = next(s for s in rec['spans'] if s['span_id'] == witness['span_id'])
        assert witness == dict(span, record_id=rec['record_id'], source_hash=rec['byte_hash'])


def verify_v2_complete(deployment):
    release = deployment['release_id']
    prefix = 'review-' + release[:12]
    proof = read('evidence/deployment-v2.json')
    assert proof['release_id'] == release and proof['dependency_reads_verified']
    assert proof['contracts'] == deployment['contracts']
    for name, entry in deployment['contracts'].items():
        matches = list((ROOT / 'deployments/operations').glob('deploy-v2-' + name + '-*.json'))
        journal = next(p for p in matches if json.loads(p.read_text())['transaction_hash'] == entry['deployment_transaction'])
        receipt = verify_operation(journal.stem)
        assert receipt['data']['contract_address'] == entry['address']
    for name in ['bind', 'capacity', 'policy']:
        verify_operation(name + '-v2-' + release[:20])
    for name in ['reject-self-enrollment', 'reject-direct-assessment', 'reject-unchanged-reset', 'reject-unreviewed-configuration']:
        verify_operation(prefix + '-' + name, False)

    inputs = read('evidence/review-v2-inputs.json')
    consensus = read('evidence/consensus-v2.json')
    assert inputs['release_id'] == consensus['release_id'] == release
    assert set(consensus['results']) == {'incident', 'disclosure', 'normal_injection'}
    for source in inputs['sources'] + inputs['wire']:
        for rec in [source['publication'], source['ownership']]:
            data = (ROOT / 'tests/fixtures/public' / rec['url'].rsplit('/', 1)[1]).read_bytes()
            assert sha(data) == rec['byte_hash'] and len(data) == rec['byte_length']
            for span in rec['spans']:
                assert sha(data[span['start']:span['end']]) == span['quote_hash']
    for kind, result in consensus['results'].items():
        sources = inputs['wire'] if kind == 'normal_injection' else inputs['sources']
        request = inputs['requests'][kind]
        assert result['certificate_id'] == request['request_id'] + ':1'
        assert result['normal_unmodified_execution'] and result['batch_commitment_verified']
        assert result['publication_retry_same_generation']
        assert result['selected_subset'] == ([0] if kind == 'normal_injection' else [0, 1, 2])
        verify_callbacks(prefix + '-seal-' + kind)
        verify_callbacks(prefix + '-retry-publication-' + kind)
        for pair, relation in result['pair_relations'].items():
            left, right = map(int, pair.split(':'))
            assert relation == ('SHARED_ORIGIN' if kind == 'normal_injection' else 'INDEPENDENT')
            paths = list((ROOT / 'evidence/receipts').glob(f'{prefix}-assess-{kind}-{left}-{right}-*-child0.json'))
            accepted = [p for p in paths if succeeded(json.loads(p.read_text()))]
            assert accepted, pair
            receipt = verify_callbacks(accepted[-1].stem.removesuffix('-child0'))
            records = [r for i in [left, right] for r in [sources[i]['publication'], sources[i]['ownership']]]
            verify_assessment(receipt, records, relation, result['accepted_witnesses'][pair])
    disclosure = consensus['results']['disclosure']
    assert all(disclosure[k] for k in ['owner_relevance_attestation_required', 'subscription_retry_same_generation', 'finalized_delivery_acknowledged', 'admitted'])
    verify_callbacks(prefix + '-configure-disclosure')
    verify_callbacks(prefix + '-retry-subscription-disclosure')
    verify_callbacks(prefix + '-deliver-disclosure', True)
    verify_operation(prefix + '-admit-disclosure')

    email = read('evidence/email-admission-v2.json')
    assert email['release_id'] == release and email['complete_email_to_admission']
    assert email['admission']['request_id'] == email['request_id']
    assert email['admission']['status'] == 'ADMITTED'
    assert {'accept', 'open', 'seal', 'configure', 'deliver', 'admit'} <= set(email['steps'])
    for step, value in email['steps'].items():
        assert value['verified'] and value['finalized'], step
        receipt = verify_operation(Path(value['receipt_path']).stem)
        assert receipt['hash'] == value['transaction_hash']
        assert receipt['from_address'].lower() == email['wallet'].lower()
        contract = ('relation_docket' if value['method'] in ['open_batch', 'reserve_assessment', 'seal_batch']
                    else 'certificate_hub' if value['method'] == 'deliver_certificate' else 'incident_consumer')
        assert receipt['to_address'].lower() == deployment['contracts'][contract]['address'].lower()
        call = calldata_value(receipt['data']['calldata'])
        assert call['method'] == value['method'] and call.get('args', []) == value['args'], step
        assert not call.get('kwargs') and set(call) <= {'method', 'args', 'kwargs'}, step
        if step in ['seal', 'configure', 'deliver']:
            verify_callbacks(Path(value['receipt_path']).stem, step == 'deliver', ack_suffix='-child0')
        if value['method'] == 'reserve_assessment':
            child = verify_callbacks(Path(value['receipt_path']).stem)
            left, right = value['args'][3:5]
            pair = str(left) + ':' + str(right)
            sources = email['batch']['manifest']
            records = [r for i in [left, right] for r in [sources[i]['publication'], sources[i]['ownership']]]
            verify_assessment(child, records, 'INDEPENDENT', email['batch']['pairs'][pair]['witnesses'])
    assert email['steps']['configure']['args'][2] is True
    request = json.loads(email['steps']['open']['args'][0])
    assert sha(email['claim']) == request['subject_digest']
    assert sha(email['consequence']) == request['consequence_digest']
    assert request['subject_text'] == email['claim'] and request['consequence_text'] == email['consequence']
    assert len(email['captures']) == 3 and all(c['captured_bytes_verified'] for c in email['captures'])
    records = read('evidence/release-records-v2.json')
    assert records['release_id'] == release
    assert all(records[k] for k in ['sdk_semantic_bindings_verified', 'stable_current_batches', 'interrupted_continuation_equals_rebuild'])
    assert read('evidence/dependency-audit-v2.json')['metadata']['vulnerabilities']['total'] == 0
    replacement = read('evidence/replacement-browser-v2.json')
    assert replacement['release_id'] == release and replacement['request_id'] == email['request_id']
    assert all(replacement[k] for k in ['finalized_owner_can_open_recovery', 'edited_url_requires_capture',
                                      'captured_replacement_host_enabled', 'changed_url_invalidates_capture',
                                      'unchanged_capture_cannot_reset_revision'])
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    deployment = read('deployments/studionet.json')
    for name, entry in deployment['contracts'].items():
        source = (ROOT / 'contracts' / (name + '.py')).read_bytes()
        assert hashlib.sha256(source).hexdigest() == entry['source_hash'], name
    probe = read('deployments/validator-probe.json')
    probe_source = ROOT / probe.get('source_path', 'tests/integration/validator_probe.py')
    assert hashlib.sha256(probe_source.read_bytes()).hexdigest() == probe['source_hash']
    assert deployment['owners']['incident'] != deployment['owners']['disclosure']
    captures = 0
    for path in (ROOT / 'evidence/sources').glob('*.txt'):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == path.stem, path.name
        captures += 1
    receipt_count = signed_count = 0
    for path in (ROOT / 'deployments/operations').glob('*.json'):
        journal = json.loads(path.read_text())
        params = journal.get('broadcast_params')
        if params:
            assert '0x' + keccak(bytes.fromhex(params[0][2:])).hex() == journal['transaction_hash'], path.name
            signed_count += 1
        receipt_path = ROOT / 'evidence/receipts' / path.name
        if not receipt_path.exists():
            assert journal.get('status') != 'FINALIZED', path.name
            continue
        receipt = json.loads(receipt_path.read_text())
        assert receipt['hash'] == journal['transaction_hash'], path.name
        if journal.get('status') == 'FINALIZED':
            assert finalized(receipt), path.name
            assert succeeded(receipt) == journal['execution_success'], path.name
        if params:
            assert receipt['sim_config']['signed_rollup_transaction'] == params[0], path.name
        if finalized(receipt):
            receipt_count += 1

    if args.require_complete:
        scenarios = read('evidence/scenario-results.json')
        for kind in ['incident', 'disclosure']:
            copied = scenarios['controlled_wire_' + kind]
            assert copied['admission'] is False and copied['subset'] == [0] and copied['delivery_acknowledged']
            verify_delivery('deliver-controlled_wire_' + kind)
            result = scenarios['controlled_measurement_' + kind]
            assert result['admission'] is True and result['subset'] == [0, 1, 2]
            assert result['durable_origin_baseline'] and result['corrected_admission'] is False
            assert len(result['corrected_subset']) < 3
            assert result['corrected_generation'] == result['generation'] + 1
            for field in ['delivery_acknowledged', 'replacement_acknowledged',
                          'frozen_admission_refused', 'stale_delivery_refused']:
                assert result[field], field
            generation = result['generation']
            verify_operation(f'restored-admit-{kind}-g{generation}')
            verify_delivery(f'restored-delivery-{kind}-g{generation}')
            verify_delivery(f'restored-duplicate-{kind}-g{generation}')
            verify_delivery(f'replacement-delivery-{kind}-g{result["corrected_generation"]}')
            for prefix in ['frozen', 'stale', 'reduced']:
                verify_operation(f'{prefix}-durable-{kind}', False)
        domains = read('evidence/three-domain-results.json')
        assert len(set(domains['domains'])) == 3 and domains['admission'] is False
        assert set(domains['relations'].values()) == {'SHARED_ORIGIN'}
        assert domains['selected_subset'] == [0] and domains['finalized_delivery_acknowledged']
        verify_delivery('deliver-three-domains')
        verify_operation('refuse-three-domains', False)
        recovery = read('evidence/recovery-results.json')
        assert recovery['exact_rebuilt_records_preserved'] and recovery['consumer_successors_verified']
        assert recovery['records_before'] == recovery['records_after'] > 0
        for original, retry in read('evidence/consensus-recovery.json').items():
            failed = read(f'evidence/receipts/{original}.json')
            assert finalized(failed) and failed['result_name'] == 'MAJORITY_DISAGREE'
            assert failed['hash'] == retry['original_transaction_hash']
            verify_operation(retry['retry_operation_id'])
        if deployment.get('schema_version') == 2:
            verify_v2_complete(deployment)

    print(json.dumps({'finalized_operation_receipts_verified': receipt_count,
                      'signed_journals_verified': signed_count,
                      'contract_source_hashes_verified': len(deployment['contracts']),
                      'captured_source_hashes_verified': captures,
                      'historical_probe_source_verified': True,
                      'current_release_v2_verified': args.require_complete and deployment.get('schema_version') == 2,
                      'complete_scenarios_required': args.require_complete}))


if __name__ == '__main__':
    main()
