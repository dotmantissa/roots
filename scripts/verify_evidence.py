"""Audit retained public receipts and evidence without sending network requests."""
import argparse
import hashlib
import json
from pathlib import Path

from eth_utils import keccak
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    deployment = read('deployments/studionet.json')
    for name, entry in deployment['contracts'].items():
        source = (ROOT / 'contracts' / (name + '.py')).read_bytes()
        assert hashlib.sha256(source).hexdigest() == entry['source_hash'], name
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

    print(json.dumps({'finalized_operation_receipts_verified': receipt_count,
                      'signed_journals_verified': signed_count,
                      'contract_source_hashes_verified': len(deployment['contracts']),
                      'captured_source_hashes_verified': captures,
                      'complete_scenarios_required': args.require_complete}))


if __name__ == '__main__':
    main()
