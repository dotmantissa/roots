"""Exercise the actual integration journal at an uncertain RPC send boundary."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from eth_utils import keccak
from scripts.network import operation, BoundedProvider


@pytest.mark.parametrize('accepted_before_disconnect', [False, True])
def test_lost_send_response_preserves_and_resumes_signed_bytes(
        tmp_path, monkeypatch, accepted_before_disconnect):
    monkeypatch.chdir(tmp_path)
    raw = '0x012345'
    tx_hash = '0x' + keccak(bytes.fromhex(raw[2:])).hex()
    params = [raw, {'controlled': True}]
    path = Path('deployments/operations/interrupted.json')
    receipt = {'hash': tx_hash, 'status': 7, 'result_name': 'MAJORITY_AGREE',
               'consensus_data': {'leader_receipt': [
                   {'mode': 'leader', 'execution_result': 'SUCCESS'}]}}
    sent = []
    accepted = False

    def request(method, args):
        nonlocal accepted
        assert method == 'eth_sendRawTransaction'
        journal = json.loads(path.read_text())
        assert journal['status'] == 'SIGNED'
        assert journal['broadcast_params'] == args == params
        sent.append(args)
        if len(sent) == 1:
            accepted = accepted_before_disconnect
            raise ConnectionError('Response lost after send')
        accepted = True
        return {'result': tx_hash}

    def get_transaction(hash_value):
        assert hash_value == tx_hash
        if not accepted:
            raise RuntimeError('Transaction not found')
        return receipt

    client = SimpleNamespace(provider=SimpleNamespace(make_request=request),
        get_transaction=get_transaction,
        wait_for_transaction_receipt=lambda *args, **kwargs: receipt)
    with pytest.raises(ConnectionError):
        operation(client, 'interrupted',
                  lambda: client.provider.make_request('eth_sendRawTransaction', params)['result'])
    assert json.loads(path.read_text())['transaction_hash'] == tx_hash

    def forbid_new_signature():
        raise AssertionError('Recovery must not prepare another transaction')

    assert operation(client, 'interrupted', forbid_new_signature) == receipt
    assert len(sent) == (1 if accepted_before_disconnect else 2)
    assert json.loads(path.read_text())['status'] == 'FINALIZED'


def test_modified_signed_journal_is_refused_before_rpc(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = Path('deployments/operations/modified.json')
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'transaction_hash': '0x' + '00' * 32,
                               'status': 'SIGNED', 'broadcast_params': ['0x012345']}))
    with pytest.raises(RuntimeError, match='signed journal hash mismatch'):
        operation(SimpleNamespace(), 'modified', lambda: None)


def test_http_quota_retries_the_exact_rpc_without_resigning(monkeypatch):
    import requests
    calls = []

    def post(url, *, json, timeout):
        calls.append(json)
        response = requests.Response()
        response.status_code = 429 if len(calls) == 1 else 200
        response._content = b'{"jsonrpc":"2.0","result":"accepted"}'
        return response

    monkeypatch.setattr('scripts.network.requests.post', post)
    monkeypatch.setattr('scripts.network.time.sleep', lambda seconds: None)
    result = BoundedProvider('https://example.test').make_request(
        'eth_sendRawTransaction', ['0x012345'])
    assert result['result'] == 'accepted'
    assert len(calls) == 2 and calls[0] == calls[1]
