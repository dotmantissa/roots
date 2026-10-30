"""Signed Studio operations with durable, operation-addressable receipts."""
import json,os,time,hashlib
from pathlib import Path
from dotenv import load_dotenv
from eth_account import Account
from eth_utils import keccak
from genlayer_py.client.genlayer_client import GenLayerClient
from genlayer_py.provider import GenLayerProvider
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus
import requests
load_dotenv()

class BoundedProvider(GenLayerProvider):
    """Keep an unavailable RPC from hanging an integration process indefinitely."""
    def make_request(self, method, params):
        payload = {
            'jsonrpc': '2.0', 'id': int(time.time() * 1000),
            'method': method, 'params': params}
        for attempt in range(81):
            try:
                response = requests.post(self.url, json=payload, timeout=30)
                response.raise_for_status()
                result = response.json()
                self._raise_on_error(result, method)
                return result
            except Exception as error:
                quota = '-32029' in str(error) or (
                    isinstance(error, requests.exceptions.HTTPError)
                    and error.response is not None and error.response.status_code == 429)
                if not quota or attempt == 80:
                    raise
                print(method, 'Studio quota reached; retrying exact RPC in 60 seconds', flush=True)
                time.sleep(60)

def client(key='DEPLOYER_PRIVATE_KEY'):
    inner = GenLayerClient(studionet, Account.from_key(os.environ[key]))
    inner.provider = BoundedProvider(studionet.rpc_urls['default']['http'][0])
    inner.w3.provider = inner.provider
    inner.initialize_consensus_smart_contract()
    return inner

def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,default=str,indent=2));temp.replace(path)

def succeeded(receipt):
    entries=receipt.get('consensus_data',{}).get('leader_receipt',[])
    return receipt.get('result_name') == 'MAJORITY_AGREE' and any(e.get('mode')=='leader' and e.get('execution_result')=='SUCCESS' for e in entries)

def operation(c,operation_id,send,expected_success=True):
    path=Path('deployments/operations')/(operation_id+'.json')
    if path.exists():
        journal=json.loads(path.read_text());h=journal['transaction_hash']
        if journal.get('status')=='SIGNED':
            params=journal['broadcast_params']
            if '0x'+keccak(bytes.fromhex(params[0][2:])).hex()!=h:
                raise RuntimeError(operation_id+' signed journal hash mismatch')
            try:
                existing=c.get_transaction(h)
            except Exception as error:
                if 'not found' not in str(error).lower():raise
                existing=None
            if not existing:
                # Reuse the exact signed bytes even if the first response was lost.
                returned=c.provider.make_request('eth_sendRawTransaction',params)['result']
                if returned!=h:raise RuntimeError(operation_id+' broadcast hash mismatch')
            journal['status']='BROADCAST';atomic(path,journal)
    else:
        request=c.provider.make_request
        def journal_request(method,params):
            if method=='eth_sendRawTransaction':
                signed_hash='0x'+keccak(bytes.fromhex(params[0][2:])).hex()
                atomic(path,{'operation_id':operation_id,'transaction_hash':signed_hash,
                    'network':'studionet','status':'SIGNED','broadcast_params':params})
                return request(method,params)
            return request(method,params)
        c.provider.make_request=journal_request
        try:h=str(send())
        finally:c.provider.make_request=request
        journal=json.loads(path.read_text()) if path.exists() else {'operation_id':operation_id,'network':'studionet'}
        if journal.get('transaction_hash',h)!=h:raise RuntimeError(operation_id+' signed broadcast hash mismatch')
        journal.update(transaction_hash=h,status='BROADCAST');atomic(path,journal)
        print(operation_id,'broadcast',h,flush=True)
    receipt_path=Path('evidence/receipts')/(operation_id+'.json')
    if receipt_path.exists():
        cached=json.loads(receipt_path.read_text())
        if cached.get('hash')==h and (cached.get('status') in [7,'FINALIZED'] or cached.get('status_name')=='FINALIZED'):
            if expected_success and not succeeded(cached):raise RuntimeError(operation_id+' recorded execution failed')
            print(operation_id,'verified finalized receipt reused',flush=True)
            return cached
    for attempt in range(3):
        try:
            r=c.wait_for_transaction_receipt(h,status=TransactionStatus.FINALIZED,retries=60,interval=30000)
            break
        except Exception:
            if attempt==2:raise
            print(operation_id,'receipt transport interrupted, resuming same broadcast',flush=True)
            time.sleep(10)
    atomic(Path('evidence/receipts')/(operation_id+'.json'),r)
    ok=succeeded(r)
    journal.update(status='FINALIZED',execution_success=ok,address=r.get('to_address'))
    atomic(path,journal)
    if expected_success and not ok:
        errs=[e.get('genvm_result') for e in r.get('consensus_data',{}).get('leader_receipt',[]) if e.get('mode')=='leader']
        raise RuntimeError(operation_id+' execution failed: '+json.dumps(errs))
    print(operation_id,'finalized', 'success' if ok else 'refused',flush=True)
    return r
