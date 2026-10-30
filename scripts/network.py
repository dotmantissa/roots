"""Signed Studio operations with durable, operation-addressable receipts."""
import json,os,time,hashlib
from pathlib import Path
from dotenv import load_dotenv
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus
load_dotenv()

class QuotaClient:
    """Resume explicit RPC quota refusals without replacing a signed operation.

    Other transport failures still propagate: their broadcast outcome may be
    ambiguous and must not trigger a fresh transaction.
    """
    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        method = getattr(self.inner, name)
        if not callable(method):
            return method
        def invoke(*args, **kwargs):
            for attempt in range(81):
                try:
                    return method(*args, **kwargs)
                except Exception as error:
                    if '-32029' not in str(error) or attempt == 80:
                        raise
                    print(name, 'hourly Studio quota reached; retrying in 60 seconds', flush=True)
                    time.sleep(60)
        return invoke

def client(key='DEPLOYER_PRIVATE_KEY'):
    return QuotaClient(create_client(chain=studionet,account=Account.from_key(os.environ[key])))

def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,default=str,indent=2));temp.replace(path)

def succeeded(receipt):
    entries=receipt.get('consensus_data',{}).get('leader_receipt',[])
    return receipt.get('result_name') == 'MAJORITY_AGREE' and any(e.get('mode')=='leader' and e.get('execution_result')=='SUCCESS' for e in entries)

def operation(c,operation_id,send,expected_success=True):
    path=Path('deployments/operations')/(operation_id+'.json')
    if path.exists(): h=json.loads(path.read_text())['transaction_hash']
    else:
        h=str(send());atomic(path,{'operation_id':operation_id,'transaction_hash':h,'network':'studionet','status':'BROADCAST'})
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
    atomic(path,{'operation_id':operation_id,'transaction_hash':h,'network':'studionet','status':'FINALIZED','execution_success':ok,'address':r.get('to_address')})
    if expected_success and not ok:
        errs=[e.get('genvm_result') for e in r.get('consensus_data',{}).get('leader_receipt',[]) if e.get('mode')=='leader']
        raise RuntimeError(operation_id+' execution failed: '+json.dumps(errs))
    print(operation_id,'finalized', 'success' if ok else 'refused',flush=True)
    return r
