def addr(value):
    return "0x" + value.hex() if isinstance(value, bytes) else str(value)

import json
import hashlib
from types import SimpleNamespace
import pytest


def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def sha(x):
    return hashlib.sha256(x.encode() if isinstance(x,str) else x).hexdigest()

def rec(name,content='Independent measurement by a disclosed organization.',revision=1):
    data=content.encode()
    return {'record_id':name,'authority':name,'channel':'public','url':'https://evidence.example/'+name,'capture_url':'https://evidence.example/'+name,'byte_hash':sha(data),'byte_length':len(data),'revision':revision,'scope':'measurement and editorial control','spans':[{'span_id':'whole','start':0,'end':len(data),'quote_hash':sha(data)}]}

def manifest(n=6):
    return [{'publisher_id':f'publisher{i}','publisher_revision':1,'publication':rec(f'pub{i}'),'ownership':rec(f'owner{i}')} for i in range(n)]

def decision(label='INDEPENDENT'):
    return {'relation':label,'rule_id':'R_INDEPENDENT_PROCESS' if label=='INDEPENDENT' else 'R_AMBIGUOUS' if label=='UNKNOWN' else 'R_SYNDICATION','scope':'editorial_or_measurement_origin','witnesses':[] if label=='UNKNOWN' else [{'source_hash':'a'*64,'span_id':'whole','record_id':'pub0','start':0,'end':5,'quote_hash':'b'*64}],'coverage':label!='UNKNOWN','unresolved':label=='UNKNOWN'}

def matrix(n=6,label='INDEPENDENT'):
    return {f'{a}:{b}':decision(label) for a in range(n) for b in range(a+1,n)}

def request(owner,consumer,n=6):
    return {'request_id':'batch1','owner':addr(owner),'parties':[addr(owner)],'policy_id':'three_origins','policy_revision':1,'subject_id':'river_reading','subject_digest':'a'*64,'manifest_digest':sha(canonical(manifest(n))),'consumer':addr(consumer),'consequence_digest':'b'*64,'generation':1,'deadline':'2099-01-01T00:00:00+00:00'}

@pytest.fixture
def refs(monkeypatch,direct_deploy):
    # Cross-contract reads are isolated here. Real authenticated messages are exercised on Studio.
    def connect(module,view):
        def get(_):
            return SimpleNamespace(view=lambda:view,emit=lambda **kw:SimpleNamespace(**{name:(lambda *a:None) for name in ['publish_certificate','subscribe','receive_certificate','acknowledge_revision']}))
        monkeypatch.setattr(module.gl,'get_contract_at',get)
    return connect

def module_of(contract):
    import sys
    return sys.modules[type(contract).__module__]
