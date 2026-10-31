from conftest import addr
import json
from types import SimpleNamespace
import pytest
from conftest import manifest,request,matrix,module_of

@pytest.fixture
def docket(direct_deploy,direct_owner,direct_bob,refs):
    c=direct_deploy('contracts/relation_docket.py',addr(direct_bob))
    m=module_of(c)
    sources=manifest()
    refs(m,SimpleNamespace(get_policy=lambda *a:{'min_origins':3},get_publisher=lambda key:{'revision':1,'status':'ACTIVE','evidence':sources[int(key[-1])]['ownership']}))
    c.authorize_requester(addr(direct_owner), 10)
    c.bind_hub(addr(direct_bob))
    c.open_batch(json.dumps(request(direct_owner,direct_bob)),json.dumps(sources))
    return c,m

def test_complete_fifteen_pairs_and_mutated_subset(docket,direct_vm):
    c,m=docket
    b=c.get_batch('batch1');b['pairs']=matrix();del b['pairs']['4:5'];c.batches['batch1']=m.canon(b)
    with direct_vm.expect_revert('Incomplete matrix'):
        c.seal_batch('batch1',1,'[0,1,2,3,4,5]')
    b['pairs']=matrix();c.batches['batch1']=m.canon(b)
    with direct_vm.expect_revert('canonical maximum'):
        c.seal_batch('batch1',1,'[0,1,2]')
    c.seal_batch('batch1',1,'[0,1,2,3,4,5]')
    assert len(c.get_batch('batch1')['non_merge_witnesses'])==15
    assert c.get_batch('batch1')['status']=='SEALED'

def test_copies_unknown_and_same_publisher_never_inflate(docket):
    c,m=docket
    sources=manifest();pairs=matrix(label='SHARED_ORIGIN')
    assert m.maximum_subset(sources,pairs)==[0]
    assert m.maximum_subset(sources,matrix(label='UNKNOWN'))==[0]
    sources[1]['publisher_id']=sources[0]['publisher_id']
    assert len(m.maximum_subset(sources,matrix()))==5
    pairs=matrix();pairs['0:1']=dict(pairs['0:1'],relation='UNKNOWN',witnesses=[])
    assert m.maximum_subset(manifest(),pairs)==[0,2,3,4,5]

def test_request_owner_and_conflicting_reuse(docket,direct_vm,direct_bob,direct_owner):
    c,m=docket
    r=request(direct_owner,direct_bob)
    c.open_batch(json.dumps(r),json.dumps(manifest()))
    r['subject_text']='Changed exact claim';r['subject_digest']=m.hashlib.sha256(r['subject_text'].encode()).hexdigest()
    with direct_vm.expect_revert('Conflicting request'):
        c.open_batch(json.dumps(r),json.dumps(manifest()))
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Request owner'):
        c.open_batch(json.dumps(r),json.dumps(manifest()))

def test_appeal_freezes_and_history(docket,direct_vm,direct_bob):
    c,m=docket
    b=c.get_batch('batch1');b['pairs']=matrix();c.batches['batch1']=m.canon(b)
    c.appeal_relation('appeal','batch1',1,0,1)
    assert c.get_batch('batch1')['generation']==2
    assert c.get_batch('batch1')['pairs']=={}
    assert not c.is_current('batch1',1)
    assert c.list_history(0,10)['items'][0]['status']=='SUPERSEDED'
    c.appeal_relation('appeal','batch1',1,0,1)
    with direct_vm.expect_revert('Incomplete'):
        c.seal_batch('batch1',2,'[0,1,2]')

def test_correction_and_deadline(docket,direct_vm,refs,monkeypatch):
    c,m=docket
    sources=manifest()
    refs(m,SimpleNamespace(get_publisher=lambda key:{'revision':2,'status':'ACTIVE','evidence':sources[int(key[-1])]['ownership']}))
    assert not c.is_current('batch1',1)
    with direct_vm.expect_revert('frozen'):
        c.seal_batch('batch1',1,'[0]')
    direct_vm.warp('2100-01-01T00:00:00Z')
    monkeypatch.setitem(m.gl.message_raw,'datetime','2100-01-01T00:00:00+00:00')
    c.expire_batch('batch1')
    assert c.get_batch('batch1')['status']=='TIMEOUT'

def test_source_and_complete_packet_limits_fail_before_evaluation(docket,direct_vm):
    c,m=docket
    too_large=manifest(2)[0]['publication'];too_large['byte_length']=49153
    with direct_vm.expect_revert('Invalid integer'):
        m.record(too_large)
    b=c.get_batch('batch1')
    b['manifest'][0]['publication']['byte_length']=16384
    c.batches['batch1']=m.canon(b)
    with direct_vm.expect_revert('Complete packet exceeds budget'):
        c.reserve_assessment('oversize','batch1',1,0,1)
    assert c.get_batch('batch1')['pairs']=={}
