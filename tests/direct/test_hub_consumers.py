from conftest import addr
import json
from types import SimpleNamespace
import pytest
from conftest import manifest,request,matrix,module_of

def certificate(owner,consumer):
    b=request(owner,consumer,3)
    b.update(status='FINALIZED',certificate_id='batch1:1',manifest=manifest(3),pairs=matrix(3),selected_subset=[0,1,2],supported_origin_ids=['publisher0','publisher1','publisher2'],non_merge_witnesses=[],unresolved=False,coverage=True,superseded_by='',prior_certificates=[],batch_digest='c'*64)
    return b

def test_hub_auth_finality_and_subscription(direct_deploy,direct_vm,direct_owner,direct_bob,refs):
    c=direct_deploy('contracts/certificate_hub.py',addr(direct_bob));m=module_of(c)
    cert=certificate(direct_owner,direct_bob);cert['status']='SEALED'
    refs(m,SimpleNamespace(get_batch=lambda *a:cert,is_current=lambda *a:True,get_authority=lambda:{'owner':addr(direct_bob)}))
    with direct_vm.expect_revert('Finalized docket'):
        c.publish_certificate(json.dumps(cert))
    direct_vm.sender=direct_bob
    c.publish_certificate(json.dumps(cert));c.publish_certificate(json.dumps(cert))
    assert c.list_certificates(0,10)['total']==1
    config={k:cert[k] for k in ['request_id','policy_id','policy_revision','subject_id','subject_digest','manifest_digest','consumer','consequence_digest','generation','deadline','subject_text','consequence_text','admission_scope']}
    c.subscribe('sub',addr(direct_bob),'batch1',m.digest(config))
    c.deliver_certificate('delivery','batch1:1',addr(direct_bob))
    c.deliver_certificate('delivery','batch1:1',addr(direct_bob))
    c.acknowledge_revision('delivery','batch1:1',1)
    assert c.get_delivery('delivery')['acknowledgement']['generation']==1
    refs(m,SimpleNamespace(is_current=lambda *a:False,get_authority=lambda:{'owner':addr(direct_bob)}))
    assert c.get_certificate('batch1:1')['status']=='QUARANTINED'
    with direct_vm.expect_revert('stale'):
        c.deliver_certificate('late','batch1:1',addr(direct_bob))

@pytest.mark.parametrize('file,action',[('incident_consumer','admit_incident'),('disclosure_consumer','admit_disclosure')])
def test_consumers_exact_boundary_duplicates_and_correction(file,action,direct_deploy,direct_vm,direct_owner,direct_bob,refs):
    c=direct_deploy(f'contracts/{file}.py',addr(direct_bob),addr(direct_owner));m=module_of(c)
    address=str(m.gl.message.contract_address);cert=certificate(direct_owner,address)
    config={k:cert[k] for k in ['request_id','policy_id','policy_revision','subject_id','subject_digest','manifest_digest','consumer','consequence_digest','generation','deadline','subject_text','consequence_text','admission_scope']}
    refs(m,SimpleNamespace(is_active=lambda *a:True,get_certificate=lambda *a:cert,get_batch=lambda *a:dict(cert,**config),get_subscription=lambda *a:m.digest(config)))
    c.configure('config',json.dumps(config),True)
    with direct_vm.expect_revert('Finalized certificate'):
        getattr(c,action)('a','batch1',cert['subject_digest'],cert['consequence_digest'])
    payload=dict(cert,operation_id='delivery',configuration_digest=m.digest(config))
    with direct_vm.expect_revert('Authenticated'):
        c.receive_certificate(json.dumps(payload))
    direct_vm.sender=direct_bob
    c.receive_certificate(json.dumps(payload));c.receive_certificate(json.dumps(payload))
    direct_vm.sender=direct_owner
    getattr(c,action)('a','batch1',cert['subject_digest'],cert['consequence_digest'])
    getattr(c,action)('a','batch1',cert['subject_digest'],cert['consequence_digest'])
    assert c.get_action('a')['status']=='ADMITTED'
    with direct_vm.expect_revert('binding'):
        getattr(c,action)('bad','batch1','c'*64,cert['consequence_digest'])
    direct_vm.sender=direct_bob
    forged=dict(payload,selected_subset=[0,1])
    with direct_vm.expect_revert('Mutated'):
        c.receive_certificate(json.dumps(forged))
    direct_vm.sender=direct_owner
    refs(m,SimpleNamespace(is_active=lambda *a:False,get_batch=lambda *a:dict(cert,**config)))
    with direct_vm.expect_revert('stale'):
        getattr(c,action)('fresh','batch1',cert['subject_digest'],cert['consequence_digest'])
    config['generation']=2
    c.configure('config2',json.dumps(config),True)
    with direct_vm.expect_revert('awaiting'):
        getattr(c,action)('fresh','batch1',cert['subject_digest'],cert['consequence_digest'])

@pytest.mark.parametrize('file,action',[('incident_consumer','admit_incident'),('disclosure_consumer','admit_disclosure')])
def test_new_receipt_rejects_reordered_and_unresolved_use(file,action,direct_deploy,direct_vm,direct_owner,direct_bob,refs):
    c=direct_deploy(f'contracts/{file}.py',addr(direct_bob),addr(direct_owner));m=module_of(c)
    cert=certificate(direct_owner,str(m.gl.message.contract_address))
    config={k:cert[k] for k in ['request_id','policy_id','policy_revision','subject_id','subject_digest','manifest_digest','consumer','consequence_digest','generation','deadline','subject_text','consequence_text','admission_scope']}
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Consumer owner'):
        c.configure('unauthorized',json.dumps(config),True)
    direct_vm.sender=direct_owner
    refs(m,SimpleNamespace(is_active=lambda *a:True,get_certificate=lambda *a:cert,get_batch=lambda *a:dict(cert,**config),get_subscription=lambda *a:m.digest(config)))
    c.configure('first-config',json.dumps(config),True)
    refs(m,SimpleNamespace(is_active=lambda *a:True,get_certificate=lambda *a:cert,get_batch=lambda *a:dict(cert,**config),get_subscription=lambda *a:m.digest(config)))
    first=dict(cert,operation_id='first-delivery',configuration_digest=m.digest(config))
    direct_vm.sender=direct_bob;c.receive_certificate(json.dumps(first))
    direct_vm.sender=direct_owner
    config=dict(config,generation=2);c.configure('second-config',json.dumps(config),True)
    cert=dict(cert,generation=2,certificate_id='batch1:2',status='UNRESOLVED',unresolved=True)
    second=dict(cert,operation_id='second-delivery',configuration_digest=m.digest(config))
    direct_vm.sender=direct_bob;c.receive_certificate(json.dumps(second));c.receive_certificate(json.dumps(second))
    with direct_vm.expect_revert('configuration mismatch'):
        c.receive_certificate(json.dumps(first))
    state=c.get_state('batch1');assert state['last_generation']==2 and state['receipt']['operation_id']=='second-delivery'
    direct_vm.sender=direct_owner
    with direct_vm.expect_revert('Three certified'):
        getattr(c,action)('unresolved-use','batch1',cert['subject_digest'],cert['consequence_digest'])
