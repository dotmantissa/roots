from conftest import addr
import json
from conftest import rec

def test_publisher_permissions_revision_idempotency(direct_deploy,direct_vm,direct_owner,direct_bob):
    c=direct_deploy('contracts/source_registry.py')
    r=rec('owner')
    c.register_publisher('register','publisher',addr(direct_owner),json.dumps(r))
    c.register_publisher('register','publisher',addr(direct_owner),json.dumps(r))
    assert c.get_publisher('publisher')['revision']==1
    with direct_vm.expect_revert('Conflicting'):
        c.register_publisher('register','publisher',addr(direct_owner),json.dumps(rec('different')))
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Publisher principal'):
        c.correct_affiliation('correct','publisher',json.dumps(rec('owner',revision=2)),False)
    direct_vm.sender=direct_owner
    c.correct_affiliation('correct','publisher',json.dumps(rec('owner',revision=2)),True)
    assert c.get_publisher('publisher')['status']=='QUARANTINED'
    assert c.get_publisher('publisher')['revision']==2
    assert c.list_records('publishers',0,10)['total']==1

def test_policy_locked_versions(direct_deploy,direct_vm,direct_bob,direct_owner):
    c=direct_deploy('contracts/source_registry.py')
    policy=json.dumps({'min_origins':3,'max_sources':6,'unresolved_consequence':'REFUSE_ADMISSION'})
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Registry owner'):
        c.register_source_policy('p','policy',1,policy)
    direct_vm.sender=direct_owner
    c.register_source_policy('p','policy',1,policy)
    c.register_source_policy('p','policy',1,policy)
    with direct_vm.expect_revert('version exists'):
        c.register_source_policy('p2','policy',1,policy)
    with direct_vm.expect_revert('gap'):
        c.register_source_policy('p3','policy',3,policy)
    c.register_source_policy('p2','policy',2,policy)
    assert c.get_policy('policy',1)['revision']==1
    assert c.list_records('policies',0,10)['total']==2
