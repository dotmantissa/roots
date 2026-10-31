import json
from types import SimpleNamespace
import pytest
from conftest import addr, rec, manifest, request, matrix, module_of, canonical, sha


def test_namespace_requires_enrollment_and_has_authenticated_recovery(direct_deploy, direct_vm, direct_owner, direct_bob):
    c = direct_deploy('contracts/source_registry.py')
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('Registry owner enrollment'):
        c.register_publisher('squat', 'recognizable-org', addr(direct_bob), canonical(rec('owner')))
    direct_vm.sender = direct_owner
    c.register_publisher('enroll', 'recognizable-org', addr(direct_bob), canonical(rec('owner')))
    direct_vm.sender = direct_bob
    c.nominate_principal('recognizable-org', addr(direct_owner))
    with direct_vm.expect_revert('Nominated principal'):
        c.accept_principal('recognizable-org')
    direct_vm.sender = direct_owner
    c.accept_principal('recognizable-org')
    assert c.get_publisher('recognizable-org')['revision'] == 2
    c.recover_principal('recover', 'recognizable-org', addr(direct_bob), canonical(rec('restored', revision=3)))
    c.recover_principal('recover', 'recognizable-org', addr(direct_bob), canonical(rec('restored', revision=3)))
    assert c.get_publisher('recognizable-org')['principal'].lower() == addr(direct_bob).lower()
    assert c.get_publisher('recognizable-org')['revision'] == 3


@pytest.fixture
def reserved_docket(direct_deploy, direct_owner, direct_bob, refs):
    c = direct_deploy('contracts/relation_docket.py', addr(direct_bob))
    m = module_of(c)
    sources = manifest(3)
    refs(m, SimpleNamespace(get_policy=lambda *a:{'min_origins':3}, get_publisher=lambda key:{'revision':sources[int(key[-1])]['publisher_revision'], 'status':'ACTIVE', 'evidence':sources[int(key[-1])]['ownership']}))
    c.authorize_requester(addr(direct_owner), 2)
    c.bind_hub(addr(direct_bob))
    c.open_batch(canonical(request(direct_owner, direct_bob,3)), canonical(sources))
    return c, m, sources


def test_failed_children_consume_attempts_and_direct_execution_is_refused(reserved_docket, direct_vm):
    c, m, sources = reserved_docket
    with direct_vm.expect_revert('Finalized assessment reservation'):
        c.assess_pair('batch1', 1, 0, 1, 'fake')
    for i in range(3):
        c.reserve_assessment(f'attempt-{i}', 'batch1', 1, 0, 1)
        # No child is executed: its failure cannot undo a finalized reservation.
    assert c.get_batch('batch1')['attempts']['0:1'] == 3
    with direct_vm.expect_revert('Assessment retry limit'):
        c.reserve_assessment('fourth', 'batch1', 1, 0, 1)
    with direct_vm.expect_revert('Material evidence revision'):
        c.acknowledge_revision('reset', 'batch1', canonical(sources), '2099-02-01T00:00:00Z')
    sources[0]['publication'] = dict(sources[0]['publication'], revision=2, url='https://mirror.example/report')
    c.acknowledge_revision('mirror', 'batch1', canonical(sources), '2099-02-01T00:00:00Z')
    assert c.get_batch('batch1')['attempts']['0:1'] == 3
    with direct_vm.expect_revert('Assessment retry limit'):
        c.reserve_assessment('mirror-fourth', 'batch1', 2, 0, 1)


def test_appeal_commitments_include_generation_and_all_parties(reserved_docket):
    c,m,_ = reserved_docket
    initial = c.get_batch('batch1')
    initial['pairs'] = matrix(3)
    c.batches['batch1'] = m.canon(initial)
    c.appeal_relation('appeal', 'batch1', 1, 0, 1)
    current = c.get_batch('batch1')
    assert current['batch_digest'] == m.batch_commitment(current)
    assert current['batch_digest'] != initial['batch_digest']
    assert m.batch_commitment(dict(current,parties=[])) != current['batch_digest']


def test_public_callers_cannot_take_reserved_capacity(reserved_docket, direct_vm, direct_bob):
    c,m,sources=reserved_docket
    direct_vm.sender=direct_bob
    r=request(direct_bob,direct_bob,3);r['request_id']='attack'
    with direct_vm.expect_revert('Authorized requester capacity'):
        c.open_batch(canonical(r),canonical(sources))
    with direct_vm.expect_revert('Docket owner'):
        c.authorize_requester(addr(direct_bob),1024)
    assert c.get_capacity(addr(direct_bob))['quota']==0


def test_structured_witnesses_require_exact_coverage_and_cannot_collide(direct_deploy,direct_vm):
    c=direct_deploy('contracts/relation_docket.py','0x'+'1'*40);m=module_of(c)
    records=[rec(x) for x in ['a','a:b','c','c:d']]
    packet=[{'record':r} for r in records]
    result={'relation':'INDEPENDENT','rule_id':'R_INDEPENDENT_PROCESS','witness_ids':[canonical([r['record_id'],'whole']) for r in [records[1],records[3]]]}
    with direct_vm.expect_revert('Incomplete evidence coverage'):
        m.canonical_decision(result,packet)
    result['witness_ids']=[canonical([r['record_id'],'whole']) for r in records]
    decision=m.canonical_decision(result,packet)
    assert decision['coverage'] and len(decision['witnesses'])==4
    assert canonical(['a:b','c']) != canonical(['a','b:c'])


@pytest.mark.parametrize('url',['https://127.0.0.1:8443/data','https://10.0.0.1/data','https://localhost/data','https://good.org@127.0.0.1/data','https://good.org\\@evil.org/data','https://good.org:444/data','https://[::1]/data','https://good.org/#fragment'])
def test_contract_and_capture_url_boundary(direct_deploy,direct_vm,url):
    c=direct_deploy('contracts/source_registry.py');m=module_of(c)
    with direct_vm.expect_revert():
        m.record(dict(rec('a'),url=url))


def test_contract_schemas_reject_extra_fields_utf8_overflow_and_wrong_preimages(reserved_docket,direct_vm):
    c,m,sources=reserved_docket
    with direct_vm.expect_revert('Unexpected or missing fields'):
        m.record(dict(rec('a'),injected=True))
    with direct_vm.expect_revert('Invalid text size'):
        m.record(dict(rec('a'),record_id='é'*65))
    r=c.get_batch('batch1')
    payload={k:r[k] for k in m.REQUEST_FIELDS}
    with direct_vm.expect_revert('Preimage digest mismatch'):
        m.envelope(canonical(dict(payload,subject_text='unrelated hidden claim')))


def test_transport_exceptions_have_terminal_unavailable_outcome(direct_deploy,monkeypatch):
    c=direct_deploy('contracts/relation_docket.py','0x'+'1'*40);m=module_of(c)
    def timeout(*args): raise TimeoutError('Transport timed out')
    monkeypatch.setattr(m.gl.nondet.web,'get',timeout)
    result=m.evaluate_pair([rec('a')])
    assert result['relation']=='UNKNOWN' and result['rule_id']=='R_UNAVAILABLE'
    assert m.independent_validator(m.gl.vm.Return(result),lambda:m.evaluate_pair([rec('a')]),[rec('a')])


def test_independent_consensus_accepts_distinct_valid_multispan_choices(direct_deploy):
    c=direct_deploy('contracts/relation_docket.py','0x'+'1'*40);m=module_of(c)
    records=[rec(f'r{i}','Owners disclose separate measurement processes. More original measurements.') for i in range(4)]
    for r in records:
        r['spans'].append(dict(r['spans'][0],span_id='alternate'))
    packet=[{'record':r} for r in records]
    def choice(span,rule='R_INDEPENDENT_PROCESS'):
        return m.canonical_decision({'relation':'INDEPENDENT','rule_id':rule,'witness_ids':[canonical([r['record_id'],span]) for r in records]},packet)
    first=choice('whole');second=choice('alternate')
    verified=[]
    assert m.independent_validator(m.gl.vm.Return(first),lambda:second,records,lambda p:verified.append(p) or True)
    assert verified==[first]
    assert not m.independent_validator(m.gl.vm.Return(first),lambda:second,records,lambda p:False)
    assert not m.independent_validator(m.gl.vm.Return(dict(first,witnesses=[])),lambda:second,records,lambda p:True)


def test_failed_publication_can_retry_same_generation_without_reassessment(reserved_docket,monkeypatch,direct_vm,direct_bob):
    c,m,_=reserved_docket
    batch=c.get_batch('batch1');batch['pairs']=matrix(3);c.batches['batch1']=canonical(batch)
    original=m.gl.get_contract_at;emitted=[]
    def get(address):
        if str(address).lower() == str(c.hub).lower():
            return SimpleNamespace(emit=lambda **kw:SimpleNamespace(publish_certificate=lambda raw:emitted.append(json.loads(raw))),view=lambda:SimpleNamespace(has_certificate=lambda *a:False,get_publisher=original(address).view().get_publisher))
        return original(address)
    monkeypatch.setattr(m.gl,'get_contract_at',get)
    c.seal_batch('batch1',1,'[0,1,2]')
    assert not c.publication_state('batch1')['published']
    c.seal_batch('batch1',1,'[0,1,2]')
    assert len(emitted)==2 and emitted[0]==emitted[1]
    assert c.get_batch('batch1')['generation']==1
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Request owner publication retry'):
        c.seal_batch('batch1',1,'[0,1,2]')


@pytest.mark.parametrize('file',['incident_consumer','disclosure_consumer'])
def test_failed_subscription_can_retry_original_configuration_and_requires_relevance_review(file,direct_deploy,direct_vm,direct_owner,direct_bob,monkeypatch):
    c=direct_deploy(f'contracts/{file}.py',addr(direct_bob),addr(direct_owner));m=module_of(c)
    batch=request(direct_owner,str(m.gl.message.contract_address),3)
    config=m.configuration_value(batch);emitted=[]
    monkeypatch.setattr(m.gl,'get_contract_at',lambda address:SimpleNamespace(view=lambda:SimpleNamespace(get_batch=lambda *a:batch,get_subscription=lambda *a:''),emit=lambda **kw:SimpleNamespace(subscribe=lambda *a:emitted.append(a))))
    with direct_vm.expect_revert('Owner must review'):
        c.configure('config',canonical(config),False)
    c.configure('config',canonical(config),True)
    c.configure('config',canonical(config),True)
    assert len(emitted)==2 and emitted[0]==emitted[1]
    assert c.get_state('batch1')['subscription_digest']==''
    with direct_vm.expect_revert('Reuse the original'):
        c.configure('different',canonical(config),True)
    c.nominate_owner(addr(direct_bob))
    direct_vm.sender=direct_bob;c.accept_owner()
    assert c.get_authority()['owner'].lower()==addr(direct_bob).lower()


def test_expiry_changes_views_and_refuses_delivery_and_unique_delivery_is_bounded(direct_deploy,direct_vm,direct_owner,direct_bob,refs,monkeypatch):
    from test_hub_consumers import certificate
    c=direct_deploy('contracts/certificate_hub.py',addr(direct_bob));m=module_of(c)
    cert=certificate(direct_owner,direct_bob);cert['status']='SEALED'
    refs(m,SimpleNamespace(get_batch=lambda *a:cert,is_current=lambda *a:True,get_authority=lambda:{'owner':addr(direct_owner)}))
    direct_vm.sender=direct_bob;c.publish_certificate(canonical(cert))
    c.subscribe('subscription',addr(direct_bob),'batch1',m.digest(m.configuration_value(cert)))
    direct_vm.sender=direct_owner;c.deliver_certificate('delivery','batch1:1',addr(direct_bob))
    with direct_vm.expect_revert('Reuse the certificate delivery'):
        c.deliver_certificate('unbounded','batch1:1',addr(direct_bob))
    direct_vm.sender=direct_bob
    with direct_vm.expect_revert('Request or consumer owner'):
        c.deliver_certificate('public','batch1:1',addr(direct_bob))
    monkeypatch.setitem(m.gl.message_raw,'datetime','2100-01-01T00:00:00Z')
    assert not c.is_active('batch1:1')
    assert c.get_certificate('batch1:1')['status']=='TIMEOUT'
    direct_vm.sender=direct_owner
    with direct_vm.expect_revert('stale'):
        c.deliver_certificate('delivery','batch1:1',addr(direct_bob))


def test_validator_verifies_exact_utf8_citation_preimages(direct_deploy,monkeypatch):
    c=direct_deploy('contracts/relation_docket.py','0x'+'1'*40);m=module_of(c)
    records=[rec(f'r{i}','é Separately measured by this organization.') for i in range(4)]
    packet=[{'record':r,'untrusted_text':'é Separately measured by this organization.'} for r in records]
    proposal=m.canonical_decision({'relation':'INDEPENDENT','rule_id':'R_INDEPENDENT_PROCESS','witness_ids':[[r['record_id'],'whole'] for r in records]},packet)
    monkeypatch.setattr(m,'fetch_packet',lambda r:packet)
    seen=[]
    monkeypatch.setattr(m.gl.nondet,'exec_prompt',lambda prompt,**kw:seen.append(prompt) or {'supported':True})
    assert m.verify_pair_proposal(records,proposal)
    assert 'exact_cited_quotes' in seen[0] and 'é Separately measured' in seen[0]
    proposal['witnesses'][0]['end']=1
    assert not m.verify_pair_proposal(records,proposal)


def test_operation_ids_cannot_poison_request_namespace(reserved_docket,direct_owner,direct_bob):
    c,m,sources=reserved_docket
    c.reserve_assessment('future_request','batch1',1,0,1)
    second=request(direct_owner,direct_bob,3);second['request_id']='future_request'
    c.open_batch(canonical(second),canonical(sources))
    assert c.get_batch('future_request')['generation']==1


def test_subscription_operation_cannot_overwrite_request_binding(direct_deploy,direct_vm,direct_owner,direct_bob,refs):
    from test_hub_consumers import certificate
    c=direct_deploy('contracts/certificate_hub.py',addr(direct_bob));m=module_of(c)
    batch=certificate(direct_owner,direct_bob)
    refs(m,SimpleNamespace(get_batch=lambda *a:batch))
    direct_vm.sender=direct_bob
    op=addr(direct_bob)+':batch1';config=m.digest(m.configuration_value(batch))
    c.subscribe(op,addr(direct_bob),'batch1',config)
    c.subscribe(op,addr(direct_bob),'batch1',config)
    assert c.get_subscription(addr(direct_bob),'batch1')==config


@pytest.mark.parametrize('file',['incident_consumer','disclosure_consumer'])
def test_delivery_id_cannot_collide_with_configuration_id(file,direct_deploy,direct_vm,direct_owner,direct_bob,refs):
    from test_hub_consumers import certificate
    c=direct_deploy(f'contracts/{file}.py',addr(direct_bob),addr(direct_owner));m=module_of(c)
    cert=certificate(direct_owner,str(m.gl.message.contract_address));config=m.configuration_value(cert)
    refs(m,SimpleNamespace(get_batch=lambda *a:cert,get_certificate=lambda *a:cert,is_active=lambda *a:True,get_subscription=lambda *a:m.digest(config)))
    c.configure('same-public-id',canonical(config),True)
    direct_vm.sender=direct_bob
    c.receive_certificate(canonical(dict(cert,configuration_digest=m.digest(config),operation_id='same-public-id')))
    assert c.get_state('batch1')['receipt']['operation_id']=='same-public-id'
