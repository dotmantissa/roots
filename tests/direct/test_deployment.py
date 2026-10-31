from eth_account import Account
from scripts.deploy import fingerprint,resolve_owners,deployment_args


def test_deployment_identity_includes_constructor_dependencies_and_owner():
    owner='0x'+'1'*40;old=['0x'+'2'*40];new=['0x'+'3'*40]
    assert fingerprint('a'*64,old,owner)!=fingerprint('a'*64,new,owner)
    assert fingerprint('a'*64,old,owner)!=fingerprint('a'*64,old,'0x'+'4'*40)
    contracts={'source_registry':{'address':old[0]},'relation_docket':{'address':new[0]},'certificate_hub':{'address':'0x'+'5'*40}}
    owners={'incident':'0x'+'6'*40,'disclosure':'0x'+'7'*40}
    assert deployment_args('relation_docket',contracts,owners)==old
    assert deployment_args('certificate_hub',contracts,owners)==new
    assert deployment_args('incident_consumer',contracts,owners)==[contracts['certificate_hub']['address'],owners['incident']]


def test_missing_local_owner_keys_preserve_existing_authorities():
    previous={'owners':{'incident':'0x'+'1'*40,'disclosure':'0x'+'2'*40}}
    def forbid_generate(kind): raise AssertionError('Existing owner must never be regenerated')
    result=resolve_owners(previous,{'DEPLOYER_PRIVATE_KEY':'0x'+'3'*64},forbid_generate)
    assert result['incident']==previous['owners']['incident'] and result['disclosure']==previous['owners']['disclosure']
