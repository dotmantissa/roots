from eth_account import Account
from scripts.deploy import fingerprint,resolve_owners,deployment_args
import json
from scripts import deploy


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


def test_transferred_live_consumer_owner_survives_stale_local_key():
    key='0x'+'4'*64
    previous={'owners':{'incident':Account.from_key(key).address,'disclosure':'0x'+'2'*40}}
    live={'incident':'0x'+'5'*40,'disclosure':'0x'+'2'*40}
    def forbid_generate(kind): raise AssertionError('Existing owner must never be regenerated')
    result=resolve_owners(previous,{'DEPLOYER_PRIVATE_KEY':'0x'+'3'*64,'INCIDENT_OWNER_PRIVATE_KEY':key},forbid_generate,live)
    assert result['incident']==live['incident']


def test_hub_only_upgrade_replaces_the_one_time_bound_docket(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);monkeypatch.setattr(deploy,'ROOT',tmp_path)
    monkeypatch.setenv('DEPLOYER_PRIVATE_KEY','0x'+'3'*64)
    for kind,index in [('INCIDENT',6),('DISCLOSURE',7)]:
        monkeypatch.delenv(kind+'_OWNER_PRIVATE_KEY',raising=False)
        monkeypatch.setenv(kind+'_OWNER_ADDRESS','0x'+str(index)*40)
    (tmp_path/'contracts').mkdir()
    for name in deploy.NAMES:(tmp_path/'contracts'/f'{name}.py').write_text(name+':initial')
    steward=Account.from_key('0x'+'3'*64).address
    class Network:
        def __init__(self):self.contracts={};self.bindings={};self.transferred_owners={}
        def deploy_contract(self,code,args):
            address='0x'+str(len(self.contracts)+1).zfill(40)
            self.contracts[address]=(code.decode().split(':')[0],args)
            return {'hash':'0x'+str(len(self.contracts)).zfill(64),'data':{'contract_address':address}}
        def write_contract(self,address,function_name,args):
            if function_name=='bind_hub':
                assert address not in self.bindings or self.bindings[address]==args[0],'Old docket cannot bind a replacement hub'
                self.bindings[address]=args[0]
            return {'hash':'0x'+'0'*64}
        def read_contract(self,address,function_name,args):
            name,constructor=self.contracts[address]
            if name=='source_registry':return {'owner':steward}
            if name=='relation_docket':return {'owner':steward,'registry':constructor[0],'hub':self.bindings[address]}
            if name=='certificate_hub':return {'owner':steward,'docket':constructor[0]}
            return {'owner':self.transferred_owners.get(address,constructor[1]),'hub':constructor[0]}
    network=Network();journals={}
    def operation(client,name,send):
        if name not in journals:journals[name]=send()
        return journals[name]
    monkeypatch.setattr(deploy,'client',lambda:network);monkeypatch.setattr(deploy,'operation',operation)
    deploy.main();first=json.loads((tmp_path/'deployments/studionet.json').read_text())
    transferred='0x'+'8'*40
    network.transferred_owners[first['contracts']['incident_consumer']['address']]=transferred
    monkeypatch.delenv('INCIDENT_OWNER_ADDRESS')
    monkeypatch.setenv('INCIDENT_OWNER_PRIVATE_KEY','0x'+'4'*64)
    (tmp_path/'contracts/certificate_hub.py').write_text('certificate_hub:updated')
    deploy.main();second=json.loads((tmp_path/'deployments/studionet.json').read_text())
    assert second['owners']['incident']==transferred
    assert first['contracts']['source_registry']['address']==second['contracts']['source_registry']['address']
    for name in ['relation_docket','certificate_hub','incident_consumer','disclosure_consumer']:
        assert first['contracts'][name]['address']!=second['contracts'][name]['address']
    assert len(network.contracts)==9
    deploy.verify_stack(network,second)
