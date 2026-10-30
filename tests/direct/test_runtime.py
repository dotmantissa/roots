from conftest import addr

def test_pinned_runtime_storage_identity(direct_deploy,direct_owner):
    probe=direct_deploy('contracts/runtime_probe.py')
    result=probe.identity()
    assert result['owner'].lower()==addr(direct_owner).lower()
    assert result['runner']=='1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6'
