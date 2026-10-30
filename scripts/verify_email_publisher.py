"""Verify actual email signed publisher operations against finalized contract state."""
import json
from pathlib import Path
from network import client,operation,atomic
c=client();d=json.loads(Path('deployments/studionet.json').read_text())
for name,revision in [('registration',1),('correction',2)]:
 path=Path('evidence/email-publisher-'+name+'.json')
 if not path.exists():continue
 evidence=json.loads(path.read_text())
 broadcast=next(x for x in evidence['operations'] if x.get('transaction_hash'))
 op='email-publisher-'+name
 atomic(Path('deployments/operations')/(op+'.json'),{'operation_id':op,'transaction_hash':broadcast['transaction_hash']})
 receipt=operation(c,op,lambda:None)
 publisher=c.read_contract(address=d['contracts']['source_registry']['address'],function_name='get_publisher',args=[evidence['publisher_id']])
 assert publisher['principal'].lower()==receipt['from_address'].lower()
 assert publisher['revision']>=revision and publisher['status']=='ACTIVE'
 evidence.update(network='studionet',finalized=True,publisher=publisher)
 atomic(path,evidence)
 print('Finalized email publisher',name,'verified')
