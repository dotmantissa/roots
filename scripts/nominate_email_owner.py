"""Nominate an embedded email wallet; only that wallet can accept in Applications."""
import argparse
import json
from pathlib import Path
from network import client, operation

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--consumer',choices=['incident','disclosure'],required=True)
parser.add_argument('--address',required=True)
args=parser.parse_args()
deployment=json.loads(Path('deployments/studionet.json').read_text())
owner=client(args.consumer.upper()+'_OWNER_PRIVATE_KEY')
address=deployment['contracts'][args.consumer+'_consumer']['address']
operation(owner,'nominate-email-'+deployment['release_id'][:12]+'-'+args.consumer+'-'+args.address[2:18].lower(),lambda:owner.write_contract(address=address,function_name='nominate_owner',args=[args.address]))
print('Nomination finalized. Sign in with the nominated email wallet and choose Applications → Connect authorized email wallet → Accept my ownership nomination.')
