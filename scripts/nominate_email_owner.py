"""Nominate an embedded email wallet; only that wallet can accept in Applications."""
import argparse
import json
from pathlib import Path
from network import client, operation

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--consumer',choices=['incident','disclosure'],required=True)
parser.add_argument('--address',required=True)
parser.add_argument('--batch-quota',type=int,default=0,help='Allocate lifetime batch capacity using the docket steward key')
args=parser.parse_args()
deployment=json.loads(Path('deployments/studionet.json').read_text())
owner=client(args.consumer.upper()+'_OWNER_PRIVATE_KEY')
address=deployment['contracts'][args.consumer+'_consumer']['address']
if args.batch_quota:
    steward=client()
    operation(steward,'email-capacity-'+deployment['release_id'][:12]+'-'+args.address[2:18].lower()+'-'+str(args.batch_quota),lambda:steward.write_contract(address=deployment['contracts']['relation_docket']['address'],function_name='authorize_requester',args=[args.address,args.batch_quota]))
operation(owner,'nominate-email-'+deployment['release_id'][:12]+'-'+args.consumer+'-'+args.address[2:18].lower(),lambda:owner.write_contract(address=address,function_name='nominate_owner',args=[args.address]))
print('Nomination finalized. Sign in with the nominated email wallet and choose Applications → Connect authorized email wallet → Accept my ownership nomination.')
