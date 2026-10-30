import json
from pathlib import Path
from dotenv import load_dotenv
import os
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus
load_dotenv()
c = create_client(chain=studionet, account=Account.from_key(os.environ["DEPLOYER_PRIVATE_KEY"]))
p = Path("deployments/runtime-probe.json")
if p.exists():
    h = json.loads(p.read_text())["transaction_hash"]
else:
    h = c.deploy_contract(code=Path("contracts/runtime_probe.py").read_bytes(), args=[])
    p.write_text(json.dumps({"transaction_hash":str(h), "network":"studionet", "runner":"1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6"}, indent=2))
    print("Broadcast", h, flush=True)
r = c.wait_for_transaction_receipt(h, status=TransactionStatus.FINALIZED, retries=120, interval=5000)
Path("evidence/runtime-probe-receipt.json").write_text(json.dumps(r,default=str,indent=2))
print(json.dumps(r,default=str))
