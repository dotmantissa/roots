"""Provision only necessary server secrets, through stdin and without echoing values."""
from dotenv import load_dotenv
import os,subprocess
load_dotenv()
for name in ['PRIVY_APP_ID','PRIVY_APP_SECRET','DATABASE_URL','VITE_PRIVY_APP_ID']:
    kind='secret' if name in ['PRIVY_APP_SECRET','DATABASE_URL'] else 'config'
    r=subprocess.run(['vercel','env','add',name,'production','--type',kind,'--force','--yes','--scope','mantissas-projects','--project','roots'],input=os.environ[name],text=True,capture_output=True)
    print(name,'configured' if r.returncode==0 else 'failed',flush=True)
    if r.returncode:raise SystemExit('Host environment configuration failed. No secret output is printed.')
for name in ['WEB_ORIGIN','CAPTURE_ORIGIN']:
    r=subprocess.run(['vercel','env','add',name,'production','--type','config','--force','--yes','--scope','mantissas-projects','--project','roots'],input='https://roots-mauve-delta.vercel.app',text=True,capture_output=True)
    print(name,'configured' if r.returncode==0 else 'failed',flush=True)
    if r.returncode:raise SystemExit('Public origin configuration failed')
