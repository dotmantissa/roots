import {useState} from 'react';
import {Dialog} from './components';
import {Address,type Deployment} from '../../../packages/sdk/src/schema';
import type {useTransactions} from './useTransactions';
export function AuthorityForm({deployment,address,write,onClose,onDone}:{deployment:Deployment;address:string|undefined;write:ReturnType<typeof useTransactions>['write'];onClose:()=>void;onDone:()=>void}){
 const [contract,setContract]=useState<keyof Deployment['contracts']>('incident_consumer');const [principal,setPrincipal]=useState('');const [quota,setQuota]=useState(16);const [action,setAction]=useState('nominate_owner');const [error,setError]=useState('');const [busy,setBusy]=useState(false);
 const key=contract==='source_registry'?'registry':contract==='relation_docket'?'docket':contract==='incident_consumer'?'incident':'disclosure';const owner=deployment.owners[key];const nominee=deployment.pending_owners?.[key];const authorized=action==='accept_owner'?nominee?.toLowerCase()===address?.toLowerCase():owner?.toLowerCase()===address?.toLowerCase();
 return <Dialog title="Connect an authorized email wallet" onClose={onClose}><form className="simple-form" onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{if(!authorized)throw Error('Sign with the current owner or nominated email wallet');await write(contract,action,action==='accept_owner'?[]:action==='authorize_requester'?[Address.parse(principal),quota]:[Address.parse(principal)]);onDone();}catch(e){setError((e as Error).message);}finally{setBusy(false);}}}>
 <p>The current owner nominates a wallet. Its email account then accepts ownership using its embedded wallet. Batch capacity is separately allocated by the docket steward.</p>
 <label>Authority<select value={contract} onChange={e=>{setContract(e.target.value as keyof Deployment['contracts']);setAction('nominate_owner');}}><option value="incident_consumer">Incident application</option><option value="disclosure_consumer">Disclosure application</option><option value="source_registry">Publisher enrollment steward</option><option value="relation_docket">Batch capacity steward</option></select></label>
 <p>Current owner: <code>{owner}</code><br/>Nominated wallet: <code>{nominee||'None'}</code><br/>Your email wallet: <code>{address||'Still preparing'}</code></p>
 <label>Authority action<select value={action} onChange={e=>setAction(e.target.value)}><option value="nominate_owner">Nominate a new email wallet</option><option value="accept_owner">Accept my ownership nomination</option>{contract==='relation_docket'&&<option value="authorize_requester">Allocate requester capacity</option>}</select></label>
 {action!=='accept_owner'&&<label>Authorized wallet address<input required value={principal} onChange={e=>setPrincipal(e.target.value)} placeholder="0x…"/></label>}
 {action==='authorize_requester'&&<label>Lifetime batch allocation<input required type="number" min={0} max={1024} value={quota} onChange={e=>setQuota(Number(e.target.value))}/></label>}
 {!authorized&&<p className="form-note">The authority shown above must sign this action. Nominations cannot be claimed by another wallet.</p>}
 {error&&<p className="error-message" role="alert">{error}</p>}<div className="dialog-footer"><span>Ownership changes after acceptance finalizes.</span><button className="button" disabled={busy||!authorized}>Submit authority change</button></div>
 </form></Dialog>;
}
