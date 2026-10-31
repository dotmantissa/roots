import {useState} from 'react';
import {api} from './api';
import {Dialog} from './components';
import {Address,canonical,type Publisher,type RecordCommitment} from '../../../packages/sdk/src/schema';
import type {useTransactions} from './useTransactions';
export function CustodyForm({publisher,address,registryOwner,write,onClose,onDone}:{publisher:Publisher;address:string|undefined;registryOwner:string|undefined;write:ReturnType<typeof useTransactions>['write'];onClose:()=>void;onDone:()=>void}){
 const [action,setAction]=useState('correct_affiliation');const [principal,setPrincipal]=useState('');const [url,setUrl]=useState('');const [busy,setBusy]=useState(false);const [error,setError]=useState('');
 const authorized=action==='recover_principal'?registryOwner?.toLowerCase()===address?.toLowerCase():action==='accept_principal'?!!address:address?.toLowerCase()===publisher.principal.toLowerCase();
 return <Dialog title="Correct affiliation or recover custody" onClose={onClose}><form className="simple-form" onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{
  if(action==='nominate_principal')await write('source_registry',action,[publisher.publisher_id,Address.parse(principal)]);
  else if(action==='accept_principal')await write('source_registry',action,[publisher.publisher_id]);
  else {const {record}=await api<{record:RecordCommitment}>('/captures',{record_id:publisher.evidence.record_id,authority:publisher.publisher_id,url,scope:'Public ownership and editorial affiliation',revision:publisher.revision+1},true);await write('source_registry',action,action==='recover_principal'?[crypto.randomUUID(),publisher.publisher_id,Address.parse(principal),canonical(record)]:[crypto.randomUUID(),publisher.publisher_id,canonical(record),false]);}
  onDone();
 }catch(e){setError((e as Error).message);}finally{setBusy(false);}}}>
 <p>The enrolled custodian can correct disclosures or nominate a replacement. The replacement must accept with its own wallet. The registry steward can recover an identity with a revised authorized public disclosure. Every custody change freezes older publisher revisions.</p>
 <label>Publisher<input readOnly value={publisher.publisher_id}/></label><p>Current custodian: <code>{publisher.principal}</code></p>
 <label>Custody action<select value={action} onChange={e=>setAction(e.target.value)}><option value="correct_affiliation">Correct public affiliation</option><option value="nominate_principal">Nominate replacement custodian</option><option value="accept_principal">Accept my custody nomination</option><option value="recover_principal">Steward identity recovery</option></select></label>
 {['nominate_principal','recover_principal'].includes(action)&&<label>Authorized replacement wallet<input required value={principal} onChange={e=>setPrincipal(e.target.value)} placeholder="0x…"/></label>}
 {['correct_affiliation','recover_principal'].includes(action)&&<label>Updated authorized disclosure URL<input required type="url" value={url} onChange={e=>setUrl(e.target.value)}/></label>}
 {!authorized&&<p className="form-note">Sign with the current custodian or the registry steward for this action.</p>}{action==='accept_principal'&&<p className="form-note">Only the exact nominated wallet can accept. The contract verifies that nomination.</p>}{error&&<p className="error-message" role="alert">{error}</p>}
 <div className="dialog-footer"><span>Revision changes require successor assessment.</span><button className="button" disabled={busy||!authorized}>Submit custody action</button></div>
 </form></Dialog>;
}
